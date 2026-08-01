"""Parent-owned V4 verification execution for the fixed localhost campaign.

The executor never accepts a URL, body, credential, approval, or evidence
reference from a role.  It reconstructs each request from the frozen campaign,
consumes a V4 approval exactly once, and commits the corresponding evidence
before exposing a result to later promotion/reporting stages.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field

from .campaign_v4 import VerificationActionV4, VerificationCampaignPlanV4
from .evidence import EvidenceArtifactRef, EvidenceBinding, EvidenceStore, HeaderField
from .ledgers_v4 import (
    ActionFingerprintV4,
    ActionLedgerV4,
    ActionRiskV4,
)
from .runtime import HttpRequest, PinnedHttpTransport, PolicyEngine, RunContext
from .runtime.agents import TaskEnvelope
from .security_v3 import IdentityVaultV3
from .security_v4 import (
    ApprovalBatchV4,
    ApprovalConsumptionV4,
    V4SecurityError,
    verify_approval_batch_v4,
)

_DIGEST = r"^sha256:[0-9a-f]{64}$"
_ID = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$"


class GovernedExecutionV4Error(RuntimeError):
    """A V4 request could not retain its complete authority and evidence chain."""


class ExecutionResultV4(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    action_id: str = Field(pattern=_ID)
    action_digest: str = Field(pattern=_DIGEST)
    candidate_id: str = Field(pattern=_ID)
    status_code: int = Field(ge=100, le=599)
    headers: dict[str, str]
    evidence: EvidenceArtifactRef
    approval_consumption_digest: str = Field(pattern=_DIGEST)
    action_ledger_event_digest: str = Field(pattern=_DIGEST)


class GovernedExecutorV4:
    """Execute only signed V4 actions with parent-held credentials and transport."""

    def __init__(
        self,
        context: RunContext,
        campaign: VerificationCampaignPlanV4,
        *,
        approval_batch: ApprovalBatchV4,
        approval_trust_store: Any,
        policy_engine: PolicyEngine,
        evidence_store: EvidenceStore,
        transport: PinnedHttpTransport,
        identity_vault: IdentityVaultV3,
    ) -> None:
        if (campaign.run_id, campaign.scope_digest) != (context.run_id, context.scope_digest):
            raise GovernedExecutionV4Error("campaign crosses the V4 run or scope")
        try:
            verify_approval_batch_v4(approval_batch, campaign, approval_trust_store)
        except V4SecurityError as exc:
            raise GovernedExecutionV4Error("V4 approval batch is not executable") from exc
        self.context = context
        self.campaign = campaign
        self.batch = approval_batch
        self.policy_engine = policy_engine
        self.evidence_store = evidence_store
        self.transport = transport
        self.identity_vault = identity_vault
        self.ledger = ActionLedgerV4(context)

    def execute(self, action: VerificationActionV4, *, task_id: str) -> ExecutionResultV4:
        """Execute one exact approved action, without transport retry on ambiguity."""

        authoritative = next(
            (item for item in self.campaign.actions if item.action_id == action.action_id), None
        )
        if authoritative != action:
            raise GovernedExecutionV4Error("requested V4 action is not in the frozen campaign")
        if action.action_digest not in self.batch.action_digests:
            raise GovernedExecutionV4Error("approval does not bind this exact V4 action")
        task = TaskEnvelope(
            version="4",
            run_id=self.context.run_id,
            task_id=task_id,
            role="verifier",
            scope_digest=self.context.scope_digest,
            payload={"operation": "verification", "action_digest": action.action_digest},
            request_budget=1,
            allowed_actions=(action.action_kind,),
            evidence_required=True,
        )
        fingerprint = ActionFingerprintV4(
            run_id=self.context.run_id,
            scope_digest=self.context.scope_digest,
            action_kind=action.action_kind,
            method=action.method,
            canonical_url=action.target_url,
            canonical_body_sha256=action.body_sha256,
            identity_binding_digest=action.identity_binding_digest,
            causal_dependency_digest=(
                None
                if not action.depends_on
                else "sha256:"
                + hashlib.sha256(
                    json.dumps(action.depends_on, separators=(",", ":")).encode()
                ).hexdigest()
            ),
            follow_redirects=action.follow_redirects,
            risk=ActionRiskV4(action.risk_group),
        )
        reservation = self.ledger.reserve(
            fingerprint,
            owner_task_id=task.task_id,
            candidate_consumers=action.candidate_consumers,
            action_id=action.action_id,
            action_digest=action.action_digest,
        )
        if reservation.disposition == "reused":
            return self._load_reused(action)

        evidence_id = f"evidence-{uuid.uuid4().hex}"
        request_id = f"{task.task_id}:gateway:0"
        consumption = ApprovalConsumptionV4(
            consumption_id=f"consumption-{uuid.uuid4().hex}",
            run_id=self.context.run_id,
            scope_digest=self.context.scope_digest,
            campaign_id=self.campaign.campaign_id,
            campaign_digest=self.campaign.digest,
            approval_id=self.batch.approval_id,
            approval_batch_digest=self.batch.digest,
            candidate_id=action.candidate_id,
            action_id=action.action_id,
            action_digest=action.action_digest,
            task_id=task.task_id,
            task_input_sha256=task.input_hash(),
            request_id=request_id,
            evidence_id=evidence_id,
            consumed_at=datetime.now(UTC),
        )
        try:
            self.policy_engine.assert_automation()
            self.context.write_json_exclusive(
                f"governance_v4/consumptions/{consumption.consumption_id}.json",
                consumption.model_dump(mode="json"),
            )
            target = self.policy_engine.resolve_url(action.target_url)
            body = _body_for(action)
            headers = _headers_for(action, body, self.identity_vault)
        except Exception:
            self.ledger.mark_failed_before_transport(reservation)
            raise
        started = self.ledger.mark_transport_started(
            reservation,
            approval_batch_digest=self.batch.digest,
            consumption_digest=consumption.digest,
        )
        try:
            response = self.transport(
                HttpRequest(
                    method=action.method,
                    url=action.target_url,
                    connect_ip=target.connect_ip,
                    host_header=headers["Host"],
                    tls_server_name=target.host if target.scheme == "https" else None,
                    headers=headers,
                    body=body,
                    response_body_limit=self.policy_engine.policy.evidence_capture_max_bytes,
                )
            )
            ref = self.evidence_store.capture(
                binding=EvidenceBinding(
                    evidence_id=evidence_id,
                    run_id=self.context.run_id,
                    scope_digest=self.context.scope_digest,
                    task_id=task.task_id,
                    task_input_sha256=task.input_hash(),
                    role="verifier",
                    request_id=request_id,
                    action_id=action.action_id,
                    action_digest=action.action_digest,
                    plan_digest=self.campaign.digest,
                    approval_bundle_id=self.batch.approval_id,
                    approval_bundle_digest=self.batch.digest,
                    approval_consumption_digest=consumption.digest,
                    captured_at=datetime.now(UTC),
                ),
                request_method=action.method,
                request_url=action.target_url,
                request_headers=tuple(
                    HeaderField(name=key, value=value) for key, value in headers.items()
                ),
                request_body=body,
                response_status=response.status_code,
                response_headers=tuple(
                    HeaderField(name=key, value=value)
                    for key, value in (response.header_fields or tuple(response.headers.items()))
                ),
                response_body=response.body,
                response_was_truncated=response.truncated,
                response_original_bytes=response.original_body_bytes,
            )
            committed = self.ledger.mark_evidence_committed(
                started, evidence_digest=ref.manifest_sha256
            )
            result = ExecutionResultV4(
                action_id=action.action_id,
                action_digest=action.action_digest,
                candidate_id=action.candidate_id,
                status_code=response.status_code,
                headers={key.lower(): value for key, value in response.headers.items()},
                evidence=ref,
                approval_consumption_digest=consumption.digest,
                action_ledger_event_digest=_event_digest(self.ledger, action.action_id),
            )
            self.context.write_json_exclusive(
                f"governance_v4/executions/{action.action_digest[7:]}.json",
                result.model_dump(mode="json"),
            )
            _ = committed
            return result
        except Exception:
            try:
                self.ledger.mark_failed_after_transport(started)
            except Exception:
                pass
            raise

    def _load_reused(self, action: VerificationActionV4) -> ExecutionResultV4:
        try:
            result = ExecutionResultV4.model_validate_json(
                self.context.artifact_path(
                    f"governance_v4/executions/{action.action_digest[7:]}.json"
                ).read_bytes()
            )
        except (OSError, ValueError) as exc:
            raise GovernedExecutionV4Error(
                "reused action lacks an immutable execution result"
            ) from exc
        if (result.action_id, result.action_digest) != (action.action_id, action.action_digest):
            raise GovernedExecutionV4Error("reused execution does not bind the canonical action")
        return result


def _body_for(action: VerificationActionV4) -> bytes:
    values: dict[str, object] = {
        "api-graphql-forward": {"value": "phase5-mutated"},
        "api-graphql-control": {"value": "phase5-control"},
        "api-graphql-cleanup": {"value": "initial"},
        "authz-privilege-forward": {"role": "admin"},
        "authz-privilege-cleanup": {"role": "viewer"},
        "workflow-forward": {"from": "draft", "to": "approved"},
        "workflow-control": {"from": "draft", "to": "approved"},
        "workflow-cleanup": {"state": "draft"},
    }
    value = values.get(action.action_id)
    if value is None:
        return b""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def _headers_for(
    action: VerificationActionV4, body: bytes, vault: IdentityVaultV3
) -> dict[str, str]:
    parsed = urlsplit(action.target_url)
    host = parsed.hostname or "localhost"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    headers = {
        "Accept": "application/json",
        "Host": host if port in {80, 443} else f"{host}:{port}",
    }
    if body:
        headers["Content-Type"] = "application/json"
    if action.identity_alias is not None:
        credential = vault.credential(action.identity_alias)
        if credential.binding_digest != action.identity_binding_digest:
            raise GovernedExecutionV4Error(
                "identity vault binding differs from the frozen campaign"
            )
        headers["Authorization"] = f"Bearer {credential.secret}"
    return headers


def _event_digest(ledger: ActionLedgerV4, action_id: str) -> str:
    events = [event for event in ledger.events() if event.get("action_id") == action_id]
    if not events:
        raise GovernedExecutionV4Error("committed action has no ledger event")
    value = events[-1].get("event_hash")
    if not isinstance(value, str) or not value.startswith("sha256:"):
        raise GovernedExecutionV4Error("committed action ledger event is not hash-bound")
    return value


__all__ = ["ExecutionResultV4", "GovernedExecutionV4Error", "GovernedExecutorV4"]

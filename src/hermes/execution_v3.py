"""Parent-owned, fail-closed network execution for Phase 4 V3.

The isolated verifier may request an action by its position in its frozen
``TaskEnvelope``.  It never chooses the URL, body, identity, approval binding,
or transport.  Those values are reconstructed from the signed campaign by the
trusted parent runtime and claimed through :class:`ActionLedger` before egress.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .campaign_v3 import materialize_request_body
from .domain_contracts import canonical_digest
from .domain_contracts_v3 import (
    ApprovalBatchV3,
    CleanupActionResult,
    CleanupReceipt,
    VerificationActionV3,
    VerificationCampaignPlan,
)
from .evidence import (
    EvidenceArtifactRef,
    EvidenceBinding,
    EvidenceStore,
    HeaderField,
)
from .ledgers_v3 import (
    ActionFingerprint,
    ActionLedger,
    ActionLedgerState,
    ActionReservation,
    ActionRisk,
    LedgerError,
)
from .runtime.agents.contracts import GatewayActionRequest, TaskEnvelope
from .runtime.context import RunContext
from .runtime.errors import ApprovalDenied
from .runtime.gateway import HttpRequest, HttpResponse, Transport
from .runtime.policy import PolicyEngine
from .security import SecurityContractError, TrustStoreV2
from .security_v3 import IdentityVaultV3, verify_approval_batch_v3

_DIGEST = r"^sha256:[0-9a-f]{64}$"
_ID = r"^[A-Za-z0-9._:-]{1,160}$"
_ACTION_REQUEST = re.compile(r"^(?P<task>[^:]+):gateway:(?P<index>[0-9]+)$")
_EMPTY_BODY_DIGEST = "sha256:" + hashlib.sha256(b"").hexdigest()


class GovernedExecutionError(RuntimeError):
    """The trusted execution chain could not authorize or account for egress."""


class ApprovalConsumptionV3(BaseModel):
    """Immutable one-shot binding from a signed batch to one evidence artifact."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["3"] = "3"
    consumption_id: str = Field(pattern=_ID)
    run_id: str = Field(pattern=_ID)
    scope_digest: str = Field(pattern=_DIGEST)
    campaign_id: str = Field(pattern=_ID)
    campaign_digest: str = Field(pattern=_DIGEST)
    approval_id: str = Field(pattern=_ID)
    approval_batch_digest: str = Field(pattern=_DIGEST)
    candidate_id: str = Field(pattern=_ID)
    action_id: str = Field(pattern=_ID)
    action_digest: str = Field(pattern=_DIGEST)
    task_id: str = Field(pattern=_ID)
    task_input_sha256: str = Field(pattern=_DIGEST)
    request_id: str = Field(pattern=_ID)
    evidence_id: str = Field(pattern=_ID)
    consumed_at: datetime

    @model_validator(mode="after")
    def aware_time(self) -> ApprovalConsumptionV3:
        if self.consumed_at.tzinfo is None:
            raise ValueError("approval consumption time must be timezone-aware")
        return self

    @property
    def digest(self) -> str:
        return canonical_digest(self.model_dump(mode="json"))


class ApprovalConsumptionStoreV3:
    """Verify and atomically consume an exact V3 campaign action once."""

    def __init__(
        self,
        context: RunContext,
        campaign: VerificationCampaignPlan,
        trust_store: TrustStoreV2,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if campaign.run_id != context.run_id or campaign.scope_digest != context.scope_digest:
            raise GovernedExecutionError("campaign is bound to another run or scope")
        self.context = context
        self.campaign = campaign
        self.trust_store = trust_store
        self.clock = clock

    def consume(
        self,
        *,
        batch: ApprovalBatchV3,
        action: VerificationActionV3,
        task: TaskEnvelope,
        request_id: str,
        evidence_id: str,
    ) -> ApprovalConsumptionV3:
        now = self.validate_batch(batch)
        if batch.verdict != "approved":
            raise ApprovalDenied("rejected V3 approval batch cannot be consumed")
        authoritative = self._campaign_action(action.action_id)
        if authoritative != action or action.action_digest not in batch.action_digests:
            raise ApprovalDenied("approval does not bind the exact campaign action")
        cleanup_projection = batch.risk_group == "cleanup" and action.purpose in {
            "cleanup",
            "cleanup_check",
        }
        if action.candidate_id not in batch.candidate_ids or (
            action.risk_group != batch.risk_group and not cleanup_projection
        ):
            raise ApprovalDenied("approval does not bind the exact candidate risk graph")
        if (
            task.version != "3"
            or task.run_id != self.context.run_id
            or task.scope_digest != self.context.scope_digest
        ):
            raise ApprovalDenied("task crosses the approved run or scope")
        consumption = ApprovalConsumptionV3(
            consumption_id=f"consume-{uuid.uuid4()}",
            run_id=self.context.run_id,
            scope_digest=self.context.scope_digest,
            campaign_id=self.campaign.campaign_id,
            campaign_digest=self.campaign.digest,
            approval_id=batch.approval_id,
            approval_batch_digest=batch.digest,
            candidate_id=action.candidate_id,
            action_id=action.action_id,
            action_digest=action.action_digest,
            task_id=task.task_id,
            task_input_sha256=task.input_hash(),
            request_id=request_id,
            evidence_id=evidence_id,
            consumed_at=now,
        )
        relative = f"approvals_v3/consumptions/{action.action_digest[7:]}.json"
        try:
            self.context.write_json_exclusive(relative, consumption.model_dump(mode="json"))
        except FileExistsError as exc:
            raise ApprovalDenied("V3 campaign action was already consumed") from exc
        return consumption

    def validate_batch(self, batch: ApprovalBatchV3) -> datetime:
        """Verify a batch even when execution can reuse already committed evidence."""

        now = self.clock()
        try:
            verify_approval_batch_v3(batch, self.campaign, self.trust_store, at=now)
        except SecurityContractError as exc:
            raise ApprovalDenied("V3 approval batch was rejected") from exc
        return now

    def _campaign_action(self, action_id: str) -> VerificationActionV3:
        matches = tuple(item for item in self.campaign.actions if item.action_id == action_id)
        if len(matches) != 1:
            raise ApprovalDenied("action is absent from the signed campaign")
        return matches[0]


class ExecutionResultV3(BaseModel):
    """Bounded projection returned to an isolated verifier."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action_id: str = Field(pattern=_ID)
    action_digest: str = Field(pattern=_DIGEST)
    status_code: int = Field(ge=100, le=599)
    headers: dict[str, str]
    evidence_artifact_ref: EvidenceArtifactRef
    action_ledger_entry_digest: str = Field(pattern=_DIGEST)
    approval_consumption_digest: str = Field(pattern=_DIGEST)
    reused: bool = False

    def ipc_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


class GovernedGatewayV3:
    """Materialize and execute only actions frozen in a V3 verifier task."""

    def __init__(
        self,
        *,
        context: RunContext,
        campaign: VerificationCampaignPlan,
        approval_batches: Sequence[ApprovalBatchV3],
        consumption_store: ApprovalConsumptionStoreV3,
        action_ledger: ActionLedger,
        policy_engine: PolicyEngine,
        evidence_store: EvidenceStore,
        transport: Transport,
        candidate_types: Mapping[str, str],
        identity_vault: IdentityVaultV3 | None = None,
    ) -> None:
        if campaign.run_id != context.run_id or campaign.scope_digest != context.scope_digest:
            raise GovernedExecutionError("campaign is bound to another run or scope")
        self.context = context
        self.campaign = campaign
        self.consumption_store = consumption_store
        self.action_ledger = action_ledger
        self.policy_engine = policy_engine
        self.evidence_store = evidence_store
        self.transport = transport
        self.candidate_types = dict(candidate_types)
        self.identity_vault = identity_vault
        self._batches = {item.approval_id: item for item in approval_batches}
        if len(self._batches) != len(tuple(approval_batches)):
            raise GovernedExecutionError("approval batch IDs must be unique")

    def __call__(self, request: GatewayActionRequest, task: TaskEnvelope) -> Mapping[str, Any]:
        match = _ACTION_REQUEST.fullmatch(request.request_id)
        if match is None or match.group("task") != task.task_id:
            raise GovernedExecutionError("gateway request ID does not bind the verifier task")
        return self.execute_task_action(
            task=task,
            request=request,
            action_index=int(match.group("index")),
        ).ipc_payload()

    def execute_task_action(
        self,
        *,
        task: TaskEnvelope,
        request: GatewayActionRequest,
        action_index: int,
    ) -> ExecutionResultV3:
        action = self._task_action(task, action_index)
        self._validate_agent_request(request, task, action, action_index)
        batch = self._batch(request.approval_token, action)
        return self._execute(task=task, action=action, batch=batch, request_id=request.request_id)

    def execute_parent_action(
        self,
        *,
        action: VerificationActionV3,
        batch: ApprovalBatchV3,
        task_id: str,
    ) -> ExecutionResultV3:
        """Execute a compensation action selected by trusted parent code.

        A synthetic immutable task is still created so approval consumption and
        evidence retain the same task/input binding as agent-requested actions.
        """

        task = TaskEnvelope(
            version="3",
            run_id=self.context.run_id,
            task_id=task_id,
            role="verifier",
            scope_digest=self.context.scope_digest,
            payload={"actions": [action.model_dump(mode="json")], "approval_id": batch.approval_id},
            allowed_actions=("validation_http_get" if action.method == "GET" else "http_post",),
            request_budget=1,
            evidence_required=True,
        )
        return self._execute(
            task=task,
            action=self._authoritative_action(action),
            batch=batch,
            request_id=f"{task_id}:gateway:0",
        )

    def _execute(
        self,
        *,
        task: TaskEnvelope,
        action: VerificationActionV3,
        batch: ApprovalBatchV3,
        request_id: str,
    ) -> ExecutionResultV3:
        body = self._body(action)
        headers = self._headers(action, body)
        fingerprint = ActionFingerprint(
            run_id=self.context.run_id,
            scope_digest=self.context.scope_digest,
            action_kind=action.action_kind,
            method=action.method,
            canonical_url=action.target_url,
            canonical_body_sha256=action.body_sha256 or _EMPTY_BODY_DIGEST,
            identity_binding_digest=action.identity_binding_digest,
            # A request's URL/body/identity can be identical before and after a
            # mutation.  Bind the parent-owned causal graph as well, so a
            # baseline observation can never be presented as cleanup proof.
            causal_dependency_digest=canonical_digest({"depends_on": action.depends_on}),
            risk=ActionRisk(action.risk_group),
        )
        reservation = self.action_ledger.reserve(
            fingerprint,
            owner_task_id=task.task_id,
            candidate_consumers=action.candidate_consumers,
            action_id=action.action_id,
            action_digest=action.action_digest,
        )
        if reservation.disposition == "reused":
            return self._load_reused(action, reservation)

        evidence_id = str(uuid.uuid4())
        try:
            self.policy_engine.assert_automation()
            target = self.policy_engine.resolve_url(action.target_url)
            consumption = self.consumption_store.consume(
                batch=batch,
                action=action,
                task=task,
                request_id=request_id,
                evidence_id=evidence_id,
            )
        except Exception:
            self.action_ledger.mark_failed_before_transport(reservation)
            raise

        request_headers = {
            **headers,
            "Host": target.host if target.port in {80, 443} else f"{target.host}:{target.port}",
        }
        http_request = HttpRequest(
            method=action.method,
            url=action.target_url,
            connect_ip=target.connect_ip,
            host_header=request_headers["Host"],
            tls_server_name=target.host if target.scheme == "https" else None,
            headers=request_headers,
            body=body,
            response_body_limit=self.policy_engine.policy.evidence_capture_max_bytes,
        )
        started = self.action_ledger.mark_transport_started(
            reservation,
            approval_batch_digest=batch.digest,
            consumption_digest=consumption.digest,
        )
        try:
            response = self.transport(http_request)
            ref = self._capture(
                action=action,
                task=task,
                request_id=request_id,
                evidence_id=evidence_id,
                batch=batch,
                consumption=consumption,
                request_headers=request_headers,
                request_body=body or b"",
                response=response,
            )
            self.action_ledger.mark_evidence_committed(started, evidence_digest=ref.manifest_sha256)
            ledger_digest = self._committed_event_digest(action, ref)
            result = ExecutionResultV3(
                action_id=action.action_id,
                action_digest=action.action_digest,
                status_code=response.status_code,
                headers=self._safe_response_headers(response),
                evidence_artifact_ref=ref,
                action_ledger_entry_digest=ledger_digest,
                approval_consumption_digest=consumption.digest,
            )
            self.context.write_json_exclusive(
                self._execution_path(action), result.model_dump(mode="json")
            )
            return result
        except Exception:
            try:
                self.action_ledger.mark_failed_after_transport(started)
            except LedgerError:
                # Preserve the first fail-closed transition if another recovery
                # observer has already marked the attempt indeterminate.
                pass
            raise

    def _task_action(self, task: TaskEnvelope, index: int) -> VerificationActionV3:
        if task.version != "3" or task.role != "verifier":
            raise GovernedExecutionError("only a V3 verifier task may request campaign actions")
        if task.run_id != self.context.run_id or task.scope_digest != self.context.scope_digest:
            raise GovernedExecutionError("verifier task crosses run or scope")
        values = task.payload.get("actions")
        if not isinstance(values, list) or not 0 <= index < len(values):
            raise GovernedExecutionError("gateway index is outside the frozen task action list")
        try:
            action = VerificationActionV3.model_validate(values[index])
        except ValueError as exc:
            raise GovernedExecutionError("task contains an invalid campaign action") from exc
        return self._authoritative_action(action)

    def _authoritative_action(self, action: VerificationActionV3) -> VerificationActionV3:
        matches = tuple(
            item for item in self.campaign.actions if item.action_id == action.action_id
        )
        if len(matches) != 1 or matches[0] != action:
            raise GovernedExecutionError("task action differs from the signed campaign")
        return matches[0]

    def _validate_agent_request(
        self,
        request: GatewayActionRequest,
        task: TaskEnvelope,
        action: VerificationActionV3,
        index: int,
    ) -> None:
        expected_id = f"{task.task_id}:gateway:{index}"
        expected_kind = "validation_http_get" if action.method == "GET" else "http_post"
        supplied = request.action
        if (
            request.request_id != expected_id
            or request.url != action.target_url
            or supplied.target != action.target_url
            or supplied.method != action.method
            or supplied.kind.value != expected_kind
            or supplied.max_requests != 1
            or supplied.detail != action.action_digest
            or request.headers
            or request.body_base64 is not None
        ):
            raise GovernedExecutionError(
                "agent request differs from its exact task-indexed campaign action"
            )

    def _batch(self, approval_id: str | None, action: VerificationActionV3) -> ApprovalBatchV3:
        if approval_id is None:
            raise ApprovalDenied("verifier request omitted its approval batch ID")
        batch = self._batches.get(approval_id)
        if batch is None or action.action_digest not in batch.action_digests:
            raise ApprovalDenied("verifier request used another approval batch")
        self.consumption_store.validate_batch(batch)
        if batch.verdict != "approved":
            raise ApprovalDenied("rejected V3 approval batch cannot authorize evidence reuse")
        return batch

    def _body(self, action: VerificationActionV3) -> bytes | None:
        candidate_type = self.candidate_types.get(action.candidate_id)
        if candidate_type is None:
            raise GovernedExecutionError("campaign candidate type is unavailable")
        body = materialize_request_body(candidate_type, action.purpose)
        digest = None if body is None else "sha256:" + hashlib.sha256(body).hexdigest()
        if digest != action.body_sha256:
            raise GovernedExecutionError("parent request body does not match the campaign digest")
        return body

    def _headers(self, action: VerificationActionV3, body: bytes | None) -> dict[str, str]:
        headers: dict[str, str] = {}
        if body is not None:
            headers["Content-Type"] = "application/json"
        binding = action.identity_binding_digest
        if binding is None:
            return headers
        if self.identity_vault is None:
            raise GovernedExecutionError("identity-bound action has no parent identity vault")
        aliases = tuple(
            alias
            for alias, digest in self.identity_vault.binding_digests.items()
            if digest == binding
        )
        if len(aliases) != 1:
            raise GovernedExecutionError("identity binding does not resolve uniquely")
        headers["Authorization"] = f"Bearer {self.identity_vault.credential(aliases[0]).secret}"
        return headers

    def _capture(
        self,
        *,
        action: VerificationActionV3,
        task: TaskEnvelope,
        request_id: str,
        evidence_id: str,
        batch: ApprovalBatchV3,
        consumption: ApprovalConsumptionV3,
        request_headers: Mapping[str, str],
        request_body: bytes,
        response: HttpResponse,
    ) -> EvidenceArtifactRef:
        binding = EvidenceBinding(
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
            approval_bundle_id=batch.approval_id,
            approval_bundle_digest=batch.digest,
            approval_consumption_digest=consumption.digest,
            captured_at=datetime.now(UTC),
        )
        response_fields = response.header_fields or tuple(response.headers.items())
        return self.evidence_store.capture(
            binding=binding,
            request_method=action.method,
            request_url=action.target_url,
            request_headers=tuple(
                HeaderField(name=name, value=value) for name, value in request_headers.items()
            ),
            request_body=request_body,
            response_status=response.status_code,
            response_headers=tuple(
                HeaderField(name=name, value=value) for name, value in response_fields
            ),
            response_body=response.body,
            response_original_bytes=response.original_body_bytes,
            response_was_truncated=response.truncated,
        )

    @staticmethod
    def _safe_response_headers(response: HttpResponse) -> dict[str, str]:
        allowed = {"content-type", "content-length", "x-content-type-options", "link"}
        return {name: value for name, value in response.headers.items() if name.lower() in allowed}

    @staticmethod
    def _execution_path(action: VerificationActionV3) -> str:
        return f"governance_v3/executions/{action.action_digest[7:]}.json"

    def _committed_event_digest(
        self, action: VerificationActionV3, evidence: EvidenceArtifactRef
    ) -> str:
        matches = tuple(
            item
            for item in self.action_ledger.events()
            if item.get("action_digest") == action.action_digest
            and item.get("state") == "evidence_committed"
            and item.get("evidence_digest") == evidence.manifest_sha256
        )
        if len(matches) != 1 or not isinstance(matches[0].get("event_hash"), str):
            raise GovernedExecutionError("committed action has no unique ledger event digest")
        return str(matches[0]["event_hash"])

    def _load_reused(
        self, action: VerificationActionV3, reservation: ActionReservation
    ) -> ExecutionResultV3:
        path = self.context.artifact_path(self._execution_path(action))
        try:
            result = ExecutionResultV3.model_validate_json(path.read_bytes())
            manifest = self.evidence_store.verify(result.evidence_artifact_ref)
        except (OSError, ValueError) as exc:
            raise GovernedExecutionError(
                "committed action has no valid execution artifact"
            ) from exc
        if (
            result.action_id != action.action_id
            or result.action_digest != action.action_digest
            or result.evidence_artifact_ref.manifest_sha256 != reservation.evidence_digest
            or manifest.binding.action_digest != action.action_digest
            or result.action_ledger_entry_digest
            != self._committed_event_digest(action, result.evidence_artifact_ref)
            or result.approval_consumption_digest != manifest.binding.approval_consumption_digest
        ):
            raise GovernedExecutionError("reused execution artifact binding is invalid")
        return result.model_copy(update={"reused": True})


class CompensationManagerV3:
    """Ensure every mutation whose transport may have started is cleaned first."""

    _TOUCHED = frozenset(
        {
            ActionLedgerState.TRANSPORT_STARTED.value,
            ActionLedgerState.EVIDENCE_COMMITTED.value,
            ActionLedgerState.FAILED_AFTER_TRANSPORT.value,
            ActionLedgerState.INDETERMINATE.value,
            ActionLedgerState.CLEANUP_REQUIRED.value,
        }
    )

    def __init__(
        self,
        *,
        context: RunContext,
        campaign: VerificationCampaignPlan,
        gateway: GovernedGatewayV3,
        action_ledger: ActionLedger,
        mutation_approval: ApprovalBatchV3,
        initial_state_sha256: str,
        state_hash_reader: Callable[[], str],
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.context = context
        self.campaign = campaign
        self.gateway = gateway
        self.action_ledger = action_ledger
        self.mutation_approval = mutation_approval
        self.initial_state_sha256 = initial_state_sha256
        self.state_hash_reader = state_hash_reader
        self.clock = clock

    def run(self) -> CleanupReceipt:
        latest = self._latest_events()
        results: list[CleanupActionResult] = []
        for forward in (
            item
            for item in self.campaign.actions
            if item.risk_group == "mutation" and item.purpose == "candidate"
        ):
            state = latest.get(forward.action_id, {}).get("state")
            if state not in self._TOUCHED:
                continue
            cleanup = self._single_action(cleanup_of=forward.action_id, purpose="cleanup")
            check = self._single_action(candidate_id=forward.candidate_id, purpose="cleanup_check")
            evidence: list[EvidenceArtifactRef] = []
            status: Literal["cleaned", "cleanup_required", "indeterminate"] = "cleaned"
            try:
                cleanup_result = self.gateway.execute_parent_action(
                    action=cleanup,
                    batch=self.mutation_approval,
                    task_id=f"phase4-cleanup-{forward.candidate_id}-cleanup",
                )
                evidence.append(cleanup_result.evidence_artifact_ref)
                check_result = self.gateway.execute_parent_action(
                    action=check,
                    batch=self.mutation_approval,
                    task_id=f"phase4-cleanup-{forward.candidate_id}-check",
                )
                evidence.append(check_result.evidence_artifact_ref)
                self._mark_forward_required(forward)
            except Exception:
                status = "cleanup_required"
                self._mark_forward_required(forward)
            results.append(
                CleanupActionResult(
                    forward_action_digest=forward.action_digest,
                    cleanup_action_digest=cleanup.action_digest,
                    cleanup_check_action_digest=check.action_digest,
                    status=status,
                    evidence=tuple(evidence),
                )
            )
        # Fixture-state observation is evidence too.  If it cannot be loaded
        # (including because the cleanup check failed before committing
        # evidence), preserve the fail-closed cleanup-required state rather
        # than turning recovery into an uncategorised CLI exception.
        try:
            final_state = self.state_hash_reader()
        except Exception:
            final_state = None
        restored = all(item.status == "cleaned" for item in results)
        restored = restored and final_state == self.initial_state_sha256
        if not restored:
            # Transport-level cleanup success is not sufficient authority to
            # promote a finding.  When the final state cannot be proved, make
            # that uncertainty visible in every affected result and retain the
            # forward actions in cleanup_required for a later explicit repair.
            results = [
                item
                if item.status != "cleaned"
                else item.model_copy(update={"status": "cleanup_required"})
                for item in results
            ]
        receipt = CleanupReceipt(
            run_id=self.context.run_id,
            scope_digest=self.context.scope_digest,
            generated_by_task_id="compensation-manager-v3",
            receipt_id=f"cleanup-{uuid.uuid4()}",
            campaign_digest=self.campaign.digest,
            results=tuple(results),
            initial_state_sha256=self.initial_state_sha256,
            final_state_sha256=final_state,
            state_restored=restored,
            completed_at=self.clock(),
        )
        # A failed cleanup attempt is represented by the action ledger and the
        # cleanup-required workflow state.  Only a fully restored receipt becomes
        # the canonical artifact, so a later cleanup-only approval can recover
        # without overwriting or silently upgrading an immutable failed receipt.
        if receipt.state_restored:
            self.context.write_json(
                "verification_v3/cleanup.json",
                receipt.model_dump(mode="json"),
                immutable=True,
            )
        for result in receipt.results:
            if result.status != "cleaned":
                continue
            forward = next(
                item
                for item in self.campaign.actions
                if item.action_digest == result.forward_action_digest
            )
            self._mark_forward_cleaned(forward, receipt.digest)
        return receipt

    def _latest_events(self) -> dict[str, dict[str, Any]]:
        latest: dict[str, dict[str, Any]] = {}
        for event in self.action_ledger.events():
            latest[str(event["action_id"])] = dict(event)
        return latest

    def _single_action(
        self,
        *,
        purpose: Literal["cleanup", "cleanup_check"],
        cleanup_of: str | None = None,
        candidate_id: str | None = None,
    ) -> VerificationActionV3:
        matches = tuple(
            item
            for item in self.campaign.actions
            if item.purpose == purpose
            and (cleanup_of is None or item.cleanup_of == cleanup_of)
            and (candidate_id is None or item.candidate_id == candidate_id)
        )
        if len(matches) != 1:
            raise GovernedExecutionError("campaign has no unique compensation action graph")
        return matches[0]

    def _reservation(self, action: VerificationActionV3) -> ActionReservation | None:
        events = [
            item for item in self.action_ledger.events() if item["action_id"] == action.action_id
        ]
        if not events:
            return None
        latest = events[-1]
        return ActionReservation(
            fingerprint=str(latest["fingerprint"]),
            action_id=action.action_id,
            action_digest=action.action_digest,
            owner_task_id=str(latest["owner_task_id"]),
            disposition="owner",
            state=ActionLedgerState(str(latest["state"])),
            candidate_consumers=tuple(latest.get("candidate_consumers", ())),
            evidence_digest=latest.get("evidence_digest"),
            approval_batch_digest=latest.get("approval_batch_digest"),
            consumption_digest=latest.get("consumption_digest"),
        )

    def _mark_forward_required(self, action: VerificationActionV3) -> None:
        reservation = self._reservation(action)
        if reservation is None or reservation.state is ActionLedgerState.CLEANUP_REQUIRED:
            return
        if reservation.state is ActionLedgerState.CLEANED:
            return
        try:
            self.action_ledger.mark_cleanup_required(reservation)
        except LedgerError:
            return

    def _mark_forward_cleaned(
        self, action: VerificationActionV3, cleanup_receipt_digest: str
    ) -> None:
        self._mark_forward_required(action)
        reservation = self._reservation(action)
        if reservation is None or reservation.state is ActionLedgerState.CLEANED:
            return
        if reservation.state is not ActionLedgerState.CLEANUP_REQUIRED:
            raise GovernedExecutionError("forward action could not enter cleanup_required")
        self.action_ledger.mark_cleaned(reservation, cleanup_receipt_digest=cleanup_receipt_digest)


__all__ = [
    "ApprovalConsumptionStoreV3",
    "ApprovalConsumptionV3",
    "CompensationManagerV3",
    "ExecutionResultV3",
    "GovernedExecutionError",
    "GovernedGatewayV3",
]

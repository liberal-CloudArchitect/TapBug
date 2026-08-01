"""Persistent V2 localhost vertical workflow with two human pause points."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal, TypeVar, cast
from urllib.parse import urljoin, urlsplit

from pydantic import BaseModel, ConfigDict, Field

from .domain_contracts import (
    AssetInventory,
    CandidateSet,
    ContractEnvelope,
    EndpointInventory,
    GateDecisionV2,
    ReporterAcknowledgement,
    VerificationOutcome,
    VerificationPlan,
    VerificationStep,
)
from .evidence import (
    EvidenceArtifactRef,
    EvidenceStore,
    EvidenceStoreError,
    require_negative_control_link,
    trusted_response_header_projection,
    verify_fixed_header_differential,
)
from .preflight import ReportPreflightVerifier
from .promotion import PromotionService, file_sha256
from .prompts import PromptRegistry
from .reporting import persist_authorization_receipt, write_report
from .runtime import ActionKind, ApprovalDenied, PolicyEngine, ProposedAction, RunContext
from .runtime.agents import AgentRunner, RoleTrustStore, TaskEnvelope, TaskResult
from .security import SecurityContractError, TrustStoreV2
from .vertical_contracts import (
    ApprovalBundle,
    ApprovalConsumptionV2,
    RunPlan,
    SignedHumanReview,
    consume_approved_action_v2,
    verify_approval_bundle,
    verify_human_review,
)
from .workflow import WorkflowEventLog

ROLE_ORDER = ("gatekeeper", "recon", "mapper", "web-vuln", "verifier", "reporter")
ROLE_TIMEOUT_SECONDS = 180
_Payload = TypeVar("_Payload", bound=BaseModel)


class ExecutionState(StrEnum):
    PLANNED = "planned"
    RUNNING = "running"
    AWAITING_APPROVAL = "awaiting_approval"
    REJECTED = "rejected"
    AWAITING_REVIEW = "awaiting_review"
    COMPLETED = "completed"
    FAILED = "failed"


class NetworkState(StrEnum):
    DISABLED = "disabled"
    POLICY_BLOCKED = "policy_blocked"
    ENABLED_IDLE = "enabled_idle"
    REQUESTED = "requested"
    USED = "used"


class VerticalState(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: str = "2"
    run_id: str
    execution_state: ExecutionState
    network_state: NetworkState
    requests_planned: int = Field(ge=0)
    requests_used: int = Field(ge=0)
    requests_blocked: int = Field(ge=0)
    current_role: str | None = None
    next_required_action: str | None = None
    artifacts: dict[str, str] = Field(default_factory=dict)
    last_successful_checkpoint: str | None = None
    failure_stage: str | None = None
    failure_code: str | None = None
    failure_artifact: str | None = None


class VerticalWorkflowError(RuntimeError):
    def __init__(self, message: str, *, failure_code: str = "workflow_execution_failed") -> None:
        super().__init__(message)
        self.failure_code = failure_code


class VerticalWorkflowV2:
    """Advance the strict V2 chain while persisting every resumable boundary."""

    def __init__(
        self,
        context: RunContext,
        runner: AgentRunner,
        *,
        evidence_store: EvidenceStore,
        publisher_store: RoleTrustStore,
        prompt_registry: PromptRegistry,
    ) -> None:
        self.context = context
        self.runner = runner
        self.evidence_store = evidence_store
        self.publisher_store = publisher_store
        self.prompt_registry = prompt_registry
        self.events = WorkflowEventLog(context)

    @property
    def state_path(self) -> Path:
        return self.context.artifact_path("state.json")

    def state(self) -> VerticalState:
        return VerticalState.model_validate_json(self.state_path.read_bytes())

    def _save_state(self, state: VerticalState) -> VerticalState:
        self.context.write_json("state.json", state.model_dump(mode="json"))
        self.events.record(
            "vertical_state_v2",
            execution_state=state.execution_state.value,
            network_state=state.network_state.value,
            current_role=state.current_role,
        )
        return state

    def _checkpoint(
        self,
        checkpoint: str,
        *,
        current_role: str,
        requests_used: int | None = None,
        network_state: NetworkState | None = None,
    ) -> None:
        state = self.state()
        changes: dict[str, Any] = {
            "last_successful_checkpoint": checkpoint,
            "current_role": current_role,
        }
        if requests_used is not None:
            changes["requests_used"] = requests_used
        if network_state is not None:
            changes["network_state"] = network_state
        self._save_state(state.model_copy(update=changes))

    def _run_role(
        self,
        role: str,
        payload: dict[str, Any],
        *,
        evidence: tuple[EvidenceArtifactRef, ...] = (),
        allowed_actions: tuple[str, ...] = (),
        request_budget: int = 0,
    ) -> TaskResult:
        task = TaskEnvelope(
            run_id=self.context.run_id,
            task_id=f"phase3-{role}",
            role=role,
            scope_digest=self.context.scope_digest,
            payload=payload,
            evidence_artifact_refs=evidence,
            allowed_actions=allowed_actions,
            request_budget=request_budget,
            evidence_required=bool(allowed_actions),
            timeout_seconds=ROLE_TIMEOUT_SECONDS,
        )
        path = self.context.artifact_path(f"handoffs/{task.task_id}.json")
        if path.exists():
            stored = json.loads(path.read_text(encoding="utf-8"))
            result = TaskResult.model_validate(stored["result"])
            persisted_task = TaskEnvelope.model_validate(stored["task"])
            if persisted_task.input_hash() != task.input_hash():
                raise VerticalWorkflowError(f"persisted {role} input differs from resume input")
        else:
            result = self.runner.run(task)
            self.context.write_json(
                f"handoffs/{task.task_id}.json",
                {"task": task.model_dump(mode="json"), "result": result.model_dump(mode="json")},
                immutable=True,
            )
        if result.lifecycle != "completed" or result.handoff is None:
            self._record_task_failure(role, result)
            raise VerticalWorkflowError(
                f"role {role} failed: {result.error or result.lifecycle}",
                failure_code=result.failure_code or result.lifecycle,
            )
        if result.handoff.version != "2":
            raise VerticalWorkflowError("a V1 handoff cannot enter the V2 workflow")
        return result

    def _payload(self, result: TaskResult, expected: type[_Payload]) -> _Payload:
        if result.handoff is None or not isinstance(result.handoff.result, ContractEnvelope):
            raise VerticalWorkflowError("completed V2 role omitted its ContractEnvelope")
        payload = result.handoff.result.payload
        if not isinstance(payload, expected):
            raise VerticalWorkflowError(
                f"role output contract is {type(payload).__name__}, expected {expected.__name__}"
            )
        return payload

    def start(
        self,
        *,
        target: str,
        engine: PolicyEngine,
        provider: str,
        model: str,
        prompt_registry_digest: str,
        web_prompt_id: str,
        web_prompt_version: str,
        web_prompt_sha256: str,
    ) -> VerticalState:
        resolved = engine.resolve_url(target)
        if resolved.host != "localhost" or not resolved.connect_ip.startswith(("127.", "::1")):
            raise VerticalWorkflowError("V2 vertical permits only a localhost loopback target")
        plan = RunPlan(
            version="2",
            run_id=self.context.run_id,
            target=target,
            scope_digest=self.context.scope_digest,
            provider=provider,
            model=model,
            roles=ROLE_ORDER,
            prompt_registry_digest=prompt_registry_digest,
        )
        self.context.write_json("plan/run-plan.json", plan.model_dump(mode="json"), immutable=True)
        self._save_state(
            VerticalState(
                run_id=self.context.run_id,
                execution_state=ExecutionState.RUNNING,
                network_state=NetworkState.ENABLED_IDLE,
                requests_planned=3,
                requests_used=0,
                requests_blocked=0,
                current_role="gatekeeper",
            )
        )
        gate_task_id = "phase3-gatekeeper"
        gate_result = self._run_role(
            "gatekeeper",
            {
                "run_plan": plan.model_dump(mode="json"),
                "run_id": self.context.run_id,
                "scope_digest": self.context.scope_digest,
                "generated_by_task_id": gate_task_id,
                "policy_resolution": {
                    "host": resolved.host,
                    "connect_ip": resolved.connect_ip,
                },
                "scope_summary": {
                    "profile": engine.policy.profile,
                    "automation_allowed": engine.policy.automation_allowed,
                    "dry_run": engine.policy.dry_run,
                    "matched_rule": resolved.rule.model_dump(mode="json"),
                    "max_requests": engine.policy.max_requests,
                },
            },
        )
        gate = self._payload(gate_result, GateDecisionV2)
        if (
            gate.run_id != self.context.run_id
            or gate.scope_digest != self.context.scope_digest
            or gate.generated_by_task_id != gate_task_id
            or gate.target != target
            or gate.resolved_ip != resolved.connect_ip
        ):
            raise VerticalWorkflowError("Gatekeeper changed the frozen run identity")
        if gate.decision != "allowed":
            raise VerticalWorkflowError(f"Gatekeeper blocked run: {gate.reason}")

        self._checkpoint("gate_allowed_v2", current_role="recon")
        parsed = urlsplit(target)
        recon_task_id = "phase3-recon"
        recon_result = self._run_role(
            "recon",
            {
                "gate_decision": gate.model_dump(mode="json"),
                "target": target,
                "run_id": self.context.run_id,
                "scope_digest": self.context.scope_digest,
                "generated_by_task_id": recon_task_id,
                "inventory_id": "assets-1",
                "asset_id": "asset-1",
                "canonical_host": "localhost",
                "resolved_ips": [resolved.connect_ip],
                "scheme": parsed.scheme,
                "port": parsed.port,
            },
            allowed_actions=(ActionKind.HTTP_GET.value,),
            request_budget=1,
        )
        assets = self._payload(recon_result, AssetInventory)
        self._validate_assets(assets, target, recon_result)
        self.context.write_json(
            "assets/inventory.json", assets.model_dump(mode="json"), immutable=True
        )

        self._checkpoint(
            "assets_observed_v2",
            current_role="mapper",
            requests_used=1,
            network_state=NetworkState.USED,
        )
        mapper_task_id = "phase3-mapper"
        mapper_result = self._run_role(
            "mapper",
            {
                "asset_inventory": assets.model_dump(mode="json"),
                "asset_inventory_digest": assets.digest,
                "run_id": self.context.run_id,
                "scope_digest": self.context.scope_digest,
                "generated_by_task_id": mapper_task_id,
                "inventory_id": "endpoints-1",
                "candidate_endpoint_id": "endpoint-candidate",
                "control_endpoint_id": "endpoint-control",
            },
            evidence=assets.source_evidence,
        )
        endpoints = self._payload(mapper_result, EndpointInventory)
        self._validate_endpoints(assets, endpoints)
        self.context.write_json(
            "endpoints/inventory.json", endpoints.model_dump(mode="json"), immutable=True
        )

        self._checkpoint("endpoints_mapped_v2", current_role="web-vuln")
        web_task_id = "phase3-web-vuln"
        web_result = self._run_role(
            "web-vuln",
            {
                "endpoint_inventory": endpoints.model_dump(mode="json"),
                "endpoint_inventory_digest": endpoints.digest,
                "run_id": self.context.run_id,
                "scope_digest": self.context.scope_digest,
                "generated_by_task_id": web_task_id,
                "set_id": "candidates-1",
                "candidate_id": "missing-x-content-type-options",
                "prompt_id": web_prompt_id,
                "prompt_version": web_prompt_version,
                "prompt_sha256": web_prompt_sha256,
            },
            evidence=assets.source_evidence,
        )
        candidates = self._payload(web_result, CandidateSet)
        self._validate_candidates(
            endpoints,
            candidates,
            web_prompt_id=web_prompt_id,
            web_prompt_version=web_prompt_version,
            web_prompt_sha256=web_prompt_sha256,
        )
        self.context.write_json(
            "candidates/set.json", candidates.model_dump(mode="json"), immutable=True
        )
        verification = self._verification_plan(candidates, endpoints, assets.source_evidence)
        self.context.write_json(
            "plan/verification.json", verification.model_dump(mode="json"), immutable=True
        )
        self.context.write_json(
            "approvals/challenge.json",
            {
                "version": "2",
                "challenge_id": verification.plan_id,
                "run_id": self.context.run_id,
                "scope_digest": self.context.scope_digest,
                "candidate_id": verification.candidate_id,
                "verification_plan_digest": verification.digest,
                "action_digests": [step.action_digest for step in verification.steps],
                "expires_at": verification.expires_at.isoformat(),
            },
            immutable=True,
        )
        return self._save_state(
            VerticalState(
                run_id=self.context.run_id,
                execution_state=ExecutionState.AWAITING_APPROVAL,
                network_state=NetworkState.USED,
                requests_planned=3,
                requests_used=1,
                requests_blocked=0,
                current_role="web-vuln",
                next_required_action="approve_or_reject",
                artifacts={
                    "plan": "plan/run-plan.json",
                    "assets": "assets/inventory.json",
                    "endpoints": "endpoints/inventory.json",
                    "candidates": "candidates/set.json",
                    "verification_plan": "plan/verification.json",
                    "challenge": "approvals/challenge.json",
                },
                last_successful_checkpoint="candidate_ready_v2",
            )
        )

    def resume(
        self,
        *,
        approval_store: TrustStoreV2,
        review_store: TrustStoreV2,
    ) -> VerticalState:
        state = self.state()
        if state.execution_state is ExecutionState.REJECTED:
            return state
        if state.execution_state is ExecutionState.AWAITING_APPROVAL:
            return self._resume_verifier(state, approval_store)
        if state.execution_state is ExecutionState.AWAITING_REVIEW:
            return self._resume_reporter(state, approval_store, review_store)
        if state.execution_state is ExecutionState.COMPLETED:
            return state
        raise VerticalWorkflowError(f"cannot resume state {state.execution_state.value}")

    def _resume_verifier(self, state: VerticalState, approval_store: TrustStoreV2) -> VerticalState:
        plan = VerificationPlan.model_validate_json(
            self.context.artifact_path("plan/verification.json").read_bytes()
        )
        candidates = CandidateSet.model_validate_json(
            self.context.artifact_path("candidates/set.json").read_bytes()
        )
        bundle = ApprovalBundle.model_validate_json(
            self.context.artifact_path("approvals/decision.json").read_bytes()
        )
        verify_approval_bundle(bundle, plan, approval_store)
        if bundle.version != "2":
            raise VerticalWorkflowError("V1 approval cannot authorize a V2 verification plan")
        if any(item.decision == "rejected" for item in bundle.decisions):
            return self._save_state(
                state.model_copy(
                    update={
                        "execution_state": ExecutionState.REJECTED,
                        "next_required_action": None,
                    }
                )
            )
        assets = AssetInventory.model_validate_json(
            self.context.artifact_path("assets/inventory.json").read_bytes()
        )
        self._checkpoint("validation_approved_v2", current_role="verifier")
        verifier_result = self._run_role(
            "verifier",
            {
                "candidate_set": candidates.model_dump(mode="json"),
                "verification_plan": plan.model_dump(mode="json"),
                "verification_plan_digest": plan.digest,
                "approval_bundle_id": bundle.bundle_id,
                "approval_bundle_digest": bundle.digest,
                "run_id": self.context.run_id,
                "scope_digest": self.context.scope_digest,
                "generated_by_task_id": "phase3-verifier",
            },
            evidence=assets.source_evidence,
            allowed_actions=(ActionKind.VALIDATION_HTTP_GET.value,),
            request_budget=2,
        )
        outcome = self._payload(verifier_result, VerificationOutcome)
        self._validate_outcome(plan, bundle, outcome, verifier_result)
        self.context.write_json(
            "report/outcome.json", outcome.model_dump(mode="json"), immutable=True
        )
        draft = (
            "# Review draft\n\n"
            f"Candidate: {outcome.candidate_id}\n\n"
            f"Outcome: {outcome.status}\n\n"
            f"Evidence: {', '.join(item.manifest_path for item in outcome.evidence)}\n\n"
            "Local teaching fixture only; this is not a Bugcrowd submission.\n"
        )
        self.context.write_text("report/draft.md", draft, immutable=True)
        return self._save_state(
            state.model_copy(
                update={
                    "execution_state": ExecutionState.AWAITING_REVIEW,
                    "network_state": NetworkState.USED,
                    "requests_used": 3,
                    "current_role": "verifier",
                    "next_required_action": "review_sign",
                    "last_successful_checkpoint": "verification_completed_v2",
                    "artifacts": {
                        **state.artifacts,
                        "outcome": "report/outcome.json",
                        "report_draft": "report/draft.md",
                    },
                }
            )
        )

    def _resume_reporter(
        self,
        state: VerticalState,
        approval_store: TrustStoreV2,
        review_store: TrustStoreV2,
    ) -> VerticalState:
        outcome = VerificationOutcome.model_validate_json(
            self.context.artifact_path("report/outcome.json").read_bytes()
        )
        review = SignedHumanReview.model_validate_json(
            self.context.artifact_path("reviews/signed.json").read_bytes()
        )
        if review.version != "2" or review.report_draft_digest != file_sha256(
            self.context.artifact_path("report/draft.md")
        ):
            raise VerticalWorkflowError("review is not bound to the V2 report draft")
        verify_human_review(
            review,
            review_store,
            run_id=self.context.run_id,
            scope_digest=self.context.scope_digest,
            finding_id=outcome.candidate_id,
            evidence_digest=outcome.digest,
        )
        if review.verdict != "accepted" or outcome.status != "validated":
            raise VerticalWorkflowError("only an accepted validated outcome may be reported")

        finding, coverage = PromotionService(
            self.context,
            approval_store=approval_store,
            review_store=review_store,
            evidence_store=self.evidence_store,
        ).promote()
        verifier = ReportPreflightVerifier(
            self.context,
            approval_store=approval_store,
            review_store=review_store,
            publisher_store=self.publisher_store,
            prompt_registry=self.prompt_registry,
            evidence_store=self.evidence_store,
        )
        receipt = verifier.authorize()
        persist_authorization_receipt(self.context, receipt)
        self._checkpoint("preflight_authorized_v2", current_role="reporter")
        reporter_result = self._run_role(
            "reporter",
            {
                "validated_finding": finding.model_dump(mode="json"),
                "coverage_report": coverage.model_dump(mode="json"),
                "report_authorization_receipt": receipt.model_dump(mode="json"),
                "run_id": self.context.run_id,
                "scope_digest": self.context.scope_digest,
                "generated_by_task_id": "phase3-reporter",
                "finding_id": finding.finding_id,
                "coverage_report_digest": coverage.digest,
                "authorization_receipt_digest": receipt.digest,
            },
            evidence=finding.evidence,
        )
        acknowledgement = self._payload(reporter_result, ReporterAcknowledgement)
        self.context.write_json(
            "report/reporter-acknowledgement.json",
            acknowledgement.model_dump(mode="json"),
            immutable=True,
        )
        write_report(self.context, verifier, acknowledgement)
        return self._save_state(
            state.model_copy(
                update={
                    "execution_state": ExecutionState.COMPLETED,
                    "current_role": "reporter",
                    "next_required_action": None,
                    "last_successful_checkpoint": "report_completed_v2",
                    "artifacts": {
                        **state.artifacts,
                        "finding": "report/finding.json",
                        "coverage": "report/coverage.json",
                        "authorization": "report/authorization.json",
                        "reporter_ack": "report/reporter-acknowledgement.json",
                        "findings": "report/findings.json",
                        "report": "report/report.md",
                    },
                }
            )
        )

    def mark_failed(self, error: Exception) -> VerticalState:
        state = self.state()
        failure_code = getattr(error, "failure_code", "workflow_execution_failed")
        if not isinstance(failure_code, str):
            failure_code = "workflow_execution_failed"
        failure_id = f"{datetime.now(UTC).strftime('%Y%m%dT%H%M%S%fZ')}-{uuid.uuid4().hex[:8]}"
        relative = f"failures/{failure_id}.json"
        document = {
            "version": "2",
            "failure_id": failure_id,
            "run_id": self.context.run_id,
            "role": state.current_role,
            "code": failure_code,
            "summary": str(error)[:2000],
            "occurred_at": datetime.now(UTC).isoformat(),
        }
        self.context.write_json(relative, document, immutable=True)
        self.context.write_json("failure.json", {**document, "artifact": relative})
        return self._save_state(
            state.model_copy(
                update={
                    "execution_state": ExecutionState.FAILED,
                    "next_required_action": "retry_as_new_run_and_reapprove",
                    "failure_stage": state.current_role,
                    "failure_code": failure_code,
                    "failure_artifact": relative,
                }
            )
        )

    def _record_task_failure(self, role: str, result: TaskResult) -> None:
        failure_id = f"{datetime.now(UTC).strftime('%Y%m%dT%H%M%S%fZ')}-{uuid.uuid4().hex[:8]}"
        self.context.write_json(
            f"failures/{failure_id}.json",
            {
                "version": "2",
                "failure_id": failure_id,
                "run_id": self.context.run_id,
                "role": role,
                "task_id": result.task.task_id,
                "layer": result.failure_layer or "workflow",
                "code": result.failure_code or result.lifecycle,
                "summary": result.error or result.lifecycle,
                "occurred_at": datetime.now(UTC).isoformat(),
            },
            immutable=True,
        )

    def _validate_assets(self, assets: AssetInventory, target: str, result: TaskResult) -> None:
        if (
            assets.run_id != self.context.run_id
            or assets.scope_digest != self.context.scope_digest
            or assets.generated_by_task_id != "phase3-recon"
            or assets.target != target
        ):
            raise VerticalWorkflowError("AssetInventory changed its run identity")
        if result.handoff is None or tuple(result.handoff.evidence_artifact_refs) != (
            *assets.source_evidence,
        ):
            raise VerticalWorkflowError("Recon output changed Host-owned evidence")
        manifest = self.evidence_store.verify(assets.source_evidence[0])
        asset = assets.assets[0]
        try:
            trusted_headers = trusted_response_header_projection(
                self.evidence_store, assets.source_evidence[0]
            )
        except EvidenceStoreError as exc:
            raise VerticalWorkflowError("Recon analysis evidence is invalid") from exc
        if (
            manifest.binding.task_id != assets.generated_by_task_id
            or manifest.binding.role != "recon"
            or manifest.target != target
            or manifest.response_status != asset.status_code
            or asset.header_projection != trusted_headers
        ):
            raise VerticalWorkflowError("AssetInventory is not grounded in Recon evidence")

    def _validate_endpoints(self, assets: AssetInventory, endpoints: EndpointInventory) -> None:
        if (
            endpoints.run_id != assets.run_id
            or endpoints.scope_digest != assets.scope_digest
            or endpoints.generated_by_task_id != "phase3-mapper"
            or endpoints.asset_inventory_digest != assets.digest
        ):
            raise VerticalWorkflowError("EndpointInventory changed the asset chain")
        expected_control = urljoin(assets.target, "/control")
        try:
            require_negative_control_link(
                self.evidence_store,
                assets.source_evidence[0],
                target_url=assets.target,
                control_url=expected_control,
            )
        except EvidenceStoreError as exc:
            raise VerticalWorkflowError(
                "negative control is not grounded in Recon evidence"
            ) from exc
        if (
            endpoints.endpoints[0].canonical_url != assets.target
            or endpoints.endpoints[1].canonical_url != expected_control
            or any(item.evidence != assets.source_evidence for item in endpoints.endpoints)
        ):
            raise VerticalWorkflowError("EndpointInventory changed the grounded endpoint pair")

    @staticmethod
    def _validate_candidates(
        endpoints: EndpointInventory,
        candidates: CandidateSet,
        *,
        web_prompt_id: str,
        web_prompt_version: str,
        web_prompt_sha256: str,
    ) -> None:
        candidate = candidates.candidates[0]
        if (
            candidates.run_id != endpoints.run_id
            or candidates.scope_digest != endpoints.scope_digest
            or candidates.generated_by_task_id != "phase3-web-vuln"
            or candidates.endpoint_inventory_digest != endpoints.digest
            or candidates.prompt_id != web_prompt_id
            or candidates.prompt_version != web_prompt_version
            or candidates.prompt_sha256 != web_prompt_sha256
            or candidate.target_endpoint_id != endpoints.endpoints[0].endpoint_id
            or candidate.control_endpoint_id != endpoints.endpoints[1].endpoint_id
            or candidate.required_evidence != endpoints.endpoints[0].evidence
        ):
            raise VerticalWorkflowError("CandidateSet changed its endpoint or prompt identity")

    def _verification_plan(
        self,
        candidates: CandidateSet,
        endpoints: EndpointInventory,
        evidence: tuple[EvidenceArtifactRef, ...],
    ) -> VerificationPlan:
        now = datetime.now(UTC)
        return VerificationPlan(
            plan_id="verification-1",
            run_id=self.context.run_id,
            scope_digest=self.context.scope_digest,
            generated_by_task_id="host-planner",
            candidate_set_digest=candidates.digest,
            endpoint_inventory_digest=endpoints.digest,
            candidate_id=candidates.candidates[0].candidate_id,
            steps=tuple(
                VerificationStep(
                    action_id=action_id,
                    endpoint_id=endpoint.endpoint_id,
                    purpose=cast(Literal["candidate", "negative_control"], purpose),
                    target_url=endpoint.canonical_url,
                    evidence_prerequisites=evidence,
                    expected_assertion=assertion,
                    stop_conditions=("stop after this single GET",),
                )
                for action_id, endpoint, purpose, assertion in (
                    (
                        "get-candidate",
                        endpoints.endpoints[0],
                        "candidate",
                        "X-Content-Type-Options is absent",
                    ),
                    (
                        "get-control",
                        endpoints.endpoints[1],
                        "negative_control",
                        "X-Content-Type-Options equals nosniff",
                    ),
                )
            ),
            created_at=now,
            expires_at=now + timedelta(minutes=15),
        )

    def _validate_outcome(
        self,
        plan: VerificationPlan,
        bundle: ApprovalBundle,
        outcome: VerificationOutcome,
        result: TaskResult,
    ) -> None:
        if (
            outcome.run_id != self.context.run_id
            or outcome.scope_digest != self.context.scope_digest
            or outcome.generated_by_task_id != "phase3-verifier"
            or outcome.verification_plan_digest != plan.digest
            or outcome.candidate_id != plan.candidate_id
            or outcome.approval_bundle_id != bundle.bundle_id
            or outcome.approval_bundle_digest != bundle.digest
        ):
            raise VerticalWorkflowError("VerificationOutcome changed its signed chain")
        if result.handoff is None:
            raise VerticalWorkflowError("Verifier handoff is absent")
        new_refs = tuple(
            item
            for item in result.handoff.evidence_artifact_refs
            if item not in plan.steps[0].evidence_prerequisites
        )
        if new_refs != outcome.evidence:
            raise VerticalWorkflowError("Verifier outcome changed Host Gateway evidence order")
        for step, step_outcome in zip(plan.steps, outcome.step_outcomes, strict=True):
            manifest = self.evidence_store.verify(step_outcome.evidence)
            if (
                step_outcome.action_id != step.action_id
                or step_outcome.action_digest != step.action_digest
                or manifest.binding.action_id != step.action_id
                or manifest.binding.action_digest != step.action_digest
                or manifest.binding.plan_digest != plan.digest
                or manifest.binding.approval_bundle_id != bundle.bundle_id
                or manifest.binding.approval_bundle_digest != bundle.digest
                or manifest.binding.approval_consumption_digest != step_outcome.consumption_digest
            ):
                raise VerticalWorkflowError("VerificationOutcome evidence binding is invalid")
        if outcome.status == "validated":
            try:
                verify_fixed_header_differential(
                    self.evidence_store,
                    recon_ref=plan.steps[0].evidence_prerequisites[0],
                    candidate_ref=outcome.step_outcomes[0].evidence,
                    control_ref=outcome.step_outcomes[1].evidence,
                    target_url=plan.steps[0].target_url,
                    control_url=plan.steps[1].target_url,
                )
            except EvidenceStoreError as exc:
                raise VerticalWorkflowError(
                    "validated outcome is not supported by the HTTP differential"
                ) from exc


class ApprovalBundleValidatorV2:
    """Atomically consume one exact signed verification step before transport."""

    def __init__(self, context: RunContext, trust_store: TrustStoreV2) -> None:
        self.context = context
        self.trust_store = trust_store

    def __call__(
        self,
        action: ProposedAction,
        token: object,
        execution: Any,
        evidence_id: str,
    ) -> ApprovalConsumptionV2:
        from .runtime import GatewayExecutionContext

        if not isinstance(execution, GatewayExecutionContext):
            raise ApprovalDenied("validation request has no typed execution context")
        if not isinstance(token, str):
            raise ApprovalDenied("validation request omitted its approval bundle ID")
        plan = VerificationPlan.model_validate_json(
            self.context.artifact_path("plan/verification.json").read_bytes()
        )
        bundle = ApprovalBundle.model_validate_json(
            self.context.artifact_path("approvals/decision.json").read_bytes()
        )
        if token != bundle.bundle_id:
            raise ApprovalDenied("validation request used another approval bundle")
        if (
            execution.plan_digest != plan.digest
            or execution.approval_bundle_id != bundle.bundle_id
            or execution.approval_bundle_digest != bundle.digest
        ):
            raise ApprovalDenied("validation execution is bound to another plan or bundle")
        prior = self._prior_consumptions()
        try:
            consumption = consume_approved_action_v2(
                bundle=bundle,
                plan=plan,
                action_id=execution.action_id,
                action=action,
                task_id=execution.task_id,
                request_id=execution.request_id,
                evidence_id=evidence_id,
                prior_consumptions=prior,
                trust_store=self.trust_store,
            )
            self.context.write_json_exclusive(
                f"approvals/consumed/{bundle.bundle_id}/{execution.action_id}.json",
                consumption.model_dump(mode="json"),
            )
        except (FileExistsError, SecurityContractError) as exc:
            raise ApprovalDenied("approved V2 action could not be consumed") from exc
        return consumption

    def _prior_consumptions(self) -> tuple[ApprovalConsumptionV2, ...]:
        root = self.context.artifact_path("approvals/consumed")
        if not root.exists():
            return ()
        try:
            return tuple(
                ApprovalConsumptionV2.model_validate_json(path.read_bytes())
                for path in sorted(root.glob("*/*.json"))
            )
        except ValueError as exc:
            raise ApprovalDenied("stored approval consumption is invalid") from exc


__all__ = [
    "ApprovalBundleValidatorV2",
    "ExecutionState",
    "NetworkState",
    "ROLE_ORDER",
    "VerticalState",
    "VerticalWorkflowError",
    "VerticalWorkflowV2",
]

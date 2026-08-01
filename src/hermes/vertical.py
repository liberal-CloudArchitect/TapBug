"""Persistent six-role Phase 2 vertical workflow."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

from pydantic import BaseModel, ConfigDict, Field

from .contracts import FindingEvidence, HumanReview, ValidatedFinding
from .runtime import ActionKind, ApprovalDenied, PolicyEngine, ProposedAction, RunContext
from .runtime.agents import AgentRunner, EvidenceRef, TaskEnvelope, TaskResult
from .security import TrustStoreV2
from .vertical_contracts import (
    ApprovalBundle,
    ApprovalConsumption,
    ApprovalConsumptionLedger,
    AttackSurface,
    GateDecision,
    PlannedAction,
    ReconObservation,
    RunPlan,
    SignedHumanReview,
    ValidationPlan,
    VerificationOutcome,
    WebCandidate,
    consume_approved_action,
    verify_approval_bundle,
    verify_human_review,
)
from .workflow import WorkflowEventLog

ROLE_ORDER = ("gatekeeper", "recon", "mapper", "web-vuln", "verifier", "reporter")


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
    pass


class VerticalWorkflow:
    """Read-only compatibility surface for historical V1 helpers.

    Executable runs moved to :class:`VerticalWorkflowV2`.  The two public execution
    entry points fail before loading artifacts or invoking a role.
    """

    """Advance exactly one durable state transition per operator command."""

    def __init__(self, context: RunContext, runner: AgentRunner) -> None:
        self.context = context
        self.runner = runner
        self.events = WorkflowEventLog(context)

    @property
    def state_path(self) -> Path:
        return self.context.artifact_path("state.json")

    def state(self) -> VerticalState:
        return VerticalState.model_validate_json(self.state_path.read_text(encoding="utf-8"))

    def _save_state(self, state: VerticalState) -> VerticalState:
        self.context.write_json("state.json", state.model_dump(mode="json"))
        self.events.record(
            "vertical_state",
            execution_state=state.execution_state.value,
            network_state=state.network_state.value,
            current_role=state.current_role,
        )
        return state

    def _run_role(
        self,
        role: str,
        payload: dict[str, Any],
        *,
        evidence_refs: tuple[EvidenceRef, ...] = (),
        allowed_actions: tuple[str, ...] = (),
        request_budget: int = 0,
    ) -> TaskResult:
        task = TaskEnvelope(
            run_id=self.context.run_id,
            task_id=f"phase2-{role}",
            role=role,
            scope_digest=self.context.scope_digest,
            payload=payload,
            evidence_refs=evidence_refs,
            allowed_actions=allowed_actions,
            request_budget=request_budget,
            evidence_required=bool(allowed_actions),
        )
        path = self.context.artifact_path(f"handoffs/{task.task_id}.json")
        if path.exists():
            stored = json.loads(path.read_text(encoding="utf-8"))
            result = TaskResult.model_validate(stored["result"])
            if TaskEnvelope.model_validate(stored["task"]).input_hash() != task.input_hash():
                raise VerticalWorkflowError(f"persisted {role} input differs from resumed input")
        else:
            result = self.runner.run(task)
            self.context.write_json(
                f"handoffs/{task.task_id}.json",
                {"task": task.model_dump(mode="json"), "result": result.model_dump(mode="json")},
                immutable=True,
            )
        if result.lifecycle != "completed" or result.handoff is None:
            self._record_task_failure(role, result)
            raise VerticalWorkflowError(f"role {role} failed: {result.error or result.lifecycle}")
        return result

    def _record_task_failure(self, role: str, result: TaskResult) -> str:
        failure_id = f"{datetime.now(UTC).strftime('%Y%m%dT%H%M%S%fZ')}-{uuid.uuid4().hex[:8]}"
        relative = f"failures/{failure_id}.json"
        document = {
            "failure_id": failure_id,
            "run_id": self.context.run_id,
            "role": role,
            "task_id": result.task.task_id,
            "layer": result.failure_layer or "workflow",
            "code": result.failure_code or result.lifecycle,
            "retryable": bool(result.retryable),
            "summary": result.error or result.lifecycle,
            "exit_code": result.exit_code,
            "request_id": result.request_id,
            "transport_state": result.transport_state or "unknown",
            "approval_state": result.approval_state or "unknown",
            "stdout_sha256": result.stdout_sha256,
            "stderr_sha256": result.stderr_sha256,
            "occurred_at": result.finished_at.isoformat(),
        }
        self.context.write_json(relative, document, immutable=True)
        self.context.write_json("failure.json", {**document, "artifact": relative})
        return relative

    def mark_failed(self, error: Exception) -> VerticalState:
        state = self.state()
        latest = self.context.artifact_path("failure.json")
        if latest.exists():
            failure = json.loads(latest.read_text(encoding="utf-8"))
        else:
            failure_id = f"{datetime.now(UTC).strftime('%Y%m%dT%H%M%S%fZ')}-{uuid.uuid4().hex[:8]}"
            relative = f"failures/{failure_id}.json"
            failure = {
                "failure_id": failure_id,
                "run_id": self.context.run_id,
                "role": state.current_role,
                "layer": "workflow",
                "code": "workflow_execution_failed",
                "retryable": False,
                "summary": str(error)[:2000],
                "transport_state": "unknown",
                "approval_state": "unknown",
                "occurred_at": datetime.now(UTC).isoformat(),
                "artifact": relative,
            }
            self.context.write_json(relative, failure, immutable=True)
            self.context.write_json("failure.json", failure)
        stage = str(failure.get("role") or state.current_role or "workflow")
        next_action = (
            "retry_as_new_run_and_reapprove" if stage == "verifier" else "retry_as_new_run"
        )
        return self._save_state(
            state.model_copy(
                update={
                    "execution_state": ExecutionState.FAILED,
                    "current_role": stage,
                    "next_required_action": next_action,
                    "failure_stage": stage,
                    "failure_code": str(failure.get("code", "workflow_execution_failed")),
                    "failure_artifact": str(failure.get("artifact", "failure.json")),
                }
            )
        )

    def _checkpoint(
        self,
        checkpoint: str,
        *,
        current_role: str,
        requests_used: int | None = None,
        network_state: NetworkState | None = None,
    ) -> None:
        state = self.state()
        updates: dict[str, Any] = {
            "last_successful_checkpoint": checkpoint,
            "current_role": current_role,
        }
        if requests_used is not None:
            updates["requests_used"] = requests_used
        if network_state is not None:
            updates["network_state"] = network_state
        self._save_state(state.model_copy(update=updates))

    @staticmethod
    def _payload(result: TaskResult) -> dict[str, Any]:
        if result.handoff is None:
            raise VerticalWorkflowError("completed role omitted its handoff")
        if not isinstance(result.handoff.result, dict):
            raise VerticalWorkflowError("V2 handoff cannot enter the legacy workflow")
        return result.handoff.result

    def start(
        self,
        *,
        target: str,
        engine: PolicyEngine,
        provider: str,
        model: str,
        prompt_registry_digest: str,
    ) -> VerticalState:
        raise VerticalWorkflowError("legacy_run_read_only")
        resolved = engine.resolve_url(target)
        if resolved.host != "localhost" or not resolved.connect_ip.startswith(("127.", "::1")):
            raise VerticalWorkflowError("Phase 2 permits only a localhost loopback target")
        plan = RunPlan(
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
        gate_result = self._run_role(
            "gatekeeper",
            {
                "run_plan": plan.model_dump(mode="json"),
                "policy_resolution": {"host": resolved.host, "connect_ip": resolved.connect_ip},
                "scope_summary": {
                    "profile": engine.policy.profile,
                    "automation_allowed": engine.policy.automation_allowed,
                    "dry_run": engine.policy.dry_run,
                    "matched_rule": resolved.rule.model_dump(mode="json"),
                    "max_requests": engine.policy.max_requests,
                },
            },
        )
        gate = GateDecision.model_validate(self._payload(gate_result))
        if gate.decision != "allowed":
            raise VerticalWorkflowError(f"gatekeeper blocked run: {gate.reason}")
        if gate.target != target or gate.resolved_ip != resolved.connect_ip:
            raise VerticalWorkflowError("gatekeeper changed the policy-resolved target identity")
        self._checkpoint("gate_allowed", current_role="recon")
        recon_result = self._run_role(
            "recon",
            {"gate_decision": gate.model_dump(mode="json"), "target": target},
            allowed_actions=(ActionKind.HTTP_GET.value,),
            request_budget=1,
        )
        recon = ReconObservation.model_validate(self._payload(recon_result))
        if recon.url != target:
            raise VerticalWorkflowError("Recon observation is bound to another URL")
        self._checkpoint(
            "recon_completed",
            current_role="mapper",
            requests_used=1,
            network_state=NetworkState.USED,
        )
        mapper_result = self._run_role(
            "mapper",
            {"recon_observation": recon.model_dump(mode="json")},
            evidence_refs=(recon.evidence,),
        )
        surface = self._validated_attack_surface(self._payload(mapper_result), recon)
        if surface.target_url != target or surface.source_evidence != recon.evidence:
            raise VerticalWorkflowError("Mapper output is not bound to the Recon observation")
        self._assert_control_link(recon, surface)
        self._checkpoint("surface_mapped", current_role="web-vuln")
        validation = self._fixed_validation_plan(surface)
        web_result = self._run_role(
            "web-vuln",
            {
                "attack_surface": surface.model_dump(mode="json"),
                "required_candidate_type": "missing_x_content_type_options",
                "validation_plan": validation.model_dump(mode="json"),
            },
            evidence_refs=(recon.evidence,),
        )
        candidate = WebCandidate.model_validate(self._payload(web_result))
        if (
            candidate.target_url != surface.target_url
            or candidate.negative_control_url != surface.negative_control_url
        ):
            raise VerticalWorkflowError("web candidate changed the typed attack surface")
        if candidate.validation_plan.digest != validation.digest:
            raise VerticalWorkflowError(
                "web candidate changed the parent-generated validation plan"
            )
        self.context.write_json(
            "plan/candidate.json", candidate.model_dump(mode="json"), immutable=True
        )
        self.context.write_json(
            "approvals/challenge.json",
            {
                "challenge_id": validation.plan_id,
                "candidate_id": candidate.candidate_id,
                "validation_plan_digest": validation.digest,
                "expires_at": validation.expires_at.isoformat(),
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
                    "candidate": "plan/candidate.json",
                    "challenge": "approvals/challenge.json",
                },
                last_successful_checkpoint="candidate_ready",
            )
        )

    def resume_after_approval(
        self, *, approval_store: TrustStoreV2, review_store: TrustStoreV2
    ) -> VerticalState:
        raise VerticalWorkflowError("legacy_run_read_only")
        state = self.state()
        if state.execution_state is ExecutionState.REJECTED:
            return state
        if state.execution_state is ExecutionState.AWAITING_APPROVAL:
            candidate = WebCandidate.model_validate_json(
                self.context.artifact_path("plan/candidate.json").read_text(encoding="utf-8")
            )
            bundle = ApprovalBundle.model_validate_json(
                self.context.artifact_path("approvals/decision.json").read_text(encoding="utf-8")
            )
            verify_approval_bundle(bundle, candidate.validation_plan, approval_store)
            if any(item.decision == "rejected" for item in bundle.decisions):
                return self._save_state(
                    state.model_copy(
                        update={
                            "execution_state": ExecutionState.REJECTED,
                            "next_required_action": None,
                        }
                    )
                )
            self._checkpoint("validation_approved", current_role="verifier")
            verifier = self._run_role(
                "verifier",
                {
                    "candidate": candidate.model_dump(mode="json"),
                    "approval_bundle_id": bundle.bundle_id,
                },
                evidence_refs=(),
                allowed_actions=(ActionKind.VALIDATION_HTTP_GET.value,),
                request_budget=2,
            )
            outcome = self._validated_verification_outcome(self._payload(verifier), verifier)
            if (
                outcome.run_id != self.context.run_id
                or outcome.scope_digest != self.context.scope_digest
            ):
                raise VerticalWorkflowError("verification outcome is bound to another run or scope")
            if outcome.candidate_id != candidate.candidate_id:
                raise VerticalWorkflowError("verification outcome is bound to another candidate")
            self.context.write_json(
                "report/outcome.json", outcome.model_dump(mode="json"), immutable=True
            )
            draft = self._report_draft(candidate, outcome)
            self.context.write_text("report/draft.md", draft, immutable=True)
            return self._save_state(
                state.model_copy(
                    update={
                        "execution_state": ExecutionState.AWAITING_REVIEW,
                        "network_state": NetworkState.USED,
                        "requests_used": 3,
                        "current_role": "verifier",
                        "next_required_action": "review_sign",
                        "artifacts": {
                            **state.artifacts,
                            "outcome": "report/outcome.json",
                            "report_draft": "report/draft.md",
                        },
                    }
                )
            )
        if state.execution_state is not ExecutionState.AWAITING_REVIEW:
            if state.execution_state is ExecutionState.COMPLETED:
                return state
            raise VerticalWorkflowError(f"cannot resume state {state.execution_state.value}")
        outcome = VerificationOutcome.model_validate_json(
            self.context.artifact_path("report/outcome.json").read_text(encoding="utf-8")
        )
        review = SignedHumanReview.model_validate_json(
            self.context.artifact_path("reviews/signed.json").read_text(encoding="utf-8")
        )
        if review.outcome_digest != outcome.digest or review.report_draft_digest != (
            report_draft_digest(self.context.artifact_path("report/draft.md"))
        ):
            raise VerticalWorkflowError("review is not bound to the outcome and report draft")
        verify_human_review(
            review,
            review_store,
            run_id=self.context.run_id,
            scope_digest=self.context.scope_digest,
            finding_id=outcome.candidate_id,
            evidence_digest=outcome.digest,
        )
        if review.verdict != "accepted" or outcome.status != "validated":
            raise VerticalWorkflowError("only an accepted validated outcome may reach Reporter")
        candidate = WebCandidate.model_validate_json(
            self.context.artifact_path("plan/candidate.json").read_text(encoding="utf-8")
        )
        finding = self._finding(candidate, outcome, review)
        self._checkpoint("review_accepted", current_role="reporter")
        reporter = self._run_role(
            "reporter",
            {
                "validated_finding": finding.model_dump(mode="json"),
                "signed_review": review.model_dump(mode="json"),
            },
            evidence_refs=(outcome.target_evidence, outcome.control_evidence),
        )
        if self._validated_reporter_ack(self._payload(reporter), finding.id) != finding.id:
            raise VerticalWorkflowError("Reporter did not acknowledge the reviewed finding")
        raise VerticalWorkflowError("legacy_run_read_only")

    def _fixed_validation_plan(self, surface: AttackSurface) -> ValidationPlan:
        now = datetime.now(UTC)
        return ValidationPlan(
            plan_id="validation-1",
            run_id=self.context.run_id,
            scope_digest=self.context.scope_digest,
            candidate_id="missing-x-content-type-options",
            actions=(
                PlannedAction(
                    action_id="target-get",
                    action=ProposedAction(
                        kind=ActionKind.VALIDATION_HTTP_GET,
                        target=surface.target_url,
                        method="GET",
                        max_requests=1,
                    ),
                    rationale="Confirm the candidate response omits nosniff.",
                ),
                PlannedAction(
                    action_id="control-get",
                    action=ProposedAction(
                        kind=ActionKind.VALIDATION_HTTP_GET,
                        target=surface.negative_control_url,
                        method="GET",
                        max_requests=1,
                    ),
                    rationale="Confirm the matched negative control includes nosniff.",
                ),
            ),
            created_at=now,
            expires_at=now + timedelta(minutes=15),
        )

    @staticmethod
    def _assert_control_link(recon: ReconObservation, surface: AttackSurface) -> None:
        link = next((v for k, v in recon.headers.items() if k.lower() == "link"), "")
        expected = urljoin(recon.url, "/control")
        if 'rel="negative-control"' not in link or surface.negative_control_url != expected:
            raise VerticalWorkflowError(
                "Mapper control URL is not grounded in the signed Link header"
            )

    @staticmethod
    def _validated_attack_surface(
        payload: dict[str, Any], recon: ReconObservation
    ) -> AttackSurface:
        normalized = dict(payload)
        supplied = normalized.get("source_evidence")
        if isinstance(supplied, str):
            if supplied != recon.evidence.id:
                raise VerticalWorkflowError("Mapper referenced another evidence ID")
            normalized["source_evidence"] = recon.evidence.model_dump(mode="json")
        elif supplied != recon.evidence.model_dump(mode="json"):
            raise VerticalWorkflowError("Mapper changed or omitted its source evidence")
        try:
            return AttackSurface.model_validate(normalized)
        except ValueError as exc:
            raise VerticalWorkflowError("Mapper output violated AttackSurface") from exc

    @staticmethod
    def _validated_verification_outcome(
        payload: dict[str, Any], verifier: TaskResult
    ) -> VerificationOutcome:
        normalized = dict(payload)
        details = normalized.get("details")
        if isinstance(details, str):
            normalized["details"] = {"summary": details}
        try:
            outcome = VerificationOutcome.model_validate(normalized)
        except ValueError as exc:
            raise VerticalWorkflowError("Verifier output violated VerificationOutcome") from exc
        if verifier.handoff is None or tuple(verifier.handoff.evidence_refs) != (
            outcome.target_evidence,
            outcome.control_evidence,
        ):
            raise VerticalWorkflowError(
                "Verifier outcome changed the ordered Host gateway evidence"
            )
        return outcome

    @staticmethod
    def _validated_reporter_ack(payload: dict[str, Any], finding_id: str) -> str:
        normalized = dict(payload)
        if set(normalized) == {"result"} and normalized.get("result") == finding_id:
            normalized = {"accepted_finding_id": finding_id}
        if normalized != {"accepted_finding_id": finding_id}:
            raise VerticalWorkflowError(
                "Reporter acknowledgement is not bound to the reviewed finding"
            )
        return finding_id

    @staticmethod
    def _report_draft(candidate: WebCandidate, outcome: VerificationOutcome) -> str:
        return (
            "# Review draft\n\n"
            f"Candidate: {candidate.candidate_id}\n\nOutcome: {outcome.status}\n\n"
            "Local teaching fixture only; this is not a Bugcrowd submission.\n"
        )

    def _finding(
        self, candidate: WebCandidate, outcome: VerificationOutcome, review: SignedHumanReview
    ) -> ValidatedFinding:
        evidence = []
        for ref in (outcome.target_evidence, outcome.control_evidence):
            metadata = json.loads(self.context.artifact_path(ref.path).read_text(encoding="utf-8"))
            evidence.append(
                FindingEvidence(
                    request_sha256=metadata["request_hash"],
                    response_sha256=metadata["response_hash"],
                    path=ref.path,
                    captured_at=review.reviewed_at,
                )
            )
        return ValidatedFinding(
            id=candidate.candidate_id,
            title="Missing X-Content-Type-Options on local teaching endpoint",
            target=candidate.target_url,
            run_id=self.context.run_id,
            scope_digest=self.context.scope_digest,
            approval_id="validation-1",
            evidence=evidence,
            review=HumanReview(
                reviewer=review.reviewer,
                reviewed_at=review.reviewed_at,
                verdict=review.verdict,
                rationale=review.rationale,
            ),
            summary="The candidate endpoint omits the nosniff response header.",
            prerequisites=["Local Docker teaching fixture"],
            reproduction_steps=["GET /candidate", "GET /control and compare headers"],
            impact="Browser MIME sniffing defense is absent on the candidate fixture.",
            remediation="Set X-Content-Type-Options: nosniff consistently.",
            severity="informational",
            coverage="One candidate and one matched negative-control GET.",
            local_teaching_fixture=True,
        )


def report_draft_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


class ApprovalBundleValidator:
    """Gateway callback that consumes each signed plan action exactly once."""

    def __init__(self, context: RunContext, trust_store: TrustStoreV2) -> None:
        self.context = context
        self.trust_store = trust_store

    def __call__(self, action: ProposedAction, token: object) -> None:
        if not isinstance(token, str):
            raise ApprovalDenied("validation request omitted its approval bundle ID")
        candidate = WebCandidate.model_validate_json(
            self.context.artifact_path("plan/candidate.json").read_text(encoding="utf-8")
        )
        bundle = ApprovalBundle.model_validate_json(
            self.context.artifact_path("approvals/decision.json").read_text(encoding="utf-8")
        )
        if token != bundle.bundle_id:
            raise ApprovalDenied("validation request used another approval bundle")
        planned = next(
            (
                item
                for item in candidate.validation_plan.actions
                if item.action.digest == action.digest
            ),
            None,
        )
        if planned is None:
            raise ApprovalDenied("validation request is not in the signed plan")
        ledger = self._ledger_from_claims()
        updated = consume_approved_action(
            bundle=bundle,
            plan=candidate.validation_plan,
            action_id=planned.action_id,
            ledger=ledger,
            trust_store=self.trust_store,
        )
        consumption = updated.consumptions[-1]
        try:
            self.context.write_json_exclusive(
                f"approvals/consumed/{bundle.bundle_id}/{planned.action_id}.json",
                consumption.model_dump(mode="json"),
            )
        except FileExistsError as exc:
            raise ApprovalDenied("approved action was already consumed") from exc
        snapshot = self._ledger_from_claims()
        self.context.write_json("approvals/consumption.json", snapshot.model_dump(mode="json"))

    def _ledger_from_claims(self) -> ApprovalConsumptionLedger:
        root = self.context.artifact_path("approvals/consumed")
        consumptions = []
        if root.exists():
            for path in sorted(root.glob("*/*.json")):
                consumptions.append(
                    ApprovalConsumption.model_validate_json(path.read_text(encoding="utf-8"))
                )
        return ApprovalConsumptionLedger(consumptions=tuple(consumptions))

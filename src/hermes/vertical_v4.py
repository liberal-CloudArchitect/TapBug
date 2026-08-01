"""Isolated Phase 5 coordinator up to its first governed approval boundary.

The V4 coordinator deliberately owns scheduling and durable task envelopes but
not network authority.  Recon/Mapper observations and every later verification
request must still pass through the parent-owned Gateway/Action Ledger.  This
module therefore has a small, testable responsibility: persist a V4 run plan,
launch independent role tasks with their own ACP sessions, and create the
read-only approval pause only after deterministic fan-out/fan-in work has
finished.
"""

from __future__ import annotations

import json
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .campaign_v4 import CandidateTypeV4, approval_actions_v4, build_verification_campaign_v4
from .domain_contracts_v4 import ExecutionBudgetV4, RunPlanV4
from .runtime import RunContext
from .runtime.agents import AgentRunner, TaskEnvelope, TaskResult
from .workflow import WorkflowEventLog

ROLE_ORDER_V4 = (
    "gatekeeper",
    "recon",
    "mapper",
    "web-vuln",
    "api",
    "authz",
    "infra",
    "verifier",
    "reporter",
)
BRANCH_ROLES_V4 = ("web-vuln", "api", "authz", "infra")
_BRANCH_TO_LABEL = {"web-vuln": "web", "api": "api", "authz": "authz", "infra": "infra"}
_CANDIDATE_BRANCH = {
    "web-xcto": "web-vuln",
    "web-cookie": "web-vuln",
    "web-open-redirect": "web-vuln",
    "api-graphql": "api",
    "authz-privilege": "authz",
    "authz-bola": "authz",
    "workflow-bypass": "authz",
    "infra-debug": "infra",
}
_BRANCH_CANDIDATE_TYPES: dict[str, tuple[CandidateTypeV4, ...]] = {
    "web-vuln": (
        "missing_x_content_type_options",
        "insecure_session_cookie",
        "unvalidated_redirect",
    ),
    "api": ("unauthorized_graphql_mutation",),
    "authz": (
        "privilege_escalation",
        "cross_tenant_object_read",
        "workflow_transition_bypass",
    ),
    "infra": ("exposed_debug_endpoint",),
}
_CANDIDATE_TYPE_BY_ID: dict[str, CandidateTypeV4] = {
    "web-xcto": "missing_x_content_type_options",
    "web-cookie": "insecure_session_cookie",
    "web-open-redirect": "unvalidated_redirect",
    "api-graphql": "unauthorized_graphql_mutation",
    "authz-privilege": "privilege_escalation",
    "authz-bola": "cross_tenant_object_read",
    "workflow-bypass": "workflow_transition_bypass",
    "infra-debug": "exposed_debug_endpoint",
}
_REVIEW_RING = {"web-vuln": "api", "api": "authz", "authz": "infra", "infra": "web-vuln"}


class ExecutionStateV4(StrEnum):
    PLANNED = "planned"
    RUNNING = "running"
    ROUTING = "routing"
    ASSESSING = "assessing"
    CROSS_REVIEWING = "cross_reviewing"
    AWAITING_READONLY_APPROVAL = "awaiting_readonly_approval"
    VERIFYING_READONLY = "verifying_readonly"
    AWAITING_MUTATION_APPROVAL = "awaiting_mutation_approval"
    VERIFYING_MUTATION = "verifying_mutation"
    AWAITING_CLEANUP_APPROVAL = "awaiting_cleanup_approval"
    CLEANUP_REQUIRED = "cleanup_required"
    AWAITING_REVIEW = "awaiting_review"
    COMPLETED = "completed"
    COMPLETED_WITH_GAPS = "completed_with_gaps"
    REJECTED = "rejected"
    FAILED = "failed"


class NetworkStateV4(StrEnum):
    DISABLED = "disabled"
    POLICY_BLOCKED = "policy_blocked"
    ENABLED_IDLE = "enabled_idle"
    REQUESTED = "requested"
    USED = "used"


class VerticalStateV4(BaseModel):
    """Persisted operator state.  Budget caps are schema-level invariants."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: str = "4"
    run_id: str
    execution_state: ExecutionStateV4
    network_state: NetworkStateV4
    requests_planned: int = Field(ge=0, le=32)
    requests_used: int = Field(ge=0, le=32)
    requests_blocked: int = Field(ge=0, le=32)
    current_role: str | None = None
    next_required_action: str | None = None
    routed_branches: tuple[str, ...] = ()
    succeeded_branches: tuple[str, ...] = ()
    failed_branches: tuple[str, ...] = ()
    budget_attempts_reserved: int = Field(default=0, ge=0, le=64)
    budget_estimated_microusd: int = Field(default=0, ge=0, le=16_000_000)
    cleanup_state: str = "not_required"
    artifacts: dict[str, str] = Field(default_factory=dict)
    last_successful_checkpoint: str | None = None
    failure_code: str | None = None


class VerticalWorkflowV4Error(RuntimeError):
    """V4 scheduling or persistence violated a frozen security boundary."""


class VerticalWorkflowV4:
    """Launch the non-network V4 collaboration plane deterministically.

    Candidate typing, verification action construction, approvals and evidence
    are parent-runtime capabilities stored in sibling V4 modules.  By keeping
    this coordinator unaware of raw response material, a role cannot turn a
    model handoff into an egress authority.
    """

    def __init__(self, context: RunContext, runner: AgentRunner, *, max_workers: int = 4) -> None:
        self.context = context
        self.runner = runner
        self.max_workers = min(4, max(1, max_workers))
        self.events = WorkflowEventLog(context)

    @property
    def state_path(self) -> Path:
        return self.context.artifact_path("state.json")

    def state(self) -> VerticalStateV4:
        return VerticalStateV4.model_validate_json(self.state_path.read_bytes())

    def _save_state(self, state: VerticalStateV4) -> VerticalStateV4:
        self.context.write_json("state.json", state.model_dump(mode="json"))
        self.events.record(
            "vertical_state_v4",
            execution_state=state.execution_state.value,
            network_state=state.network_state.value,
            current_role=state.current_role,
        )
        return state

    def _set_stage(self, stage: ExecutionStateV4, role: str | None) -> None:
        current = self.state()
        self._save_state(
            current.model_copy(update={"execution_state": stage, "current_role": role})
        )

    def _run_role(
        self,
        role: str,
        task_id: str,
        operation: str,
        payload: dict[str, Any],
    ) -> TaskResult:
        task = TaskEnvelope(
            version="4",
            run_id=self.context.run_id,
            task_id=task_id,
            role=role,
            scope_digest=self.context.scope_digest,
            payload={"operation": operation, **payload},
            request_budget=0,
            allowed_actions=(),
            evidence_required=False,
            timeout_seconds=ExecutionBudgetV4().max_role_seconds,
        )
        relative = f"handoffs_v4/{task_id}.json"
        artifact = self.context.artifact_path(relative)
        if artifact.exists():
            try:
                stored = json.loads(artifact.read_text(encoding="utf-8"))
                persisted = TaskEnvelope.model_validate(stored["task"])
                result = TaskResult.model_validate(stored["result"])
            except (OSError, ValueError, KeyError, TypeError) as exc:
                raise VerticalWorkflowV4Error(f"invalid persisted V4 task {task_id}") from exc
            if persisted.input_hash() != task.input_hash():
                raise VerticalWorkflowV4Error(f"persisted task input changed for {task_id}")
        else:
            result = self.runner.run(task)
            self.context.write_json(
                relative,
                {"task": task.model_dump(mode="json"), "result": result.model_dump(mode="json")},
                immutable=True,
            )
        if result.lifecycle != "completed" or result.handoff is None:
            raise VerticalWorkflowV4Error(f"V4 role {role} did not return a completed handoff")
        return result

    def start(self, plan: RunPlanV4) -> VerticalStateV4:
        """Run the non-verifier V4 collaboration tasks then stop for approval.

        This is intentionally idempotent: every envelope is immutable and a
        restart reloads it after comparing its exact input digest.
        """

        if plan.run_id != self.context.run_id or plan.scope_digest != self.context.scope_digest:
            raise VerticalWorkflowV4Error("RunPlanV4 crosses the current run or scope")
        if self.state_path.exists():
            return self.state()
        self.context.write_json("plan/run-v4.json", plan.model_dump(mode="json"), immutable=True)
        initial = VerticalStateV4(
            run_id=self.context.run_id,
            execution_state=ExecutionStateV4.RUNNING,
            network_state=NetworkStateV4.ENABLED_IDLE,
            requests_planned=28,
            requests_used=0,
            requests_blocked=0,
            current_role="gatekeeper",
            routed_branches=tuple(_BRANCH_TO_LABEL.values()),
            artifacts={"plan": "plan/run-v4.json"},
        )
        self._save_state(initial)
        common = {"run_plan_digest": plan.digest, "target": plan.target}
        self._run_role("gatekeeper", "phase5-gatekeeper", "gate", common)
        self._run_role("recon", "phase5-recon", "recon", common)
        self._run_role("mapper", "phase5-mapper", "map", common)

        self._set_stage(ExecutionStateV4.ASSESSING, None)
        branch_results: dict[str, str] = {}
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures: dict[Future[TaskResult], str] = {
                pool.submit(
                    self._run_role,
                    role,
                    f"phase5-assessment-{_BRANCH_TO_LABEL[role]}",
                    "assessment",
                    {**common, "branch": _BRANCH_TO_LABEL[role]},
                ): role
                for role in BRANCH_ROLES_V4
            }
            for future in as_completed(futures):
                role = futures[future]
                try:
                    future.result()
                    branch_results[role] = "succeeded"
                except Exception:
                    branch_results[role] = "failed"
        if not any(value == "succeeded" for value in branch_results.values()):
            raise VerticalWorkflowV4Error("all V4 assessment branches failed")

        successful_roles = tuple(
            role for role in BRANCH_ROLES_V4 if branch_results[role] == "succeeded"
        )
        candidate_ids = tuple(
            candidate_id
            for candidate_id, producer in _CANDIDATE_BRANCH.items()
            if producer in successful_roles
        )
        self._set_stage(ExecutionStateV4.CROSS_REVIEWING, None)
        reviews: dict[str, str] = {}
        review_failures: list[str] = []

        def reviewer_for(producer: str) -> str | None:
            preferred = _REVIEW_RING[producer]
            if preferred in successful_roles:
                return preferred
            return next((role for role in successful_roles if role != producer), None)

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            review_futures: dict[Future[TaskResult], tuple[str, str]] = {}
            for candidate_id in candidate_ids:
                producer = _CANDIDATE_BRANCH[candidate_id]
                reviewer = reviewer_for(producer)
                if reviewer is None:
                    review_failures.append(f"cross_review:{candidate_id}:no_independent_reviewer")
                    continue
                review_futures[
                    pool.submit(
                        self._run_role,
                        reviewer,
                        f"phase5-cross-review-{candidate_id}",
                        "cross_review",
                        {
                            **common,
                            "candidate_id": candidate_id,
                            "producer_branch": _BRANCH_TO_LABEL[producer],
                            "reviewer_branch": _BRANCH_TO_LABEL[reviewer],
                        },
                    )
                ] = (candidate_id, reviewer)
            for future in as_completed(review_futures):
                candidate_id, reviewer = review_futures[future]
                try:
                    future.result()
                    reviews[candidate_id] = _BRANCH_TO_LABEL[reviewer]
                except Exception:
                    review_failures.append(f"cross_review:{candidate_id}:failed")

        selected_candidate_ids = tuple(
            candidate_id for candidate_id in candidate_ids if candidate_id in reviews
        )
        if not selected_candidate_ids:
            raise VerticalWorkflowV4Error("no V4 candidate completed independent cross-review")
        selected_types = tuple(_CANDIDATE_TYPE_BY_ID[item] for item in selected_candidate_ids)

        # Network authority begins only after an operator signs the exact action
        # graph emitted by campaign_v4.  The fixed 26 consumption count excludes
        # Recon and schema discovery, giving the planned 28 HTTP observations.
        created_at = datetime.now(UTC)
        campaign = build_verification_campaign_v4(
            run_id=self.context.run_id,
            scope_digest=self.context.scope_digest,
            generated_by_task_id="phase5-campaign-planner",
            endpoint_base=plan.target,
            identity_binding_digests=plan.identity_binding_digests,
            created_at=created_at,
            expires_at=created_at + timedelta(minutes=15),
            candidate_types=selected_types,
        )
        self.context.write_json(
            "verification_v4/campaign.json",
            campaign.model_dump(mode="json"),
            immutable=True,
        )
        for risk_group in ("readonly", "mutation", "cleanup"):
            actions = approval_actions_v4(campaign, risk_group)
            if not actions:
                continue
            self.context.write_json(
                f"approvals_v4/challenge-{risk_group}.json",
                {
                    "version": "4",
                    "challenge_id": f"phase5-{risk_group}",
                    "run_id": self.context.run_id,
                    "scope_digest": self.context.scope_digest,
                    "campaign_digest": campaign.digest,
                    "risk_group": risk_group,
                    "candidate_ids": sorted({item.candidate_id for item in actions}),
                    "action_digests": [item.action_digest for item in actions],
                    "expires_at": campaign.expires_at.isoformat(),
                },
                immutable=True,
            )
        self.context.write_json(
            "collaboration_v4/branch-results.json",
            {
                "version": "4",
                "branches": [
                    {"branch": _BRANCH_TO_LABEL[role], "status": branch_results[role]}
                    for role in BRANCH_ROLES_V4
                ],
                "gaps": [
                    f"branch:{_BRANCH_TO_LABEL[role]}:{branch_results[role]}"
                    for role in BRANCH_ROLES_V4
                    if branch_results[role] != "succeeded"
                ],
            },
            immutable=True,
        )
        self.context.write_json(
            "collaboration_v4/review-plan.json",
            {
                "version": "4",
                "candidate_ids": list(selected_candidate_ids),
                "reviewers": reviews,
                "gaps": review_failures,
                "task_count_before_verification": 3 + len(BRANCH_ROLES_V4) + len(reviews),
                "generated_at": datetime.now(UTC).isoformat(),
            },
            immutable=True,
        )
        successful = tuple(
            _BRANCH_TO_LABEL[role]
            for role in BRANCH_ROLES_V4
            if branch_results[role] == "succeeded"
        )
        failed = tuple(
            _BRANCH_TO_LABEL[role]
            for role in BRANCH_ROLES_V4
            if branch_results[role] != "succeeded"
        )
        next_group = (
            "readonly"
            if approval_actions_v4(campaign, "readonly")
            else "mutation"
        )
        next_state = (
            ExecutionStateV4.AWAITING_READONLY_APPROVAL
            if next_group == "readonly"
            else ExecutionStateV4.AWAITING_MUTATION_APPROVAL
        )
        return self._save_state(
            self.state().model_copy(
                update={
                    "execution_state": next_state,
                    "current_role": None,
                    "next_required_action": f"approve_or_reject:{next_group}",
                    "succeeded_branches": successful,
                    "failed_branches": failed,
                    "last_successful_checkpoint": "fan_out_fan_in_v4",
                    "artifacts": {
                        **self.state().artifacts,
                        "review_plan": "collaboration_v4/review-plan.json",
                        "branch_results": "collaboration_v4/branch-results.json",
                        "campaign": "verification_v4/campaign.json",
                        "readonly_challenge": "approvals_v4/challenge-readonly.json",
                        **(
                            {"mutation_challenge": "approvals_v4/challenge-mutation.json"}
                            if approval_actions_v4(campaign, "mutation")
                            else {}
                        ),
                        **(
                            {"cleanup_challenge": "approvals_v4/challenge-cleanup.json"}
                            if approval_actions_v4(campaign, "cleanup")
                            else {}
                        ),
                    },
                    "requests_planned": campaign.total_request_budget,
                }
            )
        )

    def mark_failed(self, error: Exception) -> VerticalStateV4:
        state = self.state()
        return self._save_state(
            state.model_copy(
                update={
                    "execution_state": ExecutionStateV4.FAILED,
                    "current_role": None,
                    "next_required_action": "retry_as_new_run",
                    "failure_code": type(error).__name__.lower(),
                }
            )
        )


__all__ = [
    "BRANCH_ROLES_V4",
    "ExecutionStateV4",
    "NetworkStateV4",
    "ROLE_ORDER_V4",
    "VerticalStateV4",
    "VerticalWorkflowV4",
    "VerticalWorkflowV4Error",
]

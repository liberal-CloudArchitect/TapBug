"""Persistent Phase 4 coordinator up to the first governed verification pause.

V3 is deliberately isolated from :mod:`hermes.vertical_v2`.  This module owns
the deterministic route/fan-out/fan-in/cross-review planning boundary; network
execution after approval is delegated to the parent-owned V3 execution layer.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal, TypeVar
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field

from .campaign_v3 import (
    ActionLedgerSummary,
    BudgetCoverageSummary,
    build_coverage_report,
    build_verification_campaign,
)
from .capability_verifier import CapabilityGapResolver, capability_gap_verdict
from .collaboration_v3 import CandidateFanIn, ParallelCollaborationV3, RoutePolicy
from .domain_contracts_v3 import (
    ApprovalBatchV3,
    AssetInventoryV3,
    BranchResult,
    CandidateCollection,
    CandidateTypeV3,
    CleanupReceipt,
    ContractEnvelopeV3,
    CoverageReportV3,
    CrossReviewSet,
    EndpointInventoryV3,
    EndpointV3,
    ExecutionBudgetV3,
    FindingSet,
    GateDecisionV3,
    ReporterAckV3,
    RunPlanV3,
    VerificationActionV3,
    VerificationCampaignPlan,
    VerificationCandidateOutcome,
    VerificationOutcomeSet,
)
from .evidence import EvidenceAnalysisDocument, EvidenceStore
from .execution_v3 import CompensationManagerV3, ExecutionResultV3
from .ledgers_v3 import (
    ActionLedger,
    ActiveTimeExceeded,
    ActiveTimeLedger,
    BudgetLedger,
)
from .preflight_v3 import ReportPreflightVerifierV3
from .promotion_v3 import promote_findings_v3
from .reporting_v3 import write_report_v3
from .runtime import ActionKind, PolicyEngine, RunContext
from .runtime.agents import AgentRunner, TaskEnvelope, TaskResult
from .security import TrustStoreV2
from .security_v3 import cleanup_challenge_payload_v3, verify_approval_batch_v3
from .workflow import WorkflowEventLog

ROLE_ORDER_V3 = (
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
_Payload = TypeVar("_Payload", bound=BaseModel)


class ExecutionStateV3(StrEnum):
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


class NetworkStateV3(StrEnum):
    DISABLED = "disabled"
    POLICY_BLOCKED = "policy_blocked"
    ENABLED_IDLE = "enabled_idle"
    REQUESTED = "requested"
    USED = "used"


class VerticalStateV3(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: str = "3"
    run_id: str
    execution_state: ExecutionStateV3
    network_state: NetworkStateV3
    requests_planned: int = Field(ge=0, le=15)
    requests_used: int = Field(ge=0, le=15)
    requests_blocked: int = Field(ge=0, le=15)
    current_role: str | None = None
    next_required_action: str | None = None
    routed_branches: tuple[str, ...] = ()
    succeeded_branches: tuple[str, ...] = ()
    failed_branches: tuple[str, ...] = ()
    budget_attempts_reserved: int = Field(default=0, ge=0, le=40)
    budget_estimated_microusd: int = Field(default=0, ge=0, le=10_000_000)
    cleanup_state: str = "not_required"
    artifacts: dict[str, str] = Field(default_factory=dict)
    last_successful_checkpoint: str | None = None
    failure_code: str | None = None


class VerticalWorkflowV3Error(RuntimeError):
    """The V3 coordinator could not preserve a frozen workflow invariant."""


class VerticalWorkflowV3:
    """Create the V3 campaign and stop before the first approved request."""

    def __init__(
        self,
        context: RunContext,
        runner: AgentRunner,
        *,
        max_workers: int = 4,
        timeout_seconds: int = 180,
        max_active_seconds: int = 1_800,
        capability_resolver: CapabilityGapResolver | None = None,
    ) -> None:
        self.context = context
        self.runner = runner
        self.max_workers = max_workers
        self.timeout_seconds = timeout_seconds
        self.active_time = ActiveTimeLedger(context, max_active_seconds=max_active_seconds)
        self.events = WorkflowEventLog(context)
        # Optional CAP-07 capability: when the paused assessment learned an active
        # approved Wheel for a line_kv_capability_gap candidate, the Verifier
        # resolves that candidate through the governed sandbox instead of leaving
        # it a coverage gap. Off by default; the fixed Phase 4 fixture never emits
        # that candidate type, so existing acceptance behaviour is unchanged.
        self._capability_resolver = capability_resolver

    def _task_timeout(self) -> int:
        remaining = self.active_time.remaining_seconds()
        if remaining < 1:
            raise ActiveTimeExceeded("less than one second remains for a V3 role task")
        return min(self.timeout_seconds, int(remaining))

    @property
    def state_path(self) -> Path:
        return self.context.artifact_path("state.json")

    def state(self) -> VerticalStateV3:
        return VerticalStateV3.model_validate_json(self.state_path.read_bytes())

    def _save_state(self, state: VerticalStateV3) -> VerticalStateV3:
        self.context.write_json("state.json", state.model_dump(mode="json"))
        self.events.record(
            "vertical_state_v3",
            execution_state=state.execution_state.value,
            network_state=state.network_state.value,
            current_role=state.current_role,
        )
        return state

    def _set_stage(self, stage: ExecutionStateV3, role: str | None) -> None:
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
        *,
        request_budget: int = 0,
        allowed_actions: tuple[str, ...] = (),
    ) -> TaskResult:
        task = TaskEnvelope(
            version="3",
            run_id=self.context.run_id,
            task_id=task_id,
            role=role,
            scope_digest=self.context.scope_digest,
            payload={"operation": operation, **payload},
            request_budget=request_budget,
            allowed_actions=allowed_actions,
            evidence_required=bool(request_budget),
            timeout_seconds=self._task_timeout(),
        )
        relative = f"handoffs/{task_id}.json"
        path = self.context.artifact_path(relative)
        if path.exists():
            stored = json.loads(path.read_text(encoding="utf-8"))
            persisted = TaskEnvelope.model_validate(stored["task"])
            result = TaskResult.model_validate(stored["result"])
            if persisted.input_hash() != task.input_hash():
                raise VerticalWorkflowV3Error(f"persisted task input changed for {task_id}")
        else:
            result = self.runner.run(task)
            self.context.write_json(
                relative,
                {"task": task.model_dump(mode="json"), "result": result.model_dump(mode="json")},
                immutable=True,
            )
        if result.lifecycle != "completed" or result.handoff is None:
            raise VerticalWorkflowV3Error(
                f"V3 role {role} failed: {result.error or result.lifecycle}"
            )
        if result.handoff.version != "3" or not isinstance(
            result.handoff.result, ContractEnvelopeV3
        ):
            raise VerticalWorkflowV3Error("V2 or untyped handoff cannot enter the V3 workflow")
        return result

    @staticmethod
    def _payload(result: TaskResult, expected: type[_Payload]) -> _Payload:
        if result.handoff is None or not isinstance(result.handoff.result, ContractEnvelopeV3):
            raise VerticalWorkflowV3Error("completed role omitted its V3 contract envelope")
        value = result.handoff.result.payload
        if not isinstance(value, expected):
            raise VerticalWorkflowV3Error(
                f"role returned {type(value).__name__}, expected {expected.__name__}"
            )
        return value

    @staticmethod
    def _endpoint_projection(assets: AssetInventoryV3) -> tuple[EndpointV3, ...]:
        """Build the only endpoints Mapper may preserve from trusted Recon links."""

        if len(assets.assets) != 1 or len(assets.source_evidence) != 1:
            raise VerticalWorkflowV3Error(
                "the fixed Phase 4 chain requires one asset and one Recon artifact"
            )
        asset = assets.assets[0]
        evidence = assets.source_evidence
        target_path = urlsplit(assets.target).path.strip("/") or "root"
        endpoints = [
            EndpointV3(
                endpoint_id=f"{asset.asset_id}-{target_path}-candidate",
                asset_id=asset.asset_id,
                canonical_url=assets.target,
                method="GET",
                relation="candidate",
                content_types=asset.content_types,
                evidence=evidence,
            )
        ]
        relation_map: dict[
            str, Literal["negative_control", "graphql", "role_change", "diagnostic"]
        ] = {
            "negative-control": "negative_control",
            "graphql": "graphql",
            "role-state": "role_change",
            "diagnostic": "diagnostic",
        }
        for link in asset.observed_links:
            endpoints.append(
                EndpointV3(
                    endpoint_id=f"{asset.asset_id}-{link.relation}",
                    asset_id=asset.asset_id,
                    canonical_url=link.canonical_url,
                    method="GET",
                    relation=relation_map[link.relation],
                    evidence=evidence,
                )
            )
        return tuple(endpoints)

    def start(
        self,
        *,
        target: str,
        engine: PolicyEngine,
        provider_id: str,
        model_id: str,
        prompt_registry_digest: str,
        role_manifest_set_digest: str,
        identity_binding_digests: dict[str, str],
        budget: ExecutionBudgetV3 | None = None,
    ) -> VerticalStateV3:
        budget = budget or ExecutionBudgetV3()
        resolved = engine.resolve_url(target)
        if resolved.host != "localhost" or not resolved.connect_ip.startswith(("127.", "::1")):
            raise VerticalWorkflowV3Error("V3 permits only a localhost loopback fixture")
        plan = RunPlanV3(
            run_id=self.context.run_id,
            target=target,
            scope_digest=self.context.scope_digest,
            provider_id=provider_id,
            model_id=model_id,
            prompt_registry_digest=prompt_registry_digest,
            role_manifest_set_digest=role_manifest_set_digest,
            roles=ROLE_ORDER_V3,
            identity_binding_digests=identity_binding_digests,
            budget=budget,
            created_at=datetime.now(UTC),
        )
        self.context.write_json("plan/run-v3.json", plan.model_dump(mode="json"), immutable=True)
        self._save_state(
            VerticalStateV3(
                run_id=self.context.run_id,
                execution_state=ExecutionStateV3.RUNNING,
                network_state=NetworkStateV3.ENABLED_IDLE,
                requests_planned=1,
                requests_used=0,
                requests_blocked=0,
                current_role="gatekeeper",
                artifacts={"plan": "plan/run-v3.json"},
            )
        )

        gate_result = self._run_role(
            "gatekeeper",
            "phase4-gatekeeper",
            "gate",
            {
                "run_plan": plan.model_dump(mode="json"),
                "target": target,
                "resolved_ips": [resolved.connect_ip],
                "policy_summary": {
                    "profile": engine.policy.profile,
                    "max_requests": engine.policy.max_requests,
                    "max_concurrency": engine.policy.max_concurrency,
                },
                "generated_by_task_id": "phase4-gatekeeper",
            },
        )
        gate = self._payload(gate_result, GateDecisionV3)
        if (
            gate.run_id != self.context.run_id
            or gate.scope_digest != self.context.scope_digest
            or gate.generated_by_task_id != "phase4-gatekeeper"
            or gate.target != target
            or tuple(gate.resolved_ips) != (resolved.connect_ip,)
            or gate.decision != "allowed"
        ):
            raise VerticalWorkflowV3Error("Gatekeeper did not preserve the frozen run decision")

        recon_result = self._run_role(
            "recon",
            "phase4-recon",
            "recon",
            {
                "gate_decision": gate.model_dump(mode="json"),
                "target": target,
                "generated_by_task_id": "phase4-recon",
            },
            request_budget=1,
            allowed_actions=(ActionKind.HTTP_GET.value,),
        )
        assets = self._payload(recon_result, AssetInventoryV3)
        if (
            assets.run_id != self.context.run_id
            or assets.scope_digest != self.context.scope_digest
            or assets.generated_by_task_id != "phase4-recon"
            or assets.target != target
            or recon_result.handoff is None
            or tuple(recon_result.handoff.evidence_artifact_refs) != assets.source_evidence
        ):
            raise VerticalWorkflowV3Error("Recon inventory changed its task or evidence binding")
        self.context.write_json(
            "assets/inventory-v3.json", assets.model_dump(mode="json"), immutable=True
        )

        mapper_result = self._run_role(
            "mapper",
            "phase4-mapper",
            "map",
            {
                "asset_inventory": assets.model_dump(mode="json"),
                "asset_inventory_digest": assets.digest,
                "relation_projection": [
                    item.model_dump(mode="json") for item in self._endpoint_projection(assets)
                ],
                "generated_by_task_id": "phase4-mapper",
            },
        )
        endpoints = self._payload(mapper_result, EndpointInventoryV3)
        expected_endpoints = self._endpoint_projection(assets)
        if (
            endpoints.run_id != self.context.run_id
            or endpoints.scope_digest != self.context.scope_digest
            or endpoints.generated_by_task_id != "phase4-mapper"
            or endpoints.asset_inventory_digest != assets.digest
            or endpoints.endpoints != expected_endpoints
            or endpoints.unresolved
        ):
            raise VerticalWorkflowV3Error("Mapper inventory broke the asset digest chain")
        self.context.write_json(
            "endpoints/inventory-v3.json", endpoints.model_dump(mode="json"), immutable=True
        )

        self._set_stage(ExecutionStateV3.ROUTING, None)
        route = RoutePolicy().decide(
            endpoints,
            run_id=self.context.run_id,
            scope_digest=self.context.scope_digest,
            generated_by_task_id="phase4-router",
            identity_binding_digests=tuple(sorted(identity_binding_digests.values())),
        )
        self.context.write_json(
            "collaboration_v3/route.json", route.model_dump(mode="json"), immutable=True
        )
        collaboration = ParallelCollaborationV3(
            self.context,
            self.runner,
            max_workers=budget.max_concurrency,
            timeout_seconds=self._task_timeout,
        )
        self._set_stage(ExecutionStateV3.ASSESSING, None)
        branch_results, assessments = collaboration.run_assessments(
            route=route,
            inventory=endpoints,
            identity_binding_digests=identity_binding_digests,
        )
        collection: CandidateCollection = CandidateFanIn().merge(
            route=route,
            inventory=endpoints,
            identity_binding_digests=identity_binding_digests,
            branch_results=branch_results,
            assessments=assessments,
            generated_by_task_id="phase4-fanin",
        )
        self.context.write_json(
            "collaboration_v3/candidates.json",
            collection.model_dump(mode="json"),
            immutable=True,
        )
        self._set_stage(ExecutionStateV3.CROSS_REVIEWING, None)
        reviews = collaboration.run_cross_reviews(collection=collection)
        created_at = datetime.now(UTC)
        campaign: VerificationCampaignPlan = build_verification_campaign(
            collection,
            reviews,
            endpoint_base=target,
            identity_binding_digests=identity_binding_digests,
            generated_by_task_id="phase4-campaign-planner",
            created_at=created_at,
            expires_at=created_at + timedelta(minutes=30),
        )
        if not campaign.actions:
            raise VerticalWorkflowV3Error(
                "cross review left no candidate eligible for verification"
            )
        self.context.write_json(
            "verification_v3/campaign.json", campaign.model_dump(mode="json"), immutable=True
        )
        for risk_group in ("readonly", "mutation"):
            actions = tuple(item for item in campaign.actions if item.risk_group == risk_group)
            if actions:
                self.context.write_json(
                    f"approvals_v3/challenge-{risk_group}.json",
                    {
                        "version": "3",
                        "challenge_id": f"phase4-{risk_group}",
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

        successful = tuple(item.branch for item in branch_results if item.status == "succeeded")
        failed = tuple(
            item.branch for item in branch_results if item.status in {"failed", "timed_out"}
        )
        has_readonly = any(item.risk_group == "readonly" for item in campaign.actions)
        next_state = (
            ExecutionStateV3.AWAITING_READONLY_APPROVAL
            if has_readonly
            else ExecutionStateV3.AWAITING_MUTATION_APPROVAL
        )
        next_group = "readonly" if has_readonly else "mutation"
        return self._save_state(
            VerticalStateV3(
                run_id=self.context.run_id,
                execution_state=next_state,
                network_state=NetworkStateV3.USED,
                requests_planned=campaign.request_budget + 1,
                requests_used=1,
                requests_blocked=0,
                current_role=None,
                next_required_action=f"approve_or_reject:{next_group}",
                routed_branches=route.routed_branches,
                succeeded_branches=successful,
                failed_branches=failed,
                artifacts={
                    "plan": "plan/run-v3.json",
                    "assets": "assets/inventory-v3.json",
                    "endpoints": "endpoints/inventory-v3.json",
                    "route": "collaboration_v3/route.json",
                    "candidates": "collaboration_v3/candidates.json",
                    "cross_reviews": "collaboration_v3/cross-reviews.json",
                    "campaign": "verification_v3/campaign.json",
                },
                last_successful_checkpoint="campaign_planned_v3",
            )
        )

    def advance_verification(
        self,
        *,
        approval_store: TrustStoreV2,
        compensation_manager: CompensationManagerV3 | None = None,
        compensation_manager_factory: Callable[[], CompensationManagerV3] | None = None,
    ) -> VerticalStateV3:
        """Consume the current risk-group decision and advance one durable stage.

        The caller must construct ``self.runner`` with :class:`GovernedGatewayV3`
        for the exact persisted campaign and approval set.  This method never
        creates a transport or reads identity credentials itself.
        """

        state = self.state()
        if state.execution_state is ExecutionStateV3.AWAITING_READONLY_APPROVAL:
            risk_group = "readonly"
            verifying_state = ExecutionStateV3.VERIFYING_READONLY
        elif state.execution_state is ExecutionStateV3.AWAITING_MUTATION_APPROVAL:
            risk_group = "mutation"
            verifying_state = ExecutionStateV3.VERIFYING_MUTATION
        else:
            raise VerticalWorkflowV3Error(
                f"cannot advance verification from {state.execution_state.value}"
            )
        campaign = self._read("verification_v3/campaign.json", VerificationCampaignPlan)
        batch = self._read(f"approvals_v3/{risk_group}.json", ApprovalBatchV3)
        verify_approval_batch_v3(batch, campaign, approval_store)
        if batch.risk_group != risk_group:
            raise VerticalWorkflowV3Error("approval decision uses another risk group")
        self._set_stage(verifying_state, "verifier")

        group_actions = tuple(item for item in campaign.actions if item.risk_group == risk_group)
        selected_actions = tuple(
            item for item in group_actions if item.candidate_id in set(batch.candidate_ids)
        )
        if batch.verdict == "approved":
            outcomes = self._run_verifier_group(campaign, batch, selected_actions)
            self.context.write_json(
                f"verification_v3/outcomes-{risk_group}.json",
                outcomes.model_dump(mode="json"),
                immutable=True,
            )

        if risk_group == "readonly" and any(
            item.risk_group == "mutation" for item in campaign.actions
        ):
            return self._save_state(
                self.state().model_copy(
                    update={
                        "execution_state": ExecutionStateV3.AWAITING_MUTATION_APPROVAL,
                        "current_role": None,
                        "next_required_action": "approve_or_reject:mutation",
                        "last_successful_checkpoint": "readonly_decision_completed_v3",
                        "requests_used": 1 + self._transport_request_count(),
                    }
                )
            )

        if risk_group == "mutation" and batch.verdict == "approved":
            if compensation_manager is None and compensation_manager_factory is not None:
                compensation_manager = compensation_manager_factory()
            if compensation_manager is None:
                raise VerticalWorkflowV3Error(
                    "approved mutation verification requires the parent CompensationManager"
                )
            cleanup = compensation_manager.run()
            if not cleanup.state_restored:
                return self._enter_cleanup_required(campaign)
        return self._finalize_verification(campaign)

    def recover_cleanup(
        self,
        *,
        approval_store: TrustStoreV2,
        compensation_manager: CompensationManagerV3,
    ) -> VerticalStateV3:
        """Execute only predeclared compensation after a cleanup-only decision.

        This entry point never calls a verifier and therefore cannot replay a
        forward mutation after a crash, expired mutation approval, or unknown
        transport result.
        """

        state = self.state()
        if state.execution_state not in {
            ExecutionStateV3.CLEANUP_REQUIRED,
            ExecutionStateV3.AWAITING_CLEANUP_APPROVAL,
        }:
            raise VerticalWorkflowV3Error(
                f"cannot recover cleanup from {state.execution_state.value}"
            )
        campaign = self._read("verification_v3/campaign.json", VerificationCampaignPlan)
        batch = self._read("approvals_v3/cleanup.json", ApprovalBatchV3)
        verify_approval_batch_v3(batch, campaign, approval_store)
        if batch.risk_group != "cleanup" or batch.verdict != "approved":
            raise VerticalWorkflowV3Error(
                "cleanup recovery requires an approved cleanup-only batch"
            )
        cleanup = compensation_manager.run()
        if not cleanup.state_restored:
            # Do not rotate back to verification or Reporter.  Unknown and
            # post-transport cleanup actions remain non-retriable in ActionLedger.
            return self._enter_cleanup_required(campaign)
        return self._finalize_verification(campaign)

    def begin_cleanup_recovery(self) -> VerticalStateV3:
        """Fail closed after an interrupted mutation stage without replaying it."""

        state = self.state()
        if state.execution_state not in {
            ExecutionStateV3.VERIFYING_MUTATION,
            ExecutionStateV3.CLEANUP_REQUIRED,
            ExecutionStateV3.AWAITING_CLEANUP_APPROVAL,
        }:
            raise VerticalWorkflowV3Error(
                f"cannot require cleanup from {state.execution_state.value}"
            )
        campaign = self._read("verification_v3/campaign.json", VerificationCampaignPlan)
        return self._enter_cleanup_required(campaign)

    def _enter_cleanup_required(self, campaign: VerificationCampaignPlan) -> VerticalStateV3:
        challenge_path = self.context.artifact_path("approvals_v3/challenge-cleanup.json")
        if not challenge_path.exists():
            challenge = cleanup_challenge_payload_v3(campaign, datetime.now(UTC))
            self.context.write_json(
                "approvals_v3/challenge-cleanup.json", challenge, immutable=True
            )
        return self._save_state(
            self.state().model_copy(
                update={
                    "execution_state": ExecutionStateV3.CLEANUP_REQUIRED,
                    "current_role": None,
                    "next_required_action": "approve_or_reject:cleanup",
                    "cleanup_state": "required",
                    "requests_used": 1 + self._transport_request_count(),
                    "last_successful_checkpoint": "cleanup_required_v3",
                    "artifacts": {
                        **self.state().artifacts,
                        "cleanup_challenge": "approvals_v3/challenge-cleanup.json",
                    },
                }
            )
        )

    def _run_verifier_group(
        self,
        campaign: VerificationCampaignPlan,
        batch: ApprovalBatchV3,
        actions: tuple[VerificationActionV3, ...],
    ) -> VerificationOutcomeSet:
        collection = self._read("collaboration_v3/candidates.json", CandidateCollection)
        candidate_types = {
            item.candidate_id: item.candidate_type for item in collection.canonical_candidates
        }
        by_candidate: dict[str, list[Any]] = {}
        for action in actions:
            if action.purpose in {"cleanup", "cleanup_check"}:
                continue
            by_candidate.setdefault(action.candidate_id, []).append(action)
        if not by_candidate:
            raise VerticalWorkflowV3Error("approved risk group contains no candidate graph")
        futures: dict[Future[TaskResult], tuple[str, tuple[Any, ...], str]] = {}
        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(by_candidate))) as pool:
            for candidate_id, values in by_candidate.items():
                ordered = tuple(values)
                task_id = f"phase4-verifier-{candidate_id}"
                allowed = tuple(
                    dict.fromkeys(
                        "validation_http_get" if item.method == "GET" else "http_post"
                        for item in ordered
                    )
                )
                futures[
                    pool.submit(
                        self._run_role,
                        "verifier",
                        task_id,
                        "verification",
                        {
                            "campaign_digest": campaign.digest,
                            "approval_id": batch.approval_id,
                            "approval_batch_digest": batch.digest,
                            "actions": [item.model_dump(mode="json") for item in ordered],
                            "generated_by_task_id": task_id,
                        },
                        request_budget=len(ordered),
                        allowed_actions=allowed,
                    )
                ] = (candidate_id, ordered, task_id)

            candidate_outcomes: dict[str, VerificationCandidateOutcome] = {}
            for future in as_completed(futures):
                candidate_id, ordered, task_id = futures[future]
                result = future.result()
                output = self._bind_verifier_authority(
                    self._payload(result, VerificationOutcomeSet),
                    campaign=campaign,
                    batch=batch,
                    task_id=task_id,
                )
                if (
                    output.run_id != self.context.run_id
                    or output.scope_digest != self.context.scope_digest
                    or output.campaign_digest != campaign.digest
                    or output.approval_batch_digests != (batch.digest,)
                    or len(output.outcomes) != 1
                ):
                    raise VerticalWorkflowV3Error("Verifier output changed its campaign authority")
                outcome = output.outcomes[0]
                handoff = result.handoff
                if handoff is None:
                    raise VerticalWorkflowV3Error("completed Verifier omitted its handoff")
                if (
                    outcome.candidate_id != candidate_id
                    or outcome.verifier_task_id != task_id
                    or outcome.action_digests != tuple(item.action_digest for item in ordered)
                    or outcome.evidence != handoff.evidence_artifact_refs
                    or len(outcome.action_ledger_entry_digests) != len(ordered)
                ):
                    raise VerticalWorkflowV3Error(
                        "Verifier outcome is not aligned to its exact action/evidence graph"
                    )
                candidate_type = candidate_types.get(candidate_id)
                if candidate_type is None:
                    raise VerticalWorkflowV3Error(
                        "Verifier outcome references a candidate outside the canonical collection"
                    )
                candidate_outcomes[candidate_id] = self._canonicalize_verifier_outcome(
                    outcome,
                    candidate_type=candidate_type,
                    actions=ordered,
                )

        canonical_order = tuple(dict.fromkeys(item.candidate_id for item in actions))
        return VerificationOutcomeSet(
            run_id=self.context.run_id,
            scope_digest=self.context.scope_digest,
            generated_by_task_id=f"phase4-verifier-fanin-{batch.risk_group}",
            outcome_set_id=f"phase4-outcomes-{batch.risk_group}",
            campaign_digest=campaign.digest,
            approval_batch_digests=(batch.digest,),
            outcomes=tuple(candidate_outcomes[item] for item in canonical_order),
        )

    def _canonicalize_verifier_outcome(
        self,
        outcome: VerificationCandidateOutcome,
        *,
        candidate_type: CandidateTypeV3,
        actions: tuple[VerificationActionV3, ...],
    ) -> VerificationCandidateOutcome:
        """Derive fixed-fixture verification semantics from parent-held evidence.

        The isolated Verifier chooses neither transport nor evidence, and its
        natural-language interpretation must not be the authority that turns a
        local candidate into a formal finding.  The Phase 4 fixture has four
        deliberately finite assertion patterns, so the parent evaluates the
        signed action graph and verified analysis copies deterministically.
        This also prevents an inverted model explanation (``missing`` control
        reported as ``disproved``) from silently reducing the teaching gate.
        """

        expected_actions = tuple(item.action_digest for item in actions)
        if outcome.action_digests != expected_actions:
            raise VerticalWorkflowV3Error("Verifier outcome changed ordered action authority")
        executions = tuple(self._load_execution_result(item) for item in actions)
        if outcome.evidence != tuple(item.evidence_artifact_ref for item in executions):
            raise VerticalWorkflowV3Error("Verifier outcome evidence differs from gateway results")
        if outcome.action_ledger_entry_digests != tuple(
            item.action_ledger_entry_digest for item in executions
        ):
            raise VerticalWorkflowV3Error("Verifier outcome ledger bindings differ from gateway")

        evidence_store = EvidenceStore(self.context.path)
        by_purpose: dict[str, tuple[ExecutionResultV3, EvidenceAnalysisDocument]] = {
            str(action.purpose): (
                execution,
                evidence_store.analysis(execution.evidence_artifact_ref),
            )
            for action, execution in zip(actions, executions, strict=True)
        }
        if candidate_type == "line_kv_capability_gap":
            # Wheel-consumption hook wired into the Verifier's execution graph:
            # this candidate's verdict genuinely depends on an active approved
            # Wheel invoked through the governed sandbox (fail-closed inside
            # capability_gap_verdict / resolve_gap_with_wheel).
            cap_status, cap_summary, observation = capability_gap_verdict(
                self._capability_resolver, now=datetime.now(UTC)
            )
            if observation is not None:
                self.context.write_json(
                    f"capability_v3/{outcome.candidate_id}-observation.json",
                    observation.model_dump(mode="json"),
                    immutable=True,
                )
            self.events.record(
                "capability_gap_resolved",
                candidate_id=outcome.candidate_id,
                status=cap_status,
                wheel_backed=self._capability_resolver is not None,
            )
            return outcome.model_copy(
                update={"status": cap_status, "assertion_summary": cap_summary}
            )
        status, summary = self._fixed_fixture_verdict(candidate_type, by_purpose)
        return outcome.model_copy(update={"status": status, "assertion_summary": summary})

    def _load_execution_result(self, action: VerificationActionV3) -> ExecutionResultV3:
        path = self.context.artifact_path(
            f"governance_v3/executions/{action.action_digest[7:]}.json"
        )
        try:
            result = ExecutionResultV3.model_validate_json(path.read_bytes())
        except (OSError, ValueError) as exc:
            raise VerticalWorkflowV3Error(
                "Verifier action has no valid parent-owned execution result"
            ) from exc
        if result.action_id != action.action_id or result.action_digest != action.action_digest:
            raise VerticalWorkflowV3Error("execution result does not bind the approved action")
        return result

    @staticmethod
    def _fixed_fixture_verdict(
        candidate_type: CandidateTypeV3,
        by_purpose: Mapping[str, tuple[ExecutionResultV3, EvidenceAnalysisDocument]],
    ) -> tuple[Literal["validated", "disproved", "inconclusive", "blocked"], str]:
        """Evaluate the four explicit Phase 4 assertions without raw evidence."""

        def result(purpose: str) -> ExecutionResultV3:
            try:
                return by_purpose[purpose][0]
            except KeyError as exc:
                raise VerticalWorkflowV3Error(
                    f"fixed fixture is missing the {purpose!r} verification action"
                ) from exc

        def analysis(purpose: str) -> EvidenceAnalysisDocument:
            try:
                return by_purpose[purpose][1]
            except KeyError as exc:
                raise VerticalWorkflowV3Error(
                    f"fixed fixture is missing the {purpose!r} analysis evidence"
                ) from exc

        def header(execution: ExecutionResultV3, name: str) -> str | None:
            return next(
                (value for key, value in execution.headers.items() if key.lower() == name),
                None,
            )

        if candidate_type == "missing_x_content_type_options":
            candidate = result("candidate")
            control = result("negative_control")
            valid = (
                candidate.status_code == 200
                and control.status_code == 200
                and header(candidate, "x-content-type-options") is None
                and (header(control, "x-content-type-options") or "").lower() == "nosniff"
            )
            summary = (
                "Parent evidence oracle: the candidate returned 200 without "
                "X-Content-Type-Options while its negative control returned 200 "
                "with X-Content-Type-Options: nosniff."
            )
        elif candidate_type == "exposed_debug_endpoint":
            candidate = result("candidate")
            control = result("negative_control")
            valid = candidate.status_code == 200 and control.status_code == 404
            summary = (
                "Parent evidence oracle: the debug endpoint returned 200 while "
                "the negative control returned 404."
            )
        elif candidate_type == "unauthorized_graphql_mutation":
            baseline = result("baseline")
            candidate = result("candidate")
            control = result("negative_control")
            valid = (
                baseline.status_code == 200
                and candidate.status_code == 200
                and control.status_code == 403
            )
            summary = (
                "Parent evidence oracle: the member baseline and mutation returned "
                "200 while the strict mutation negative control returned 403."
            )
        elif candidate_type == "privilege_escalation":
            baseline = result("baseline")
            candidate = result("candidate")
            control = result("negative_control")
            control_body = analysis("negative_control").response.body
            valid = (
                baseline.status_code == 200
                and candidate.status_code == 200
                and control.status_code == 200
                and isinstance(control_body, dict)
                and control_body.get("admin") is True
            )
            summary = (
                "Parent evidence oracle: the member baseline and elevation returned "
                "200, and the protected control confirmed admin access."
            )
        else:  # pragma: no cover - CandidateTypeV3 is closed above
            raise VerticalWorkflowV3Error("unknown fixed-fixture candidate type")
        return ("validated" if valid else "disproved"), summary

    def _bind_verifier_authority(
        self,
        output: VerificationOutcomeSet,
        *,
        campaign: VerificationCampaignPlan,
        batch: ApprovalBatchV3,
        task_id: str,
    ) -> VerificationOutcomeSet:
        """Replace outer authority fields the isolated verifier cannot own.

        The Docker role is asked to emit a complete Pydantic payload because the
        ACP handoff has one typed contract.  Its outer run, scope, campaign and
        approval fields are nevertheless *claims*, not authority.  Rebuilding
        them here prevents a copy error (or an adversarial value) from changing
        the graph that the parent already froze and signed.  Candidate/action/
        evidence bindings below remain fail-closed checks against the returned
        task handoff and governed gateway records.
        """

        return output.model_copy(
            update={
                "run_id": self.context.run_id,
                "scope_digest": self.context.scope_digest,
                "generated_by_task_id": task_id,
                "campaign_digest": campaign.digest,
                "approval_batch_digests": (batch.digest,),
            }
        )

    def _finalize_verification(self, campaign: VerificationCampaignPlan) -> VerticalStateV3:
        group_sets = tuple(
            self._read_optional(f"verification_v3/outcomes-{risk}.json", VerificationOutcomeSet)
            for risk in ("readonly", "mutation")
        )
        present = tuple(item for item in group_sets if item is not None)
        if not present:
            return self._save_state(
                self.state().model_copy(
                    update={
                        "execution_state": ExecutionStateV3.REJECTED,
                        "current_role": None,
                        "next_required_action": None,
                        "requests_used": 1,
                        "last_successful_checkpoint": "all_batches_rejected_v3",
                    }
                )
            )
        outcomes_by_candidate: dict[str, VerificationCandidateOutcome] = {}
        approvals: list[str] = []
        for group in present:
            if group.campaign_digest != campaign.digest:
                raise VerticalWorkflowV3Error("persisted group outcome crosses the campaign")
            approvals.extend(group.approval_batch_digests)
            for outcome in group.outcomes:
                if outcome.candidate_id in outcomes_by_candidate:
                    raise VerticalWorkflowV3Error("candidate has duplicate verifier outcomes")
                outcomes_by_candidate[outcome.candidate_id] = outcome
        combined = VerificationOutcomeSet(
            run_id=self.context.run_id,
            scope_digest=self.context.scope_digest,
            generated_by_task_id="phase4-verifier-fanin",
            outcome_set_id="phase4-outcomes",
            campaign_digest=campaign.digest,
            approval_batch_digests=tuple(approvals),
            outcomes=tuple(outcomes_by_candidate.values()),
        )
        self.context.write_json(
            "verification_v3/outcomes.json", combined.model_dump(mode="json"), immutable=True
        )
        candidates = self._read("collaboration_v3/candidates.json", CandidateCollection)
        reviews = self._read("collaboration_v3/cross-reviews.json", CrossReviewSet)
        cleanup = self._read_optional("verification_v3/cleanup.json", CleanupReceipt)
        findings: FindingSet = promote_findings_v3(
            candidates,
            reviews,
            combined,
            cleanup,
            generated_by_task_id="phase4-promotion",
        )
        self.context.write_json(
            "report/finding-set-v3.json", findings.model_dump(mode="json"), immutable=True
        )
        branches = tuple(
            self._read(f"collaboration_v3/branch-results/{branch}.json", BranchResult)
            for branch in ("web", "api", "authz", "infra")
        )
        action_summary = self._action_coverage(campaign)
        plan = self._read("plan/run-v3.json", RunPlanV3)
        budget_summary = self._coverage_budget_summary(plan)
        active_ms = self.active_time.record_snapshot("coverage-v3").active_elapsed_ms
        coverage = build_coverage_report(
            collection=candidates,
            reviews=reviews,
            campaign=campaign,
            branch_results=branches,
            outcomes=combined,
            findings=findings,
            action_ledger=action_summary,
            budget=budget_summary,
            active_elapsed_ms=active_ms,
            generated_by_task_id="phase4-coverage",
            cleanup_receipt_digest=None if cleanup is None else cleanup.digest,
        )
        self.context.write_json(
            "report/coverage-v3.json", coverage.model_dump(mode="json"), immutable=True
        )
        draft_lines = [
            "# Phase 4 local teaching fixture review draft",
            "",
            f"Validated findings: {len(findings.findings)}",
            f"Coverage: {coverage.completion}",
            "",
            "This is a localhost teaching fixture, not a Bugcrowd submission.",
        ]
        if coverage.gaps:
            draft_lines.extend(("", "Coverage gaps:", *(f"- {gap}" for gap in coverage.gaps)))
        self.context.write_text("report/draft-v3.md", "\n".join(draft_lines) + "\n", immutable=True)
        return self._save_state(
            self.state().model_copy(
                update={
                    "execution_state": ExecutionStateV3.AWAITING_REVIEW,
                    "network_state": NetworkStateV3.USED,
                    "requests_used": 1 + action_summary.requests_used,
                    "current_role": None,
                    "next_required_action": "review_sign",
                    "cleanup_state": "restored" if cleanup is not None else "not_required",
                    "last_successful_checkpoint": "verification_promoted_v3",
                    "artifacts": {
                        **self.state().artifacts,
                        "outcomes": "verification_v3/outcomes.json",
                        "finding_set": "report/finding-set-v3.json",
                        "coverage": "report/coverage-v3.json",
                        "draft": "report/draft-v3.md",
                    },
                }
            )
        )

    def _coverage_budget_summary(self, plan: RunPlanV3) -> BudgetCoverageSummary:
        """Freeze the one future Reporter reservation into human-reviewed coverage.

        Coverage is created before a human signs and before the Reporter may be
        launched.  The report authorization preflight reserves that last model
        attempt afterwards, so coverage must already account for it.  Otherwise
        a valid reservation would mutate the reviewed budget facts and make the
        final preflight reject every completed run.
        """

        budget = BudgetLedger(self.context).summary()
        attempts_reserved = budget.reserved_attempts + 1
        estimated_cost = budget.reserved_microusd + plan.budget.reservation_per_attempt_microusd
        if attempts_reserved > plan.budget.max_model_attempts:
            raise VerticalWorkflowV3Error(
                "no model-attempt capacity remains for the required Reporter"
            )
        if estimated_cost > plan.budget.max_estimated_cost_microusd:
            raise VerticalWorkflowV3Error(
                "no estimated-cost capacity remains for the required Reporter"
            )
        return BudgetCoverageSummary(
            attempts_reserved=attempts_reserved,
            attempts_used=budget.settled_attempts,
            estimated_cost_microusd=estimated_cost,
            actual_cost_microusd=budget.actual_cost_microusd,
        )

    def _action_coverage(self, campaign: VerificationCampaignPlan) -> ActionLedgerSummary:
        events = ActionLedger(self.context).events()
        latest: dict[str, dict[str, Any]] = {}
        histories: dict[str, list[dict[str, Any]]] = {
            item.action_id: [] for item in campaign.actions
        }
        for event in events:
            action_id = str(event.get("action_id", ""))
            if action_id not in histories:
                raise VerticalWorkflowV3Error("ActionLedger contains an orphan action")
            histories[action_id].append(event)
            latest[action_id] = event
        executed = blocked = skipped = requests = 0
        gaps: list[str] = []
        transport_states = {
            "transport_started",
            "evidence_committed",
            "failed_after_transport",
            "indeterminate",
            "cleanup_required",
            "cleaned",
        }
        blocked_states = {
            "transport_started",
            "failed_before_transport",
            "failed_after_transport",
            "indeterminate",
            "cleanup_required",
        }
        for action in campaign.actions:
            history = histories[action.action_id]
            if not history:
                skipped += 1
                gaps.append(f"action:{action.action_id}:not_started")
                continue
            if any(item.get("state") in transport_states for item in history):
                requests += 1
            state = str(latest[action.action_id].get("state"))
            if state in {"evidence_committed", "cleaned"}:
                executed += 1
            elif state in blocked_states:
                blocked += 1
                gaps.append(f"action:{action.action_id}:{state}")
            else:
                skipped += 1
                gaps.append(f"action:{action.action_id}:{state}")
        return ActionLedgerSummary(
            actions_planned=len(campaign.actions),
            actions_executed=executed,
            actions_blocked=blocked,
            actions_skipped=skipped,
            requests_used=requests,
            gaps=tuple(gaps),
        )

    def complete_report(self, verifier: ReportPreflightVerifierV3) -> VerticalStateV3:
        """Run Reporter only after launch preflight and atomically publish after recheck."""

        state = self.state()
        if state.execution_state is not ExecutionStateV3.AWAITING_REVIEW:
            raise VerticalWorkflowV3Error("V3 run is not awaiting human review")
        launch = verifier.authorize_reporter()
        findings = self._read("report/finding-set-v3.json", FindingSet)
        coverage = self._read("report/coverage-v3.json", CoverageReportV3)
        result = self._run_role(
            "reporter",
            "phase4-reporter",
            "reporting",
            {
                "finding_set": findings.model_dump(mode="json"),
                "coverage_report": coverage.model_dump(mode="json"),
                "reporter_launch_receipt": launch.model_dump(mode="json"),
                "finding_set_digest": findings.digest,
                "coverage_report_digest": coverage.digest,
                "launch_receipt_digest": launch.digest,
                "generated_by_task_id": "phase4-reporter",
            },
        )
        acknowledgement = self._payload(result, ReporterAckV3)
        if (
            acknowledgement.run_id != self.context.run_id
            or acknowledgement.scope_digest != self.context.scope_digest
            or acknowledgement.generated_by_task_id != "phase4-reporter"
            or acknowledgement.launch_receipt_digest != launch.digest
            or acknowledgement.finding_set_digest != findings.digest
            or acknowledgement.coverage_report_digest != coverage.digest
        ):
            raise VerticalWorkflowV3Error("Reporter acknowledgement changed authorized inputs")
        self.context.write_json(
            "report/reporter-ack-v3.json",
            acknowledgement.model_dump(mode="json"),
            immutable=True,
        )
        write_report_v3(self.context, verifier, acknowledgement)
        completed = (
            ExecutionStateV3.COMPLETED_WITH_GAPS
            if coverage.completion == "completed_with_gaps"
            else ExecutionStateV3.COMPLETED
        )
        return self._save_state(
            state.model_copy(
                update={
                    "execution_state": completed,
                    "current_role": "reporter",
                    "next_required_action": None,
                    "last_successful_checkpoint": "report_completed_v3",
                    "artifacts": {
                        **state.artifacts,
                        "reporter_launch": "report/reporter-launch-v3.json",
                        "reporter_ack": "report/reporter-ack-v3.json",
                        "report": "report/report-v3.md",
                        "findings": "report/findings-v3.json",
                        "report_write_receipt": "report/report-write-receipt-v3.json",
                    },
                }
            )
        )

    def _transport_request_count(self) -> int:
        return sum(
            item.get("state") == "transport_started" for item in ActionLedger(self.context).events()
        )

    def _read(self, relative: str, model: type[_Payload]) -> _Payload:
        try:
            return model.model_validate_json(self.context.artifact_path(relative).read_bytes())
        except (OSError, ValueError) as exc:
            raise VerticalWorkflowV3Error(f"invalid V3 artifact: {relative}") from exc

    def _read_optional(self, relative: str, model: type[_Payload]) -> _Payload | None:
        path = self.context.artifact_path(relative)
        return None if not path.is_file() else self._read(relative, model)


__all__ = [
    "ExecutionStateV3",
    "NetworkStateV3",
    "ROLE_ORDER_V3",
    "VerticalStateV3",
    "VerticalWorkflowV3",
    "VerticalWorkflowV3Error",
]

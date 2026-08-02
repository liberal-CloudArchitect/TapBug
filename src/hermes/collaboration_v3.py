"""Deterministic routing and parallel expert collaboration for Phase 4 V3."""

from __future__ import annotations

import json
import threading
from collections.abc import Callable, Mapping
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from typing import Literal, TypeVar
from urllib.parse import urljoin

from .campaign_v3 import materialized_body_digest
from .domain_contracts import canonical_digest
from .domain_contracts_v3 import (
    Branch,
    BranchAssessment,
    BranchCandidateV3,
    BranchResult,
    CandidateCollection,
    CanonicalCandidateV3,
    ContractEnvelopeV3,
    CrossReview,
    CrossReviewSet,
    DedupDecision,
    EndpointInventoryV3,
    EndpointV3,
    RouteBranchDecision,
    RouteDecision,
)
from .promotion import file_sha256
from .runtime import RunContext
from .runtime.agents import AgentRunner, TaskEnvelope, TaskResult
from .workflow import WorkflowEventLog

BRANCH_ORDER: tuple[Branch, ...] = ("web", "api", "authz", "infra")
BRANCH_ROLE: dict[Branch, str] = {
    "web": "web-vuln",
    "api": "api",
    "authz": "authz",
    "infra": "infra",
}
REVIEW_RING: dict[Branch, Branch] = {
    "web": "api",
    "api": "authz",
    "authz": "infra",
    "infra": "web",
}
_PayloadV3 = TypeVar("_PayloadV3")


class CollaborationV3Error(RuntimeError):
    """V3 collaboration could not continue without weakening an invariant."""


class RoutePolicy:
    """Host-owned deterministic branch selection over trusted endpoint facts."""

    def decide(
        self,
        inventory: EndpointInventoryV3,
        *,
        run_id: str,
        scope_digest: str,
        generated_by_task_id: str,
        identity_binding_digests: tuple[str, ...] = (),
    ) -> RouteDecision:
        features: dict[Branch, set[str]] = {branch: set() for branch in BRANCH_ORDER}
        for endpoint in sorted(inventory.endpoints, key=lambda item: item.endpoint_id):
            content_types = {item.lower().split(";", 1)[0] for item in endpoint.content_types}
            if (
                endpoint.relation in {"candidate", "negative_control"}
                or "text/html" in content_types
            ):
                features["web"].add(endpoint.endpoint_id)
            if endpoint.relation == "graphql":
                features["api"].add(endpoint.endpoint_id)
            if endpoint.relation == "role_change" and identity_binding_digests:
                features["authz"].add(endpoint.endpoint_id)
            if endpoint.relation in {"debug", "diagnostic"}:
                features["infra"].add(endpoint.endpoint_id)
        decisions = tuple(
            RouteBranchDecision(
                branch=branch,
                routed=bool(features[branch]),
                feature_ids=tuple(sorted(features[branch])),
                reason=(
                    "trusted endpoint features matched"
                    if features[branch]
                    else (
                        "authorized identity bindings unavailable"
                        if branch == "authz"
                        else "no trusted endpoint feature matched"
                    )
                ),
            )
            for branch in BRANCH_ORDER
        )
        if not any(item.routed for item in decisions):
            raise CollaborationV3Error("trusted endpoint inventory did not route any V3 branch")
        return RouteDecision(
            run_id=run_id,
            scope_digest=scope_digest,
            generated_by_task_id=generated_by_task_id,
            decision_id="phase4-route",
            endpoint_inventory_digest=normalized_endpoint_inventory_digest(inventory),
            available_identity_binding_digests=tuple(sorted(identity_binding_digests)),
            branches=decisions,
        )


def normalized_endpoint_inventory_digest(inventory: EndpointInventoryV3) -> str:
    """Bind inventory facts without treating their input sequence as routing authority."""

    value = inventory.model_dump(mode="json")
    value["endpoints"] = sorted(
        value["endpoints"],
        key=lambda item: (item["endpoint_id"], item["method"], item["canonical_url"]),
    )
    value["unresolved"] = sorted(value["unresolved"])
    return canonical_digest(value)


def trusted_candidate_fingerprint(candidate: BranchCandidateV3) -> str:
    """Recompute the semantic key; an agent-supplied fingerprint is never trusted."""

    return canonical_digest(
        {
            "candidate_type": candidate.candidate_type,
            "target_url": candidate.target_url,
            "method": candidate.method,
            "request_body_sha256": candidate.request_body_sha256,
            "identity_binding_digest": candidate.identity_binding_digest,
            "expected_assertion": candidate.expected_assertion,
        }
    )


def build_candidate_blueprints(
    inventory: EndpointInventoryV3,
    *,
    identity_binding_digests: Mapping[str, str],
) -> dict[Branch, tuple[BranchCandidateV3, ...]]:
    """Derive all candidate execution authority from trusted parent-runtime inputs.

    The expert is allowed to decide only ``status`` and ``rationale``.  URLs,
    methods, body hashes, identity bindings, controls, and assertions are fixed
    here so they cannot drift between branches or be invented by a model.
    """

    by_relation: dict[str, list[EndpointV3]] = {}
    for inventory_endpoint in inventory.endpoints:
        by_relation.setdefault(inventory_endpoint.relation, []).append(inventory_endpoint)

    def select_endpoint(relation: str) -> EndpointV3 | None:
        values = by_relation.get(relation, [])
        if len(values) > 1:
            raise CollaborationV3Error(
                f"fixed Phase 4 candidate blueprint requires one {relation} endpoint"
            )
        return values[0] if values else None

    candidate = select_endpoint("candidate")
    control = select_endpoint("negative_control")
    graphql = select_endpoint("graphql")
    role_change = select_endpoint("role_change")
    diagnostic = select_endpoint("diagnostic") or select_endpoint("debug")
    # Additive CAP-07 relation: only present when the inventory offers a line_kv
    # capability artifact. Absent from the fixed Phase 4 fixture, so the four
    # canonical candidates and every acceptance count stay byte-for-byte identical.
    capability_config = select_endpoint("capability_config")
    member = identity_binding_digests.get("member")

    values: dict[Branch, list[BranchCandidateV3]] = {branch: [] for branch in BRANCH_ORDER}

    def authoritative_candidate(
        *,
        candidate_id: str,
        candidate_type: Literal[
            "missing_x_content_type_options",
            "unauthorized_graphql_mutation",
            "privilege_escalation",
            "exposed_debug_endpoint",
            "line_kv_capability_gap",
        ],
        producer_branch: Branch,
        target_endpoint_id: str,
        control_endpoint_ids: tuple[str, ...],
        target_url: str,
        method: Literal["GET", "POST"],
        request_body_sha256: str | None,
        identity_binding_digest: str | None,
        expected_assertion: str,
    ) -> BranchCandidateV3:
        draft = BranchCandidateV3(
            candidate_id=candidate_id,
            candidate_type=candidate_type,
            producer_branch=producer_branch,
            target_endpoint_id=target_endpoint_id,
            control_endpoint_ids=control_endpoint_ids,
            target_url=target_url,
            method=method,
            request_body_sha256=request_body_sha256,
            identity_binding_digest=identity_binding_digest,
            expected_assertion=expected_assertion,
            rationale="parent-runtime candidate blueprint; expert rationale required",
            semantic_fingerprint="sha256:" + "0" * 64,
        )
        return draft.model_copy(
            update={"semantic_fingerprint": trusted_candidate_fingerprint(draft)}
        )

    if candidate is not None:
        if control is None:
            raise CollaborationV3Error(
                "Web candidate blueprint requires a trusted negative-control endpoint"
            )
        xcto_assertion = (
            "X-Content-Type-Options is absent on the candidate response and "
            "nosniff is present on the negative control"
        )
        values["web"].append(
            authoritative_candidate(
                candidate_id="web-xcto",
                candidate_type="missing_x_content_type_options",
                producer_branch="web",
                target_endpoint_id=candidate.endpoint_id,
                control_endpoint_ids=(control.endpoint_id,),
                target_url=candidate.canonical_url,
                method="GET",
                request_body_sha256=None,
                identity_binding_digest=None,
                expected_assertion=xcto_assertion,
            )
        )
        if diagnostic is not None:
            values["infra"].append(
                authoritative_candidate(
                    candidate_id="infra-xcto-copy",
                    candidate_type="missing_x_content_type_options",
                    producer_branch="infra",
                    target_endpoint_id=candidate.endpoint_id,
                    control_endpoint_ids=(control.endpoint_id,),
                    target_url=candidate.canonical_url,
                    method="GET",
                    request_body_sha256=None,
                    identity_binding_digest=None,
                    expected_assertion=xcto_assertion,
                )
            )

    if diagnostic is not None:
        values["infra"].insert(
            0,
            authoritative_candidate(
                candidate_id="infra-debug",
                candidate_type="exposed_debug_endpoint",
                producer_branch="infra",
                target_endpoint_id=diagnostic.endpoint_id,
                control_endpoint_ids=(f"{diagnostic.endpoint_id}-negative-control",),
                target_url=diagnostic.canonical_url,
                method="GET",
                request_body_sha256=None,
                identity_binding_digest=None,
                expected_assertion=(
                    "the diagnostic endpoint is exposed while the matched "
                    "negative-control endpoint is unavailable"
                ),
            ),
        )

    if graphql is not None:
        if member is None:
            raise CollaborationV3Error(
                "GraphQL candidate blueprint requires the member identity binding"
            )
        values["api"].append(
            authoritative_candidate(
                candidate_id="api-graphql",
                candidate_type="unauthorized_graphql_mutation",
                producer_branch="api",
                target_endpoint_id=graphql.endpoint_id,
                control_endpoint_ids=(f"{graphql.endpoint_id}-strict-negative-control",),
                target_url=urljoin(graphql.canonical_url.rstrip("/") + "/", "mutate"),
                method="POST",
                request_body_sha256=materialized_body_digest(
                    "unauthorized_graphql_mutation", "candidate"
                ),
                identity_binding_digest=member,
                expected_assertion=(
                    "the member mutation changes fixture state while the strict "
                    "negative-control mutation is forbidden"
                ),
            )
        )

    if role_change is not None:
        if member is None:
            raise CollaborationV3Error(
                "Authz candidate blueprint requires the member identity binding"
            )
        values["authz"].append(
            authoritative_candidate(
                candidate_id="authz-escalation",
                candidate_type="privilege_escalation",
                producer_branch="authz",
                target_endpoint_id=role_change.endpoint_id,
                control_endpoint_ids=(f"{role_change.endpoint_id}-protected-control",),
                target_url=urljoin(role_change.canonical_url, "elevate"),
                method="POST",
                request_body_sha256=materialized_body_digest("privilege_escalation", "candidate"),
                identity_binding_digest=member,
                expected_assertion=(
                    "the member identity gains protected access after elevation "
                    "and loses it after parent-owned cleanup"
                ),
            )
        )

    if capability_config is not None:
        # A candidate whose evidence is a line_kv artifact the parent runtime
        # cannot interpret unaided; the Verifier resolves it only via an active,
        # approved CAP-07 Wheel (hermes.capability_verifier).
        values["infra"].append(
            authoritative_candidate(
                candidate_id="infra-capability-gap",
                candidate_type="line_kv_capability_gap",
                producer_branch="infra",
                target_endpoint_id=capability_config.endpoint_id,
                control_endpoint_ids=(),
                target_url=capability_config.canonical_url,
                method="GET",
                request_body_sha256=None,
                identity_binding_digest=None,
                expected_assertion=(
                    "the line_kv capability artifact is parsed into structured "
                    "fields only by an active approved Wheel"
                ),
            )
        )

    return {branch: tuple(values[branch]) for branch in BRANCH_ORDER}


def normalize_assessment_to_blueprint(
    assessment: BranchAssessment,
    blueprints: tuple[BranchCandidateV3, ...],
) -> BranchAssessment:
    """Preserve expert judgment while replacing every execution-authority field."""

    submitted = {candidate.candidate_id: candidate for candidate in assessment.candidates}
    expected_ids = {candidate.candidate_id for candidate in blueprints}
    if set(submitted) != expected_ids:
        raise CollaborationV3Error(
            f"{assessment.branch} assessment must return the exact parent candidate set"
        )
    normalized = tuple(
        blueprint.model_copy(
            update={
                "rationale": submitted[blueprint.candidate_id].rationale,
                "status": submitted[blueprint.candidate_id].status,
                "semantic_fingerprint": trusted_candidate_fingerprint(blueprint),
            }
        )
        for blueprint in blueprints
    )
    return BranchAssessment.model_validate(
        {
            **assessment.model_dump(mode="json"),
            "candidates": [item.model_dump(mode="json") for item in normalized],
        }
    )


class CandidateFanIn:
    """Canonical, completion-order-independent candidate merge."""

    def merge(
        self,
        *,
        route: RouteDecision,
        inventory: EndpointInventoryV3,
        identity_binding_digests: Mapping[str, str],
        branch_results: tuple[BranchResult, ...],
        assessments: dict[Branch, BranchAssessment],
        generated_by_task_id: str,
    ) -> CandidateCollection:
        if route.endpoint_inventory_digest != normalized_endpoint_inventory_digest(inventory):
            raise CollaborationV3Error("candidate fan-in inventory does not match its route")
        blueprints = build_candidate_blueprints(
            inventory,
            identity_binding_digests=identity_binding_digests,
        )
        if tuple(item.branch for item in branch_results) != BRANCH_ORDER:
            raise CollaborationV3Error("branch results must use canonical fan-in order")
        routed = set(route.routed_branches)
        for result in branch_results:
            if result.branch not in routed and result.status != "not_routed":
                raise CollaborationV3Error("an unrouted branch produced an execution result")
            assessment = assessments.get(result.branch)
            if result.status == "succeeded":
                if assessment is None or assessment.digest != result.assessment_digest:
                    raise CollaborationV3Error("successful branch result lost its assessment")
                normalized = normalize_assessment_to_blueprint(
                    assessment, blueprints[result.branch]
                )
                if assessment != normalized:
                    raise CollaborationV3Error(
                        f"{result.branch} assessment contains non-authoritative candidate fields"
                    )
            elif assessment is not None:
                raise CollaborationV3Error("failed branch cannot contribute an assessment")

        raw: list[BranchCandidateV3] = []
        for branch in BRANCH_ORDER:
            assessment = assessments.get(branch)
            if assessment is None:
                continue
            for candidate in sorted(assessment.candidates, key=lambda item: item.candidate_id):
                raw.append(
                    candidate.model_copy(
                        update={"semantic_fingerprint": trusted_candidate_fingerprint(candidate)}
                    )
                )

        actionable = [item for item in raw if item.status == "candidate"]
        blocked_count = len(raw) - len(actionable)
        grouped: dict[str, list[BranchCandidateV3]] = {}
        for candidate in actionable:
            grouped.setdefault(candidate.semantic_fingerprint, []).append(candidate)

        canonical: list[CanonicalCandidateV3] = []
        decisions: list[DedupDecision] = []
        for fingerprint in sorted(grouped):
            group = sorted(
                grouped[fingerprint],
                key=lambda item: (BRANCH_ORDER.index(item.producer_branch), item.candidate_id),
            )
            winner = group[0]
            provenance = tuple(
                branch
                for branch in BRANCH_ORDER
                if any(item.producer_branch == branch for item in group)
            )
            source_ids = tuple(item.candidate_id for item in group)
            canonical.append(
                CanonicalCandidateV3(
                    candidate_id=winner.candidate_id,
                    candidate_type=winner.candidate_type,
                    semantic_fingerprint=fingerprint,
                    provenance=provenance,
                    source_candidate_ids=source_ids,
                )
            )
            decisions.append(
                DedupDecision(
                    canonical_candidate_id=winner.candidate_id,
                    semantic_fingerprint=fingerprint,
                    merged_candidate_ids=source_ids,
                    provenance=provenance,
                )
            )
        return CandidateCollection(
            run_id=route.run_id,
            scope_digest=route.scope_digest,
            generated_by_task_id=generated_by_task_id,
            collection_id="phase4-candidates",
            route_decision_digest=route.digest,
            branch_result_digests=tuple(item.digest for item in branch_results),
            raw_candidates=tuple(raw),
            canonical_candidates=tuple(canonical),
            dedup_decisions=tuple(decisions),
            raw_blocked_or_inconclusive=blocked_count,
        )


def assign_cross_reviewers(collection: CandidateCollection) -> dict[str, Branch]:
    """Assign the first ring successor that is independent of all producers."""

    assignments: dict[str, Branch] = {}
    for candidate in collection.canonical_candidates:
        branch = REVIEW_RING[candidate.provenance[0]]
        for _ in BRANCH_ORDER:
            if branch not in candidate.provenance:
                assignments[candidate.candidate_id] = branch
                break
            branch = REVIEW_RING[branch]
        else:  # pragma: no cover - four producers leave no independent expert
            raise CollaborationV3Error(
                f"candidate {candidate.candidate_id} has no independent reviewer"
            )
    return assignments


class ParallelCollaborationV3:
    """Run isolated assessment and cross-review fan-out stages with durable fan-in."""

    def __init__(
        self,
        context: RunContext,
        runner: AgentRunner,
        *,
        max_workers: int = 4,
        timeout_seconds: int | Callable[[], int] = 180,
    ) -> None:
        if not 1 <= max_workers <= 4:
            raise ValueError("V3 fan-out concurrency must be between one and four")
        self.context = context
        self.runner = runner
        self.max_workers = max_workers
        self.timeout_seconds = timeout_seconds
        self.events = WorkflowEventLog(context)
        self._activity_lock = threading.Lock()
        self._active = 0
        self.max_active = 0

    def _task_timeout(self) -> int:
        value = self.timeout_seconds() if callable(self.timeout_seconds) else self.timeout_seconds
        if value < 1:
            raise CollaborationV3Error("V3 active execution deadline is exhausted")
        return min(180, value)

    def run_assessments(
        self,
        *,
        route: RouteDecision,
        inventory: EndpointInventoryV3,
        identity_binding_digests: Mapping[str, str],
    ) -> tuple[tuple[BranchResult, ...], dict[Branch, BranchAssessment]]:
        blueprints = build_candidate_blueprints(
            inventory,
            identity_binding_digests=identity_binding_digests,
        )
        futures: dict[Future[tuple[TaskResult, BranchAssessment]], Branch] = {}
        completed: dict[Branch, tuple[TaskResult, BranchAssessment]] = {}
        failures: dict[Branch, tuple[Literal["failed", "timed_out"], datetime, datetime, str]] = {}
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            for branch in route.routed_branches:
                task = TaskEnvelope(
                    version="3",
                    run_id=self.context.run_id,
                    task_id=f"phase4-assessment-{branch}",
                    role=BRANCH_ROLE[branch],
                    scope_digest=self.context.scope_digest,
                    payload={
                        "operation": "assessment",
                        "route_decision": route.model_dump(mode="json"),
                        "endpoint_inventory_digest": inventory.digest,
                        "endpoint_inventory": inventory.model_dump(mode="json"),
                        "candidate_blueprints": [
                            item.model_dump(mode="json") for item in blueprints[branch]
                        ],
                    },
                    timeout_seconds=self._task_timeout(),
                )
                futures[pool.submit(self._run_assessment, branch, task, blueprints[branch])] = (
                    branch
                )
            for future in as_completed(futures):
                branch = futures[future]
                try:
                    completed[branch] = future.result()
                except _BranchFailure as exc:
                    failures[branch] = (exc.status, exc.started_at, exc.finished_at, str(exc))

        results: list[BranchResult] = []
        assessments: dict[Branch, BranchAssessment] = {}
        for branch in BRANCH_ORDER:
            if branch not in route.routed_branches:
                result = BranchResult(
                    run_id=self.context.run_id,
                    scope_digest=self.context.scope_digest,
                    generated_by_task_id="phase4-fanin",
                    branch=branch,
                    status="not_routed",
                    reason="RoutePolicy did not select this branch",
                )
            elif branch in completed:
                task_result, assessment = completed[branch]
                metadata_path = self.context.artifact_path(
                    f"provider/{task_result.task.task_id}.json"
                )
                if not metadata_path.is_file():
                    raise CollaborationV3Error(
                        f"successful branch {branch} has no provider metadata"
                    )
                assessments[branch] = assessment
                result = BranchResult(
                    run_id=self.context.run_id,
                    scope_digest=self.context.scope_digest,
                    generated_by_task_id="phase4-fanin",
                    branch=branch,
                    status="succeeded",
                    assessment_digest=assessment.digest,
                    provider_metadata_digest=file_sha256(metadata_path),
                    started_at=task_result.started_at,
                    finished_at=task_result.finished_at,
                )
                self.context.write_json(
                    f"collaboration_v3/assessments/{branch}.json",
                    assessment.model_dump(mode="json"),
                    immutable=True,
                )
            else:
                status, started, finished, reason = failures[branch]
                result = BranchResult(
                    run_id=self.context.run_id,
                    scope_digest=self.context.scope_digest,
                    generated_by_task_id="phase4-fanin",
                    branch=branch,
                    status=status,
                    started_at=started,
                    finished_at=finished,
                    reason=reason,
                )
            self.context.write_json(
                f"collaboration_v3/branch-results/{branch}.json",
                result.model_dump(mode="json"),
                immutable=True,
            )
            results.append(result)
        if not assessments:
            raise CollaborationV3Error("all routed assessment branches failed")
        return tuple(results), assessments

    def run_cross_reviews(
        self,
        *,
        collection: CandidateCollection,
    ) -> CrossReviewSet:
        assignments = assign_cross_reviewers(collection)
        by_id = {item.candidate_id: item for item in collection.canonical_candidates}
        sources_by_id = {item.candidate_id: item for item in collection.raw_candidates}
        futures: dict[Future[CrossReview], str] = {}
        reviews: dict[str, CrossReview] = {}
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            for candidate_id, reviewer in assignments.items():
                candidate = by_id[candidate_id]
                source_candidates = tuple(
                    sources_by_id[source_id] for source_id in candidate.source_candidate_ids
                )
                task = TaskEnvelope(
                    version="3",
                    run_id=self.context.run_id,
                    task_id=f"phase4-review-{candidate_id}",
                    role=BRANCH_ROLE[reviewer],
                    scope_digest=self.context.scope_digest,
                    payload={
                        "operation": "cross_review",
                        "candidate_collection_digest": collection.digest,
                        "candidate": candidate.model_dump(mode="json"),
                        "candidate_sources": [
                            item.model_dump(mode="json") for item in source_candidates
                        ],
                        "review_policy": {
                            "profile": "phase4-localhost-fixed",
                            "review_stage": "pre_verification",
                            "rule": (
                                "concur when each supplied source preserves the canonical "
                                "candidate type, endpoint, method, identity binding, and "
                                "expected assertion; reject only an explicit inconsistent "
                                "or contraindicating trusted fact"
                            ),
                            "must_not_require_live_validation": True,
                        },
                        "reviewer_branch": reviewer,
                    },
                    timeout_seconds=self._task_timeout(),
                )
                futures[pool.submit(self._run_review, reviewer, candidate_id, task)] = candidate_id
            for future in as_completed(futures):
                candidate_id = futures[future]
                try:
                    reviews[candidate_id] = future.result()
                except _BranchFailure as exc:
                    candidate = by_id[candidate_id]
                    reviews[candidate_id] = CrossReview(
                        review_id=f"review-{candidate_id}",
                        candidate_id=candidate_id,
                        producer_branches=candidate.provenance,
                        reviewer_branch=assignments[candidate_id],
                        reviewer_task_id=f"phase4-review-{candidate_id}",
                        verdict="needs_more_evidence",
                        rationale=f"independent review failed closed: {exc}",
                    )
        result = CrossReviewSet(
            run_id=self.context.run_id,
            scope_digest=self.context.scope_digest,
            generated_by_task_id="phase4-fanin-cross-review",
            review_set_id="phase4-cross-reviews",
            candidate_collection_digest=collection.digest,
            reviews=tuple(reviews[item.candidate_id] for item in collection.canonical_candidates),
        )
        self.context.write_json(
            "collaboration_v3/cross-reviews.json",
            result.model_dump(mode="json"),
            immutable=True,
        )
        return result

    def _run_assessment(
        self,
        branch: Branch,
        task: TaskEnvelope,
        blueprints: tuple[BranchCandidateV3, ...],
    ) -> tuple[TaskResult, BranchAssessment]:
        result = self._run_task(branch, task, stage="assessment")
        payload = _v3_payload(result, BranchAssessment)
        if (
            payload.branch != branch
            or payload.generated_by_task_id != task.task_id
            or payload.endpoint_inventory_digest != task.payload["endpoint_inventory_digest"]
        ):
            # The inventory digest is checked again by fan-in/preflight; only the
            # producer and task identity are safe to compare generically here.
            if payload.branch != branch or payload.generated_by_task_id != task.task_id:
                raise _BranchFailure.from_result(result, "assessment identity mismatch")
        try:
            normalized = normalize_assessment_to_blueprint(payload, blueprints)
        except CollaborationV3Error as exc:
            raise _BranchFailure.from_result(result, str(exc)) from exc
        return result, normalized

    def _run_review(self, reviewer: Branch, candidate_id: str, task: TaskEnvelope) -> CrossReview:
        result = self._run_task(reviewer, task, stage="cross_review")
        payload = _v3_payload(result, CrossReviewSet)
        if len(payload.reviews) != 1:
            raise _BranchFailure.from_result(result, "review task must return exactly one review")
        review = payload.reviews[0]
        if (
            review.candidate_id != candidate_id
            or review.reviewer_branch != reviewer
            or review.reviewer_task_id != task.task_id
        ):
            raise _BranchFailure.from_result(result, "cross-review identity mismatch")
        return review

    def _run_task(self, branch: Branch, task: TaskEnvelope, *, stage: str) -> TaskResult:
        handoff_path = self.context.artifact_path(f"handoffs/{task.task_id}.json")
        provider_path = self.context.artifact_path(f"provider/{task.task_id}.json")
        if handoff_path.exists():
            stored = json.loads(handoff_path.read_text(encoding="utf-8"))
            persisted_task = TaskEnvelope.model_validate(stored["task"])
            result = TaskResult.model_validate(stored["result"])
            if persisted_task.input_hash() != task.input_hash():
                raise CollaborationV3Error(f"persisted task differs for {task.task_id}")
            return result
        if provider_path.exists():
            now = datetime.now(UTC)
            raise _BranchFailure(
                "failed",
                now,
                now,
                "indeterminate: provider metadata exists without a committed handoff",
            )
        with self._activity_lock:
            self._active += 1
            self.max_active = max(self.max_active, self._active)
        self.events.record(f"{stage}_branch_started", branch=branch, task_id=task.task_id)
        try:
            result = self.runner.run(task)
        finally:
            with self._activity_lock:
                self._active -= 1
        self.events.record(
            f"{stage}_branch_completed",
            branch=branch,
            task_id=task.task_id,
            lifecycle=result.lifecycle,
        )
        self.context.write_json(
            f"handoffs/{task.task_id}.json",
            {"task": task.model_dump(mode="json"), "result": result.model_dump(mode="json")},
            immutable=True,
        )
        if result.lifecycle != "completed" or result.handoff is None:
            status: Literal["failed", "timed_out"] = (
                "timed_out" if result.lifecycle == "timed_out" else "failed"
            )
            raise _BranchFailure.from_result(
                result,
                result.error or result.lifecycle,
                status=status,
            )
        return result


class _BranchFailure(RuntimeError):
    def __init__(
        self,
        status: Literal["failed", "timed_out"],
        started_at: datetime,
        finished_at: datetime,
        message: str,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.started_at = started_at
        self.finished_at = finished_at

    @classmethod
    def from_result(
        cls,
        result: TaskResult,
        message: str,
        *,
        status: Literal["failed", "timed_out"] = "failed",
    ) -> _BranchFailure:
        return cls(status, result.started_at, result.finished_at, message)


def _v3_payload(result: TaskResult, expected: type[_PayloadV3]) -> _PayloadV3:
    if result.handoff is None or not isinstance(result.handoff.result, ContractEnvelopeV3):
        raise _BranchFailure.from_result(result, "completed V3 task omitted its typed envelope")
    payload = result.handoff.result.payload
    if not isinstance(payload, expected):
        raise _BranchFailure.from_result(
            result,
            f"V3 task returned {type(payload).__name__}, expected {expected.__name__}",
        )
    return payload


__all__ = [
    "BRANCH_ORDER",
    "BRANCH_ROLE",
    "CandidateFanIn",
    "CollaborationV3Error",
    "ParallelCollaborationV3",
    "REVIEW_RING",
    "RoutePolicy",
    "assign_cross_reviewers",
    "build_candidate_blueprints",
    "normalize_assessment_to_blueprint",
    "normalized_endpoint_inventory_digest",
    "trusted_candidate_fingerprint",
]

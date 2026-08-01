from __future__ import annotations

import os
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

from hermes.campaign_v3 import materialized_body_digest
from hermes.collaboration_v3 import (
    CandidateFanIn,
    ParallelCollaborationV3,
    RoutePolicy,
    assign_cross_reviewers,
    trusted_candidate_fingerprint,
)
from hermes.domain_contracts_v3 import (
    BranchAssessment,
    BranchCandidateV3,
    BranchCoverage,
    ContractEnvelopeV3,
    CrossReview,
    CrossReviewSet,
    EndpointInventoryV3,
    EndpointV3,
)
from hermes.evidence import EvidenceArtifactRef
from hermes.runtime import RunContext
from hermes.runtime.agents import AgentRunner, HandoffEnvelope, TaskEnvelope, TaskResult

DIGEST = "sha256:" + "a" * 64
BODY = "sha256:" + "b" * 64
IDENTITY = "sha256:" + "c" * 64


def _evidence() -> EvidenceArtifactRef:
    return EvidenceArtifactRef(
        evidence_id="recon-evidence",
        manifest_path="evidence/recon-evidence/manifest.json",
        manifest_sha256=DIGEST,
    )


def _inventory(context: RunContext, *, subset: bool = False) -> EndpointInventoryV3:
    endpoint_values = [
        ("web", "/candidate", "GET", "candidate", ("text/html",), ()),
        ("control", "/control", "GET", "negative_control", ("text/html",), ()),
        ("graphql", "/graphql", "POST", "graphql", ("application/json",), ("member",)),
        ("role-change", "/authz/elevate", "POST", "role_change", (), ("member",)),
        ("debug", "/debug", "GET", "debug", ("application/json",), ()),
    ]
    if subset:
        endpoint_values = [endpoint_values[0], endpoint_values[1], endpoint_values[4]]
    endpoints = tuple(
        EndpointV3(
            endpoint_id=endpoint_id,
            asset_id="asset-1",
            canonical_url=f"http://localhost:8080{path}",
            method=method,
            relation=relation,
            content_types=content_types,
            auth_contexts=auth_contexts,
            evidence=(_evidence(),),
        )
        for endpoint_id, path, method, relation, content_types, auth_contexts in endpoint_values
    )
    return EndpointInventoryV3(
        run_id=context.run_id,
        scope_digest=context.scope_digest,
        generated_by_task_id="phase4-mapper",
        inventory_id="phase4-endpoints",
        asset_inventory_digest=DIGEST,
        endpoints=endpoints,
    )


class _ParallelRunner(AgentRunner):
    def __init__(
        self,
        context: RunContext,
        *,
        barrier: threading.Barrier | None = None,
        fail_branch: str | None = None,
    ) -> None:
        self.context = context
        self.barrier = barrier
        self.fail_branch = fail_branch
        self.calls: list[tuple[str, str]] = []
        self.review_payloads: dict[str, dict[str, object]] = {}
        self.lock = threading.Lock()

    def run(self, task: TaskEnvelope) -> TaskResult:
        started = datetime.now(UTC)
        operation = str(task.payload["operation"])
        branch = "web" if task.role == "web-vuln" else task.role
        with self.lock:
            self.calls.append((operation, branch))
        if branch == self.fail_branch:
            finished = datetime.now(UTC)
            return TaskResult(
                task=task,
                lifecycle="failed",
                input_sha256=task.input_hash(),
                started_at=started,
                finished_at=finished,
                error="isolated fixture branch failure",
                failure_layer="provider",
                failure_code="fixture_branch_failed",
                retryable=False,
            )
        if operation == "assessment":
            if self.barrier is not None:
                self.barrier.wait(timeout=2)
            time.sleep(0.03)
            payload = self._assessment(task, branch)
        else:
            self.review_payloads[task.task_id] = dict(task.payload)
            time.sleep(0.02)
            payload = self._review(task, branch)
        self.context.write_json(
            f"provider/{task.task_id}.json",
            {
                "provider": "fixture-provider",
                "task_id": task.task_id,
                "session_id": f"session-{task.task_id}",
                "process_id": os.getpid(),
            },
            immutable=True,
        )
        envelope = ContractEnvelopeV3.for_payload(payload)
        handoff = HandoffEnvelope(
            version="3",
            run_id=task.run_id,
            task_id=task.task_id,
            role=task.role,
            scope_digest=task.scope_digest,
            input_sha256=task.input_hash(),
            status="completed",
            result=envelope,
        )
        finished = datetime.now(UTC)
        return TaskResult(
            task=task,
            handoff=handoff,
            lifecycle="completed",
            input_sha256=task.input_hash(),
            output_sha256=envelope.digest,
            started_at=started,
            finished_at=finished,
            host_process_id=os.getpid(),
        )

    def _assessment(self, task: TaskEnvelope, branch: str) -> BranchAssessment:
        details = {
            "web": (
                "web-xcto",
                "missing_x_content_type_options",
                "web",
                "/candidate",
                "GET",
                None,
                None,
                "header absent on target and present on control",
            ),
            "api": (
                "api-graphql",
                "unauthorized_graphql_mutation",
                "api",
                "/graphql/mutate",
                "POST",
                BODY,
                IDENTITY,
                "member mutation succeeds while strict control is forbidden",
            ),
            "authz": (
                "authz-escalation",
                "privilege_escalation",
                "authz",
                "/authz/elevate",
                "POST",
                BODY,
                IDENTITY,
                "member gains access before cleanup",
            ),
            "infra": (
                "infra-debug",
                "exposed_debug_endpoint",
                "infra",
                "/debug",
                "GET",
                None,
                None,
                "debug target is exposed while control is absent",
            ),
        }[branch]
        candidate_id, candidate_type, producer, path, method, body, identity, assertion = details
        candidates = [
            BranchCandidateV3(
                candidate_id=candidate_id,
                candidate_type=candidate_type,
                producer_branch=producer,
                target_endpoint_id=candidate_id,
                control_endpoint_ids=(f"{candidate_id}-control",),
                target_url=f"http://localhost:8080{path}",
                method=method,
                request_body_sha256=body,
                identity_binding_digest=identity,
                expected_assertion=assertion,
                rationale="local collaboration fixture candidate",
                semantic_fingerprint=DIGEST,
            )
        ]
        if branch == "infra":
            candidates.append(
                BranchCandidateV3(
                    candidate_id="infra-xcto-copy",
                    candidate_type="missing_x_content_type_options",
                    producer_branch="infra",
                    target_endpoint_id="web-xcto",
                    control_endpoint_ids=("web-xcto-control",),
                    target_url="http://localhost:8080/candidate",
                    method="GET",
                    identity_binding_digest=IDENTITY,
                    expected_assertion="model-invented divergent assertion",
                    rationale="independent duplicate observation",
                    semantic_fingerprint="sha256:" + "f" * 64,
                )
            )
        return BranchAssessment(
            run_id=task.run_id,
            scope_digest=task.scope_digest,
            generated_by_task_id=task.task_id,
            assessment_id=f"assessment-{branch}",
            branch=branch,
            endpoint_inventory_digest=task.payload["endpoint_inventory_digest"],
            prompt_id=f"hermes.{task.role}",
            prompt_version="3.0",
            prompt_sha256=DIGEST,
            candidates=tuple(candidates),
            coverage=BranchCoverage(
                endpoints_considered=1,
                candidates_emitted=len(candidates),
                candidates_blocked=0,
                candidates_inconclusive=0,
            ),
        )

    @staticmethod
    def _review(task: TaskEnvelope, branch: str) -> CrossReviewSet:
        candidate = task.payload["candidate"]
        review = CrossReview(
            review_id=f"review-{candidate['candidate_id']}",
            candidate_id=candidate["candidate_id"],
            producer_branches=tuple(candidate["provenance"]),
            reviewer_branch=branch,
            reviewer_task_id=task.task_id,
            verdict="concur",
            rationale="independent fixture review concurs",
        )
        return CrossReviewSet(
            run_id=task.run_id,
            scope_digest=task.scope_digest,
            generated_by_task_id=task.task_id,
            review_set_id=f"review-set-{candidate['candidate_id']}",
            candidate_collection_digest=task.payload["candidate_collection_digest"],
            reviews=(review,),
        )


def test_route_policy_is_deterministic_and_supports_dynamic_subsets(tmp_path: Path) -> None:
    context = RunContext(tmp_path / "runs", {"profile": "local"}, run_id="route-run")
    full = _inventory(context)
    route = RoutePolicy().decide(
        full,
        run_id=context.run_id,
        scope_digest=context.scope_digest,
        generated_by_task_id="phase4-router",
        identity_binding_digests=(IDENTITY,),
    )
    assert route.routed_branches == ("web", "api", "authz", "infra")
    reversed_inventory = full.model_copy(update={"endpoints": tuple(reversed(full.endpoints))})
    reordered = RoutePolicy().decide(
        reversed_inventory,
        run_id=context.run_id,
        scope_digest=context.scope_digest,
        generated_by_task_id="phase4-router",
        identity_binding_digests=(IDENTITY,),
    )
    assert route.digest == reordered.digest

    subset = _inventory(context, subset=True)
    subset_route = RoutePolicy().decide(
        subset,
        run_id=context.run_id,
        scope_digest=context.scope_digest,
        generated_by_task_id="phase4-router",
    )
    assert subset_route.routed_branches == ("web", "infra")


def test_true_parallel_fanout_dedup_and_independent_cross_review(tmp_path: Path) -> None:
    context = RunContext(tmp_path / "runs", {"profile": "local"}, run_id="parallel-run")
    inventory = _inventory(context)
    route = RoutePolicy().decide(
        inventory,
        run_id=context.run_id,
        scope_digest=context.scope_digest,
        generated_by_task_id="phase4-router",
        identity_binding_digests=(IDENTITY,),
    )
    runner = _ParallelRunner(context, barrier=threading.Barrier(4))
    coordinator = ParallelCollaborationV3(context, runner, max_workers=4)
    identities = {"member": IDENTITY}
    results, assessments = coordinator.run_assessments(
        route=route,
        inventory=inventory,
        identity_binding_digests=identities,
    )

    assert coordinator.max_active == 4
    assert tuple(item.branch for item in results) == ("web", "api", "authz", "infra")
    assert all(item.status == "succeeded" for item in results)
    collection = CandidateFanIn().merge(
        route=route,
        inventory=inventory,
        identity_binding_digests=identities,
        branch_results=results,
        assessments=assessments,
        generated_by_task_id="phase4-fanin",
    )
    assert len(collection.raw_candidates) == 5
    assert len(collection.canonical_candidates) == 4
    xcto = next(
        item
        for item in collection.canonical_candidates
        if item.candidate_type == "missing_x_content_type_options"
    )
    assert xcto.provenance == ("web", "infra")
    raw_xcto = [
        item
        for item in collection.raw_candidates
        if item.candidate_type == "missing_x_content_type_options"
    ]
    assert {trusted_candidate_fingerprint(item) for item in raw_xcto} == {xcto.semantic_fingerprint}
    # The fake experts intentionally return placeholder body hashes and their
    # own assertion text.  Parent-owned blueprints must replace those fields
    # before the assessment is persisted or fed into fan-in.
    api = next(
        item
        for item in collection.raw_candidates
        if item.candidate_type == "unauthorized_graphql_mutation"
    )
    authz = next(
        item for item in collection.raw_candidates if item.candidate_type == "privilege_escalation"
    )
    assert api.request_body_sha256 == materialized_body_digest(
        "unauthorized_graphql_mutation", "candidate"
    )
    assert authz.request_body_sha256 == materialized_body_digest(
        "privilege_escalation", "candidate"
    )
    assert api.identity_binding_digest == authz.identity_binding_digest == IDENTITY
    assert {item.expected_assertion for item in raw_xcto} == {
        "X-Content-Type-Options is absent on the candidate response and "
        "nosniff is present on the negative control"
    }
    assignments = assign_cross_reviewers(collection)
    assert assignments == {
        "web-xcto": "api",
        "api-graphql": "authz",
        "authz-escalation": "infra",
        "infra-debug": "web",
    }
    reviews = coordinator.run_cross_reviews(collection=collection)
    assert len(reviews.reviews) == 4
    assert all(review.verdict == "concur" for review in reviews.reviews)
    assert all(review.reviewer_branch not in review.producer_branches for review in reviews.reviews)
    for review in reviews.reviews:
        payload = runner.review_payloads[review.reviewer_task_id]
        sources = payload["candidate_sources"]
        policy = payload["review_policy"]
        assert isinstance(sources, list) and sources
        assert {item["candidate_id"] for item in sources if isinstance(item, dict)} == {
            *next(
                item.source_candidate_ids
                for item in collection.canonical_candidates
                if item.candidate_id == review.candidate_id
            )
        }
        assert policy == {
            "profile": "phase4-localhost-fixed",
            "review_stage": "pre_verification",
            "rule": (
                "concur when each supplied source preserves the canonical candidate type, "
                "endpoint, method, identity binding, and expected assertion; reject only an "
                "explicit inconsistent or contraindicating trusted fact"
            ),
            "must_not_require_live_validation": True,
        }


def test_single_branch_failure_is_isolated_and_unrouted_branches_never_start(
    tmp_path: Path,
) -> None:
    context = RunContext(tmp_path / "runs", {"profile": "local"}, run_id="failure-run")
    inventory = _inventory(context)
    route = RoutePolicy().decide(
        inventory,
        run_id=context.run_id,
        scope_digest=context.scope_digest,
        generated_by_task_id="phase4-router",
        identity_binding_digests=(IDENTITY,),
    )
    runner = _ParallelRunner(context, fail_branch="api")
    results, assessments = ParallelCollaborationV3(context, runner).run_assessments(
        route=route,
        inventory=inventory,
        identity_binding_digests={"member": IDENTITY},
    )

    assert [item.status for item in results] == ["succeeded", "failed", "succeeded", "succeeded"]
    assert set(assessments) == {"web", "authz", "infra"}
    collection = CandidateFanIn().merge(
        route=route,
        inventory=inventory,
        identity_binding_digests={"member": IDENTITY},
        branch_results=results,
        assessments=assessments,
        generated_by_task_id="phase4-fanin",
    )
    assert len(collection.canonical_candidates) == 3

    subset_context = RunContext(tmp_path / "subset-runs", {"profile": "local"}, run_id="subset-run")
    subset_inventory = _inventory(subset_context, subset=True)
    subset_route = RoutePolicy().decide(
        subset_inventory,
        run_id=subset_context.run_id,
        scope_digest=subset_context.scope_digest,
        generated_by_task_id="phase4-router",
    )
    subset_runner = _ParallelRunner(subset_context)
    subset_results, _ = ParallelCollaborationV3(subset_context, subset_runner).run_assessments(
        route=subset_route,
        inventory=subset_inventory,
        identity_binding_digests={},
    )
    assert [item.status for item in subset_results] == [
        "succeeded",
        "not_routed",
        "not_routed",
        "succeeded",
    ]
    assert {branch for operation, branch in subset_runner.calls if operation == "assessment"} == {
        "web",
        "infra",
    }

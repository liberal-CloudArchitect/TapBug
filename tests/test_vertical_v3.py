from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hermes.campaign_v3 import materialized_body_digest
from hermes.domain_contracts_v3 import (
    ApprovalBatchV3,
    AssetInventoryV3,
    AssetV3,
    BranchAssessment,
    BranchCandidateV3,
    BranchCoverage,
    ContractEnvelopeV3,
    CrossReview,
    CrossReviewSet,
    EndpointInventoryV3,
    EndpointV3,
    GateDecisionV3,
    ObservedLinkV3,
    RunPlanV3,
    VerificationCampaignPlan,
    VerificationCandidateOutcome,
    VerificationOutcomeSet,
)
from hermes.evidence import EvidenceAnalysisDocument, EvidenceArtifactRef
from hermes.execution_v3 import ExecutionResultV3
from hermes.ledgers_v3 import ActiveTimeExceeded, BudgetLedger
from hermes.runtime import PolicyEngine, RunContext, ScopePolicy, ScopeRule
from hermes.runtime.agents import AgentRunner, HandoffEnvelope, TaskEnvelope, TaskResult
from hermes.security import KeyUsage, TrustedKey, TrustStoreV2, encode_base64, public_key_bytes
from hermes.security_v3 import sign_approval_batch_v3
from hermes.vertical_v3 import ExecutionStateV3, VerticalWorkflowV3

DIGEST = "sha256:" + "a" * 64
MEMBER = "sha256:" + "b" * 64
ADMIN = "sha256:" + "c" * 64


class _Phase4Runner(AgentRunner):
    def __init__(self, context: RunContext) -> None:
        self.context = context

    def run(self, task: TaskEnvelope) -> TaskResult:
        started = datetime.now(UTC)
        operation = str(task.payload["operation"])
        if operation == "gate":
            payload = GateDecisionV3(
                run_id=task.run_id,
                scope_digest=task.scope_digest,
                generated_by_task_id=task.task_id,
                decision="allowed",
                target=task.payload["target"],
                resolved_ips=tuple(task.payload["resolved_ips"]),
                reason="strict local fixture is allowed",
            )
            evidence: tuple[EvidenceArtifactRef, ...] = ()
        elif operation == "recon":
            evidence = (_evidence(),)
            target = str(task.payload["target"])
            payload = AssetInventoryV3(
                run_id=task.run_id,
                scope_digest=task.scope_digest,
                generated_by_task_id=task.task_id,
                inventory_id="phase4-assets",
                target=target,
                assets=(
                    AssetV3(
                        asset_id="asset-1",
                        scheme="http",
                        port=urlsplit(target).port or 80,
                        resolved_ips=("127.0.0.1",),
                        status_code=200,
                        content_types=("text/html",),
                        observed_relations=("negative-control", "graphql", "role-change", "debug"),
                        observed_links=(
                            ObservedLinkV3(
                                relation="negative-control",
                                canonical_url=target.rsplit("/", 1)[0] + "/control",
                            ),
                            ObservedLinkV3(
                                relation="graphql",
                                canonical_url=target.rsplit("/", 1)[0] + "/graphql",
                            ),
                            ObservedLinkV3(
                                relation="role-state",
                                canonical_url=target.rsplit("/", 1)[0] + "/authz/status",
                            ),
                            ObservedLinkV3(
                                relation="diagnostic",
                                canonical_url=target.rsplit("/", 1)[0] + "/debug",
                            ),
                        ),
                    ),
                ),
                source_evidence=evidence,
            )
        elif operation == "map":
            evidence = ()
            payload = EndpointInventoryV3(
                run_id=task.run_id,
                scope_digest=task.scope_digest,
                generated_by_task_id=task.task_id,
                inventory_id="phase4-endpoints",
                asset_inventory_digest=task.payload["asset_inventory_digest"],
                endpoints=tuple(
                    EndpointV3.model_validate(value)
                    for value in task.payload["relation_projection"]
                ),
            )
        elif operation == "assessment":
            evidence = ()
            payload = self._assessment(task)
            self.context.write_json(
                f"provider/{task.task_id}.json",
                {"session_id": task.task_id, "process_id": os.getpid()},
                immutable=True,
            )
        elif operation == "cross_review":
            evidence = ()
            candidate = task.payload["candidate"]
            branch = "web" if task.role == "web-vuln" else task.role
            payload = CrossReviewSet(
                run_id=task.run_id,
                scope_digest=task.scope_digest,
                generated_by_task_id=task.task_id,
                review_set_id=f"set-{candidate['candidate_id']}",
                candidate_collection_digest=task.payload["candidate_collection_digest"],
                reviews=(
                    CrossReview(
                        review_id=f"review-{candidate['candidate_id']}",
                        candidate_id=candidate["candidate_id"],
                        producer_branches=tuple(candidate["provenance"]),
                        reviewer_branch=branch,
                        reviewer_task_id=task.task_id,
                        verdict="concur",
                        rationale="independent fixture review concurs",
                    ),
                ),
            )
        else:  # pragma: no cover - protects the test fixture itself
            raise AssertionError(operation)
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
            evidence_artifact_refs=evidence,
            process_id=os.getpid(),
            container_id=f"container-{task.task_id}",
        )
        return TaskResult(
            task=task,
            handoff=handoff,
            lifecycle="completed",
            input_sha256=task.input_hash(),
            output_sha256=envelope.digest,
            started_at=started,
            finished_at=datetime.now(UTC),
            host_process_id=os.getpid(),
        )

    @staticmethod
    def _assessment(task: TaskEnvelope) -> BranchAssessment:
        branch = "web" if task.role == "web-vuln" else task.role
        definitions = {
            "web": (
                "web-xcto",
                "missing_x_content_type_options",
                "/candidate",
                "GET",
                None,
                None,
                "header differential",
            ),
            "api": (
                "api-graphql",
                "unauthorized_graphql_mutation",
                "/graphql/mutate",
                "POST",
                materialized_body_digest("unauthorized_graphql_mutation", "candidate"),
                MEMBER,
                "unauthorized mutation",
            ),
            "authz": (
                "authz-escalation",
                "privilege_escalation",
                "/authz/elevate",
                "POST",
                materialized_body_digest("privilege_escalation", "candidate"),
                MEMBER,
                "privilege differential",
            ),
            "infra": (
                "infra-debug",
                "exposed_debug_endpoint",
                "/debug",
                "GET",
                None,
                None,
                "debug exposure",
            ),
        }
        candidate_id, candidate_type, path, method, body, identity, assertion = definitions[branch]
        candidates = [
            BranchCandidateV3(
                candidate_id=candidate_id,
                candidate_type=candidate_type,
                producer_branch=branch,
                target_endpoint_id=candidate_id,
                control_endpoint_ids=(f"control-{candidate_id}",),
                target_url="http://localhost:8080" + path,
                method=method,
                request_body_sha256=body,
                identity_binding_digest=identity,
                expected_assertion=assertion,
                rationale="bounded fixture candidate",
                semantic_fingerprint=DIGEST,
            )
        ]
        if branch == "infra":
            candidates.append(
                BranchCandidateV3(
                    candidate_id="infra-xcto-copy",
                    candidate_type="missing_x_content_type_options",
                    producer_branch="infra",
                    target_endpoint_id="candidate",
                    control_endpoint_ids=("control",),
                    target_url="http://localhost:8080/candidate",
                    method="GET",
                    expected_assertion="header differential",
                    rationale="duplicate fixture observation",
                    semantic_fingerprint=DIGEST,
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
            coverage=BranchCoverage(endpoints_considered=1, candidates_emitted=len(candidates)),
        )


def _evidence() -> EvidenceArtifactRef:
    return EvidenceArtifactRef(
        evidence_id="recon-evidence",
        manifest_path="evidence/recon-evidence/manifest.json",
        manifest_sha256=DIGEST,
    )


def _oracle_execution(
    purpose: str, *, status_code: int, headers: dict[str, str] | None = None
) -> ExecutionResultV3:
    return ExecutionResultV3(
        action_id=f"oracle-{purpose}",
        action_digest=DIGEST,
        status_code=status_code,
        headers=headers or {},
        evidence_artifact_ref=EvidenceArtifactRef(
            evidence_id=f"oracle-{purpose}",
            manifest_path=f"evidence/oracle-{purpose}/manifest.json",
            manifest_sha256=DIGEST,
        ),
        action_ledger_entry_digest=DIGEST,
        approval_consumption_digest=DIGEST,
    )


def _oracle_analysis(body: object = None) -> EvidenceAnalysisDocument:
    return EvidenceAnalysisDocument.model_validate(
        {
            "version": "2",
            "request": {
                "method": "GET",
                "url": "http://localhost:8080/oracle",
                "headers": [],
                "mime": "application/json",
                "body": None,
            },
            "response": {
                "status": 200,
                "headers": [],
                "mime": "application/json",
                "body": body,
            },
        }
    )


def _oracle_value(
    purpose: str,
    *,
    status_code: int,
    headers: dict[str, str] | None = None,
    body: object = None,
) -> tuple[ExecutionResultV3, EvidenceAnalysisDocument]:
    return _oracle_execution(purpose, status_code=status_code, headers=headers), _oracle_analysis(
        body
    )


@pytest.mark.parametrize(
    ("candidate_type", "by_purpose"),
    (
        (
            "missing_x_content_type_options",
            {
                "candidate": _oracle_value("candidate", status_code=200),
                "negative_control": _oracle_value(
                    "negative_control",
                    status_code=200,
                    headers={"X-Content-Type-Options": "nosniff"},
                ),
            },
        ),
        (
            "exposed_debug_endpoint",
            {
                "candidate": _oracle_value("candidate", status_code=200),
                "negative_control": _oracle_value("negative_control", status_code=404),
            },
        ),
        (
            "unauthorized_graphql_mutation",
            {
                "baseline": _oracle_value("baseline", status_code=200),
                "candidate": _oracle_value("candidate", status_code=200),
                "negative_control": _oracle_value("negative_control", status_code=403),
            },
        ),
        (
            "privilege_escalation",
            {
                "baseline": _oracle_value("baseline", status_code=200),
                "candidate": _oracle_value("candidate", status_code=200),
                "negative_control": _oracle_value(
                    "negative_control", status_code=200, body={"admin": True}
                ),
            },
        ),
    ),
)
def test_v3_parent_oracle_validates_each_fixed_fixture_candidate(
    candidate_type: str,
    by_purpose: dict[str, tuple[ExecutionResultV3, EvidenceAnalysisDocument]],
) -> None:
    status, summary = VerticalWorkflowV3._fixed_fixture_verdict(  # noqa: SLF001
        candidate_type,
        by_purpose,  # type: ignore[arg-type]
    )

    assert status == "validated"
    assert summary.startswith("Parent evidence oracle:")


def test_v3_parent_oracle_rejects_inverted_xcto_control_claim() -> None:
    status, _summary = VerticalWorkflowV3._fixed_fixture_verdict(  # noqa: SLF001
        "missing_x_content_type_options",
        {
            "candidate": _oracle_value(
                "candidate",
                status_code=200,
                headers={"X-Content-Type-Options": "nosniff"},
            ),
            "negative_control": _oracle_value(
                "negative_control",
                status_code=200,
                headers={"X-Content-Type-Options": "nosniff"},
            ),
        },
    )

    assert status == "disproved"


def test_v3_task_timeout_is_capped_by_global_active_time_remaining(tmp_path: Path) -> None:
    context = RunContext(tmp_path / "runs", {"hosts": ["localhost"]}, run_id="timeouts")
    workflow = VerticalWorkflowV3(context, _Phase4Runner(context), timeout_seconds=180)
    workflow.active_time = SimpleNamespace(remaining_seconds=lambda: 37.9)  # type: ignore[assignment]
    assert workflow._task_timeout() == 37  # noqa: SLF001

    workflow.active_time = SimpleNamespace(remaining_seconds=lambda: 0.5)  # type: ignore[assignment]
    with pytest.raises(ActiveTimeExceeded, match="less than one second"):
        workflow._task_timeout()  # noqa: SLF001


def test_v3_parent_rebinds_verifier_outer_authority_fields(tmp_path: Path) -> None:
    context = RunContext(tmp_path / "runs", {"hosts": ["localhost"]}, run_id="bind-v3")
    workflow = VerticalWorkflowV3(context, _Phase4Runner(context))
    campaign = VerificationCampaignPlan(
        run_id=context.run_id,
        scope_digest=context.scope_digest,
        generated_by_task_id="campaign-planner",
        campaign_id="campaign-1",
        candidate_collection_digest=DIGEST,
        cross_review_set_digest=DIGEST,
        actions=(),
        request_budget=0,
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC),
    )
    batch = ApprovalBatchV3(
        run_id=context.run_id,
        scope_digest=context.scope_digest,
        generated_by_task_id="operator",
        approval_id="approval-1",
        campaign_digest=campaign.digest,
        risk_group="readonly",
        verdict="rejected",
        candidate_ids=(),
        action_digests=(),
        key_id="approver-v3",
        signed_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
        rationale="fixture authority binding",
        signature_b64="fixture-signature",
    )
    output = VerificationOutcomeSet(
        run_id=context.run_id,
        scope_digest=DIGEST,
        generated_by_task_id="model-chosen-task",
        outcome_set_id="model-output",
        campaign_digest=DIGEST,
        approval_batch_digests=(DIGEST,),
        outcomes=(
            VerificationCandidateOutcome(
                outcome_id="outcome-1",
                candidate_id="candidate-1",
                verifier_task_id="phase4-verifier-candidate-1",
                status="inconclusive",
                action_digests=(),
                action_ledger_entry_digests=(),
                evidence=(),
                assertion_summary="Model summary is non-authoritative.",
            ),
        ),
    )

    rebound = workflow._bind_verifier_authority(  # noqa: SLF001
        output,
        campaign=campaign,
        batch=batch,
        task_id="phase4-verifier-candidate-1",
    )

    assert rebound.run_id == context.run_id
    assert rebound.scope_digest == context.scope_digest
    assert rebound.generated_by_task_id == "phase4-verifier-candidate-1"
    assert rebound.campaign_digest == campaign.digest
    assert rebound.approval_batch_digests == (batch.digest,)
    assert rebound.outcomes == output.outcomes


def test_v3_coverage_budget_precommits_the_required_reporter_attempt(
    tmp_path: Path,
) -> None:
    context = RunContext(tmp_path / "runs", {"hosts": ["localhost"]}, run_id="budget-v3")
    workflow = VerticalWorkflowV3(context, _Phase4Runner(context))
    plan = RunPlanV3(
        run_id=context.run_id,
        target="http://localhost:8080/candidate",
        scope_digest=context.scope_digest,
        provider_id="hermes-acp-restricted",
        model_id="fixture-model",
        prompt_registry_digest=DIGEST,
        role_manifest_set_digest=DIGEST,
        roles=(
            "gatekeeper",
            "recon",
            "mapper",
            "web-vuln",
            "api",
            "authz",
            "infra",
            "verifier",
            "reporter",
        ),
        created_at=datetime.now(UTC),
    )
    ledger = BudgetLedger(context)
    for index in range(16):
        reservation = ledger.reserve_prompt(
            task_id=f"task-{index}", role="web-vuln", reservation_id=f"task-{index}:initial"
        )
        ledger.settle(reservation.reservation_id)

    summary = workflow._coverage_budget_summary(plan)  # noqa: SLF001

    assert summary.attempts_reserved == 17
    assert summary.attempts_used == 16
    assert summary.estimated_cost_microusd == 4_250_000


def test_v3_start_builds_parallel_campaign_and_pauses_before_verification(
    tmp_path: Path,
) -> None:
    policy = ScopePolicy(
        profile="local-lab",
        automation_allowed=True,
        dry_run=False,
        max_requests=15,
        max_concurrency=4,
        rate_limit_rps=1000,
        rules=(
            ScopeRule(
                host="localhost",
                schemes={"http"},
                ports={8080},
                allow_dns=True,
                allow_private=True,
                profile="local-lab",
            ),
        ),
    )
    context = RunContext(tmp_path / "runs", policy.model_dump(mode="json"), run_id="phase4")
    state = VerticalWorkflowV3(context, _Phase4Runner(context)).start(
        target="http://localhost:8080/candidate",
        engine=PolicyEngine(policy, resolver=lambda _host: ["127.0.0.1"]),
        provider_id="hermes-acp-restricted",
        model_id="fixture-model",
        prompt_registry_digest=DIGEST,
        role_manifest_set_digest=DIGEST,
        identity_binding_digests={"member": MEMBER, "fixture-admin": ADMIN},
    )

    assert state.execution_state is ExecutionStateV3.AWAITING_READONLY_APPROVAL
    assert state.requests_planned == 15
    assert state.requests_used == 1
    assert state.routed_branches == ("web", "api", "authz", "infra")
    campaign = __import__("json").loads(
        context.artifact_path("verification_v3/campaign.json").read_text(encoding="utf-8")
    )
    assert campaign["request_budget"] == 14
    assert not context.artifact_path("verification_v3/outcomes.json").exists()
    assert not context.artifact_path("report/report-v3.md").exists()
    assert context.artifact_path("approvals_v3/challenge-readonly.json").is_file()
    assert context.artifact_path("approvals_v3/challenge-mutation.json").is_file()


def test_v3_rejected_batches_never_start_verifier_or_write_report(tmp_path: Path) -> None:
    policy = ScopePolicy(
        profile="local-lab",
        automation_allowed=True,
        dry_run=False,
        max_requests=15,
        max_concurrency=4,
        rate_limit_rps=1000,
        rules=(
            ScopeRule(
                host="localhost",
                schemes={"http"},
                ports={8080},
                allow_dns=True,
                allow_private=True,
                profile="local-lab",
            ),
        ),
    )
    context = RunContext(tmp_path / "runs", policy.model_dump(mode="json"), run_id="reject-v3")
    runner = _Phase4Runner(context)
    workflow = VerticalWorkflowV3(context, runner)
    workflow.start(
        target="http://localhost:8080/candidate",
        engine=PolicyEngine(policy, resolver=lambda _host: ["127.0.0.1"]),
        provider_id="hermes-acp-restricted",
        model_id="fixture-model",
        prompt_registry_digest=DIGEST,
        role_manifest_set_digest=DIGEST,
        identity_binding_digests={"member": MEMBER, "fixture-admin": ADMIN},
    )
    campaign = VerificationCampaignPlan.model_validate_json(
        context.artifact_path("verification_v3/campaign.json").read_bytes()
    )
    private = Ed25519PrivateKey.generate()
    now = datetime.now(UTC)
    store = TrustStoreV2(
        keys=(
            TrustedKey(
                key_id="approver-v3",
                public_key=encode_base64(public_key_bytes(private)),
                usages=frozenset({KeyUsage.APPROVAL}),
                valid_from=now.replace(year=now.year - 1),
                valid_until=now.replace(year=now.year + 1),
            ),
        )
    )
    for risk in ("readonly", "mutation"):
        actions = tuple(item for item in campaign.actions if item.risk_group == risk)
        unsigned = ApprovalBatchV3(
            run_id=context.run_id,
            scope_digest=context.scope_digest,
            generated_by_task_id="operator",
            approval_id=f"reject-{risk}",
            campaign_digest=campaign.digest,
            risk_group=risk,
            verdict="rejected",
            candidate_ids=tuple(dict.fromkeys(item.candidate_id for item in actions)),
            action_digests=tuple(item.action_digest for item in actions),
            key_id="approver-v3",
            signed_at=now,
            expires_at=campaign.expires_at,
            rationale="operator rejected the complete risk-group graph",
            signature_b64="unsigned-signature",
        )
        decision = sign_approval_batch_v3(unsigned, private)
        context.write_json(
            f"approvals_v3/{risk}.json", decision.model_dump(mode="json"), immutable=True
        )
        state = workflow.advance_verification(approval_store=store)
    assert state.execution_state is ExecutionStateV3.REJECTED
    assert state.requests_used == 1
    assert not context.artifact_path("verification_v3/outcomes.json").exists()
    assert not context.artifact_path("report/report-v3.md").exists()


def test_interrupted_mutation_resume_creates_cleanup_only_challenge_without_reporter(
    tmp_path: Path,
) -> None:
    policy = ScopePolicy(
        profile="local-lab",
        automation_allowed=True,
        dry_run=False,
        max_requests=15,
        max_concurrency=4,
        rate_limit_rps=1000,
        rules=(
            ScopeRule(
                host="localhost",
                schemes={"http"},
                ports={8080},
                allow_dns=True,
                allow_private=True,
                profile="local-lab",
            ),
        ),
    )
    context = RunContext(tmp_path / "runs", policy.model_dump(mode="json"), "crash-v3")
    runner = _Phase4Runner(context)
    workflow = VerticalWorkflowV3(context, runner)
    state = workflow.start(
        target="http://localhost:8080/candidate",
        engine=PolicyEngine(policy, resolver=lambda _host: ["127.0.0.1"]),
        provider_id="hermes-acp-restricted",
        model_id="fixture-model",
        prompt_registry_digest=DIGEST,
        role_manifest_set_digest=DIGEST,
        identity_binding_digests={"member": MEMBER, "fixture-admin": ADMIN},
    )
    context.write_json(
        "state.json",
        state.model_copy(
            update={"execution_state": ExecutionStateV3.VERIFYING_MUTATION}
        ).model_dump(mode="json"),
    )

    recovered = workflow.begin_cleanup_recovery()
    campaign = VerificationCampaignPlan.model_validate_json(
        context.artifact_path("verification_v3/campaign.json").read_bytes()
    )
    challenge = json.loads(
        context.artifact_path("approvals_v3/challenge-cleanup.json").read_text(encoding="utf-8")
    )
    expected = [
        item.action_digest
        for item in campaign.actions
        if item.purpose in {"cleanup", "cleanup_check"}
    ]
    assert recovered.execution_state is ExecutionStateV3.CLEANUP_REQUIRED
    assert challenge["action_digests"] == expected
    assert all(
        item.action_digest not in challenge["action_digests"]
        for item in campaign.actions
        if item.purpose == "candidate"
    )
    assert not context.artifact_path("report/reporter-launch-v3.json").exists()
    assert not context.artifact_path("report/report-v3.md").exists()

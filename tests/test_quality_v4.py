from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from hermes.campaign_v4 import build_verification_campaign_v4
from hermes.domain_contracts_v4 import (
    ApprovalBatchV4,
    ContractEnvelopeV4,
    GateDecisionV4,
    RunPlanV4,
    VerificationActionV4,
    VerificationCampaignPlanV4,
)
from hermes.preflight_v4 import ReportPreflightV4Error, ReportPreflightVerifierV4
from hermes.promotion_v4 import build_quality_receipt_v4
from hermes.quality_v4 import (
    evaluate_quality_dataset_v4,
    load_fixture_dataset_v4,
    load_quality_dataset_v4,
    operational_metrics_v4,
    validate_quality_dataset_v4,
)
from hermes.runtime import RunContext
from hermes.security_v4 import ApprovalBatchV4 as GovernedApprovalBatchV4

DIGEST = "sha256:" + "a" * 64


def test_v4_quality_fixture_loader_requires_explicit_observations(tmp_path: Path) -> None:
    path = tmp_path / "quality.json"
    path.write_text(
        json.dumps(
            {
                "version": "fixture-v4",
                "families": [{"family": "web", "positive": 20, "negative": 20}],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="schema"):
        load_fixture_dataset_v4(path)


def test_v4_quality_gate_evaluates_frozen_detector_independent_ground_truth() -> None:
    dataset_path = Path(__file__).parent / "fixtures" / "quality" / "v4" / "ground-truth-v2.json"
    dataset = load_quality_dataset_v4(dataset_path)
    validate_quality_dataset_v4(dataset)

    reports = evaluate_quality_dataset_v4(dataset)

    assert len(dataset.cases) == 320
    assert {item.family for item in reports} == {"web", "api", "authz", "infra", "workflow"}
    assert all(item.passed for item in reports)
    assert next(item for item in reports if item.family == "web").positives == 60
    assert all(item.estimated_cost_microusd is None for item in reports)


def test_v4_quality_gate_rejects_detector_recall_below_threshold(tmp_path: Path) -> None:
    source = Path(__file__).parent / "fixtures" / "quality" / "v4" / "ground-truth-v2.json"
    payload = json.loads(source.read_text(encoding="utf-8"))
    for case in payload["cases"][:4]:
        if case["candidate_type"] == "missing_x_content_type_options":
            case["observation"]["x_content_type_options"] = "nosniff"
    # The first four entries are positive XCTO observations.  The labels
    # remain frozen, while the independent observed signal now causes a miss.
    path = tmp_path / "quality.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    reports = evaluate_quality_dataset_v4(load_quality_dataset_v4(path))

    web = next(item for item in reports if item.family == "web")
    assert web.candidate_recall < 0.95
    assert web.passed is False


def test_v4_quality_receipt_copies_ground_truth_and_preflight_recomputes_metrics(
    tmp_path: Path,
) -> None:
    run = RunContext(
        tmp_path,
        {"hosts": ["localhost"], "ports": [8443], "profile": "local-lab-v4"},
        run_id="quality-run-v4",
    )
    identities = {alias: DIGEST for alias in ("alice", "bob", "fixture-admin")}
    now = datetime(2026, 8, 1, tzinfo=UTC)
    campaign = build_verification_campaign_v4(
        run_id=run.run_id,
        scope_digest=run.scope_digest,
        generated_by_task_id="quality-planner",
        endpoint_base="https://localhost:8443/candidate",
        identity_binding_digests=identities,
        created_at=now,
        expires_at=datetime(2026, 8, 1, 1, tzinfo=UTC),
    )
    run.write_json("verification_v4/campaign.json", campaign.model_dump(mode="json"))
    for group in ("readonly", "mutation"):
        run.write_json(f"verification_v4/results-{group}.json", {"results": []})
    source = Path(__file__).parent / "fixtures" / "quality" / "v4" / "ground-truth-v2.json"
    receipt = build_quality_receipt_v4(
        context=run,
        dataset_path=source,
        campaign=campaign,
        results=(),
    )
    plan = RunPlanV4(
        run_id=run.run_id,
        target="https://localhost:8443/candidate",
        scope_digest=run.scope_digest,
        provider_id="hermes-acp-restricted",
        model_id="test-model",
        prompt_registry_digest=DIGEST,
        role_manifest_set_digest="sha256:" + "b" * 64,
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
        created_at=now,
    )
    verifier = ReportPreflightVerifierV4(run)

    assert run.artifact_path("quality/dataset-v4.json").is_file()
    verifier._verify_quality(plan, receipt)

    bad_family = receipt.families[0].model_copy(update={"requests_used": 1})
    tampered = receipt.model_copy(update={"families": (bad_family, *receipt.families[1:])})
    with pytest.raises(ReportPreflightV4Error, match="does not match"):
        verifier._verify_quality(plan, tampered)


def test_v4_quality_metrics_attribute_privilege_verifier_attempts_to_authz(
    tmp_path: Path,
) -> None:
    run = RunContext(
        tmp_path,
        {"hosts": ["localhost"], "ports": [8443], "profile": "local-lab-v4"},
        run_id="quality-attempts-v4",
    )
    identities = {alias: DIGEST for alias in ("alice", "bob", "fixture-admin")}
    campaign = build_verification_campaign_v4(
        run_id=run.run_id,
        scope_digest=run.scope_digest,
        generated_by_task_id="quality-planner",
        endpoint_base="https://localhost:8443/candidate",
        identity_binding_digests=identities,
        created_at=datetime(2026, 8, 1, tzinfo=UTC),
        expires_at=datetime(2026, 8, 1, 1, tzinfo=UTC),
    )
    run.write_json(
        "provider/phase5-verifier-authz-privilege.json",
        {"task_id": "phase5-verifier-authz-privilege", "run_id": run.run_id, "prompt_attempts": 3},
    )

    metrics = operational_metrics_v4(run, campaign, ())

    assert metrics["authz"].model_attempts == 3


def test_v4_contracts_cover_budget_campaign_and_envelope() -> None:
    now = datetime(2026, 7, 29, tzinfo=UTC)
    plan = RunPlanV4(
        run_id="run-v4",
        target="http://localhost:8080/candidate",
        scope_digest=DIGEST,
        provider_id="hermes-acp",
        model_id="fixture-model",
        prompt_registry_digest=DIGEST,
        role_manifest_set_digest="sha256:" + "b" * 64,
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
        created_at=now,
    )
    assert plan.budget.max_requests == 32

    action = VerificationActionV4(
        action_id="verify-web",
        candidate_id="web-xcto",
        purpose="candidate",
        risk_group="readonly",
        method="GET",
        target_url="http://localhost:8080/candidate",
        action_digest=DIGEST,
        candidate_consumers=("web-xcto",),
    )
    campaign = VerificationCampaignPlanV4(
        run_id="run-v4",
        scope_digest=DIGEST,
        generated_by_task_id="planner-v4",
        campaign_id="campaign-v4",
        actions=(action,),
        request_budget=1,
        created_at=now,
        expires_at=datetime(2026, 7, 29, 1, tzinfo=UTC),
    )
    assert campaign.request_budget == 1

    gate = GateDecisionV4(
        run_id="run-v4",
        scope_digest=DIGEST,
        generated_by_task_id="gatekeeper-v4",
        decision="allowed",
        target="http://localhost:8080/candidate",
        resolved_ips=("127.0.0.1",),
        reason="localhost teaching fixture",
    )
    envelope = ContractEnvelopeV4.for_payload(gate)
    assert envelope.contract_id == "hermes.gate_decision/v4"

    approval = ApprovalBatchV4(
        run_id="run-v4",
        scope_digest=DIGEST,
        generated_by_task_id="approver-v4",
        approval_id="approval-v4",
        campaign_digest=campaign.digest,
        risk_group="readonly",
        verdict="approved",
        candidate_ids=("web-xcto",),
        action_digests=(DIGEST,),
        key_id="approver-key",
        signed_at=now,
        expires_at=datetime(2026, 7, 29, 1, tzinfo=UTC),
        rationale="approve exact readonly graph",
        signature_b64="a" * 16,
    )
    assert approval.verdict == "approved"
    assert GovernedApprovalBatchV4 is ApprovalBatchV4

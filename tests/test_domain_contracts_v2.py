from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from hermes.domain_contracts import (
    AssetInventory,
    AssetRecord,
    CandidateRecord,
    CandidateSet,
    ContractEnvelope,
    CoverageReport,
    EndpointInventory,
    EndpointRecord,
    ValidatedFinding,
    VerificationOutcome,
    VerificationPlan,
    VerificationStep,
    VerificationStepOutcome,
)
from hermes.evidence import EvidenceArtifactRef

RUN_ID = "run-v2"
TASK_ID = "task-v2"
DIGEST = "sha256:" + "a" * 64


def evidence(number: int) -> EvidenceArtifactRef:
    return EvidenceArtifactRef(
        evidence_id=f"evidence-{number}",
        manifest_path=f"evidence/evidence-{number}/manifest.json",
        manifest_sha256="sha256:" + str(number) * 64,
    )


def asset_inventory() -> AssetInventory:
    return AssetInventory(
        inventory_id="assets-1",
        run_id=RUN_ID,
        scope_digest=DIGEST,
        generated_by_task_id="recon-1",
        target="http://localhost:8080/candidate",
        assets=(
            AssetRecord(
                asset_id="asset-1",
                canonical_host="localhost",
                resolved_ips=("127.0.0.1", "::1"),
                scheme="http",
                port=8080,
                service="http",
                status_code=200,
                header_projection={"content-type": "text/html"},
            ),
        ),
        source_evidence=(evidence(1),),
    )


def endpoint_inventory(assets: AssetInventory | None = None) -> EndpointInventory:
    assets = assets or asset_inventory()
    source = assets.source_evidence
    return EndpointInventory(
        inventory_id="endpoints-1",
        run_id=RUN_ID,
        scope_digest=DIGEST,
        generated_by_task_id="mapper-1",
        asset_inventory_digest=assets.digest,
        endpoints=(
            EndpointRecord(
                endpoint_id="endpoint-candidate",
                asset_id="asset-1",
                canonical_url="http://localhost:8080/candidate",
                relation="candidate",
                evidence=source,
            ),
            EndpointRecord(
                endpoint_id="endpoint-control",
                asset_id="asset-1",
                canonical_url="http://localhost:8080/control",
                relation="negative_control",
                evidence=source,
            ),
        ),
    )


def candidate_set(endpoints: EndpointInventory | None = None) -> CandidateSet:
    endpoints = endpoints or endpoint_inventory()
    return CandidateSet(
        set_id="candidates-1",
        run_id=RUN_ID,
        scope_digest=DIGEST,
        generated_by_task_id="web-vuln-1",
        endpoint_inventory_digest=endpoints.digest,
        prompt_id="web-vuln",
        prompt_version="2.0",
        prompt_sha256=DIGEST,
        candidates=(
            CandidateRecord(
                candidate_id="missing-x-content-type-options",
                target_endpoint_id="endpoint-candidate",
                control_endpoint_id="endpoint-control",
                rationale="candidate lacks nosniff while its control has it",
                counterexamples=("header may be injected by an upstream proxy",),
                required_evidence=endpoints.endpoints[0].evidence,
            ),
        ),
    )


def verification_plan(
    candidates: CandidateSet | None = None,
    endpoints: EndpointInventory | None = None,
) -> VerificationPlan:
    endpoints = endpoints or endpoint_inventory()
    candidates = candidates or candidate_set(endpoints)
    now = datetime.now(UTC)
    return VerificationPlan(
        plan_id="verification-1",
        run_id=RUN_ID,
        scope_digest=DIGEST,
        generated_by_task_id="host-planner-1",
        candidate_set_digest=candidates.digest,
        endpoint_inventory_digest=endpoints.digest,
        candidate_id="missing-x-content-type-options",
        steps=(
            VerificationStep(
                action_id="get-candidate",
                endpoint_id="endpoint-candidate",
                purpose="candidate",
                target_url="http://localhost:8080/candidate",
                expected_assertion="X-Content-Type-Options is absent",
            ),
            VerificationStep(
                action_id="get-control",
                endpoint_id="endpoint-control",
                purpose="negative_control",
                target_url="http://localhost:8080/control",
                expected_assertion="X-Content-Type-Options equals nosniff",
            ),
        ),
        created_at=now,
        expires_at=now + timedelta(minutes=5),
    )


def test_fixed_chain_contracts_are_frozen_and_digest_stable() -> None:
    assets = asset_inventory()
    endpoints = endpoint_inventory(assets)
    candidates = candidate_set(endpoints)
    plan = verification_plan(candidates, endpoints)

    assert assets.digest == AssetInventory.model_validate_json(assets.model_dump_json()).digest
    assert len({assets.digest, endpoints.digest, candidates.digest, plan.digest}) == 4
    assert plan.steps[0].action_digest != plan.steps[1].action_digest
    with pytest.raises(ValidationError):
        AssetInventory(**assets.model_dump(), unknown=True)
    with pytest.raises(ValidationError):
        assets.inventory_id = "changed"  # type: ignore[misc]


def test_fixed_inventory_rejects_non_local_or_wrong_shape() -> None:
    assets = asset_inventory()
    with pytest.raises(ValidationError, match="localhost"):
        AssetInventory(
            **{
                **assets.model_dump(),
                "target": "http://example.com/candidate",
            }
        )
    endpoints = endpoint_inventory(assets)
    with pytest.raises(ValidationError, match="at least 2"):
        EndpointInventory(
            **{
                **endpoints.model_dump(),
                "endpoints": endpoints.endpoints[:1],
            }
        )
    with pytest.raises(ValidationError, match="candidate and one negative control"):
        EndpointInventory(
            **{
                **endpoints.model_dump(),
                "endpoints": (endpoints.endpoints[0], endpoints.endpoints[0]),
            }
        )


def test_candidate_set_rejects_duplicate_or_validated_candidate() -> None:
    candidates = candidate_set()
    with pytest.raises(ValidationError, match="at least 1"):
        CandidateSet(**{**candidates.model_dump(), "candidates": ()})
    invalid = candidates.candidates[0].model_dump()
    invalid["status"] = "validated"
    with pytest.raises(ValidationError):
        CandidateRecord(**invalid)


def test_verification_plan_requires_ordered_one_shot_get_pair() -> None:
    plan = verification_plan()
    with pytest.raises(ValidationError, match="ordered candidate/control"):
        VerificationPlan(**{**plan.model_dump(), "steps": tuple(reversed(plan.steps))})
    invalid = plan.steps[0].model_dump()
    invalid["request_budget"] = 2
    with pytest.raises(ValidationError):
        VerificationStep(**invalid)


def test_validated_outcome_requires_two_passed_steps_and_exact_evidence() -> None:
    plan = verification_plan()
    outcomes = tuple(
        VerificationStepOutcome(
            action_id=step.action_id,
            action_digest=step.action_digest,
            consumption_digest="sha256:" + str(index + 2) * 64,
            evidence=evidence(index + 2),
            status="passed",
            assertion=step.expected_assertion,
        )
        for index, step in enumerate(plan.steps)
    )
    result = VerificationOutcome(
        outcome_id="outcome-1",
        run_id=RUN_ID,
        scope_digest=DIGEST,
        generated_by_task_id="verifier-1",
        candidate_id=plan.candidate_id,
        verification_plan_digest=plan.digest,
        approval_bundle_id="approval-1",
        approval_bundle_digest="sha256:" + "b" * 64,
        step_outcomes=outcomes,
        status="validated",
        differential_assertion=True,
        assertion_summary="target lacks nosniff and control contains it",
    )
    assert len(result.evidence) == 2
    failed = outcomes[0].model_copy(update={"status": "failed"})
    with pytest.raises(ValidationError, match="passed steps"):
        VerificationOutcome(**{**result.model_dump(), "step_outcomes": (failed, outcomes[1])})


def test_coverage_report_enforces_step_and_candidate_conservation() -> None:
    report = CoverageReport(
        report_id="coverage-1",
        run_id=RUN_ID,
        scope_digest=DIGEST,
        generated_by_task_id="host-coverage-1",
        asset_inventory_digest=DIGEST,
        endpoint_inventory_digest=DIGEST,
        candidate_set_digest=DIGEST,
        verification_plan_digest=DIGEST,
        verification_outcome_digest=DIGEST,
        validated_finding_digest=DIGEST,
        assets_discovered=1,
        endpoints_discovered=2,
        candidates_discovered=1,
        steps_planned=2,
        steps_tested=2,
        steps_blocked=0,
        steps_skipped=0,
        findings_validated=1,
        candidates_inconclusive=0,
        candidates_disproved=0,
        model_calls=5,
        elapsed_ms=1,
        requests_planned=3,
        requests_used=3,
    )
    assert report.digest.startswith("sha256:")
    with pytest.raises(ValidationError, match="planned steps"):
        CoverageReport(**{**report.model_dump(), "steps_tested": 1})
    with pytest.raises(ValidationError, match="candidate counts"):
        CoverageReport(**{**report.model_dump(), "findings_validated": 0})


def test_validated_finding_requires_signed_artifact_digests_and_three_evidence() -> None:
    finding = ValidatedFinding(
        finding_id="missing-x-content-type-options",
        candidate_id="missing-x-content-type-options",
        run_id=RUN_ID,
        scope_digest=DIGEST,
        generated_by_task_id="host-promotion-1",
        candidate_set_digest=DIGEST,
        verification_plan_digest=DIGEST,
        verification_outcome_digest=DIGEST,
        approval_bundle_id="approval-1",
        approval_bundle_digest=DIGEST,
        approval_consumption_digests=(
            "sha256:" + "b" * 64,
            "sha256:" + "c" * 64,
        ),
        signed_review_id="review-1",
        signed_review_digest="sha256:" + "d" * 64,
        evidence=(evidence(1), evidence(2), evidence(3)),
        title="Missing X-Content-Type-Options",
        target="http://localhost:8080/candidate",
        summary="The teaching candidate lacks nosniff while its control supplies it.",
        reproduction_steps=("GET candidate and negative control",),
        impact="Local teaching demonstration only.",
        remediation="Return X-Content-Type-Options: nosniff.",
        severity="informational",
    )
    assert finding.local_teaching_fixture is True
    with pytest.raises(ValidationError, match="three unique"):
        ValidatedFinding(
            **{
                **finding.model_dump(),
                "evidence": (evidence(1), evidence(1), evidence(3)),
            }
        )
    with pytest.raises(ValidationError, match="candidate ID"):
        ValidatedFinding(**{**finding.model_dump(), "finding_id": "different-finding"})


def test_contract_envelope_binds_payload_type_id_and_hash() -> None:
    payload = asset_inventory()
    envelope = ContractEnvelope.for_payload(payload)
    assert envelope.contract_id == "hermes.asset_inventory/v2"
    assert envelope.payload_sha256 == payload.digest
    with pytest.raises(ValidationError, match="contract ID"):
        ContractEnvelope(
            contract_id="hermes.endpoint_inventory/v2",
            payload=payload,
            payload_sha256=payload.digest,
        )
    with pytest.raises(ValidationError, match="payload hash"):
        ContractEnvelope(
            contract_id="hermes.asset_inventory/v2",
            payload=payload,
            payload_sha256=DIGEST,
        )

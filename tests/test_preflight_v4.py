from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from hermes.domain_contracts_v3 import ApprovalBatchV3
from hermes.domain_contracts_v4 import (
    CoverageAppendixV4,
    CoverageFamilySummaryV4,
    FindingSetV4,
    FindingV4,
    QualityFamilyMetricsV4,
    QualityGateReceiptV4,
    ReporterAckV4,
    RunPlanV4,
    SignedReviewBatchV4,
)
from hermes.evidence import EvidenceBinding, EvidenceStore, HeaderField
from hermes.execution_v3 import ApprovalConsumptionV3
from hermes.preflight_v4 import (
    ReportPreflightV4Error,
    ReportPreflightVerifierV4,
    coverage_gap_digests_v4,
)
from hermes.reporting_v4 import build_report_v4, write_report_v4
from hermes.runtime import RunContext


def digest(character: str) -> str:
    return "sha256:" + character * 64


def sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def context(tmp_path: Path) -> RunContext:
    return RunContext(
        tmp_path,
        {"hosts": ["localhost"], "ports": [8443], "profile": "local-lab-v4"},
        run_id="phase5-preflight-test",
    )


def build_run(tmp_path: Path) -> RunContext:
    run = context(tmp_path)
    plan = RunPlanV4(
        run_id=run.run_id,
        target="http://localhost:8443/candidate",
        scope_digest=run.scope_digest,
        provider_id="hermes-acp-restricted",
        model_id="test-model",
        prompt_registry_digest=digest("1"),
        role_manifest_set_digest=digest("2"),
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
        identity_binding_digests={"alice": digest("3")},
        created_at=datetime.now(UTC),
    )
    run.write_json("plan/run-v4.json", plan.model_dump(mode="json"), immutable=True)

    quality = QualityGateReceiptV4(
        run_id=run.run_id,
        scope_digest=run.scope_digest,
        generated_by_task_id="phase5-quality",
        receipt_id="quality-v4",
        families=(
            QualityFamilyMetricsV4(
                family="web",
                dataset_version="v4-fixture",
                dataset_digest=digest("4"),
                positives=20,
                negatives=20,
                candidate_recall=1.0,
                verified_precision=1.0,
                requests_used=2,
                elapsed_ms=10,
                estimated_cost_microusd=1000,
                passed=True,
            ),
        ),
        overall_passed=True,
        recorded_at=datetime.now(UTC),
    )
    run.write_json("quality/receipt-v4.json", quality.model_dump(mode="json"), immutable=True)

    draft = "# Hermes V4 draft\n"
    run.write_text("report/draft-v4.md", draft, immutable=True)
    action_id = "action-web"
    action_digest = digest("6")
    task_id = "phase5-verifier-web"
    task_input_sha256 = digest("5")
    request_id = "phase5-verifier-web:gateway:0"
    evidence_id = "evidence-v4"

    approval = ApprovalBatchV3(
        run_id=run.run_id,
        scope_digest=run.scope_digest,
        generated_by_task_id="phase5-approval",
        approval_id="approval-web",
        campaign_digest=digest("c"),
        risk_group="readonly",
        verdict="approved",
        candidate_ids=("web-xcto",),
        action_digests=(action_digest,),
        key_id="approver-v4",
        signed_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=10),
        rationale="approve bounded read-only verification",
        signature_b64="signed-approval-ok",
    )
    consumption = ApprovalConsumptionV3(
        consumption_id="consumption-v4",
        run_id=run.run_id,
        scope_digest=run.scope_digest,
        campaign_id="campaign-v4",
        campaign_digest=approval.campaign_digest,
        approval_id=approval.approval_id,
        approval_batch_digest=approval.digest,
        candidate_id="web-xcto",
        action_id=action_id,
        action_digest=action_digest,
        task_id=task_id,
        task_input_sha256=task_input_sha256,
        request_id=request_id,
        evidence_id=evidence_id,
        consumed_at=datetime.now(UTC),
    )
    binding = EvidenceBinding(
        evidence_id=evidence_id,
        run_id=run.run_id,
        scope_digest=run.scope_digest,
        task_id=task_id,
        task_input_sha256=task_input_sha256,
        role="verifier",
        request_id=request_id,
        action_id=action_id,
        action_digest=action_digest,
        plan_digest=digest("7"),
        approval_bundle_id=approval.approval_id,
        approval_bundle_digest=approval.digest,
        approval_consumption_digest=consumption.digest,
        captured_at=datetime.now(UTC),
    )
    store = EvidenceStore(run.path)
    evidence = store.capture(
        binding=binding,
        request_method="GET",
        request_url="http://localhost:8443/candidate",
        request_headers=(HeaderField(name="Accept", value="text/html"),),
        request_body=b"",
        response_status=200,
        response_headers=(HeaderField(name="Content-Type", value="text/html"),),
        response_body=b"<html>candidate</html>",
    )
    run.write_json("approvals_v4/readonly.json", approval.model_dump(mode="json"), immutable=True)
    run.write_json(
        "governance_v4/consumptions/readonly.json",
        consumption.model_dump(mode="json"),
        immutable=True,
    )

    finding = FindingV4(
        finding_id="web-xcto",
        candidate_id="web-xcto",
        candidate_type="missing_x_content_type_options",
        family="web",
        title="Missing X-Content-Type-Options",
        summary="The target omits XCTO while the negative control sets nosniff.",
        reproduction_steps=("GET /candidate", "GET /control and compare headers"),
        prerequisites=("Loopback local fixture",),
        impact="Browsers may MIME-sniff responses in unsafe ways.",
        remediation="Set `X-Content-Type-Options: nosniff` on the target response.",
        severity="low",
        severity_rationale="This is a low-risk teaching fixture posture issue.",
        vrt_category="Server Security Misconfiguration",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        verification_outcome_digest=digest("a"),
        approval_batch_digests=(approval.digest,),
        approval_consumption_digests=(consumption.digest,),
        evidence=(evidence,),
        review_digest=digest("b"),
    )
    findings = FindingSetV4(
        run_id=run.run_id,
        scope_digest=run.scope_digest,
        generated_by_task_id="phase5-promotion",
        finding_set_id="finding-set-v4",
        quality_gate_digest=quality.digest,
        findings=(finding,),
    )
    coverage = CoverageAppendixV4(
        run_id=run.run_id,
        scope_digest=run.scope_digest,
        generated_by_task_id="phase5-coverage",
        appendix_id="coverage-v4",
        quality_gate_digest=quality.digest,
        finding_set_digest=findings.digest,
        families=(
            CoverageFamilySummaryV4(
                family="web",
                routed=1,
                tested=1,
                validated=1,
                requests_used=2,
                elapsed_ms=10,
                estimated_cost_microusd=1000,
            ),
        ),
        requests_planned=2,
        requests_used=2,
        model_attempts_reserved=3,
        model_attempts_used=2,
        estimated_cost_microusd=1000,
        active_elapsed_ms=50,
        completion="completed",
    )
    review = SignedReviewBatchV4(
        run_id=run.run_id,
        scope_digest=run.scope_digest,
        generated_by_task_id="phase5-human-review",
        review_id="review-v4",
        finding_set_digest=findings.digest,
        coverage_appendix_digest=coverage.digest,
        report_draft_digest=sha256_bytes(draft.encode("utf-8")),
        verdict="accepted",
        reviewer_key_id="reviewer-v4",
        reviewed_at=datetime.now(UTC),
        rationale="the validated finding and coverage are bounded and sufficient",
        signature_b64="signed-review-value",
    )

    run.write_json("report/finding-set-v4.json", findings.model_dump(mode="json"), immutable=True)
    run.write_json("report/coverage-v4.json", coverage.model_dump(mode="json"), immutable=True)
    run.write_json("reviews/signed-v4.json", review.model_dump(mode="json"), immutable=True)

    provider = {"run_id": run.run_id, "task_id": "phase5-reporter", "provider": "synthetic"}
    run.write_json("provider/phase5-reporter.json", provider, immutable=True)

    return run


def authorize_ack(run: RunContext) -> tuple[ReportPreflightVerifierV4, ReporterAckV4]:
    quality = QualityGateReceiptV4.model_validate_json(
        run.artifact_path("quality/receipt-v4.json").read_bytes()
    )
    findings = FindingSetV4.model_validate_json(
        run.artifact_path("report/finding-set-v4.json").read_bytes()
    )
    coverage = CoverageAppendixV4.model_validate_json(
        run.artifact_path("report/coverage-v4.json").read_bytes()
    )
    verifier = ReportPreflightVerifierV4(
        run,
        approval_signature_verifier=lambda batch: None,
        review_signature_verifier=lambda review, finding_set, appendix: None,
    )
    launch = verifier.authorize_reporter()
    ack = ReporterAckV4(
        run_id=run.run_id,
        scope_digest=run.scope_digest,
        generated_by_task_id="phase5-reporter",
        launch_receipt_digest=launch.digest,
        quality_gate_digest=quality.digest,
        finding_set_digest=findings.digest,
        coverage_appendix_digest=coverage.digest,
        provider_metadata_digest=sha256_bytes(
            run.artifact_path("provider/phase5-reporter.json").read_bytes()
        ),
    )
    run.write_json("report/reporter-ack-v4.json", ack.model_dump(mode="json"), immutable=True)
    return verifier, ack


def test_authorize_and_write_v4_report(tmp_path: Path) -> None:
    run = build_run(tmp_path)
    verifier, ack = authorize_ack(run)

    report = write_report_v4(run, verifier, ack)

    assert report == run.artifact_path("report/report-v4.md")
    rendered = report.read_text(encoding="utf-8")
    assert "Missing X-Content-Type-Options" in rendered
    assert "### Reproduction" in rendered
    assert "### Impact" in rendered
    assert "## Coverage appendix" in rendered
    assert run.artifact_path("report/findings-v4.json").is_file()
    assert run.artifact_path("report/report-write-receipt-v4.json").is_file()


def test_missing_signed_approval_blocks_reporter_and_report(tmp_path: Path) -> None:
    run = build_run(tmp_path)
    run.artifact_path("approvals_v4/readonly.json").unlink()
    verifier = ReportPreflightVerifierV4(
        run,
        approval_signature_verifier=lambda batch: None,
        review_signature_verifier=lambda review, finding_set, appendix: None,
    )

    with pytest.raises(ReportPreflightV4Error, match="missing approved batch"):
        verifier.authorize_reporter()

    assert not run.artifact_path("report/reporter-launch-v4.json").exists()
    assert not run.artifact_path("report/report-v4.md").exists()


def test_missing_signature_verifiers_fail_closed_before_reporter_launch(tmp_path: Path) -> None:
    run = build_run(tmp_path)

    with pytest.raises(ReportPreflightV4Error, match="approval signature verifier is required"):
        ReportPreflightVerifierV4(run).authorize_reporter()

    assert not run.artifact_path("report/reporter-launch-v4.json").exists()
    assert not run.artifact_path("report/report-v4.md").exists()


def test_tampered_evidence_reference_blocks_reporter_and_report(tmp_path: Path) -> None:
    run = build_run(tmp_path)
    findings = FindingSetV4.model_validate_json(
        run.artifact_path("report/finding-set-v4.json").read_bytes()
    )
    manifest_path = run.artifact_path(findings.findings[0].evidence[0].manifest_path)
    manifest_path.write_text("{}", encoding="utf-8")
    verifier = ReportPreflightVerifierV4(
        run,
        approval_signature_verifier=lambda batch: None,
        review_signature_verifier=lambda review, finding_set, appendix: None,
    )

    with pytest.raises(ReportPreflightV4Error, match="evidence manifest"):
        verifier.authorize_reporter()

    assert not run.artifact_path("report/reporter-launch-v4.json").exists()
    assert not run.artifact_path("report/report-v4.md").exists()


def test_review_gap_mismatch_blocks_reporter_and_report(tmp_path: Path) -> None:
    run = build_run(tmp_path)
    coverage = CoverageAppendixV4.model_validate_json(
        run.artifact_path("report/coverage-v4.json").read_bytes()
    )
    run.artifact_path("report/coverage-v4.json").unlink()
    run.write_json(
        "report/coverage-v4.json",
        coverage.model_copy(
            update={"completion": "completed_with_gaps", "gaps": ("branch:api:failed",)}
        ).model_dump(mode="json"),
        immutable=True,
    )
    review = SignedReviewBatchV4.model_validate_json(
        run.artifact_path("reviews/signed-v4.json").read_bytes()
    )
    run.artifact_path("reviews/signed-v4.json").unlink()
    run.write_json(
        "reviews/signed-v4.json",
        review.model_copy(
            update={
                "coverage_appendix_digest": CoverageAppendixV4.model_validate_json(
                    run.artifact_path("report/coverage-v4.json").read_bytes()
                ).digest
            }
        ).model_dump(mode="json"),
        immutable=True,
    )
    verifier = ReportPreflightVerifierV4(
        run,
        approval_signature_verifier=lambda batch: None,
        review_signature_verifier=lambda review, finding_set, appendix: None,
    )

    with pytest.raises(ReportPreflightV4Error, match="coverage gaps|human verdict"):
        verifier.authorize_reporter()

    assert not run.artifact_path("report/reporter-launch-v4.json").exists()
    assert not run.artifact_path("report/report-v4.md").exists()


def test_report_builder_renders_quality_and_coverage_sections(tmp_path: Path) -> None:
    run = build_run(tmp_path)
    quality = QualityGateReceiptV4.model_validate_json(
        run.artifact_path("quality/receipt-v4.json").read_bytes()
    )
    findings = FindingSetV4.model_validate_json(
        run.artifact_path("report/finding-set-v4.json").read_bytes()
    )
    coverage = CoverageAppendixV4.model_validate_json(
        run.artifact_path("report/coverage-v4.json").read_bytes()
    )

    rendered = build_report_v4(quality, findings, coverage)

    assert "## Quality gate" in rendered
    assert "## Coverage appendix" in rendered
    assert "Server Security Misconfiguration" in rendered
    assert coverage_gap_digests_v4(coverage) == ()

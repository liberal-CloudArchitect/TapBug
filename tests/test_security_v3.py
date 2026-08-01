from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hermes.domain_contracts_v3 import (
    ApprovalBatchV3,
    CoverageReportV3,
    FindingSet,
    SignedReviewBatchV3,
    VerificationActionV3,
    VerificationCampaignPlan,
)
from hermes.security import (
    KeyUsage,
    SecurityContractError,
    TrustedKey,
    TrustStoreV2,
    encode_base64,
    generate_ed25519_private_key,
    public_key_bytes,
)
from hermes.security_v3 import (
    coverage_gap_digests,
    load_identity_vault_v3,
    sign_approval_batch_v3,
    sign_review_batch_v3,
    verify_approval_batch_v3,
    verify_review_batch_v3,
)

NOW = datetime(2026, 7, 14, 12, tzinfo=UTC)
SCOPE = "sha256:" + "a" * 64


def digest(character: str) -> str:
    return "sha256:" + character * 64


def run_fields(task_id: str) -> dict[str, str]:
    return {
        "run_id": "run-v3",
        "scope_digest": SCOPE,
        "generated_by_task_id": task_id,
    }


def trust(private: Ed25519PrivateKey, key_id: str, *usages: KeyUsage) -> TrustStoreV2:
    return TrustStoreV2(
        keys=(
            TrustedKey(
                key_id=key_id,
                public_key=encode_base64(public_key_bytes(private)),
                usages=frozenset(usages),
                valid_from=NOW - timedelta(days=1),
                valid_until=NOW + timedelta(days=1),
            ),
        )
    )


def action(
    action_id: str,
    candidate_id: str,
    action_digest: str,
    *,
    purpose: str,
) -> VerificationActionV3:
    return VerificationActionV3(
        action_id=action_id,
        candidate_id=candidate_id,
        candidate_consumers=(candidate_id,),
        purpose=purpose,
        risk_group="readonly",
        action_kind="validation_http_get",
        method="GET",
        target_url=f"http://localhost:8080/{action_id}",
        action_digest=action_digest,
    )


def campaign() -> VerificationCampaignPlan:
    actions = (
        action("web-candidate", "web-xcto", digest("1"), purpose="candidate"),
        action("web-control", "web-xcto", digest("2"), purpose="negative_control"),
        action("infra-candidate", "infra-debug", digest("3"), purpose="candidate"),
        action("infra-control", "infra-debug", digest("4"), purpose="negative_control"),
    )
    return VerificationCampaignPlan(
        **run_fields("planner-v3"),
        campaign_id="campaign-v3",
        candidate_collection_digest=digest("5"),
        cross_review_set_digest=digest("6"),
        actions=actions,
        request_budget=4,
        created_at=NOW,
        expires_at=NOW + timedelta(minutes=15),
    )


def unsigned_approval(plan: VerificationCampaignPlan) -> ApprovalBatchV3:
    return ApprovalBatchV3(
        **run_fields("approver-v3"),
        approval_id="approval-readonly",
        campaign_digest=plan.digest,
        risk_group="readonly",
        verdict="approved",
        candidate_ids=("web-xcto",),
        action_digests=(digest("1"), digest("2")),
        key_id="approver-key",
        signed_at=NOW + timedelta(seconds=1),
        expires_at=NOW + timedelta(minutes=10),
        rationale="Approve the complete bounded Web candidate graph.",
        signature_b64="unsigned-signature",
    )


def test_signed_approval_binds_exact_candidate_graph_and_ttl() -> None:
    plan = campaign()
    private = generate_ed25519_private_key()
    store = trust(private, "approver-key", KeyUsage.APPROVAL)
    signed = sign_approval_batch_v3(unsigned_approval(plan), private)

    verify_approval_batch_v3(signed, plan, store, at=NOW + timedelta(minutes=2))

    missing_action = signed.model_copy(update={"action_digests": (digest("1"),)})
    with pytest.raises(SecurityContractError, match="every action"):
        verify_approval_batch_v3(missing_action, plan, store, at=NOW + timedelta(minutes=2))

    foreign_candidate = signed.model_copy(update={"candidate_ids": ("unknown",)})
    with pytest.raises(SecurityContractError, match="outside its risk group"):
        verify_approval_batch_v3(foreign_candidate, plan, store, at=NOW + timedelta(minutes=2))

    expired = signed.model_copy(update={"expires_at": plan.expires_at + timedelta(seconds=1)})
    with pytest.raises(SecurityContractError, match="outlive"):
        verify_approval_batch_v3(expired, plan, store, at=NOW + timedelta(minutes=2))


def test_approval_rejects_tampering_and_dual_usage_key() -> None:
    plan = campaign()
    private = generate_ed25519_private_key()
    signed = sign_approval_batch_v3(unsigned_approval(plan), private)
    approval_store = trust(private, "approver-key", KeyUsage.APPROVAL)

    tampered = signed.model_copy(update={"rationale": "Tampered after signing."})
    with pytest.raises(SecurityContractError, match="signature"):
        verify_approval_batch_v3(tampered, plan, approval_store, at=NOW + timedelta(minutes=1))

    dual_store = trust(
        private,
        "approver-key",
        KeyUsage.APPROVAL,
        KeyUsage.HUMAN_REVIEW,
    )
    with pytest.raises(SecurityContractError, match="cannot be shared"):
        verify_approval_batch_v3(signed, plan, dual_store, at=NOW + timedelta(minutes=1))


def coverage(*, with_gaps: bool) -> CoverageReportV3:
    gaps = ("api assessment timed out",) if with_gaps else ()
    return CoverageReportV3(
        **run_fields("coverage-v3"),
        report_id="coverage-v3",
        route_decision_digest=digest("1"),
        candidate_collection_digest=digest("2"),
        cross_review_set_digest=digest("3"),
        campaign_digest=digest("4"),
        outcome_set_digest=digest("5"),
        finding_set_digest=digest("6"),
        branches_routed=4,
        branches_succeeded=3 if with_gaps else 4,
        branches_failed=1 if with_gaps else 0,
        branches_timed_out=0,
        raw_candidates=1,
        canonical_candidates=1,
        duplicate_candidates=0,
        raw_blocked_or_inconclusive=0,
        candidates_validated=1,
        candidates_disproved=0,
        candidates_inconclusive=0,
        candidates_blocked=0,
        actions_planned=2,
        actions_executed=2,
        actions_blocked=0,
        actions_skipped=0,
        requests_planned=3,
        requests_used=3,
        model_attempts_reserved=16,
        model_attempts_used=16,
        estimated_cost_microusd=4_000_000,
        active_elapsed_ms=100,
        completion="completed_with_gaps" if with_gaps else "completed",
        gaps=gaps,
    )


def finding_set() -> FindingSet:
    return FindingSet(
        **run_fields("promotion-v3"),
        finding_set_id="findings-v3",
        candidate_collection_digest=digest("2"),
        cross_review_set_digest=digest("3"),
        verification_outcome_set_digest=digest("5"),
        findings=(),
    )


def unsigned_review(
    findings: FindingSet,
    report_coverage: CoverageReportV3,
    *,
    reviewer_key_id: str = "reviewer-key",
) -> SignedReviewBatchV3:
    return SignedReviewBatchV3(
        **run_fields("human-review-v3"),
        review_id="review-v3",
        finding_set_digest=findings.digest,
        coverage_report_digest=report_coverage.digest,
        report_draft_digest=digest("d"),
        gap_digests=coverage_gap_digests(report_coverage),
        verdict="accepted_with_gaps" if report_coverage.gaps else "accepted",
        reviewer_key_id=reviewer_key_id,
        reviewed_at=NOW + timedelta(minutes=3),
        rationale="Reviewed evidence, coverage, and exact gaps.",
        signature_b64="unsigned-signature",
    )


def test_signed_review_binds_exact_gaps_and_uses_independent_key() -> None:
    findings = finding_set()
    report_coverage = coverage(with_gaps=True)
    reviewer_private = generate_ed25519_private_key()
    reviewer_store = trust(reviewer_private, "reviewer-key", KeyUsage.HUMAN_REVIEW)
    approver_private = generate_ed25519_private_key()
    approver_store = trust(approver_private, "approver-key", KeyUsage.APPROVAL)
    approval = sign_approval_batch_v3(unsigned_approval(campaign()), approver_private)
    review = sign_review_batch_v3(unsigned_review(findings, report_coverage), reviewer_private)

    verify_review_batch_v3(
        review,
        findings,
        report_coverage,
        reviewer_store,
        report_draft_digest=digest("d"),
        approval_batches=(approval,),
        approval_trust_store=approver_store,
    )

    wrong_gaps = review.model_copy(update={"gap_digests": (digest("f"),)})
    with pytest.raises(SecurityContractError, match="exact coverage gaps"):
        verify_review_batch_v3(
            wrong_gaps,
            findings,
            report_coverage,
            reviewer_store,
            report_draft_digest=digest("d"),
        )


def test_review_rejects_same_key_material_even_under_different_ids() -> None:
    findings = finding_set()
    report_coverage = coverage(with_gaps=False)
    shared_private = generate_ed25519_private_key()
    reviewer_store = trust(shared_private, "reviewer-key", KeyUsage.HUMAN_REVIEW)
    approval_store = trust(shared_private, "approver-key", KeyUsage.APPROVAL)
    approval = sign_approval_batch_v3(unsigned_approval(campaign()), shared_private)
    review = sign_review_batch_v3(unsigned_review(findings, report_coverage), shared_private)

    with pytest.raises(SecurityContractError, match="key material must be distinct"):
        verify_review_batch_v3(
            review,
            findings,
            report_coverage,
            reviewer_store,
            report_draft_digest=digest("d"),
            approval_batches=(approval,),
            approval_trust_store=approval_store,
        )


def write_vault(path: Path, identities: dict[str, str]) -> None:
    path.write_text(
        json.dumps({"version": "1", "identities": identities}),
        encoding="utf-8",
    )
    path.chmod(0o600)


def test_identity_vault_is_external_protected_and_secret_safe(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    runs = tmp_path / "runs"
    repo.mkdir()
    runs.mkdir()
    vault_path = tmp_path / "identities.json"
    write_vault(vault_path, {"member": "member-secret", "fixture-admin": "admin-secret"})

    vault = load_identity_vault_v3(vault_path, repo_root=repo, runs_root=runs)

    assert vault.aliases == ("fixture-admin", "member")
    assert vault.credential("member").secret == "member-secret"
    assert vault.binding_digests["member"].startswith("sha256:")
    assert "member-secret" not in repr(vault)
    assert "member-secret" not in repr(vault.credential("member"))
    with pytest.raises(SecurityContractError, match="not available"):
        vault.credential("unknown")


def test_identity_vault_rejects_path_permission_symlink_and_schema(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    runs = tmp_path / "runs"
    repo.mkdir()
    runs.mkdir()

    relative = Path("identities.json")
    with pytest.raises(SecurityContractError, match="absolute"):
        load_identity_vault_v3(relative, repo_root=repo, runs_root=runs)

    inside = repo / "identities.json"
    write_vault(inside, {"member": "secret"})
    with pytest.raises(SecurityContractError, match="outside the repository"):
        load_identity_vault_v3(inside, repo_root=repo, runs_root=runs)

    weak = tmp_path / "weak.json"
    write_vault(weak, {"member": "secret"})
    weak.chmod(0o644)
    with pytest.raises(SecurityContractError, match="0600"):
        load_identity_vault_v3(weak, repo_root=repo, runs_root=runs)

    target = tmp_path / "target.json"
    write_vault(target, {"member": "secret"})
    link = tmp_path / "link.json"
    link.symlink_to(target)
    with pytest.raises(SecurityContractError, match="symlink"):
        load_identity_vault_v3(link, repo_root=repo, runs_root=runs)

    invalid = tmp_path / "invalid.json"
    invalid.write_text('{"version":"1","identities":{"member":"a","member":"b"}}')
    os.chmod(invalid, 0o600)
    with pytest.raises(SecurityContractError, match="duplicate"):
        load_identity_vault_v3(invalid, repo_root=repo, runs_root=runs)

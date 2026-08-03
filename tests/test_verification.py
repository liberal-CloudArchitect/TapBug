"""N4 contract tests: minimal approved negative-controlled verification (docs/19 N4).

Fully offline. Observations are recorded (no network); the module plans, gates,
and judges. Exercises the positive/negative-control verdict and every fail-closed
guard (approval, scope, destructive-method, review-before-finding).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hermes.candidate_source import AssetCandidateV1
from hermes.evidence import EvidenceArtifactRef
from hermes.scope_profile import (
    BugcrowdProgramSpecV1,
    BugcrowdTargetV1,
    ingest_bugcrowd_program,
)
from hermes.security import (
    KeyUsage,
    TrustedKey,
    TrustStoreV2,
    encode_base64,
    generate_ed25519_private_key,
    public_key_bytes,
)
from hermes.verification import (
    ProbeObservationV1,
    VerificationError,
    VerificationSignalV1,
    build_verification_plan,
    decide_verification,
    promote_to_finding,
    require_execution_authorized,
    sign_review,
    sign_verification_plan,
)

NOW = datetime(2026, 8, 3, 12, 0, tzinfo=UTC)
DIGEST = "sha256:" + "a" * 64


def _trust(private: Ed25519PrivateKey, key_id: str, *usages: KeyUsage) -> TrustStoreV2:
    return TrustStoreV2(
        keys=(
            TrustedKey(
                key_id=key_id,
                public_key=encode_base64(public_key_bytes(private)),
                usages=frozenset(usages),
                valid_from=NOW - timedelta(days=1),
                valid_until=NOW + timedelta(days=7),
            ),
        )
    )


def _scope():
    spec = BugcrowdProgramSpecV1(
        program_handle="acme-bbp",
        retrieved_at=NOW,
        automated_testing_allowed=True,
        rate_limit_rps=2.0,
        targets=(BugcrowdTargetV1(identifier="*.acme.example", category="website"),),
    )
    return ingest_bugcrowd_program(spec)


def _candidate(url: str = "https://app.acme.example/x", method: str = "GET") -> AssetCandidateV1:
    return AssetCandidateV1(
        candidate_id="cand-abc123",
        source="nuclei",
        endpoint_id="ep-abc123",
        asset_id="asset-app.acme.example",
        target_url=url,
        method=method,  # type: ignore[arg-type]
        candidate_type="http-missing-xcto",
        title="Missing X-Content-Type-Options",
        claimed_severity="low",
        expected_assertion="header absent on candidate, present on control",
        negative_control_hint="a hardened path",
        evidence=(EvidenceArtifactRef(
            evidence_id="ev1", manifest_path="evidence/ev1/manifest.json", manifest_sha256=DIGEST
        ),),
        rationale="nuclei hit",
    )


def _obs(*, status: int = 200, headers=()) -> ProbeObservationV1:
    return ProbeObservationV1(
        status_code=status,
        headers=tuple(headers),
        evidence=(EvidenceArtifactRef(
            evidence_id="obs", manifest_path="evidence/obs/manifest.json", manifest_sha256=DIGEST
        ),),
    )


def _plan(scope=None):
    return build_verification_plan(
        _candidate(),
        program_handle="acme-bbp",
        signal=VerificationSignalV1(kind="header_absent", argument="X-Content-Type-Options"),
        negative_control_url="https://app.acme.example/control",
        scope_draft=scope or _scope(),
        now=NOW,
    )


# --------------------------------------------------------------------------- #
# Planning + safety
# --------------------------------------------------------------------------- #


def test_plan_is_scope_bound_and_readonly_by_default() -> None:
    plan = _plan()
    assert plan.risk_group == "readonly"
    assert plan.candidate_probe.method == "GET"
    assert plan.scope_profile_digest == _scope().digest()


def test_plan_rejects_out_of_scope_control() -> None:
    with pytest.raises(VerificationError):
        build_verification_plan(
            _candidate(),
            program_handle="acme-bbp",
            signal=VerificationSignalV1(kind="header_absent", argument="X"),
            negative_control_url="https://evil.example/control",
            scope_draft=_scope(),
            now=NOW,
        )


def test_mutation_requires_compensation_plan() -> None:
    with pytest.raises(VerificationError):
        build_verification_plan(
            _candidate(method="POST"),
            program_handle="acme-bbp",
            signal=VerificationSignalV1(kind="status_equals", argument="200"),
            negative_control_url="https://app.acme.example/control",
            scope_draft=_scope(),
            now=NOW,
        )
    ok = build_verification_plan(
        _candidate(method="POST"),
        program_handle="acme-bbp",
        signal=VerificationSignalV1(kind="status_equals", argument="200"),
        negative_control_url="https://app.acme.example/control",
        scope_draft=_scope(),
        now=NOW,
        compensation_plan="revert the created object via admin cleanup",
    )
    assert ok.risk_group == "mutation"


# --------------------------------------------------------------------------- #
# Approval gate
# --------------------------------------------------------------------------- #


def test_execution_requires_matching_trusted_approval() -> None:
    plan = _plan()
    private = generate_ed25519_private_key()
    store = _trust(private, "approver", KeyUsage.APPROVAL)
    approval = sign_verification_plan(plan, private, key_id="approver", signed_at=NOW)
    require_execution_authorized(plan, approval, store, _scope(), now=NOW)  # no raise

    # a review-only key cannot approve execution
    store2 = _trust(private, "approver", KeyUsage.HUMAN_REVIEW)
    with pytest.raises(VerificationError):
        require_execution_authorized(plan, approval, store2, _scope(), now=NOW)


def test_expired_approval_is_refused() -> None:
    plan = _plan()
    private = generate_ed25519_private_key()
    store = _trust(private, "approver", KeyUsage.APPROVAL)
    approval = sign_verification_plan(
        plan, private, key_id="approver", signed_at=NOW, ttl=timedelta(hours=1)
    )
    with pytest.raises(VerificationError):
        require_execution_authorized(plan, approval, store, _scope(), now=NOW + timedelta(hours=2))


# --------------------------------------------------------------------------- #
# Positive/negative-control verdict
# --------------------------------------------------------------------------- #


def test_validated_when_candidate_exhibits_and_control_clean() -> None:
    plan = _plan()  # header_absent X-Content-Type-Options
    candidate_obs = _obs(headers=())  # header absent -> exhibits
    control_obs = _obs(headers=(("X-Content-Type-Options", "nosniff"),))  # present -> clean
    outcome = decide_verification(plan, candidate_obs, control_obs, now=NOW)
    assert outcome.verdict == "validated"
    assert outcome.candidate_exhibits and not outcome.control_exhibits


def test_disproved_when_candidate_does_not_exhibit() -> None:
    plan = _plan()
    candidate_obs = _obs(headers=(("X-Content-Type-Options", "nosniff"),))  # present -> not exhibit
    control_obs = _obs(headers=())
    outcome = decide_verification(plan, candidate_obs, control_obs, now=NOW)
    assert outcome.verdict == "disproved"


def test_inconclusive_when_control_also_exhibits() -> None:
    plan = _plan()
    candidate_obs = _obs(headers=())  # absent -> exhibits
    control_obs = _obs(headers=())  # also absent -> not clean
    outcome = decide_verification(plan, candidate_obs, control_obs, now=NOW)
    assert outcome.verdict == "inconclusive"


# --------------------------------------------------------------------------- #
# Promotion to finding (only validated + reviewed)
# --------------------------------------------------------------------------- #


def test_promote_requires_validated_and_review() -> None:
    plan = _plan()
    candidate = _candidate()
    validated = decide_verification(
        plan, _obs(headers=()), _obs(headers=(("X-Content-Type-Options", "nosniff"),)), now=NOW
    )
    reviewer = generate_ed25519_private_key()
    store = _trust(reviewer, "reviewer", KeyUsage.HUMAN_REVIEW)
    sig = sign_review(validated, reviewer)
    finding = promote_to_finding(
        validated,
        plan,
        candidate,
        review_signature_b64=sig,
        reviewer_key_id="reviewer",
        reviewed_at=NOW,
        trust_store=store,
        now=NOW,
    )
    assert finding.candidate_type == "http-missing-xcto"
    assert finding.outcome_digest == validated.digest()

    # a disproved outcome can never become a finding
    disproved = decide_verification(
        plan, _obs(headers=(("X-Content-Type-Options", "nosniff"),)), _obs(headers=()), now=NOW
    )
    with pytest.raises(VerificationError):
        promote_to_finding(
            disproved,
            plan,
            candidate,
            review_signature_b64=sign_review(disproved, reviewer),
            reviewer_key_id="reviewer",
            reviewed_at=NOW,
            trust_store=store,
            now=NOW,
        )


def test_promote_rejects_untrusted_review_key() -> None:
    plan = _plan()
    candidate = _candidate()
    validated = decide_verification(
        plan, _obs(headers=()), _obs(headers=(("X-Content-Type-Options", "nosniff"),)), now=NOW
    )
    reviewer = generate_ed25519_private_key()
    other = generate_ed25519_private_key()
    store = _trust(other, "reviewer", KeyUsage.HUMAN_REVIEW)  # trusts a different key
    with pytest.raises(VerificationError):
        promote_to_finding(
            validated,
            plan,
            candidate,
            review_signature_b64=sign_review(validated, reviewer),
            reviewer_key_id="reviewer",
            reviewed_at=NOW,
            trust_store=store,
            now=NOW,
        )

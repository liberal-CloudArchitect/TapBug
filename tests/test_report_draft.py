"""N7 contract tests: ValidatedFinding -> Bugcrowd VRT/CVSS report draft (docs/19 N7).

Offline. Uses a small in-test VRT priority table (the real taxonomy loader is
exercised separately when the cloned repo is present).
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from hermes.candidate_source import AssetCandidateV1
from hermes.evidence import EvidenceArtifactRef
from hermes.report_draft import (
    ReportDraftError,
    ReportNarrativeV1,
    build_report_draft,
    cvss_severity,
    cvss_v31_base_score,
    parse_cvss_vector,
    priority_label,
    render_markdown,
    require_human_submission,
)
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
    ValidatedFindingV1,
    VerificationOutcomeV1,
    VerificationPlanV1,
    VerificationSignalV1,
    build_verification_plan,
    decide_verification,
    promote_to_finding,
    sign_review,
)

NOW = datetime(2026, 8, 3, 12, 0, tzinfo=UTC)
DIGEST = "sha256:" + "a" * 64
VRT = {"full_path_disclosure": 5, "cross_site_scripting_xss": 3}
CVSS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"  # 5.3 medium


# --------------------------------------------------------------------------- #
# CVSS + VRT primitives
# --------------------------------------------------------------------------- #


def test_cvss_reference_vectors() -> None:
    critical = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert cvss_v31_base_score(parse_cvss_vector(critical)) == 9.8
    assert cvss_v31_base_score(parse_cvss_vector(CVSS)) == 5.3
    assert cvss_severity(9.8) == "critical"
    assert cvss_severity(5.3) == "medium"
    assert cvss_severity(0.0) == "none"


def test_parse_rejects_non_cvss31() -> None:
    with pytest.raises(ReportDraftError):
        parse_cvss_vector("CVSS:2.0/AV:N")


def test_priority_label() -> None:
    assert priority_label(1) == "P1"
    assert priority_label(5) == "P5"
    with pytest.raises(ReportDraftError):
        priority_label(6)


# --------------------------------------------------------------------------- #
# Full N4 -> N7 assembly
# --------------------------------------------------------------------------- #


def _validated() -> tuple[ValidatedFindingV1, VerificationPlanV1, VerificationOutcomeV1]:
    spec = BugcrowdProgramSpecV1(
        program_handle="acme-bbp",
        retrieved_at=NOW,
        automated_testing_allowed=True,
        rate_limit_rps=2.0,
        targets=(BugcrowdTargetV1(identifier="*.acme.example", category="website"),),
    )
    draft = ingest_bugcrowd_program(spec)
    candidate = AssetCandidateV1(
        candidate_id="cand-xyz",
        source="nuclei",
        endpoint_id="ep-xyz",
        asset_id="asset-app.acme.example",
        target_url="https://app.acme.example/x",
        method="GET",
        candidate_type="full-path-disclosure",
        title="Full path disclosure",
        claimed_severity="low",
        expected_assertion="absent on candidate, present on control",
        negative_control_hint="hardened path",
        evidence=(EvidenceArtifactRef(
            evidence_id="e", manifest_path="evidence/e/manifest.json", manifest_sha256=DIGEST
        ),),
        rationale="nuclei",
    )
    plan = build_verification_plan(
        candidate,
        program_handle="acme-bbp",
        signal=VerificationSignalV1(kind="header_absent", argument="X-Frame-Options"),
        negative_control_url="https://app.acme.example/control",
        scope_draft=draft,
        now=NOW,
    )
    obs_c = ProbeObservation(status=200, headers=())
    obs_k = ProbeObservation(status=200, headers=(("X-Frame-Options", "DENY"),))
    outcome = decide_verification(plan, obs_c, obs_k, now=NOW)
    reviewer = generate_ed25519_private_key()
    store = TrustStoreV2(keys=(TrustedKey(
        key_id="reviewer",
        public_key=encode_base64(public_key_bytes(reviewer)),
        usages=frozenset({KeyUsage.HUMAN_REVIEW}),
        valid_from=NOW,
    ),))
    finding = promote_to_finding(
        outcome, plan, candidate,
        review_signature_b64=sign_review(outcome, reviewer),
        reviewer_key_id="reviewer", reviewed_at=NOW, trust_store=store, now=NOW,
    )
    return finding, plan, outcome


def ProbeObservation(*, status: int, headers):  # noqa: N802 - test helper
    from hermes.verification import ProbeObservationV1

    return ProbeObservationV1(
        status_code=status,
        headers=tuple(headers),
        evidence=(EvidenceArtifactRef(
            evidence_id="o", manifest_path="evidence/o/manifest.json", manifest_sha256=DIGEST
        ),),
    )


def _narrative() -> ReportNarrativeV1:
    return ReportNarrativeV1(
        title="Full path disclosure on app.acme.example",
        summary="The application discloses its full filesystem path in an error response.",
        steps_to_reproduce=("Request GET /x", "Observe the absolute path in the response"),
        impact="Aids further attacks by revealing server layout.",
    )


def test_build_draft_binds_provenance_and_classifies() -> None:
    finding, plan, outcome = _validated()
    draft = build_report_draft(
        finding, plan, outcome,
        vrt_category_id="full_path_disclosure",
        vrt_priorities=VRT,
        cvss=parse_cvss_vector(CVSS),
        narrative=_narrative(),
        now=NOW,
    )
    assert draft.priority == "P5"
    assert draft.cvss_base_score == 5.3
    assert draft.cvss_severity == "medium"
    assert draft.submitted is False
    assert draft.finding_digest == finding.digest()
    assert draft.outcome_digest == outcome.digest()
    # evidence carries both candidate + control observations
    assert len(draft.evidence) == 2


def test_build_draft_rejects_unknown_vrt_category() -> None:
    finding, plan, outcome = _validated()
    with pytest.raises(ReportDraftError):
        build_report_draft(
            finding, plan, outcome,
            vrt_category_id="not_a_real_category",
            vrt_priorities=VRT,
            cvss=parse_cvss_vector(CVSS),
            narrative=_narrative(),
            now=NOW,
        )


def test_render_markdown_marks_draft_and_omits_submit() -> None:
    finding, plan, outcome = _validated()
    draft = build_report_draft(
        finding, plan, outcome,
        vrt_category_id="full_path_disclosure",
        vrt_priorities=VRT,
        cvss=parse_cvss_vector(CVSS),
        narrative=_narrative(),
        now=NOW,
    )
    md = render_markdown(draft)
    assert "DRAFT" in md
    assert "P5" in md and "CVSS:3.1" in md
    assert "app.acme.example" in md


def test_require_human_submission_always_raises() -> None:
    with pytest.raises(ReportDraftError):
        require_human_submission()

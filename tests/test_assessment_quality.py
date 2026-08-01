from __future__ import annotations

from pathlib import Path

from hermes.assessment import AccessSample, Observation, SafeCandidateDetector
from hermes.contracts import FindingStatus
from hermes.quality import FixtureCase, evaluate_candidate_quality, load_fixture_dataset


def test_public_json_and_spa_fallback_never_become_validated_findings() -> None:
    detector = SafeCandidateDetector()
    public_api = detector.api_access(
        Observation(
            target="https://example.test/api/public",
            status_code=200,
            content_type="application/json",
            body='{"status":"public"}',
        )
    )
    fallback = detector.sensitive_path(
        Observation(
            target="https://example.test/.env",
            status_code=200,
            content_type="text/html",
            body="<html><div id='app'></div></html>",
        )
    )

    assert public_api.status is FindingStatus.CANDIDATE
    assert fallback.status is FindingStatus.CANDIDATE
    assert "authorization" in public_api.rationale.lower()
    assert "spa" in fallback.rationale.lower()


def test_idor_requires_two_authorized_identities_and_owned_objects() -> None:
    detector = SafeCandidateDetector()
    candidate = detector.idor(
        AccessSample(identity="alice", object_owner="alice", object_id="1", status_code=200),
        AccessSample(identity="alice", object_owner="bob", object_id="2", status_code=200),
    )

    assert candidate.status is FindingStatus.CANDIDATE
    assert "two distinct" in candidate.rationale.lower()


def test_quality_metrics_keep_candidate_recall_separate_from_verified_precision() -> None:
    report = evaluate_candidate_quality(
        [
            FixtureCase(id="public-api", expected="none"),
            FixtureCase(id="missing-header", expected="candidate"),
        ],
        candidate_ids={"missing-header"},
        verified_ids=set(),
    )

    assert report.candidate_recall == 1.0
    assert report.verified_precision is None
    assert report.false_positive_candidates == 0


def test_frozen_quality_fixture_has_a_version_and_independent_truth() -> None:
    fixture = Path(__file__).parent / "fixtures" / "quality" / "baseline-v1.json"

    version, cases = load_fixture_dataset(fixture)

    assert version == "fixture-v1"
    assert {case.id for case in cases} == {"public-api", "missing-header", "owned-object-control"}

"""N3 contract tests: nuclei hits -> disciplined, scope-tied candidates (docs/19 N3)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from hermes.candidate_source import (
    CandidateSourceError,
    build_candidate_set,
    parse_nuclei_line,
    require_verification_before_promotion,
)
from hermes.recon_adapter import build_recon_inventory, parse_httpx_line
from hermes.scope_profile import (
    BugcrowdProgramSpecV1,
    BugcrowdTargetV1,
    ingest_bugcrowd_program,
)

NOW = datetime(2026, 8, 3, 12, 0, tzinfo=UTC)


def _inventory():
    spec = BugcrowdProgramSpecV1(
        program_handle="acme-bbp",
        retrieved_at=NOW,
        automated_testing_allowed=True,
        rate_limit_rps=2.0,
        targets=(
            BugcrowdTargetV1(identifier="https://api.acme.example", category="api"),
            BugcrowdTargetV1(identifier="*.acme.example", category="website"),
        ),
    )
    draft = ingest_bugcrowd_program(spec)
    probes = [
        parse_httpx_line({"url": "https://api.acme.example/v1", "status_code": 200}),
        parse_httpx_line({"url": "https://app.acme.example/", "status_code": 200}),
    ]
    return build_recon_inventory(
        [p for p in probes if p is not None],
        scope_draft=draft,
        program_handle="acme-bbp",
        generated_by="recon",
        source_tools=("httpx",),
        now=NOW,
    ).inventory


def _nuclei(url: str, *, tid: str = "http-missing-security-headers", sev: str = "low") -> dict:
    return {
        "template-id": tid,
        "info": {"name": tid.replace("-", " "), "severity": sev},
        "type": "http",
        "host": url,
        "matched-at": url,
    }


def test_parse_nuclei_line() -> None:
    m = parse_nuclei_line(_nuclei("https://api.acme.example/v1", tid="exposure-config", sev="high"))
    assert m is not None
    assert m.template_id == "exposure-config"
    assert m.severity == "high"
    assert m.matched_url == "https://api.acme.example/v1"


def test_parse_nuclei_line_skips_incomplete() -> None:
    assert parse_nuclei_line({"info": {"severity": "low"}}) is None  # no template-id/matched


def test_candidates_are_never_validated_and_require_verification() -> None:
    inv = _inventory()
    matches = [parse_nuclei_line(_nuclei("https://api.acme.example/v1"))]
    result = build_candidate_set(
        [m for m in matches if m is not None], inv, generated_by="n3", now=NOW
    )
    cand = result.candidate_set.candidates[0]
    assert cand.status == "candidate"
    assert cand.requires_active_verification is True
    assert cand.source == "nuclei"
    assert cand.expected_assertion and cand.negative_control_hint
    # provenance chained N1 -> N2 -> N3
    assert result.candidate_set.recon_inventory_digest == inv.digest()
    assert result.candidate_set.scope_profile_digest == inv.scope_profile_digest


def test_hit_outside_inventory_is_dropped() -> None:
    inv = _inventory()
    matches = [
        parse_nuclei_line(_nuclei("https://api.acme.example/v1")),  # in inventory
        parse_nuclei_line(_nuclei("https://evil.example/")),  # not in inventory -> dropped
        parse_nuclei_line(_nuclei("https://other.acme.example/")),  # host not probed -> dropped
    ]
    result = build_candidate_set(
        [m for m in matches if m is not None], inv, generated_by="n3", now=NOW
    )
    assert len(result.candidate_set.candidates) == 1
    assert "https://evil.example/" in result.candidate_set.dropped_out_of_inventory


def test_evidence_bound_to_match_bytes() -> None:
    import hashlib

    inv = _inventory()
    m = parse_nuclei_line(_nuclei("https://api.acme.example/v1"))
    assert m is not None
    result = build_candidate_set([m], inv, generated_by="n3", now=NOW)
    cand = result.candidate_set.candidates[0]
    raw = result.evidence[cand.candidate_id]
    assert cand.evidence[0].manifest_sha256 == "sha256:" + hashlib.sha256(raw).hexdigest()


def test_dedup_by_endpoint_and_type() -> None:
    inv = _inventory()
    matches = [
        parse_nuclei_line(_nuclei("https://api.acme.example/v1", tid="dup")),
        parse_nuclei_line(_nuclei("https://api.acme.example/v1", tid="dup")),
    ]
    result = build_candidate_set(
        [m for m in matches if m is not None], inv, generated_by="n3", now=NOW
    )
    assert len(result.candidate_set.candidates) == 1


def test_raises_when_no_hit_is_in_scope() -> None:
    inv = _inventory()
    m = parse_nuclei_line(_nuclei("https://evil.example/"))
    assert m is not None
    with pytest.raises(CandidateSourceError):
        build_candidate_set([m], inv, generated_by="n3", now=NOW)


def test_promotion_guard_raises() -> None:
    inv = _inventory()
    m = parse_nuclei_line(_nuclei("https://api.acme.example/v1"))
    assert m is not None
    cand = build_candidate_set([m], inv, generated_by="n3", now=NOW).candidate_set.candidates[0]
    with pytest.raises(CandidateSourceError):
        require_verification_before_promotion(cand)

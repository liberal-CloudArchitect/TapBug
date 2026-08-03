"""Native governed detection tests: Hermes actively finds candidates, no network.

Probes run through GovernedEgress + a ReplayTransport (canned responses), so
detection logic, discipline, and the governed path are all exercised offline.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from hermes.detection import DetectionError, run_detection
from hermes.governed_egress import (
    EgressResponseV1,
    GovernedEgress,
    ReplayTransport,
)
from hermes.recon_adapter import build_recon_inventory, parse_httpx_line
from hermes.scope_profile import (
    BugcrowdProgramSpecV1,
    BugcrowdTargetV1,
    ingest_bugcrowd_program,
)

NOW = datetime(2026, 8, 3, 12, 0, tzinfo=UTC)


class _Clock:
    def __init__(self) -> None:
        self.t = 0.0

    def monotonic(self) -> float:
        return self.t

    def sleep(self, seconds: float) -> None:
        self.t += seconds


def _draft():
    spec = BugcrowdProgramSpecV1(
        program_handle="acme-bbp",
        retrieved_at=NOW,
        automated_testing_allowed=True,
        rate_limit_rps=2.0,
        targets=(BugcrowdTargetV1(identifier="*.acme.example", category="website"),),
    )
    return ingest_bugcrowd_program(spec)


def _inventory(draft):
    probe = parse_httpx_line({"url": "https://app.acme.example/x", "status_code": 200})
    return build_recon_inventory(
        [probe], scope_draft=draft, program_handle="acme-bbp",
        generated_by="recon", source_tools=("httpx",), now=NOW,
    ).inventory


def _egress(draft, responses):
    clock = _Clock()
    return GovernedEgress(
        scope_draft=draft,
        transport=ReplayTransport(responses),
        monotonic=clock.monotonic,
        sleep=clock.sleep,
    )


def test_detects_missing_header_and_exposed_path() -> None:
    draft = _draft()
    responses = {
        # endpoint response: has XFO/CSP/HSTS, MISSING X-Content-Type-Options
        ("GET", "https://app.acme.example/x"): EgressResponseV1(
            status_code=200,
            headers=(
                ("X-Frame-Options", "DENY"),
                ("Content-Security-Policy", "default-src 'self'"),
                ("Strict-Transport-Security", "max-age=63072000"),
            ),
        ),
        ("GET", "https://app.acme.example/.git/config"): EgressResponseV1(status_code=200),
        ("GET", "https://app.acme.example/.env"): EgressResponseV1(status_code=404),
        ("GET", "https://app.acme.example/server-status"): EgressResponseV1(status_code=404),
    }
    result = run_detection(
        _inventory(draft), _egress(draft, responses), generated_by="det", now=NOW
    )
    types = {c.candidate_type for c in result.candidate_set.candidates}
    assert types == {"missing-x-content-type-options", "exposed-git-config"}
    for c in result.candidate_set.candidates:
        assert c.source == "hermes_active"
        assert c.status == "candidate" and c.requires_active_verification is True
    # chained to the scope-authorized inventory
    assert result.candidate_set.recon_inventory_digest == _inventory(draft).digest()


def test_no_false_positive_when_hardened() -> None:
    draft = _draft()
    responses = {
        ("GET", "https://app.acme.example/x"): EgressResponseV1(
            status_code=200,
            headers=(
                ("X-Content-Type-Options", "nosniff"),
                ("X-Frame-Options", "DENY"),
                ("Content-Security-Policy", "default-src 'self'"),
                ("Strict-Transport-Security", "max-age=63072000"),
            ),
        ),
        ("GET", "https://app.acme.example/.git/config"): EgressResponseV1(status_code=404),
        ("GET", "https://app.acme.example/.env"): EgressResponseV1(status_code=404),
        ("GET", "https://app.acme.example/server-status"): EgressResponseV1(status_code=404),
    }
    with pytest.raises(DetectionError):  # clean target -> no candidates
        run_detection(_inventory(draft), _egress(draft, responses), generated_by="det", now=NOW)


def test_evidence_bound_and_audited() -> None:
    import hashlib

    draft = _draft()
    responses = {
        ("GET", "https://app.acme.example/x"): EgressResponseV1(status_code=200, headers=()),
        ("GET", "https://app.acme.example/.git/config"): EgressResponseV1(status_code=404),
        ("GET", "https://app.acme.example/.env"): EgressResponseV1(status_code=404),
        ("GET", "https://app.acme.example/server-status"): EgressResponseV1(status_code=404),
    }
    egress = _egress(draft, responses)
    result = run_detection(_inventory(draft), egress, generated_by="det", now=NOW)
    # every probe (whether it fired or not) is audited in scope
    assert egress.audit and all(a.allowed for a in egress.audit)
    cand = result.candidate_set.candidates[0]
    raw = result.evidence[cand.candidate_id]
    assert cand.evidence[0].manifest_sha256 == "sha256:" + hashlib.sha256(raw).hexdigest()

"""GOV-02 real-asset governed-egress tests: scope + rate-limit + budget + audit.

Fully offline: a fake in-memory transport and a fake clock exercise every
governance edge deterministically, and close the N4 live loop end to end.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from hermes.candidate_source import AssetCandidateV1
from hermes.evidence import EvidenceArtifactRef
from hermes.governed_egress import (
    EgressRequestV1,
    EgressResponseV1,
    GovernedEgress,
    GovernedEgressError,
    execute_verification_plan,
)
from hermes.scope_profile import (
    BugcrowdProgramSpecV1,
    BugcrowdTargetV1,
    ingest_bugcrowd_program,
)
from hermes.verification import (
    VerificationSignalV1,
    build_verification_plan,
    decide_verification,
)

NOW = datetime(2026, 8, 3, 12, 0, tzinfo=UTC)
DIGEST = "sha256:" + "a" * 64


class FakeClock:
    def __init__(self) -> None:
        self.t = 0.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.t

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.t += seconds


class FakeTransport:
    def __init__(self, responses: dict[str, EgressResponseV1]) -> None:
        self.responses = responses
        self.calls: list[str] = []

    def perform(self, request: EgressRequestV1) -> EgressResponseV1:
        self.calls.append(request.url)
        return self.responses.get(request.url, EgressResponseV1(status_code=404))


def _scope(*, automated: bool = True, max_requests: int = 100, rps: float = 1.0):
    spec = BugcrowdProgramSpecV1(
        program_handle="acme-bbp",
        retrieved_at=NOW,
        automated_testing_allowed=automated,
        rate_limit_rps=rps,
        targets=(BugcrowdTargetV1(identifier="*.acme.example", category="website"),),
    )
    return ingest_bugcrowd_program(
        spec, default_rate_limit_rps=rps, max_requests=max_requests, max_concurrency=1
    )


def _egress(scope=None, transport=None, clock=None) -> GovernedEgress:
    clock = clock or FakeClock()
    return GovernedEgress(
        scope_draft=scope or _scope(),
        transport=transport or FakeTransport({}),
        monotonic=clock.monotonic,
        sleep=clock.sleep,
    )


def _req(url: str, method: str = "GET") -> EgressRequestV1:
    return EgressRequestV1(method=method, url=url)  # type: ignore[arg-type]


def test_refuses_construction_without_automation() -> None:
    with pytest.raises(GovernedEgressError):
        _egress(scope=_scope(automated=False))  # no-automation -> dry_run on -> refused


def test_in_scope_request_performs_and_audits() -> None:
    clock = FakeClock()
    transport = FakeTransport({"https://app.acme.example/x": EgressResponseV1(status_code=200)})
    egress = _egress(transport=transport, clock=clock)
    response, evidence = egress.perform(_req("https://app.acme.example/x"), now=NOW)
    assert response.status_code == 200
    assert isinstance(evidence, EvidenceArtifactRef)
    assert egress.audit[-1].allowed is True
    assert transport.calls == ["https://app.acme.example/x"]


def test_out_of_scope_request_is_refused_and_audited() -> None:
    egress = _egress()
    with pytest.raises(GovernedEgressError):
        egress.perform(_req("https://evil.example/"), now=NOW)
    assert egress.audit[-1].allowed is False
    assert "scope" in egress.audit[-1].reason


def test_budget_is_enforced() -> None:
    egress = _egress(scope=_scope(max_requests=2))
    egress.perform(_req("https://app.acme.example/a"), now=NOW)
    egress.perform(_req("https://app.acme.example/b"), now=NOW)
    assert egress.remaining_budget == 0
    with pytest.raises(GovernedEgressError):
        egress.perform(_req("https://app.acme.example/c"), now=NOW)


def test_rate_limit_paces_requests() -> None:
    clock = FakeClock()  # t starts at 0
    egress = _egress(scope=_scope(rps=1.0), clock=clock)  # 1 req/s -> 1.0s min interval
    egress.perform(_req("https://app.acme.example/a"), now=NOW)  # first: no wait
    egress.perform(_req("https://app.acme.example/b"), now=NOW)  # second: must wait ~1.0s
    assert clock.sleeps == [1.0]
    assert egress.audit[-1].waited_seconds == 1.0

    # if the clock has already advanced past the interval, no wait is inserted
    clock.t += 5.0
    egress.perform(_req("https://app.acme.example/c"), now=NOW)
    assert clock.sleeps == [1.0]  # unchanged


def test_execute_verification_plan_closes_the_n4_loop() -> None:
    scope = _scope()
    candidate = AssetCandidateV1(
        candidate_id="cand-xyz",
        source="nuclei",
        endpoint_id="ep-xyz",
        asset_id="asset-app.acme.example",
        target_url="https://app.acme.example/candidate",
        method="GET",
        candidate_type="http-missing-xcto",
        title="Missing XCTO",
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
        signal=VerificationSignalV1(kind="header_absent", argument="X-Content-Type-Options"),
        negative_control_url="https://app.acme.example/control",
        scope_draft=scope,
        now=NOW,
    )
    transport = FakeTransport({
        "https://app.acme.example/candidate": EgressResponseV1(status_code=200, headers=()),
        "https://app.acme.example/control": EgressResponseV1(
            status_code=200, headers=(("X-Content-Type-Options", "nosniff"),)
        ),
    })
    egress = _egress(scope=scope, transport=transport)
    candidate_obs, control_obs = execute_verification_plan(plan, egress, now=NOW)
    outcome = decide_verification(plan, candidate_obs, control_obs, now=NOW)
    assert outcome.verdict == "validated"
    # both probes are audited in-scope
    assert [a.allowed for a in egress.audit] == [True, True]

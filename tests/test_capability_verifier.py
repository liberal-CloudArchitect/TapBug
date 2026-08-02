"""The Verifier role node resolves a line_kv_capability_gap candidate via the
governed Wheel (or reports a coverage gap when none is active).

capability_gap_verdict is the logic wired into VerticalWorkflowV3's Verifier
(_canonicalize_verifier_outcome); the sandbox is faked here for determinism.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pytest

from hermes.capability_verifier import CapabilityGapResolver, capability_gap_verdict
from hermes.learning_recovery import ActiveWheelView
from hermes.wheel_consumption import WheelConsumptionError

_D = "sha256:" + "0" * 64
_D2 = "sha256:" + "1" * 64
_NOW = datetime(2026, 8, 2, tzinfo=UTC)
_GAP = "gap-line-kv-unparsed-field"


@dataclass
class _FakeResult:
    passed: bool
    output_json: str
    failure_reason: str | None = None


class _FakeSandbox:
    def __init__(self, result: _FakeResult) -> None:
        self.result = result

    def execute_json(self, artifact_root, *, entrypoint: str, input_json: str) -> _FakeResult:
        return self.result


def _resolver(sandbox, *, status: str = "active") -> CapabilityGapResolver:
    return CapabilityGapResolver(
        active_wheel=ActiveWheelView(
            wheel_id="line-kv-parser",
            wheel_manifest_digest=_D,
            activation_digest=_D2,
            status=status,  # type: ignore[arg-type]
            problem_card_ids=(_GAP,),
        ),
        sandbox=sandbox,
        wheel_artifact_root=Path("/wheel"),
        entrypoint="wheel:parse_response",
        problem_card_id=_GAP,
        resume_run_id="cap07-resume-1",
        paused_run_id="assess-parent-1",
        scope_digest=_D,
        wheel_activation_digest=_D2,
        gap_text="Service: Hermes\nVersion: 1",
    )


def test_no_active_wheel_is_a_coverage_gap() -> None:
    status, summary, obs = capability_gap_verdict(None, now=_NOW)
    assert status == "inconclusive"
    assert "no active approved Wheel" in summary
    assert obs is None


def test_active_wheel_match_validates_the_candidate() -> None:
    sandbox = _FakeSandbox(
        _FakeResult(True, '{"matched":true,"fields":{"service":"hermes","version":"1"}}')
    )
    status, summary, obs = capability_gap_verdict(_resolver(sandbox), now=_NOW)
    assert status == "validated"
    assert obs is not None and obs.matched is True
    assert obs.fields == {"service": "hermes", "version": "1"}
    assert "resolved by governed Wheel" in summary


def test_active_wheel_no_match_stays_inconclusive() -> None:
    sandbox = _FakeSandbox(_FakeResult(True, '{"matched":false,"fields":{}}'))
    status, summary, obs = capability_gap_verdict(_resolver(sandbox), now=_NOW)
    assert status == "inconclusive"
    assert obs is not None and obs.matched is False


def test_inactive_wheel_fails_closed() -> None:
    sandbox = _FakeSandbox(_FakeResult(True, '{"matched":true,"fields":{}}'))
    with pytest.raises(WheelConsumptionError):
        capability_gap_verdict(_resolver(sandbox, status="approved"), now=_NOW)


def test_sandbox_violation_fails_closed() -> None:
    sandbox = _FakeSandbox(_FakeResult(False, "", failure_reason="network-none violation"))
    with pytest.raises(WheelConsumptionError):
        capability_gap_verdict(_resolver(sandbox), now=_NOW)


def test_line_kv_capability_gap_is_an_allowed_candidate_type() -> None:
    # The Verifier routes this candidate type to the Wheel; it must be a member of
    # the closed V3 candidate set and have a promotion presentation entry.
    from typing import get_args

    from hermes.domain_contracts_v3 import CandidateTypeV3
    from hermes.promotion_v3 import _PRESENTATION

    assert "line_kv_capability_gap" in get_args(CandidateTypeV3)
    assert "line_kv_capability_gap" in _PRESENTATION

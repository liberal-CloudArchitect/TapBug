"""CAP-07 Wheel-consumption hook: a resumed assessment invokes the active Wheel
in the governed sandbox to resolve its gap, producing a bound observation.

The sandbox is faked here so the hook's logic and fail-closed guards are pinned
deterministically; the real DockerSandbox invocation is covered by
scripts/run_cap07_gap_resolution_e2e.py.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from hermes.learning_recovery import ActiveWheelView
from hermes.wheel_consumption import (
    GapResolutionRequestV1,
    WheelConsumptionError,
    WheelResolvedObservationV1,
    gap_input_digest,
    resolve_gap_with_wheel,
)

_D = "sha256:" + "0" * 64
_D2 = "sha256:" + "1" * 64
_NOW = datetime(2026, 8, 2, tzinfo=UTC)
_GAP = "gap-line-kv-unparsed-field"
_INPUT = {"text": "status=leaked\nuser=alice\nrole=admin"}


@dataclass
class _FakeResult:
    passed: bool
    output_json: str
    failure_reason: str | None = None


class _FakeSandbox:
    """Records the call and returns a canned sandbox result."""

    def __init__(self, result: _FakeResult) -> None:
        self.result = result
        self.calls: list[tuple[str, str]] = []

    def execute_json(self, artifact_root, *, entrypoint: str, input_json: str) -> _FakeResult:
        self.calls.append((entrypoint, input_json))
        return self.result


def _wheel(status: str = "active") -> ActiveWheelView:
    return ActiveWheelView(
        wheel_id="line-kv-parser",
        wheel_manifest_digest=_D,
        activation_digest=_D2,
        status=status,  # type: ignore[arg-type]
        problem_card_ids=(_GAP,),
    )


def _request(**over) -> GapResolutionRequestV1:
    payload = {
        "resume_run_id": "cap07-resume-1",
        "paused_run_id": "assess-parent-1",
        "scope_digest": _D,
        "problem_card_id": _GAP,
        "wheel_manifest_digest": _D,
        "wheel_activation_digest": _D2,
        "gap_input_sha256": gap_input_digest(_INPUT),
    }
    payload.update(over)
    return GapResolutionRequestV1(**payload)  # type: ignore[arg-type]


def _resolve(sandbox, request=None, wheel=None):
    return resolve_gap_with_wheel(
        request or _request(),
        wheel or _wheel(),
        sandbox,
        wheel_artifact_root=Path("/tmp/wheel"),
        entrypoint="wheel:parse_response",
        gap_input=_INPUT,
        now=_NOW,
    )


# --- happy path ----------------------------------------------------------


def test_active_wheel_resolves_the_gap_into_a_bound_observation() -> None:
    sandbox = _FakeSandbox(
        _FakeResult(True, '{"matched":true,"fields":{"role":"admin","user":"alice"}}')
    )
    obs = _resolve(sandbox)

    assert isinstance(obs, WheelResolvedObservationV1)
    assert obs.status == "resolved"
    assert obs.matched is True
    assert obs.fields == {"role": "admin", "user": "alice"}
    assert obs.wheel_manifest_digest == _D
    assert obs.input_digest == gap_input_digest(_INPUT)
    assert obs.request_digest == _request().digest
    # the Wheel entrypoint was invoked with the exact frozen input
    assert sandbox.calls[0][0] == "wheel:parse_response"


def test_no_match_is_unresolved_not_an_error() -> None:
    sandbox = _FakeSandbox(_FakeResult(True, '{"matched":false,"fields":{}}'))
    obs = _resolve(sandbox)
    assert obs.status == "unresolved"
    assert obs.matched is False


# --- fail-closed guards --------------------------------------------------


def test_inactive_wheel_is_refused() -> None:
    sandbox = _FakeSandbox(_FakeResult(True, '{"matched":true,"fields":{}}'))
    with pytest.raises(WheelConsumptionError):
        _resolve(sandbox, wheel=_wheel(status="approved"))


def test_wheel_manifest_mismatch_is_refused() -> None:
    sandbox = _FakeSandbox(_FakeResult(True, '{"matched":true,"fields":{}}'))
    with pytest.raises(WheelConsumptionError):
        _resolve(sandbox, request=_request(wheel_manifest_digest=_D2))


def test_wheel_not_addressing_the_gap_is_refused() -> None:
    sandbox = _FakeSandbox(_FakeResult(True, '{"matched":true,"fields":{}}'))
    other = ActiveWheelView(
        wheel_id="other-wheel", wheel_manifest_digest=_D, activation_digest=_D2,
        status="active", problem_card_ids=("some-other-gap",),
    )
    with pytest.raises(WheelConsumptionError):
        _resolve(sandbox, wheel=other)


def test_gap_input_digest_mismatch_is_refused() -> None:
    sandbox = _FakeSandbox(_FakeResult(True, '{"matched":true,"fields":{}}'))
    with pytest.raises(WheelConsumptionError):
        _resolve(sandbox, request=_request(gap_input_sha256=_D2))


def test_sandbox_failure_is_a_resolution_failure() -> None:
    sandbox = _FakeSandbox(_FakeResult(False, "", failure_reason="network-none violation"))
    with pytest.raises(WheelConsumptionError):
        _resolve(sandbox)


def test_malformed_wheel_output_is_refused() -> None:
    sandbox = _FakeSandbox(_FakeResult(True, "not json"))
    with pytest.raises(WheelConsumptionError):
        _resolve(sandbox)


def test_output_without_matched_bool_is_refused() -> None:
    sandbox = _FakeSandbox(_FakeResult(True, '{"fields":{"a":"b"}}'))
    with pytest.raises(WheelConsumptionError):
        _resolve(sandbox)


def test_observation_is_frozen() -> None:
    sandbox = _FakeSandbox(_FakeResult(True, '{"matched":true,"fields":{}}'))
    obs = _resolve(sandbox)
    with pytest.raises(ValidationError):
        obs.matched = False  # type: ignore[misc]

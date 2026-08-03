"""N8 contract tests: independent-benchmark credibility gate (docs/19 N8)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from hermes.benchmark_gate import (
    BenchmarkGateError,
    BenchmarkResultV1,
    CredibilityGateV1,
    evaluate_benchmark_gate,
    require_credible,
)

NOW = datetime(2026, 8, 3, 12, 0, tzinfo=UTC)
HARNESS = "sha256:" + "a" * 64


def _result(
    *, benchmark: str = "cybench", total: int = 40, solved: int = 20
) -> BenchmarkResultV1:
    return BenchmarkResultV1(
        benchmark=benchmark,  # type: ignore[arg-type]
        ran_at=NOW,
        model="deepseek-v4-pro",
        total_tasks=total,
        solved_tasks=solved,
        harness_digest=HARNESS,
    )


def _gate(
    *, benchmark: str = "cybench", rate: float = 0.4, min_tasks: int = 30
) -> CredibilityGateV1:
    return CredibilityGateV1(
        benchmark=benchmark,  # type: ignore[arg-type]
        min_solve_rate=rate,
        min_total_tasks=min_tasks,
    )


def test_pass_when_rate_meets_floor_and_sample_sufficient() -> None:
    verdict = evaluate_benchmark_gate(_result(total=40, solved=20), _gate(rate=0.4), now=NOW)
    assert verdict.status == "pass"
    assert verdict.solve_rate == 0.5


def test_blocked_below_solve_rate_floor() -> None:
    verdict = evaluate_benchmark_gate(_result(total=40, solved=10), _gate(rate=0.4), now=NOW)
    assert verdict.status == "blocked"
    assert "below floor" in verdict.reason


def test_blocked_on_insufficient_sample() -> None:
    verdict = evaluate_benchmark_gate(
        _result(total=5, solved=5), _gate(rate=0.4, min_tasks=30), now=NOW
    )
    assert verdict.status == "blocked"
    assert "insufficient sample" in verdict.reason


def test_blocked_on_benchmark_mismatch() -> None:
    verdict = evaluate_benchmark_gate(
        _result(benchmark="cybench"), _gate(benchmark="nyu_ctf"), now=NOW
    )
    assert verdict.status == "blocked"
    assert "gate is for" in verdict.reason


def test_result_rejects_solved_exceeding_total() -> None:
    with pytest.raises(ValueError):
        BenchmarkResultV1(
            benchmark="cybench",
            ran_at=NOW,
            model="m",
            total_tasks=10,
            solved_tasks=11,
            harness_digest=HARNESS,
        )


def test_require_credible_raises_when_blocked() -> None:
    with pytest.raises(BenchmarkGateError):
        require_credible(_result(total=40, solved=1), _gate(rate=0.4), now=NOW)
    # passes through when credible
    verdict = require_credible(_result(total=40, solved=30), _gate(rate=0.4), now=NOW)
    assert verdict.status == "pass"


def test_verdict_binds_result_and_gate_digests() -> None:
    result = _result()
    gate = _gate()
    verdict = evaluate_benchmark_gate(result, gate, now=NOW)
    assert verdict.result_digest == result.digest()
    assert verdict.gate_digest == gate.digest()

"""N8 — independent benchmark credibility gate (docs/19 node N8, docs/15 §10.4).

Before Hermes' detection output may be trusted for a real, authorized program, it
must first prove a reproducible detection rate on an *independent* benchmark
(Cybench, AutoPenBench, NYU CTF Bench — cloned via ``scripts/fetch_external_repos.sh``).
This module is the **contract + fail-closed gate** that turns a benchmark run into
a go / no-go decision the active nodes (N1 activation, N3 candidate generation,
N4 verification) consult: below the configured solve-rate floor, or on too small a
sample, the gate is ``blocked`` and real-program active testing is refused.

Scope of this module: the frozen result/gate/verdict contracts and the pure
evaluation, fully unit-tested without running any benchmark. Actually *running*
Cybench (Docker challenge containers + model API keys, hours-level) happens on the
self-hosted runner via ``scripts/run_cybench_baseline.py``; this module only
scores and gates the result it produces.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .domain_contracts import canonical_digest

BenchmarkName = Literal["cybench", "auto_pen_bench", "nyu_ctf"]

_DIGEST = r"^sha256:[0-9a-f]{64}$"


class BenchmarkGateError(RuntimeError):
    """Detection credibility could not be established from a benchmark run."""


class BenchmarkResultV1(BaseModel):
    """One independent-benchmark run, reduced to what the gate needs."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"] = "1"
    benchmark: BenchmarkName
    ran_at: datetime
    model: str = Field(min_length=1, max_length=256)
    total_tasks: int = Field(ge=1, le=100_000)
    solved_tasks: int = Field(ge=0, le=100_000)
    # Cybench-style intermediate subtask credit in [0,1]; optional.
    subtask_score: float | None = Field(default=None, ge=0.0, le=1.0)
    # sha256 of the harness/config used, so a score is bound to how it was produced.
    harness_digest: str = Field(pattern=_DIGEST)

    @model_validator(mode="after")
    def _coherent(self) -> BenchmarkResultV1:
        if self.solved_tasks > self.total_tasks:
            raise ValueError("solved_tasks cannot exceed total_tasks")
        if self.ran_at.tzinfo is None:
            raise ValueError("ran_at must be timezone-aware")
        return self

    @property
    def solve_rate(self) -> float:
        return self.solved_tasks / self.total_tasks

    def digest(self) -> str:
        return canonical_digest(self)


class CredibilityGateV1(BaseModel):
    """The per-benchmark threshold policy that decides go / no-go."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    benchmark: BenchmarkName
    min_solve_rate: float = Field(ge=0.0, le=1.0)
    min_total_tasks: int = Field(ge=1, le=100_000)

    def digest(self) -> str:
        return canonical_digest(self)


class BenchmarkGateVerdictV1(BaseModel):
    """The go / no-go decision the active nodes consult."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["pass", "blocked"]
    benchmark: BenchmarkName
    solve_rate: float
    reason: str
    result_digest: str = Field(pattern=_DIGEST)
    gate_digest: str = Field(pattern=_DIGEST)
    evaluated_at: datetime


def evaluate_benchmark_gate(
    result: BenchmarkResultV1,
    gate: CredibilityGateV1,
    *,
    now: datetime,
) -> BenchmarkGateVerdictV1:
    """Score a benchmark run against its gate (fail-closed).

    Blocked when: the result is for a different benchmark than the gate; the
    sample is smaller than ``min_total_tasks``; or the solve rate is below
    ``min_solve_rate``. Otherwise ``pass``.
    """

    if now.tzinfo is None:
        raise BenchmarkGateError("evaluation time must be timezone-aware")

    def verdict(status: Literal["pass", "blocked"], reason: str) -> BenchmarkGateVerdictV1:
        return BenchmarkGateVerdictV1(
            status=status,
            benchmark=result.benchmark,
            solve_rate=result.solve_rate,
            reason=reason,
            result_digest=result.digest(),
            gate_digest=gate.digest(),
            evaluated_at=now,
        )

    if result.benchmark != gate.benchmark:
        return verdict("blocked", f"gate is for {gate.benchmark!r}, result is {result.benchmark!r}")
    if result.total_tasks < gate.min_total_tasks:
        return verdict(
            "blocked",
            f"insufficient sample: {result.total_tasks} < required {gate.min_total_tasks}",
        )
    if result.solve_rate < gate.min_solve_rate:
        return verdict(
            "blocked",
            f"solve rate {result.solve_rate:.3f} below floor {gate.min_solve_rate:.3f}",
        )
    return verdict(
        "pass", f"solve rate {result.solve_rate:.3f} meets floor {gate.min_solve_rate:.3f}"
    )


def require_credible(
    result: BenchmarkResultV1,
    gate: CredibilityGateV1,
    *,
    now: datetime,
) -> BenchmarkGateVerdictV1:
    """Raise unless the benchmark result clears the gate.

    This is the call an active node makes before touching a real program: no
    credible, in-date benchmark → no real-asset active testing.
    """

    result_verdict = evaluate_benchmark_gate(result, gate, now=now)
    if result_verdict.status != "pass":
        raise BenchmarkGateError(f"detection credibility not established: {result_verdict.reason}")
    return result_verdict

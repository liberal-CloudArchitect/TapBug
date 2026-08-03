#!/usr/bin/env python3
"""N8 driver: score a Cybench (or other) benchmark run and apply the credibility gate.

docs/19 node N8 / docs/15 §10.4. This driver does NOT run Cybench itself — running
the benchmark (Docker challenge containers + model API keys, hours-level) is a
human/CI step on the self-hosted runner, using the repo cloned by
``scripts/fetch_external_repos.sh`` (``CYBENCH_ROOT``). This driver takes the
benchmark's per-task results, reduces them to ``BenchmarkResultV1``, evaluates the
``CredibilityGateV1``, writes an auditable record, and **exits non-zero when the
gate is blocked** so CI fails until detection credibility is established.

Input results file (produced from a Cybench run; you map its output to this shape):

  {
    "benchmark": "cybench",
    "model": "deepseek-v4-pro",
    "tasks": [
      {"id": "task-1", "solved": true,  "subtask_fraction": 1.0},
      {"id": "task-2", "solved": false, "subtask_fraction": 0.25}
    ]
  }

Usage:
  run_cybench_baseline.py --results tasks.json --min-solve-rate 0.10 --min-tasks 30
  # on the runner, after producing tasks.json from a real Cybench run
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from hermes.benchmark_gate import (  # noqa: E402
    BenchmarkResultV1,
    CredibilityGateV1,
    evaluate_benchmark_gate,
)


def _load_result(path: Path, *, model_override: str | None) -> BenchmarkResultV1:
    raw: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    benchmark = str(raw.get("benchmark", "cybench"))
    model = model_override or str(raw.get("model", "unknown"))
    tasks = raw.get("tasks")
    if not isinstance(tasks, list) or not tasks:
        raise ValueError("results file must contain a non-empty 'tasks' list")
    total = len(tasks)
    solved = sum(1 for t in tasks if isinstance(t, dict) and bool(t.get("solved")))
    fractions = [
        float(t["subtask_fraction"])
        for t in tasks
        if isinstance(t, dict) and isinstance(t.get("subtask_fraction"), int | float)
    ]
    subtask = round(sum(fractions) / len(fractions), 6) if fractions else None
    # Bind the score to exactly the results bytes that produced it.
    harness_digest = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    return BenchmarkResultV1(
        benchmark=benchmark,  # type: ignore[arg-type]
        ran_at=datetime.now(UTC),
        model=model,
        total_tasks=total,
        solved_tasks=solved,
        subtask_score=subtask,
        harness_digest=harness_digest,
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--results", type=Path, required=True, help="per-task results JSON")
    ap.add_argument(
        "--benchmark", default="cybench", choices=["cybench", "auto_pen_bench", "nyu_ctf"]
    )
    ap.add_argument("--model", default=None, help="override model label")
    ap.add_argument("--min-solve-rate", type=float, default=0.10)
    ap.add_argument("--min-tasks", type=int, default=30)
    ap.add_argument(
        "--artifact-root", type=Path, default=PROJECT_ROOT / "artifacts" / "benchmark"
    )
    args = ap.parse_args(argv)

    result = _load_result(args.results, model_override=args.model)
    if result.benchmark != args.benchmark:
        # honour the explicit --benchmark as the gate's benchmark identity
        result = result.model_copy(update={"benchmark": args.benchmark})
    gate = CredibilityGateV1(
        benchmark=args.benchmark,
        min_solve_rate=args.min_solve_rate,
        min_total_tasks=args.min_tasks,
    )
    now = datetime.now(UTC)
    verdict = evaluate_benchmark_gate(result, gate, now=now)

    out_root = args.artifact_root.resolve()
    out_root.mkdir(parents=True, exist_ok=True)
    out = out_root / f"{now.strftime('%Y%m%dT%H%M%SZ')}-{args.benchmark}"
    out.mkdir(parents=True, exist_ok=True)
    summary = {
        "benchmark": result.benchmark,
        "model": result.model,
        "total_tasks": result.total_tasks,
        "solved_tasks": result.solved_tasks,
        "solve_rate": result.solve_rate,
        "subtask_score": result.subtask_score,
        "gate_status": verdict.status,
        "gate_reason": verdict.reason,
        "min_solve_rate": gate.min_solve_rate,
        "min_total_tasks": gate.min_total_tasks,
        "result_digest": result.digest(),
        "gate_digest": gate.digest(),
        "artifact_root": str(out),
    }
    (out / "result.json").write_text(result.model_dump_json(indent=2) + "\n", encoding="utf-8")
    (out / "verdict.json").write_text(verdict.model_dump_json(indent=2) + "\n", encoding="utf-8")
    (out / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    # Non-zero on a blocked gate so CI fails until credibility is established.
    return 0 if verdict.status == "pass" else 3


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError) as exc:
        print(f"cybench-baseline: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

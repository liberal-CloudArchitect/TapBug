#!/usr/bin/env python3
"""Triage a Phase 5 V4 resilience artifact root — including **incomplete** runs.

``run_phase5_resilience_e2e.py`` only writes ``summary.json`` when a scenario
finishes successfully; a run that fails or is interrupted mid-flight leaves the
root without any top-level record of what actually happened.  This read-only
tool reconstructs an auditable picture from whatever on-disk artifacts exist so
partial resilience roots can still be reviewed and diagnosed.

It never launches containers, never mutates the run, and tolerates missing
files.  Run it on any resilience root:

    python scripts/resilience_triage.py artifacts/phase5-resilience-e2e/<root>

Add ``--write`` to persist the result as ``triage.json`` inside the root.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

# The four scenarios the resilience driver can exercise.
SCENARIOS = ("api-branch-failure", "mutation-crash-recovery", "cleanup-failure", "tamper-matrix")


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _run_record(run_dir: Path) -> dict[str, Any]:
    state = _load_json(run_dir / "state.json")
    state = state if isinstance(state, dict) else {}
    faults_dir = run_dir / "resilience_faults"
    injected = sorted(p.name for p in faults_dir.glob("*.json")) if faults_dir.is_dir() else []
    report_dir = run_dir / "report"
    has_report = report_dir.is_dir() and any(report_dir.iterdir())
    return {
        "run_id": state.get("run_id", run_dir.name),
        "execution_state": state.get("execution_state"),
        "cleanup_state": state.get("cleanup_state"),
        "routed_branches": state.get("routed_branches"),
        "succeeded_branches": state.get("succeeded_branches"),
        "failed_branches": state.get("failed_branches"),
        "requests_used": state.get("requests_used"),
        "requests_blocked": state.get("requests_blocked"),
        "next_required_action": state.get("next_required_action"),
        "failure_code": state.get("failure_code"),
        "injected_faults": injected,
        "has_formal_report": has_report,
    }


def summarize_resilience_root(root: Path) -> dict[str, Any]:
    """Assemble an auditable summary of a resilience root (complete or not)."""
    root = Path(root)
    if not root.is_dir():
        raise ValueError(f"not a directory: {root}")

    config = _load_json(root / "config.json")
    config = config if isinstance(config, dict) else {}
    mode = _load_json(root / "fault-injection" / "mode.json")
    mode = mode if isinstance(mode, dict) else {}

    runs_dir = root / "runs"
    runs = (
        [_run_record(d) for d in sorted(runs_dir.iterdir()) if d.is_dir()]
        if runs_dir.is_dir()
        else []
    )

    tamper_summary = _load_json(root / "tamper-summary.json")
    tamper_dir = root / "tamper"
    tamper_populated = tamper_dir.is_dir() and any(tamper_dir.iterdir())
    tamper = {
        "present": bool(tamper_summary) or tamper_populated,
        "categories": sorted(tamper_summary) if isinstance(tamper_summary, dict) else [],
        "dir_populated": tamper_populated,
    }

    has_summary = (root / "summary.json").is_file()
    fault_mode = mode.get("fault")
    formal_reports = sum(1 for r in runs if r["has_formal_report"])

    if has_summary:
        verdict = "complete (driver summary.json present)"
    elif runs:
        verdict = "incomplete — runs present but no summary.json (driver did not finish)"
    else:
        verdict = "empty — no runs and no summary.json"

    return {
        "root": root.name,
        "model": config.get("model"),
        "declared_fault_mode": fault_mode,
        "driver_summary_present": has_summary,
        "run_count": len(runs),
        "runs": runs,
        "formal_reports": formal_reports,
        "tamper": tamper,
        # Scenario coverage is best-effort: only the declared fault mode is known
        # for certain from mode.json; the rest are marked unknown, not false.
        "scenario_coverage": {
            s: ("declared" if s == fault_mode else "unknown") for s in SCENARIOS
        },
        "verdict": verdict,
        "note": (
            "Read-only triage of on-disk artifacts. A trustworthy P0 close still "
            "requires a successful `--scenario all` run whose summary.json, full "
            "tamper-matrix and every reject/crash/cleanup case land under one root."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("root", type=Path, help="A phase5-resilience artifact root directory")
    ap.add_argument("--write", action="store_true", help="Persist as <root>/triage.json")
    args = ap.parse_args(argv)
    try:
        summary = summarize_resilience_root(args.root)
    except ValueError as exc:
        print(f"resilience-triage: {exc}", file=sys.stderr)
        return 1
    text = json.dumps(summary, ensure_ascii=False, indent=2)
    if args.write:
        (args.root / "triage.json").write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

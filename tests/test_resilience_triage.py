"""Unit tests for the read-only resilience triage tool.

These build synthetic artifact trees (no Docker/ACP) and assert the tool
reconstructs an auditable picture of complete and incomplete resilience roots.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "resilience_triage",
    Path(__file__).resolve().parent.parent / "scripts" / "resilience_triage.py",
)
assert _SPEC and _SPEC.loader
resilience_triage = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(resilience_triage)
summarize_resilience_root = resilience_triage.summarize_resilience_root


def _write(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _make_root(tmp_path: Path, *, fault: str, with_summary: bool) -> Path:
    root = tmp_path / "20260801T105759Z-phase5-demo"
    _write(root / "config.json", {"model": "deepseek-v4-flash"})
    _write(root / "fault-injection" / "mode.json", {"fault": fault})
    # A faulted run that stopped in CLEANUP_REQUIRED.
    run = root / "runs" / "run-a"
    _write(
        run / "state.json",
        {
            "run_id": "run-a",
            "execution_state": "CLEANUP_REQUIRED",
            "cleanup_state": "required",
            "routed_branches": ["api", "web"],
            "succeeded_branches": ["web"],
            "failed_branches": ["api"],
            "requests_used": 4,
            "requests_blocked": 1,
            "next_required_action": "cleanup",
            "failure_code": "api_branch_failed",
        },
    )
    _write(run / "resilience_faults" / "api-graphql-cleanup.json", {"fault": fault})
    if with_summary:
        _write(root / "summary.json", {"scenario": "all", "results": []})
    return root


def test_incomplete_root_is_flagged(tmp_path: Path) -> None:
    root = _make_root(tmp_path, fault="cleanup-failure", with_summary=False)
    summary = summarize_resilience_root(root)

    assert summary["driver_summary_present"] is False
    assert "incomplete" in summary["verdict"]
    assert summary["declared_fault_mode"] == "cleanup-failure"
    assert summary["model"] == "deepseek-v4-flash"
    assert summary["run_count"] == 1

    run = summary["runs"][0]
    assert run["execution_state"] == "CLEANUP_REQUIRED"
    assert run["cleanup_state"] == "required"
    assert run["failed_branches"] == ["api"]
    assert run["injected_faults"] == ["api-graphql-cleanup.json"]
    assert run["has_formal_report"] is False
    # Only the declared scenario is known; the rest are "unknown", never false.
    assert summary["scenario_coverage"]["cleanup-failure"] == "declared"
    assert summary["scenario_coverage"]["tamper-matrix"] == "unknown"


def test_complete_root_is_recognized(tmp_path: Path) -> None:
    root = _make_root(tmp_path, fault="api-branch-failure", with_summary=True)
    summary = summarize_resilience_root(root)
    assert summary["driver_summary_present"] is True
    assert summary["verdict"].startswith("complete")


def test_tamper_summary_is_surfaced(tmp_path: Path) -> None:
    root = _make_root(tmp_path, fault="tamper-matrix", with_summary=False)
    _write(
        root / "tamper-summary.json",
        {"approval_signature": "blocked_before_reporter", "coverage": "blocked_before_reporter"},
    )
    summary = summarize_resilience_root(root)
    assert summary["tamper"]["present"] is True
    assert "approval_signature" in summary["tamper"]["categories"]
    assert "coverage" in summary["tamper"]["categories"]


def test_empty_root(tmp_path: Path) -> None:
    root = tmp_path / "empty-root"
    root.mkdir()
    summary = summarize_resilience_root(root)
    assert summary["run_count"] == 0
    assert "empty" in summary["verdict"]

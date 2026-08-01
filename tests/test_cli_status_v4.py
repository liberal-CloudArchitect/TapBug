from __future__ import annotations

import json
from pathlib import Path

from hermes import cli
from hermes.cli import _state_exit
from hermes.cli_status_v4 import status_payload_v4
from hermes.runtime import RunContext
from hermes.vertical_v4 import ExecutionStateV4, NetworkStateV4, VerticalStateV4


def test_status_reads_the_canonical_v4_ledger_paths_without_mutating_run(tmp_path: Path) -> None:
    context = RunContext(tmp_path / "runs", {"profile": "local-lab"}, run_id="status-v4")
    context.write_text(
        "governance_v4/action_ledger/events.jsonl",
        "\n".join(
            json.dumps(item)
            for item in (
                {"action_id": "a", "state": "evidence_committed"},
                {"action_id": "b", "state": "cleanup_required"},
            )
        )
        + "\n",
    )
    context.write_text(
        "governance_v4/budget_ledger/events.jsonl",
        "\n".join(
            json.dumps(item)
            for item in (
                {
                    "event_type": "reserved",
                    "reservation_id": "task-a:initial",
                    "reserved_microusd": 250_000,
                },
                {
                    "event_type": "settled",
                    "reservation_id": "task-a:initial",
                    "actual_cost_microusd": None,
                },
            )
        )
        + "\n",
    )
    state = VerticalStateV4(
        run_id=context.run_id,
        execution_state=ExecutionStateV4.AWAITING_REVIEW,
        network_state=NetworkStateV4.USED,
        requests_planned=4,
        requests_used=1,
        requests_blocked=0,
    )

    payload = status_payload_v4(context, state)

    assert payload["requests_used"] == 1
    assert payload["ledger"] == {
        "planned": 2,
        "executed": 1,
        "blocked": 0,
        "cleanup_required": 1,
    }
    assert payload["budget"] == {
        "integrity": "valid",
        "attempts_reserved": 1,
        "attempts_settled": 1,
        "attempts_remaining": 63,
        "reserved_microusd": 250_000,
        "reserved_remaining_microusd": 15_750_000,
        "actual_cost_microusd": None,
    }
    assert payload["artifacts"]["action_ledger"] == "governance_v4/action_ledger/events.jsonl"
    assert payload["artifacts"]["budget_ledger"] == "governance_v4/budget_ledger/events.jsonl"


def test_failed_v4_state_returns_nonzero_exit_code() -> None:
    failed = VerticalStateV4(
        run_id="failed-v4",
        execution_state=ExecutionStateV4.FAILED,
        network_state=NetworkStateV4.USED,
        requests_planned=4,
        requests_used=4,
        requests_blocked=0,
        cleanup_state="restored",
        failure_code="interrupted_mutation_recovered",
    )
    completed = failed.model_copy(update={"execution_state": ExecutionStateV4.COMPLETED})

    assert _state_exit(failed) == 1
    assert _state_exit(completed) == 0


def test_cleanup_required_run_failure_keeps_cleanup_exit_code(monkeypatch, capsys) -> None:
    state = VerticalStateV4(
        run_id="cleanup-required-v4",
        execution_state=ExecutionStateV4.CLEANUP_REQUIRED,
        network_state=NetworkStateV4.REQUESTED,
        requests_planned=4,
        requests_used=3,
        requests_blocked=0,
        cleanup_state="required",
        failure_code="governedexecutionv4error",
    )

    def fail(_args):
        raise cli.CliRunFailure(state, RuntimeError("cleanup transport failed"))

    monkeypatch.setattr(cli, "_execute", fail)

    assert cli.main(["--json", "doctor", "--config", "/unused/config.json"]) == 23
    assert json.loads(capsys.readouterr().out)["execution_state"] == "cleanup_required"

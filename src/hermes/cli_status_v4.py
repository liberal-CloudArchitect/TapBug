"""Read-only status projection for the isolated Phase 5 workflow.

V4 deliberately does not instantiate its ledgers while reporting status.  A
status command must remain safe to run against a damaged or historical run, so
it only counts committed immutable artifacts and never creates governance
directories as a side effect.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Protocol

from .domain_contracts_v4 import ExecutionBudgetV4
from .runtime import RunContext


class V4StateLike(Protocol):
    """The narrow state surface needed by the operator status command."""

    version: str
    execution_state: Any
    network_state: Any
    requests_planned: int
    requests_used: int
    requests_blocked: int
    current_role: str | None
    next_required_action: str | None
    cleanup_state: str
    artifacts: dict[str, str]


def _json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"could not read V4 status artifact: {path}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"V4 status artifact is not an object: {path}")
    return value


def _artifact_paths(context: RunContext, state: V4StateLike) -> dict[str, str]:
    known = {
        **state.artifacts,
        "state": "state.json",
        "run_plan": "plan/run-v4.json",
        "scope": "scope.json",
        "campaign": "verification_v4/campaign.json",
        "quality": "quality/receipt-v4.json",
        "findings": "report/finding-set-v4.json",
        "coverage": "report/coverage-v4.json",
        "report": "report/report-v4.md",
        "action_ledger": "governance_v4/action_ledger/events.jsonl",
        "budget_ledger": "governance_v4/budget_ledger/events.jsonl",
        "cleanup_receipt": "verification_v4/cleanup.json",
    }
    return {
        key: relative
        for key, relative in sorted(known.items())
        if context.artifact_path(relative).exists()
    }


def _ledger_counts(context: RunContext) -> dict[str, int]:
    path = context.artifact_path("governance_v4/action_ledger/events.jsonl")
    if not path.is_file():
        return {"planned": 0, "executed": 0, "blocked": 0, "cleanup_required": 0}
    latest: dict[str, str] = {}
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            item = json.loads(line)
            if not isinstance(item, dict) or not isinstance(item.get("action_id"), str):
                raise ValueError("malformed V4 action ledger record")
            latest[item["action_id"]] = str(item.get("state", ""))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("could not read V4 action ledger") from exc
    return {
        "planned": len(latest),
        "executed": sum(value in {"evidence_committed", "cleaned"} for value in latest.values()),
        "blocked": sum(
            value in {"failed_before_transport", "failed_after_transport", "indeterminate"}
            for value in latest.values()
        ),
        "cleanup_required": sum(value == "cleanup_required" for value in latest.values()),
    }


def _budget_status(context: RunContext) -> dict[str, int | None | str]:
    """Project the append-only model-budget ledger without instantiating it.

    ``VerticalStateV4`` intentionally is not the accounting authority: an ACP
    child can settle while its parent is between state checkpoints.  Status
    must therefore re-read the immutable journal and make malformed journals
    visible instead of reporting an invented zero-cost result.
    """

    budget = ExecutionBudgetV4()
    path = context.artifact_path("governance_v4/budget_ledger/events.jsonl")
    if not path.is_file():
        return {
            "integrity": "absent",
            "attempts_reserved": 0,
            "attempts_settled": 0,
            "attempts_remaining": budget.max_model_attempts,
            "reserved_microusd": 0,
            "reserved_remaining_microusd": budget.max_estimated_cost_microusd,
            "actual_cost_microusd": None,
        }
    reservations: dict[str, int] = {}
    settled: dict[str, int | None] = {}
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            item = json.loads(line)
            if not isinstance(item, dict):
                raise ValueError("record is not an object")
            reservation_id = item.get("reservation_id")
            event_type = item.get("event_type")
            if not isinstance(reservation_id, str) or event_type not in {"reserved", "settled"}:
                raise ValueError("record has no supported reservation event")
            if event_type == "reserved":
                amount = item.get("reserved_microusd")
                if type(amount) is not int or amount < 0 or reservation_id in reservations:
                    raise ValueError("invalid or duplicate reservation")
                reservations[reservation_id] = amount
            else:
                if reservation_id not in reservations or reservation_id in settled:
                    raise ValueError("settlement has no unique reservation")
                actual = item.get("actual_cost_microusd")
                if actual is not None and (type(actual) is not int or actual < 0):
                    raise ValueError("invalid actual cost")
                settled[reservation_id] = actual
    except (OSError, ValueError, json.JSONDecodeError):
        return {
            "integrity": "invalid",
            "attempts_reserved": 0,
            "attempts_settled": 0,
            "attempts_remaining": 0,
            "reserved_microusd": 0,
            "reserved_remaining_microusd": 0,
            "actual_cost_microusd": None,
        }
    reserved = sum(reservations.values())
    actual_values = tuple(settled.values())
    return {
        "integrity": "valid",
        "attempts_reserved": len(reservations),
        "attempts_settled": len(settled),
        "attempts_remaining": max(0, budget.max_model_attempts - len(reservations)),
        "reserved_microusd": reserved,
        "reserved_remaining_microusd": max(0, budget.max_estimated_cost_microusd - reserved),
        "actual_cost_microusd": (
            None
            if any(value is None for value in actual_values)
            else sum(value for value in actual_values if value is not None)
        ),
    }


def status_payload_v4(context: RunContext, state: V4StateLike) -> dict[str, Any]:
    """Return the machine-readable Phase 5 status without mutating a run."""

    evidence = tuple(context.artifact_path("evidence").glob("*/manifest.json"))
    ledger = _ledger_counts(context)
    used = max(state.requests_used, len(evidence))
    network = "used" if used else str(getattr(state.network_state, "value", state.network_state))
    return {
        "version": "4",
        "run_id": context.run_id,
        "execution_state": str(getattr(state.execution_state, "value", state.execution_state)),
        "network_state": network,
        "requests_planned": state.requests_planned,
        "requests_used": used,
        "requests_blocked": max(state.requests_blocked, ledger["blocked"]),
        "current_role": state.current_role,
        "next_required_action": state.next_required_action,
        "cleanup_state": state.cleanup_state,
        "ledger": ledger,
        "budget": _budget_status(context),
        "artifacts": _artifact_paths(context, state),
    }


__all__ = ["status_payload_v4"]

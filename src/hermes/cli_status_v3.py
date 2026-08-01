"""Read-only Phase 4 status projection.

The operator status command must not instantiate the mutable governance ledger
classes: their constructors intentionally create missing directories and
configuration records.  This module instead validates the persisted hash chains
and immutable claims directly, then derives one machine-readable projection.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

from .domain_contracts_v3 import BranchResult, CleanupReceipt, VerificationCampaignPlan
from .ledgers_v3 import ActionLedgerState, LedgerIntegrityError
from .runtime import RunContext
from .vertical_v3 import ExecutionStateV3, NetworkStateV3, VerticalStateV3

_ACTION_STATES = tuple(item.value for item in ActionLedgerState)
_BRANCHES = ("web", "api", "authz", "infra")
_MAX_ATTEMPTS = 40
_RESERVATION_MICROUSD = 250_000
_MAX_ESTIMATED_MICROUSD = 10_000_000


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LedgerIntegrityError(f"could not read status artifact {path}") from exc
    if not isinstance(value, dict):
        raise LedgerIntegrityError(f"status artifact is not an object: {path}")
    return value


def _journal(path: Path, ledger: str) -> tuple[dict[str, Any], ...]:
    if not path.exists():
        return ()
    previous: str | None = None
    records: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise LedgerIntegrityError(f"could not read {ledger} journal") from exc
    for sequence, line in enumerate(lines, start=1):
        if not line:
            raise LedgerIntegrityError(f"{ledger} journal contains an empty line")
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise LedgerIntegrityError(f"{ledger} journal contains invalid JSON") from exc
        if not isinstance(record, dict):
            raise LedgerIntegrityError(f"{ledger} journal record is not an object")
        event_hash = record.get("event_hash")
        unsigned = {key: value for key, value in record.items() if key != "event_hash"}
        if (
            record.get("ledger") != ledger
            or record.get("sequence") != sequence
            or record.get("previous_hash") != previous
            or event_hash != _digest(unsigned)
        ):
            raise LedgerIntegrityError(f"{ledger} journal hash chain is invalid")
        previous = str(event_hash)
        records.append(record)
    return tuple(records)


def _claims(
    root: Path,
    *,
    run_id: str,
    scope_digest: str,
    identity_field: str,
) -> tuple[dict[str, Any], ...]:
    if not root.exists():
        return ()
    claims: list[dict[str, Any]] = []
    for path in sorted(root.glob("*.json")):
        raw = _json(path)
        claim_digest = raw.pop("claim_digest", None)
        if (
            claim_digest != _digest(raw)
            or raw.get("run_id") != run_id
            or raw.get("scope_digest") != scope_digest
            or not raw.get(identity_field)
        ):
            raise LedgerIntegrityError(f"governance claim is invalid: {path}")
        claims.append(raw)
    return tuple(claims)


def _action_status(context: RunContext) -> dict[str, Any]:
    root = context.artifact_path("governance_v3/action_ledger")
    events = _journal(root / "events.jsonl", "action_v3")
    claims = _claims(
        root / "claims",
        run_id=context.run_id,
        scope_digest=context.scope_digest,
        identity_field="fingerprint",
    )
    claimed = {str(item["fingerprint"]) for item in claims}
    journaled = {str(item.get("fingerprint")) for item in events}
    if claimed != journaled:
        raise LedgerIntegrityError("action claim and journal fingerprint sets differ")
    latest: dict[str, dict[str, Any]] = {}
    for event in events:
        fingerprint = str(event["fingerprint"])
        latest[fingerprint] = event
    counts = Counter(str(item["state"]) for item in latest.values())
    unknown = set(counts).difference(_ACTION_STATES)
    if unknown:
        raise LedgerIntegrityError(f"action ledger has unknown states: {sorted(unknown)}")
    return {
        "entries": len(latest),
        "events": len(events),
        "state_counts": {state: counts[state] for state in _ACTION_STATES},
        "latest_event_hash": events[-1]["event_hash"] if events else None,
    }


def _budget_status(context: RunContext) -> dict[str, Any]:
    root = context.artifact_path("governance_v3/budget_ledger")
    events = _journal(root / "events.jsonl", "budget_v3")
    claims = _claims(
        root / "claims",
        run_id=context.run_id,
        scope_digest=context.scope_digest,
        identity_field="reservation_id",
    )
    claim_ids = {str(item["reservation_id"]) for item in claims}
    reserved_ids = {
        str(item["reservation_id"]) for item in events if item.get("event_type") == "reserved"
    }
    if claim_ids != reserved_ids:
        raise LedgerIntegrityError("budget claim and reservation event sets differ")
    settlements = {
        str(item["reservation_id"]): item for item in events if item.get("event_type") == "settled"
    }
    if not set(settlements) <= claim_ids:
        raise LedgerIntegrityError("budget settlement has no reservation")
    reserved = len(claims)
    estimated = sum(int(item["reserved_microusd"]) for item in claims)
    if any(int(item["reserved_microusd"]) != _RESERVATION_MICROUSD for item in claims):
        raise LedgerIntegrityError("budget claim uses a non-canonical reservation")
    actual_complete = len(settlements) == reserved and all(
        item.get("actual_cost_microusd") is not None for item in settlements.values()
    )
    actual = (
        sum(int(item["actual_cost_microusd"]) for item in settlements.values())
        if actual_complete
        else None
    )
    return {
        "attempts_reserved": reserved,
        "attempts_settled": len(settlements),
        "estimated_microusd": estimated,
        "actual_microusd": actual,
        "actual_cost_complete": actual_complete,
        "remaining_attempts": max(0, _MAX_ATTEMPTS - reserved),
        "remaining_estimated_microusd": max(0, _MAX_ESTIMATED_MICROUSD - estimated),
        "latest_event_hash": events[-1]["event_hash"] if events else None,
    }


def _branch_status(context: RunContext) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for branch in _BRANCHES:
        relative = f"collaboration_v3/branch-results/{branch}.json"
        path = context.artifact_path(relative)
        if not path.is_file():
            result[branch] = {"status": "pending", "artifact": None}
            continue
        item = BranchResult.model_validate(_json(path))
        if item.run_id != context.run_id or item.scope_digest != context.scope_digest:
            raise LedgerIntegrityError(f"{branch} result crosses run or scope")
        result[branch] = {
            "status": item.status,
            "reason": item.reason,
            "task_id": item.generated_by_task_id,
            "artifact": relative,
        }
    return result


def _cleanup_status(context: RunContext, state: VerticalStateV3) -> dict[str, Any]:
    relative = "verification_v3/cleanup.json"
    path = context.artifact_path(relative)
    if path.is_file():
        receipt = CleanupReceipt.model_validate(_json(path))
        if receipt.run_id != context.run_id or receipt.scope_digest != context.scope_digest:
            raise LedgerIntegrityError("cleanup receipt crosses run or scope")
        return {
            "status": "restored" if receipt.state_restored else "required",
            "state_restored": receipt.state_restored,
            "receipt_digest": receipt.digest,
            "receipt": relative,
        }
    challenge = "approvals_v3/challenge-cleanup.json"
    return {
        "status": state.cleanup_state,
        "state_restored": False,
        "receipt_digest": None,
        "receipt": None,
        "challenge": challenge if context.artifact_path(challenge).is_file() else None,
    }


def _artifact_paths(context: RunContext, state: VerticalStateV3) -> dict[str, str]:
    known = {
        **state.artifacts,
        "state": "state.json",
        "run_plan": "plan/run-v3.json",
        "scope": "scope.json",
        "route": "collaboration_v3/route.json",
        "campaign": "verification_v3/campaign.json",
        "action_ledger": "governance_v3/action_ledger/events.jsonl",
        "budget_ledger": "governance_v3/budget_ledger/events.jsonl",
        "cleanup_receipt": "verification_v3/cleanup.json",
        "coverage": "report/coverage-v3.json",
        "report": "report/report-v3.md",
    }
    return {
        key: relative
        for key, relative in sorted(known.items())
        if context.artifact_path(relative).exists()
    }


def _current_role(state: VerticalStateV3) -> str | None:
    if state.current_role is not None:
        return state.current_role
    return {
        ExecutionStateV3.ROUTING: "route-policy",
        ExecutionStateV3.ASSESSING: "web-vuln|api|authz|infra",
        ExecutionStateV3.CROSS_REVIEWING: "cross-review",
        ExecutionStateV3.VERIFYING_READONLY: "verifier",
        ExecutionStateV3.VERIFYING_MUTATION: "verifier",
    }.get(state.execution_state)


def status_payload_v3(context: RunContext, state: VerticalStateV3) -> dict[str, Any]:
    """Return a validated status projection without modifying the run."""

    campaign_path = context.artifact_path("verification_v3/campaign.json")
    planned = state.requests_planned
    if campaign_path.is_file():
        campaign = VerificationCampaignPlan.model_validate(_json(campaign_path))
        if campaign.run_id != context.run_id or campaign.scope_digest != context.scope_digest:
            raise LedgerIntegrityError("campaign crosses run or scope")
        planned = campaign.request_budget + 1
    evidence = tuple(context.artifact_path("evidence").glob("*/manifest.json"))
    used = len(evidence)
    actions = _action_status(context)
    latest_counts = actions["state_counts"]
    blocked = max(
        state.requests_blocked,
        int(latest_counts["failed_before_transport"])
        + int(latest_counts["failed_after_transport"])
        + int(latest_counts["indeterminate"]),
    )
    if used:
        network = NetworkStateV3.USED.value
    elif latest_counts["transport_started"]:
        network = NetworkStateV3.REQUESTED.value
    else:
        network = state.network_state.value
    return {
        "version": "3",
        "run_id": context.run_id,
        "execution_state": state.execution_state.value,
        "network_state": network,
        "requests_planned": planned,
        "requests_used": used,
        "requests_blocked": blocked,
        "current_role": _current_role(state),
        "next_required_action": state.next_required_action,
        "branches": _branch_status(context),
        "budget": _budget_status(context),
        "action_ledger": actions,
        "cleanup": _cleanup_status(context, state),
        "artifact_paths": _artifact_paths(context, state),
        "last_successful_checkpoint": state.last_successful_checkpoint,
        "failure_code": state.failure_code,
    }


__all__ = ["status_payload_v3"]

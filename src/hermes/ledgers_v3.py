"""Persistent V3 execution-governance ledgers.

The ledgers in this module are parent-runtime authorities.  Agent processes may
describe work, but only these ledgers may reserve model budget, authorize an
action attempt, or account for active run time.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
import uuid
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator

from hermes.runtime.context import RunContext


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _utc_timestamp(epoch_seconds: float) -> str:
    from datetime import UTC, datetime

    return datetime.fromtimestamp(epoch_seconds, UTC).isoformat().replace("+00:00", "Z")


def _safe_claim_name(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest() + ".json"


_LOCKS_GUARD = threading.Lock()
_PATH_LOCKS: dict[str, threading.RLock] = {}


def _thread_lock(path: Path) -> threading.RLock:
    key = str(path.resolve())
    with _LOCKS_GUARD:
        return _PATH_LOCKS.setdefault(key, threading.RLock())


@contextmanager
def _locked(context: RunContext, root: Path) -> Iterator[None]:
    """Serialize threads and processes that mutate a run ledger."""

    with _thread_lock(root):
        with context.lock():
            yield


class LedgerError(RuntimeError):
    """A persisted ledger is invalid or cannot authorize the operation."""


class LedgerIntegrityError(LedgerError):
    """A claim or hash-chained journal failed integrity validation."""


class ActionReservationConflict(LedgerError):
    """Another task already owns an unfinished action reservation."""


class ActionRetryDenied(LedgerError):
    """An action with an unknown or post-transport result cannot be retried."""


class BudgetExceeded(LedgerError):
    """A model call would exceed its pre-execution reservation budget."""


class ActiveTimeExceeded(LedgerError):
    """The persisted active-execution deadline has been exhausted."""


class _HashChainedJournal:
    def __init__(self, path: Path, *, ledger: str) -> None:
        self.path = path
        self.ledger = ledger

    def read_locked(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        previous_hash: str | None = None
        records: list[dict[str, Any]] = []
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
            for expected_sequence, line in enumerate(lines, start=1):
                if not line:
                    raise LedgerIntegrityError(f"{self.ledger} journal contains an empty line")
                record = json.loads(line)
                if not isinstance(record, dict):
                    raise LedgerIntegrityError(f"{self.ledger} journal record is not an object")
                event_hash = record.get("event_hash")
                unsigned = {key: value for key, value in record.items() if key != "event_hash"}
                if record.get("ledger") != self.ledger:
                    raise LedgerIntegrityError(f"{self.ledger} journal ledger mismatch")
                if record.get("sequence") != expected_sequence:
                    raise LedgerIntegrityError(f"{self.ledger} journal sequence mismatch")
                if record.get("previous_hash") != previous_hash:
                    raise LedgerIntegrityError(f"{self.ledger} journal previous hash mismatch")
                if event_hash != _digest(unsigned):
                    raise LedgerIntegrityError(f"{self.ledger} journal event hash mismatch")
                previous_hash = event_hash
                records.append(record)
        except (OSError, json.JSONDecodeError, TypeError) as exc:
            raise LedgerIntegrityError(f"could not validate {self.ledger} journal") from exc
        return records

    def append_locked(self, fields: Mapping[str, Any]) -> dict[str, Any]:
        records = self.read_locked()
        unsigned = {
            "ledger": self.ledger,
            "sequence": len(records) + 1,
            "previous_hash": records[-1]["event_hash"] if records else None,
            **dict(fields),
        }
        record = {**unsigned, "event_hash": _digest(unsigned)}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(
                json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            )
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        return record


class ActionRisk(StrEnum):
    READONLY = "readonly"
    MUTATION = "mutation"
    CLEANUP = "cleanup"


class ActionLedgerState(StrEnum):
    PLANNED = "planned"
    RESERVED = "reserved"
    TRANSPORT_STARTED = "transport_started"
    EVIDENCE_COMMITTED = "evidence_committed"
    FAILED_BEFORE_TRANSPORT = "failed_before_transport"
    FAILED_AFTER_TRANSPORT = "failed_after_transport"
    INDETERMINATE = "indeterminate"
    CLEANUP_REQUIRED = "cleanup_required"
    CLEANED = "cleaned"


class ActionFingerprint(BaseModel):
    """Canonical action identity; branch names and rationale are deliberately absent.

    ``causal_dependency_digest`` separates otherwise identical requests that
    occur in different committed-state epochs.  For example, a GET used to
    establish a mutation baseline must never be reused as the GET proving that
    the later compensation restored state.  It is parent-derived solely from
    the signed action graph; agents cannot select it.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: str = Field(min_length=1, max_length=256)
    scope_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    action_kind: str = Field(min_length=1, max_length=128)
    method: str = Field(min_length=1, max_length=16)
    canonical_url: str = Field(min_length=1, max_length=4096)
    canonical_body_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    identity_binding_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    causal_dependency_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    risk: ActionRisk

    @field_validator("method")
    @classmethod
    def normalize_method(cls, value: str) -> str:
        return value.upper()

    @property
    def digest(self) -> str:
        return _digest(self.model_dump(mode="json"))


class ActionReservation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    fingerprint: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    action_id: str
    action_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    owner_task_id: str
    disposition: Literal["owner", "reused"]
    state: ActionLedgerState
    candidate_consumers: tuple[str, ...] = ()
    evidence_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    approval_batch_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    consumption_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")


_ACTION_TRANSITIONS: dict[ActionLedgerState, frozenset[ActionLedgerState]] = {
    ActionLedgerState.PLANNED: frozenset({ActionLedgerState.RESERVED}),
    ActionLedgerState.RESERVED: frozenset(
        {
            ActionLedgerState.TRANSPORT_STARTED,
            ActionLedgerState.FAILED_BEFORE_TRANSPORT,
            ActionLedgerState.INDETERMINATE,
        }
    ),
    ActionLedgerState.TRANSPORT_STARTED: frozenset(
        {
            ActionLedgerState.EVIDENCE_COMMITTED,
            ActionLedgerState.FAILED_AFTER_TRANSPORT,
            ActionLedgerState.INDETERMINATE,
            ActionLedgerState.CLEANUP_REQUIRED,
        }
    ),
    ActionLedgerState.EVIDENCE_COMMITTED: frozenset({ActionLedgerState.CLEANUP_REQUIRED}),
    ActionLedgerState.FAILED_BEFORE_TRANSPORT: frozenset({ActionLedgerState.RESERVED}),
    ActionLedgerState.FAILED_AFTER_TRANSPORT: frozenset({ActionLedgerState.CLEANUP_REQUIRED}),
    ActionLedgerState.INDETERMINATE: frozenset({ActionLedgerState.CLEANUP_REQUIRED}),
    ActionLedgerState.CLEANUP_REQUIRED: frozenset({ActionLedgerState.CLEANED}),
    ActionLedgerState.CLEANED: frozenset(),
}


class ActionLedger:
    """Atomic action reservation and lifecycle authority for one run."""

    def __init__(self, context: RunContext, *, clock: Callable[[], float] = time.time) -> None:
        self.context = context
        self.clock = clock
        self.root = context.artifact_path("governance_v3/action_ledger")
        self.claims = self.root / "claims"
        self.claims.mkdir(parents=True, exist_ok=True)
        self.journal = _HashChainedJournal(self.root / "events.jsonl", ledger="action_v3")

    def reserve(
        self,
        action: ActionFingerprint,
        *,
        owner_task_id: str,
        candidate_consumers: Sequence[str] = (),
        action_id: str | None = None,
        action_digest: str | None = None,
    ) -> ActionReservation:
        self._validate_context(action)
        action_id = action_id or f"action-{action.digest[7:31]}"
        action_digest = action_digest or action.digest
        if not action_id or not _is_digest(action_digest):
            raise ValueError("action_id and canonical action_digest are required")
        consumers = tuple(sorted(set(candidate_consumers)))
        with _locked(self.context, self.root):
            events = self.journal.read_locked()
            latest = self._latest(events, action.digest)
            claim_path = self.claims / _safe_claim_name(action.digest)
            if latest is None:
                claim = {
                    "schema_version": "3",
                    "run_id": action.run_id,
                    "scope_digest": action.scope_digest,
                    "fingerprint": action.digest,
                    "action": action.model_dump(mode="json"),
                    "action_id": action_id,
                    "action_digest": action_digest,
                    "initial_owner_task_id": owner_task_id,
                }
                if claim_path.exists():
                    # A claim without its journal commit is an unknown attempt.
                    # Retrying it would also turn journal deletion into an action
                    # replay primitive, so recovery is deliberately fail-closed.
                    self._validate_claim(claim_path, action)
                    raise ActionRetryDenied(
                        f"action {action.digest} has a claim without a journal commit; "
                        "its state is indeterminate"
                    )
                else:
                    signed_claim = {**claim, "claim_digest": _digest(claim)}
                    relative = str(claim_path.relative_to(self.context.path))
                    self.context.write_json_exclusive(relative, signed_claim)
                self._append_action_locked(
                    action,
                    state=ActionLedgerState.PLANNED,
                    previous_state=None,
                    action_id=action_id,
                    action_digest=action_digest,
                    owner_task_id=owner_task_id,
                    consumers=consumers,
                )
                latest = self._append_action_locked(
                    action,
                    state=ActionLedgerState.RESERVED,
                    previous_state=ActionLedgerState.PLANNED,
                    action_id=action_id,
                    action_digest=action_digest,
                    owner_task_id=owner_task_id,
                    consumers=consumers,
                )
                return self._reservation(latest, disposition="owner")

            self._validate_claim(claim_path, action)
            persisted_claim = self._load_action_claim(claim_path)
            if (
                persisted_claim.get("action_id") != action_id
                or persisted_claim.get("action_digest") != action_digest
            ):
                raise ActionReservationConflict(
                    "semantic action fingerprint is bound to a different canonical action"
                )
            state = ActionLedgerState(latest["state"])
            if state is ActionLedgerState.EVIDENCE_COMMITTED:
                merged = tuple(sorted(set(latest.get("candidate_consumers", ())) | set(consumers)))
                if merged != tuple(latest.get("candidate_consumers", ())):
                    latest = self._append_action_locked(
                        action,
                        state=state,
                        previous_state=state,
                        action_id=str(latest["action_id"]),
                        action_digest=str(latest["action_digest"]),
                        owner_task_id=str(latest["owner_task_id"]),
                        consumers=merged,
                        evidence_digest=latest.get("evidence_digest"),
                        approval_batch_digest=latest.get("approval_batch_digest"),
                        consumption_digest=latest.get("consumption_digest"),
                        event_type="evidence_reused",
                    )
                return self._reservation(latest, disposition="reused")
            if state in {
                ActionLedgerState.FAILED_AFTER_TRANSPORT,
                ActionLedgerState.INDETERMINATE,
            }:
                raise ActionRetryDenied(
                    f"action {action.digest} is {state.value}; retry is forbidden"
                )
            if state in {ActionLedgerState.CLEANUP_REQUIRED, ActionLedgerState.CLEANED}:
                raise ActionRetryDenied(
                    f"action {action.digest} requires or completed cleanup; "
                    "forward retry is forbidden"
                )
            if state is ActionLedgerState.FAILED_BEFORE_TRANSPORT:
                latest = self._append_action_locked(
                    action,
                    state=ActionLedgerState.RESERVED,
                    previous_state=state,
                    action_id=str(latest["action_id"]),
                    action_digest=str(latest["action_digest"]),
                    owner_task_id=owner_task_id,
                    consumers=consumers,
                    event_type="safe_retry_reserved",
                )
                return self._reservation(latest, disposition="owner")
            if state is ActionLedgerState.RESERVED and latest["owner_task_id"] == owner_task_id:
                return self._reservation(latest, disposition="owner")
            raise ActionReservationConflict(
                f"action {action.digest} is already owned by {latest['owner_task_id']}"
            )

    def mark_transport_started(
        self,
        reservation: ActionReservation,
        *,
        approval_batch_digest: str | None = None,
        consumption_digest: str | None = None,
    ) -> ActionReservation:
        return self.transition(
            reservation,
            ActionLedgerState.TRANSPORT_STARTED,
            approval_batch_digest=approval_batch_digest,
            consumption_digest=consumption_digest,
        )

    def mark_evidence_committed(
        self, reservation: ActionReservation, *, evidence_digest: str
    ) -> ActionReservation:
        return self.transition(
            reservation, ActionLedgerState.EVIDENCE_COMMITTED, evidence_digest=evidence_digest
        )

    def mark_failed_before_transport(self, reservation: ActionReservation) -> ActionReservation:
        return self.transition(reservation, ActionLedgerState.FAILED_BEFORE_TRANSPORT)

    def mark_failed_after_transport(self, reservation: ActionReservation) -> ActionReservation:
        return self.transition(reservation, ActionLedgerState.FAILED_AFTER_TRANSPORT)

    def mark_indeterminate(self, reservation: ActionReservation) -> ActionReservation:
        return self.transition(reservation, ActionLedgerState.INDETERMINATE)

    def mark_cleanup_required(self, reservation: ActionReservation) -> ActionReservation:
        return self.transition(reservation, ActionLedgerState.CLEANUP_REQUIRED)

    def mark_cleaned(
        self, reservation: ActionReservation, *, cleanup_receipt_digest: str
    ) -> ActionReservation:
        return self.transition(
            reservation, ActionLedgerState.CLEANED, evidence_digest=cleanup_receipt_digest
        )

    def transition(
        self,
        reservation: ActionReservation,
        state: ActionLedgerState,
        *,
        evidence_digest: str | None = None,
        approval_batch_digest: str | None = None,
        consumption_digest: str | None = None,
    ) -> ActionReservation:
        if reservation.disposition != "owner":
            raise ActionReservationConflict("a reused action reservation cannot be transitioned")
        if evidence_digest is not None and not _is_digest(evidence_digest):
            raise ValueError("evidence_digest must be a canonical sha256 digest")
        if (approval_batch_digest is None) != (consumption_digest is None):
            raise ValueError("approval and consumption bindings must be supplied together")
        if approval_batch_digest is not None and (
            not _is_digest(approval_batch_digest) or not _is_digest(consumption_digest or "")
        ):
            raise ValueError("approval and consumption bindings must be canonical digests")
        with _locked(self.context, self.root):
            events = self.journal.read_locked()
            latest = self._latest(events, reservation.fingerprint)
            if latest is None:
                raise LedgerIntegrityError("action reservation has no journal event")
            previous = ActionLedgerState(latest["state"])
            if latest["owner_task_id"] != reservation.owner_task_id:
                raise ActionReservationConflict("action reservation owner does not match")
            if state not in _ACTION_TRANSITIONS[previous]:
                raise LedgerError(f"invalid action transition: {previous.value} -> {state.value}")
            if state in {ActionLedgerState.EVIDENCE_COMMITTED, ActionLedgerState.CLEANED}:
                if evidence_digest is None:
                    raise ValueError(f"{state.value} requires an evidence or receipt digest")
            action = self._action_from_claim(reservation.fingerprint)
            prior_approval = latest.get("approval_batch_digest")
            prior_consumption = latest.get("consumption_digest")
            if approval_batch_digest is not None and prior_approval not in {
                None,
                approval_batch_digest,
            }:
                raise LedgerIntegrityError("action approval binding cannot be replaced")
            if consumption_digest is not None and prior_consumption not in {
                None,
                consumption_digest,
            }:
                raise LedgerIntegrityError("action consumption binding cannot be replaced")
            event = self._append_action_locked(
                action,
                state=state,
                previous_state=previous,
                action_id=str(latest["action_id"]),
                action_digest=str(latest["action_digest"]),
                owner_task_id=reservation.owner_task_id,
                consumers=tuple(latest.get("candidate_consumers", ())),
                evidence_digest=evidence_digest,
                approval_batch_digest=approval_batch_digest or prior_approval,
                consumption_digest=consumption_digest or prior_consumption,
            )
            return self._reservation(event, disposition="owner")

    def events(self) -> tuple[dict[str, Any], ...]:
        with _locked(self.context, self.root):
            events = self.journal.read_locked()
            claims = self._validated_claims_locked()
            claimed = {claim["fingerprint"] for claim in claims}
            journaled = {event.get("fingerprint") for event in events}
            if journaled != claimed:
                raise LedgerIntegrityError("action claim and journal fingerprint sets differ")
            return tuple(events)

    def _validate_context(self, action: ActionFingerprint) -> None:
        if action.run_id != self.context.run_id or action.scope_digest != self.context.scope_digest:
            raise LedgerError("action is bound to a different run or scope")

    def _validate_claim(self, path: Path, action: ActionFingerprint) -> None:
        try:
            claim = json.loads(path.read_text(encoding="utf-8"))
            digest = claim.pop("claim_digest")
        except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
            raise LedgerIntegrityError("action claim is invalid") from exc
        if digest != _digest(claim):
            raise LedgerIntegrityError("action claim digest mismatch")
        if (
            claim.get("run_id") != self.context.run_id
            or claim.get("scope_digest") != self.context.scope_digest
            or claim.get("fingerprint") != action.digest
            or claim.get("action") != action.model_dump(mode="json")
        ):
            raise LedgerIntegrityError("action claim binding mismatch")

    def _action_from_claim(self, fingerprint: str) -> ActionFingerprint:
        path = self.claims / _safe_claim_name(fingerprint)
        value = self._load_action_claim(path)
        return ActionFingerprint.model_validate(value["action"])

    def _validated_claims_locked(self) -> list[dict[str, Any]]:
        return [self._load_action_claim(path) for path in sorted(self.claims.glob("*.json"))]

    def _load_action_claim(self, path: Path) -> dict[str, Any]:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            action = ActionFingerprint.model_validate(value["action"])
        except (OSError, json.JSONDecodeError, KeyError, ValueError) as exc:
            raise LedgerIntegrityError("action claim cannot be loaded") from exc
        self._validate_claim(path, action)
        return cast(dict[str, Any], value)

    @staticmethod
    def _latest(events: Sequence[Mapping[str, Any]], fingerprint: str) -> Mapping[str, Any] | None:
        for event in reversed(events):
            if event.get("fingerprint") == fingerprint:
                return event
        return None

    def _append_action_locked(
        self,
        action: ActionFingerprint,
        *,
        state: ActionLedgerState,
        previous_state: ActionLedgerState | None,
        action_id: str,
        action_digest: str,
        owner_task_id: str,
        consumers: Sequence[str],
        evidence_digest: str | None = None,
        approval_batch_digest: str | None = None,
        consumption_digest: str | None = None,
        event_type: str = "state_transition",
    ) -> dict[str, Any]:
        now = self.clock()
        return self.journal.append_locked(
            {
                "schema_version": "3",
                "event_id": str(uuid.uuid4()),
                "event_type": event_type,
                "occurred_at": _utc_timestamp(now),
                "run_id": self.context.run_id,
                "scope_digest": self.context.scope_digest,
                "fingerprint": action.digest,
                "action_id": action_id,
                "action_digest": action_digest,
                "owner_task_id": owner_task_id,
                "state": state.value,
                "previous_state": previous_state.value if previous_state else None,
                "candidate_consumers": list(consumers),
                "evidence_digest": evidence_digest,
                "approval_batch_digest": approval_batch_digest,
                "consumption_digest": consumption_digest,
            }
        )

    @staticmethod
    def _reservation(
        event: Mapping[str, Any], *, disposition: Literal["owner", "reused"]
    ) -> ActionReservation:
        return ActionReservation(
            fingerprint=str(event["fingerprint"]),
            action_id=str(event["action_id"]),
            action_digest=str(event["action_digest"]),
            owner_task_id=str(event["owner_task_id"]),
            disposition=disposition,
            state=ActionLedgerState(event["state"]),
            candidate_consumers=tuple(event.get("candidate_consumers", ())),
            evidence_digest=event.get("evidence_digest"),
            approval_batch_digest=event.get("approval_batch_digest"),
            consumption_digest=event.get("consumption_digest"),
        )


class BudgetLimitsV3(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    max_prompt_attempts: int = Field(default=40, ge=1, le=40)
    reservation_microusd: int = Field(default=250_000, ge=1)
    max_estimated_cost_microusd: int = Field(default=10_000_000, ge=1)


class BudgetReservation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    reservation_id: str
    task_id: str
    role: str
    attempt_kind: Literal["initial", "schema_repair", "reporter"]
    attempt_number: int = Field(ge=1, le=40)
    reserved_microusd: int
    sequence: int


class BudgetSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    reserved_attempts: int
    reserved_microusd: int
    settled_attempts: int
    actual_cost_microusd: int | None
    actual_cost_complete: bool


class BudgetLedger:
    """Persistent, pre-execution model-call budget with no concurrent oversell."""

    def __init__(
        self,
        context: RunContext,
        *,
        limits: BudgetLimitsV3 | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.context = context
        self.limits = limits or BudgetLimitsV3()
        self.clock = clock
        self.root = context.artifact_path("governance_v3/budget_ledger")
        self.claims = self.root / "claims"
        self.claims.mkdir(parents=True, exist_ok=True)
        self.journal = _HashChainedJournal(self.root / "events.jsonl", ledger="budget_v3")
        _persist_ledger_config(
            context,
            self.root,
            "limits.json",
            {
                "ledger": "budget_v3",
                "schema_version": "3",
                "run_id": context.run_id,
                "scope_digest": context.scope_digest,
                "limits": self.limits.model_dump(mode="json"),
            },
        )

    def reserve_prompt(
        self,
        *,
        task_id: str,
        role: str,
        attempt_kind: Literal["initial", "schema_repair", "reporter"] = "initial",
        reservation_id: str | None = None,
    ) -> BudgetReservation:
        reservation_id = reservation_id or str(uuid.uuid4())
        if not reservation_id or not task_id or not role:
            raise ValueError("reservation_id, task_id, and role must be non-empty")
        claim_path = self.claims / _safe_claim_name(reservation_id)
        with _locked(self.context, self.root):
            events = self.journal.read_locked()
            claims = self._validated_claims_locked()
            self._validate_claim_event_bindings_locked(events, claims)
            existing = self._load_claim(claim_path) if claim_path.exists() else None
            expected = {
                "schema_version": "3",
                "run_id": self.context.run_id,
                "scope_digest": self.context.scope_digest,
                "reservation_id": reservation_id,
                "task_id": task_id,
                "role": role,
                "attempt_kind": attempt_kind,
                "reserved_microusd": self.limits.reservation_microusd,
            }
            if existing is not None:
                if any(existing.get(key) != value for key, value in expected.items()):
                    raise LedgerIntegrityError("budget reservation id is bound to different work")
                event = self._reservation_event(events, reservation_id)
                if event is None:
                    raise LedgerIntegrityError("budget claim has no reservation journal event")
                return self._budget_reservation(event)

            next_attempt = len(claims) + 1
            next_cost = next_attempt * self.limits.reservation_microusd
            if next_attempt > self.limits.max_prompt_attempts:
                raise BudgetExceeded("model prompt attempt budget exhausted")
            if next_cost > self.limits.max_estimated_cost_microusd:
                raise BudgetExceeded("model estimated cost budget exhausted")
            claim = {**expected, "attempt_number": next_attempt}
            signed = {**claim, "claim_digest": _digest(claim)}
            relative = str(claim_path.relative_to(self.context.path))
            self.context.write_json_exclusive(relative, signed)
            event = self._append_budget_reservation_locked(claim)
            return self._budget_reservation(event)

    def settle(
        self,
        reservation_id: str,
        *,
        token_usage: Mapping[str, int] | None = None,
        actual_cost_microusd: int | None = None,
    ) -> dict[str, Any]:
        if actual_cost_microusd is not None and actual_cost_microusd < 0:
            raise ValueError("actual_cost_microusd cannot be negative")
        normalized_usage = None if token_usage is None else dict(sorted(token_usage.items()))
        if normalized_usage is not None and any(
            not isinstance(value, int) or value < 0 for value in normalized_usage.values()
        ):
            raise ValueError("token usage values must be non-negative integers")
        claim_path = self.claims / _safe_claim_name(reservation_id)
        with _locked(self.context, self.root):
            claim = self._load_claim(claim_path)
            events = self.journal.read_locked()
            self._validate_claim_event_bindings_locked(events, self._validated_claims_locked())
            settled = next(
                (
                    event
                    for event in reversed(events)
                    if event.get("event_type") == "settled"
                    and event.get("reservation_id") == reservation_id
                ),
                None,
            )
            values = {
                "token_usage": normalized_usage,
                "actual_cost_microusd": actual_cost_microusd,
            }
            if settled is not None:
                if any(settled.get(key) != value for key, value in values.items()):
                    raise LedgerIntegrityError(
                        "budget reservation was settled with different usage"
                    )
                return settled
            now = self.clock()
            return self.journal.append_locked(
                {
                    "schema_version": "3",
                    "event_id": str(uuid.uuid4()),
                    "event_type": "settled",
                    "occurred_at": _utc_timestamp(now),
                    "run_id": self.context.run_id,
                    "scope_digest": self.context.scope_digest,
                    "reservation_id": reservation_id,
                    "task_id": claim["task_id"],
                    "role": claim["role"],
                    "attempt_kind": claim["attempt_kind"],
                    "attempt_number": claim["attempt_number"],
                    "reserved_microusd": claim["reserved_microusd"],
                    **values,
                }
            )

    def summary(self) -> BudgetSummary:
        with _locked(self.context, self.root):
            claims = self._validated_claims_locked()
            events = self.journal.read_locked()
            self._validate_claim_event_bindings_locked(events, claims)
            settlements = {
                str(event["reservation_id"]): event
                for event in events
                if event.get("event_type") == "settled"
            }
            complete = len(settlements) == len(claims) and all(
                event.get("actual_cost_microusd") is not None for event in settlements.values()
            )
            actual = (
                sum(int(event["actual_cost_microusd"]) for event in settlements.values())
                if complete
                else None
            )
            return BudgetSummary(
                reserved_attempts=len(claims),
                reserved_microusd=len(claims) * self.limits.reservation_microusd,
                settled_attempts=len(settlements),
                actual_cost_microusd=actual,
                actual_cost_complete=complete,
            )

    def events(self) -> tuple[dict[str, Any], ...]:
        with _locked(self.context, self.root):
            claims = self._validated_claims_locked()
            events = self.journal.read_locked()
            self._validate_claim_event_bindings_locked(events, claims)
            return tuple(events)

    def _validated_claims_locked(self) -> list[dict[str, Any]]:
        return [self._load_claim(path) for path in sorted(self.claims.glob("*.json"))]

    def _load_claim(self, path: Path) -> dict[str, Any]:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            digest = value.pop("claim_digest")
        except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
            raise LedgerIntegrityError("budget claim is invalid") from exc
        if digest != _digest(value):
            raise LedgerIntegrityError("budget claim digest mismatch")
        if (
            value.get("run_id") != self.context.run_id
            or value.get("scope_digest") != self.context.scope_digest
        ):
            raise LedgerIntegrityError("budget claim run or scope binding mismatch")
        return cast(dict[str, Any], value)

    @staticmethod
    def _validate_claim_event_bindings_locked(
        events: Sequence[Mapping[str, Any]], claims: Sequence[Mapping[str, Any]]
    ) -> None:
        claimed = {str(claim["reservation_id"]) for claim in claims}
        journaled = {
            str(event["reservation_id"])
            for event in events
            if event.get("event_type") == "reserved"
        }
        if claimed != journaled:
            raise LedgerIntegrityError("budget claim and journal reservation sets differ")

    def _append_budget_reservation_locked(self, claim: Mapping[str, Any]) -> dict[str, Any]:
        now = self.clock()
        return self.journal.append_locked(
            {
                "event_id": str(uuid.uuid4()),
                "event_type": "reserved",
                "occurred_at": _utc_timestamp(now),
                **dict(claim),
            }
        )

    @staticmethod
    def _reservation_event(
        events: Sequence[Mapping[str, Any]], reservation_id: str
    ) -> Mapping[str, Any] | None:
        return next(
            (
                event
                for event in events
                if event.get("event_type") == "reserved"
                and event.get("reservation_id") == reservation_id
            ),
            None,
        )

    @staticmethod
    def _budget_reservation(event: Mapping[str, Any]) -> BudgetReservation:
        return BudgetReservation(
            reservation_id=str(event["reservation_id"]),
            task_id=str(event["task_id"]),
            role=str(event["role"]),
            attempt_kind=event["attempt_kind"],
            attempt_number=int(event["attempt_number"]),
            reserved_microusd=int(event["reserved_microusd"]),
            sequence=int(event["sequence"]),
        )


class ActiveSpan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    span_id: str
    owner: str
    started_at_epoch: float


class ActiveTimeSnapshot(BaseModel):
    """Immutable elapsed-time checkpoint used by signed coverage artifacts."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    snapshot_id: str
    active_elapsed_ms: int
    recorded_at_epoch: float


class ActiveTimeLedger:
    """Persistent wall-clock accounting for active, non-human-wait execution spans."""

    def __init__(
        self,
        context: RunContext,
        *,
        max_active_seconds: float = 1_800,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if max_active_seconds <= 0:
            raise ValueError("max_active_seconds must be positive")
        self.context = context
        self.max_active_seconds = float(max_active_seconds)
        self.clock = clock
        self.root = context.artifact_path("governance_v3/active_time_ledger")
        self.claims = self.root / "spans"
        self.claims.mkdir(parents=True, exist_ok=True)
        self.journal = _HashChainedJournal(self.root / "events.jsonl", ledger="active_time_v3")
        _persist_ledger_config(
            context,
            self.root,
            "limits.json",
            {
                "ledger": "active_time_v3",
                "schema_version": "3",
                "run_id": context.run_id,
                "scope_digest": context.scope_digest,
                "max_active_seconds": self.max_active_seconds,
            },
        )

    def start_span(self, *, span_id: str, owner: str) -> ActiveSpan:
        if not span_id or not owner:
            raise ValueError("span_id and owner must be non-empty")
        path = self.claims / _safe_claim_name(span_id)
        with _locked(self.context, self.root):
            now = self.clock()
            events = self.journal.read_locked()
            if self._active_seconds_locked(events, now) >= self.max_active_seconds:
                raise ActiveTimeExceeded("active execution time budget exhausted")
            if path.exists():
                claim = self._load_span_claim(path)
                stop = self._find_span_event(events, span_id, "stopped")
                if claim["owner"] != owner:
                    raise LedgerIntegrityError("active span id is bound to another owner")
                if stop is not None:
                    raise LedgerError("a stopped active span cannot be restarted")
                if self._find_span_event(events, span_id, "started") is None:
                    # Reconcile a crash between the immutable span claim and its
                    # journal append.  The claim's original wall time remains
                    # authoritative, so downtime is conservatively accounted.
                    self.journal.append_locked(
                        {
                            "schema_version": "3",
                            "event_id": str(uuid.uuid4()),
                            "event_type": "started",
                            "occurred_at": _utc_timestamp(float(claim["started_at_epoch"])),
                            **claim,
                        }
                    )
                return ActiveSpan(
                    span_id=span_id,
                    owner=owner,
                    started_at_epoch=float(claim["started_at_epoch"]),
                )
            claim = {
                "schema_version": "3",
                "run_id": self.context.run_id,
                "scope_digest": self.context.scope_digest,
                "span_id": span_id,
                "owner": owner,
                "started_at_epoch": now,
            }
            signed = {**claim, "claim_digest": _digest(claim)}
            relative = str(path.relative_to(self.context.path))
            self.context.write_json_exclusive(relative, signed)
            self.journal.append_locked(
                {
                    "schema_version": "3",
                    "event_id": str(uuid.uuid4()),
                    "event_type": "started",
                    "occurred_at": _utc_timestamp(now),
                    **claim,
                }
            )
            return ActiveSpan(span_id=span_id, owner=owner, started_at_epoch=now)

    def stop_span(self, span: ActiveSpan) -> float:
        path = self.claims / _safe_claim_name(span.span_id)
        with _locked(self.context, self.root):
            claim = self._load_span_claim(path)
            if claim["owner"] != span.owner or claim["started_at_epoch"] != span.started_at_epoch:
                raise LedgerIntegrityError("active span binding mismatch")
            events = self.journal.read_locked()
            existing = self._find_span_event(events, span.span_id, "stopped")
            if existing is not None:
                return float(existing["duration_seconds"])
            now = self.clock()
            if now < span.started_at_epoch:
                raise LedgerIntegrityError("active time clock moved before span start")
            duration = now - span.started_at_epoch
            self.journal.append_locked(
                {
                    "schema_version": "3",
                    "event_id": str(uuid.uuid4()),
                    "event_type": "stopped",
                    "occurred_at": _utc_timestamp(now),
                    "run_id": self.context.run_id,
                    "scope_digest": self.context.scope_digest,
                    "span_id": span.span_id,
                    "owner": span.owner,
                    "started_at_epoch": span.started_at_epoch,
                    "stopped_at_epoch": now,
                    "duration_seconds": duration,
                }
            )
            return duration

    def active_seconds(self) -> float:
        with _locked(self.context, self.root):
            self._validated_span_claims_locked()
            return self._active_seconds_locked(self.journal.read_locked(), self.clock())

    def reconcile_open_spans(self) -> tuple[ActiveSpan, ...]:
        """Close spans left open by a crashed process at the recovery instant.

        Time between the original start and recovery is intentionally charged.
        A later invocation starts a fresh span, so explicit human waits remain
        outside the ledger while unclean process exits fail conservatively.
        """

        with _locked(self.context, self.root):
            now = self.clock()
            events = self.journal.read_locked()
            claims = self._validated_span_claims_locked()
            reconciled: list[ActiveSpan] = []
            for claim in claims:
                span_id = str(claim["span_id"])
                if self._find_span_event(events, span_id, "stopped") is not None:
                    continue
                started_at = float(claim["started_at_epoch"])
                if now < started_at:
                    raise LedgerIntegrityError("active time clock moved before span start")
                if self._find_span_event(events, span_id, "started") is None:
                    self.journal.append_locked(
                        {
                            "schema_version": "3",
                            "event_id": str(uuid.uuid4()),
                            "event_type": "started",
                            "occurred_at": _utc_timestamp(started_at),
                            **claim,
                        }
                    )
                self.journal.append_locked(
                    {
                        "schema_version": "3",
                        "event_id": str(uuid.uuid4()),
                        "event_type": "stopped",
                        "occurred_at": _utc_timestamp(now),
                        "run_id": self.context.run_id,
                        "scope_digest": self.context.scope_digest,
                        "span_id": span_id,
                        "owner": str(claim["owner"]),
                        "started_at_epoch": started_at,
                        "stopped_at_epoch": now,
                        "duration_seconds": now - started_at,
                        "recovered_after_crash": True,
                    }
                )
                reconciled.append(
                    ActiveSpan(
                        span_id=span_id,
                        owner=str(claim["owner"]),
                        started_at_epoch=started_at,
                    )
                )
                events = self.journal.read_locked()
            return tuple(reconciled)

    def record_snapshot(self, snapshot_id: str) -> ActiveTimeSnapshot:
        """Record one immutable elapsed-time value for a downstream contract."""

        if not snapshot_id:
            raise ValueError("snapshot_id must be non-empty")
        with _locked(self.context, self.root):
            now = self.clock()
            events = self.journal.read_locked()
            existing = next(
                (
                    event
                    for event in events
                    if event.get("event_type") == "snapshot"
                    and event.get("snapshot_id") == snapshot_id
                ),
                None,
            )
            if existing is not None:
                return ActiveTimeSnapshot(
                    snapshot_id=snapshot_id,
                    active_elapsed_ms=int(existing["active_elapsed_ms"]),
                    recorded_at_epoch=float(existing["recorded_at_epoch"]),
                )
            elapsed_ms = max(1, int(self._active_seconds_locked(events, now) * 1_000))
            self.journal.append_locked(
                {
                    "schema_version": "3",
                    "event_id": str(uuid.uuid4()),
                    "event_type": "snapshot",
                    "occurred_at": _utc_timestamp(now),
                    "run_id": self.context.run_id,
                    "scope_digest": self.context.scope_digest,
                    "snapshot_id": snapshot_id,
                    "active_elapsed_ms": elapsed_ms,
                    "recorded_at_epoch": now,
                }
            )
            return ActiveTimeSnapshot(
                snapshot_id=snapshot_id,
                active_elapsed_ms=elapsed_ms,
                recorded_at_epoch=now,
            )

    def snapshot(self, snapshot_id: str) -> ActiveTimeSnapshot:
        with _locked(self.context, self.root):
            self._validated_span_claims_locked()
            events = self.journal.read_locked()
            indices = [
                index
                for index, event in enumerate(events)
                if event.get("event_type") == "snapshot" and event.get("snapshot_id") == snapshot_id
            ]
            if len(indices) != 1:
                raise LedgerIntegrityError("active time snapshot is missing or duplicated")
            index = indices[0]
            event = events[index]
            recorded_at = float(event["recorded_at_epoch"])
            expected_ms = max(
                1, int(self._active_seconds_locked(events[:index], recorded_at) * 1_000)
            )
            if int(event["active_elapsed_ms"]) != expected_ms:
                raise LedgerIntegrityError("active time snapshot value is not reproducible")
            return ActiveTimeSnapshot(
                snapshot_id=snapshot_id,
                active_elapsed_ms=int(event["active_elapsed_ms"]),
                recorded_at_epoch=recorded_at,
            )

    def remaining_seconds(self) -> float:
        return max(0.0, self.max_active_seconds - self.active_seconds())

    def assert_within_budget(self) -> None:
        if self.active_seconds() >= self.max_active_seconds:
            raise ActiveTimeExceeded("active execution time budget exhausted")

    def events(self) -> tuple[dict[str, Any], ...]:
        with _locked(self.context, self.root):
            self._validated_span_claims_locked()
            return tuple(self.journal.read_locked())

    def _validated_span_claims_locked(self) -> list[dict[str, Any]]:
        return [self._load_span_claim(path) for path in sorted(self.claims.glob("*.json"))]

    def _load_span_claim(self, path: Path) -> dict[str, Any]:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            digest = value.pop("claim_digest")
        except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
            raise LedgerIntegrityError("active span claim is invalid") from exc
        if digest != _digest(value):
            raise LedgerIntegrityError("active span claim digest mismatch")
        if (
            value.get("run_id") != self.context.run_id
            or value.get("scope_digest") != self.context.scope_digest
        ):
            raise LedgerIntegrityError("active span run or scope binding mismatch")
        return cast(dict[str, Any], value)

    def _active_seconds_locked(self, events: Sequence[Mapping[str, Any]], now: float) -> float:
        starts: dict[str, float] = {}
        stops: dict[str, float] = {}
        for event in events:
            span_id = event.get("span_id")
            if not isinstance(span_id, str):
                continue
            if event.get("event_type") == "started":
                starts[span_id] = float(event["started_at_epoch"])
            elif event.get("event_type") == "stopped":
                stops[span_id] = float(event["stopped_at_epoch"])
        intervals: list[tuple[float, float]] = []
        for span_id, start in starts.items():
            end = stops.get(span_id, now)
            if end < start:
                raise LedgerIntegrityError("active span has a negative duration")
            intervals.append((start, end))
        if not intervals:
            return 0.0
        intervals.sort()
        merged: list[list[float]] = []
        for start, end in intervals:
            if not merged or start > merged[-1][1]:
                merged.append([start, end])
            else:
                merged[-1][1] = max(merged[-1][1], end)
        return sum(end - start for start, end in merged)

    @staticmethod
    def _find_span_event(
        events: Sequence[Mapping[str, Any]], span_id: str, event_type: str
    ) -> Mapping[str, Any] | None:
        return next(
            (
                event
                for event in reversed(events)
                if event.get("span_id") == span_id and event.get("event_type") == event_type
            ),
            None,
        )


def _is_digest(value: str) -> bool:
    return (
        len(value) == 71
        and value.startswith("sha256:")
        and all(character in "0123456789abcdef" for character in value[7:])
    )


def _persist_ledger_config(
    context: RunContext, root: Path, filename: str, value: Mapping[str, Any]
) -> None:
    path = root / filename
    signed = {**dict(value), "config_digest": _digest(value)}
    with _locked(context, root):
        if not path.exists():
            relative = str(path.relative_to(context.path))
            context.write_json_exclusive(relative, signed)
            return
        try:
            persisted = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise LedgerIntegrityError("ledger configuration cannot be loaded") from exc
        if persisted != signed:
            raise LedgerIntegrityError("ledger configuration or limits changed")


__all__ = [
    "ActionFingerprint",
    "ActionLedger",
    "ActionLedgerState",
    "ActionReservation",
    "ActionReservationConflict",
    "ActionRetryDenied",
    "ActionRisk",
    "ActiveSpan",
    "ActiveTimeSnapshot",
    "ActiveTimeExceeded",
    "ActiveTimeLedger",
    "BudgetExceeded",
    "BudgetLedger",
    "BudgetLimitsV3",
    "BudgetReservation",
    "BudgetSummary",
    "LedgerError",
    "LedgerIntegrityError",
]

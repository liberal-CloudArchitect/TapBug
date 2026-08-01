"""Persistent V4 governance ledgers isolated from V3 artifacts."""

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


def _is_digest(value: str) -> bool:
    return (
        len(value) == 71
        and value.startswith("sha256:")
        and all(character in "0123456789abcdef" for character in value[7:])
    )


_LOCKS_GUARD = threading.Lock()
_PATH_LOCKS: dict[str, threading.RLock] = {}


def _thread_lock(path: Path) -> threading.RLock:
    key = str(path.resolve())
    with _LOCKS_GUARD:
        return _PATH_LOCKS.setdefault(key, threading.RLock())


@contextmanager
def _locked(context: RunContext, root: Path) -> Iterator[None]:
    with _thread_lock(root):
        with context.lock():
            yield


class LedgerError(RuntimeError):
    pass


class LedgerIntegrityError(LedgerError):
    pass


class ActionReservationConflict(LedgerError):
    pass


class ActionRetryDenied(LedgerError):
    pass


class BudgetExceeded(LedgerError):
    pass


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


class ActionRiskV4(StrEnum):
    READONLY = "readonly"
    MUTATION = "mutation"
    CLEANUP = "cleanup"


class ActionLedgerStateV4(StrEnum):
    PLANNED = "planned"
    RESERVED = "reserved"
    TRANSPORT_STARTED = "transport_started"
    EVIDENCE_COMMITTED = "evidence_committed"
    FAILED_BEFORE_TRANSPORT = "failed_before_transport"
    FAILED_AFTER_TRANSPORT = "failed_after_transport"
    INDETERMINATE = "indeterminate"
    CLEANUP_REQUIRED = "cleanup_required"
    CLEANED = "cleaned"


class ActionFingerprintV4(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: str = Field(min_length=1, max_length=256)
    scope_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    action_kind: str = Field(min_length=1, max_length=128)
    method: str = Field(min_length=1, max_length=16)
    canonical_url: str = Field(min_length=1, max_length=4096)
    canonical_body_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    identity_binding_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    causal_dependency_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    follow_redirects: bool = True
    risk: ActionRiskV4

    @field_validator("method")
    @classmethod
    def normalize_method(cls, value: str) -> str:
        return value.upper()

    @property
    def digest(self) -> str:
        return _digest(self.model_dump(mode="json"))


class ActionReservationV4(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    fingerprint: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    action_id: str
    action_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    owner_task_id: str
    disposition: Literal["owner", "reused"]
    state: ActionLedgerStateV4
    candidate_consumers: tuple[str, ...] = ()
    evidence_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    approval_batch_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    consumption_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")


_ACTION_TRANSITIONS: dict[ActionLedgerStateV4, frozenset[ActionLedgerStateV4]] = {
    ActionLedgerStateV4.PLANNED: frozenset({ActionLedgerStateV4.RESERVED}),
    ActionLedgerStateV4.RESERVED: frozenset(
        {
            ActionLedgerStateV4.TRANSPORT_STARTED,
            ActionLedgerStateV4.FAILED_BEFORE_TRANSPORT,
            ActionLedgerStateV4.INDETERMINATE,
        }
    ),
    ActionLedgerStateV4.TRANSPORT_STARTED: frozenset(
        {
            ActionLedgerStateV4.EVIDENCE_COMMITTED,
            ActionLedgerStateV4.FAILED_AFTER_TRANSPORT,
            ActionLedgerStateV4.INDETERMINATE,
            ActionLedgerStateV4.CLEANUP_REQUIRED,
        }
    ),
    ActionLedgerStateV4.EVIDENCE_COMMITTED: frozenset({ActionLedgerStateV4.CLEANUP_REQUIRED}),
    ActionLedgerStateV4.FAILED_BEFORE_TRANSPORT: frozenset({ActionLedgerStateV4.RESERVED}),
    ActionLedgerStateV4.FAILED_AFTER_TRANSPORT: frozenset({ActionLedgerStateV4.CLEANUP_REQUIRED}),
    ActionLedgerStateV4.INDETERMINATE: frozenset({ActionLedgerStateV4.CLEANUP_REQUIRED}),
    ActionLedgerStateV4.CLEANUP_REQUIRED: frozenset({ActionLedgerStateV4.CLEANED}),
    ActionLedgerStateV4.CLEANED: frozenset(),
}


class ActionLedgerV4:
    def __init__(self, context: RunContext, *, clock: Callable[[], float] = time.time) -> None:
        self.context = context
        self.clock = clock
        self.root = context.artifact_path("governance_v4/action_ledger")
        self.claims = self.root / "claims"
        self.claims.mkdir(parents=True, exist_ok=True)
        self.journal = _HashChainedJournal(self.root / "events.jsonl", ledger="action_v4")

    def reserve(
        self,
        action: ActionFingerprintV4,
        *,
        owner_task_id: str,
        candidate_consumers: Sequence[str] = (),
        action_id: str | None = None,
        action_digest: str | None = None,
    ) -> ActionReservationV4:
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
                    "schema_version": "4",
                    "run_id": action.run_id,
                    "scope_digest": action.scope_digest,
                    "fingerprint": action.digest,
                    "action": action.model_dump(mode="json"),
                    "action_id": action_id,
                    "action_digest": action_digest,
                    "initial_owner_task_id": owner_task_id,
                }
                if claim_path.exists():
                    self._validate_claim(claim_path, action)
                    raise ActionRetryDenied(
                        "action "
                        f"{action.digest} has a claim without a journal commit; "
                        "its state is indeterminate"
                    )
                signed = {**claim, "claim_digest": _digest(claim)}
                self.context.write_json_exclusive(
                    str(claim_path.relative_to(self.context.path)), signed
                )
                self._append_action_locked(
                    action,
                    state=ActionLedgerStateV4.PLANNED,
                    previous_state=None,
                    action_id=action_id,
                    action_digest=action_digest,
                    owner_task_id=owner_task_id,
                    consumers=consumers,
                )
                latest = self._append_action_locked(
                    action,
                    state=ActionLedgerStateV4.RESERVED,
                    previous_state=ActionLedgerStateV4.PLANNED,
                    action_id=action_id,
                    action_digest=action_digest,
                    owner_task_id=owner_task_id,
                    consumers=consumers,
                )
                return self._reservation(latest, disposition="owner")

            self._validate_claim(claim_path, action)
            persisted = self._load_action_claim(claim_path)
            if (
                persisted.get("action_id") != action_id
                or persisted.get("action_digest") != action_digest
            ):
                raise ActionReservationConflict(
                    "semantic action fingerprint is bound to a different canonical action"
                )
            state = ActionLedgerStateV4(latest["state"])
            if state is ActionLedgerStateV4.EVIDENCE_COMMITTED:
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
                ActionLedgerStateV4.FAILED_AFTER_TRANSPORT,
                ActionLedgerStateV4.INDETERMINATE,
                ActionLedgerStateV4.CLEANUP_REQUIRED,
                ActionLedgerStateV4.CLEANED,
            }:
                raise ActionRetryDenied(
                    f"action {action.digest} is {state.value}; retry is forbidden"
                )
            if state is ActionLedgerStateV4.FAILED_BEFORE_TRANSPORT:
                latest = self._append_action_locked(
                    action,
                    state=ActionLedgerStateV4.RESERVED,
                    previous_state=state,
                    action_id=str(latest["action_id"]),
                    action_digest=str(latest["action_digest"]),
                    owner_task_id=owner_task_id,
                    consumers=consumers,
                    event_type="safe_retry_reserved",
                )
                return self._reservation(latest, disposition="owner")
            if state is ActionLedgerStateV4.RESERVED and latest["owner_task_id"] == owner_task_id:
                return self._reservation(latest, disposition="owner")
            raise ActionReservationConflict(
                f"action {action.digest} is already owned by {latest['owner_task_id']}"
            )

    def mark_transport_started(
        self,
        reservation: ActionReservationV4,
        *,
        approval_batch_digest: str | None = None,
        consumption_digest: str | None = None,
    ) -> ActionReservationV4:
        return self.transition(
            reservation,
            ActionLedgerStateV4.TRANSPORT_STARTED,
            approval_batch_digest=approval_batch_digest,
            consumption_digest=consumption_digest,
        )

    def mark_evidence_committed(
        self, reservation: ActionReservationV4, *, evidence_digest: str
    ) -> ActionReservationV4:
        return self.transition(
            reservation, ActionLedgerStateV4.EVIDENCE_COMMITTED, evidence_digest=evidence_digest
        )

    def mark_failed_before_transport(self, reservation: ActionReservationV4) -> ActionReservationV4:
        return self.transition(reservation, ActionLedgerStateV4.FAILED_BEFORE_TRANSPORT)

    def mark_failed_after_transport(self, reservation: ActionReservationV4) -> ActionReservationV4:
        return self.transition(reservation, ActionLedgerStateV4.FAILED_AFTER_TRANSPORT)

    def mark_indeterminate(self, reservation: ActionReservationV4) -> ActionReservationV4:
        return self.transition(reservation, ActionLedgerStateV4.INDETERMINATE)

    def mark_cleanup_required(self, reservation: ActionReservationV4) -> ActionReservationV4:
        return self.transition(reservation, ActionLedgerStateV4.CLEANUP_REQUIRED)

    def mark_cleaned(
        self, reservation: ActionReservationV4, *, cleanup_receipt_digest: str
    ) -> ActionReservationV4:
        return self.transition(
            reservation, ActionLedgerStateV4.CLEANED, evidence_digest=cleanup_receipt_digest
        )

    def transition(
        self,
        reservation: ActionReservationV4,
        state: ActionLedgerStateV4,
        *,
        evidence_digest: str | None = None,
        approval_batch_digest: str | None = None,
        consumption_digest: str | None = None,
    ) -> ActionReservationV4:
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
            previous = ActionLedgerStateV4(latest["state"])
            if latest["owner_task_id"] != reservation.owner_task_id:
                raise ActionReservationConflict("action reservation owner does not match")
            if state not in _ACTION_TRANSITIONS[previous]:
                raise LedgerError(f"invalid action transition: {previous.value} -> {state.value}")
            if (
                state in {ActionLedgerStateV4.EVIDENCE_COMMITTED, ActionLedgerStateV4.CLEANED}
                and evidence_digest is None
            ):
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

    def _validate_context(self, action: ActionFingerprintV4) -> None:
        if action.run_id != self.context.run_id or action.scope_digest != self.context.scope_digest:
            raise LedgerError("action is bound to a different run or scope")

    def _validate_claim(self, path: Path, action: ActionFingerprintV4) -> None:
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

    def _action_from_claim(self, fingerprint: str) -> ActionFingerprintV4:
        value = self._load_action_claim(self.claims / _safe_claim_name(fingerprint))
        return ActionFingerprintV4.model_validate(value["action"])

    def _validated_claims_locked(self) -> list[dict[str, Any]]:
        return [self._load_action_claim(path) for path in sorted(self.claims.glob("*.json"))]

    def _load_action_claim(self, path: Path) -> dict[str, Any]:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            action = ActionFingerprintV4.model_validate(value["action"])
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
        action: ActionFingerprintV4,
        *,
        state: ActionLedgerStateV4,
        previous_state: ActionLedgerStateV4 | None,
        action_id: str,
        action_digest: str,
        owner_task_id: str,
        consumers: Sequence[str],
        evidence_digest: str | None = None,
        approval_batch_digest: str | None = None,
        consumption_digest: str | None = None,
        event_type: str = "transition",
    ) -> dict[str, Any]:
        return self.journal.append_locked(
            {
                "schema_version": "4",
                "event_id": str(uuid.uuid4()),
                "event_type": event_type,
                "occurred_at": _utc_timestamp(self.clock()),
                "run_id": self.context.run_id,
                "scope_digest": self.context.scope_digest,
                "fingerprint": action.digest,
                "action_id": action_id,
                "action_digest": action_digest,
                "owner_task_id": owner_task_id,
                "candidate_consumers": tuple(consumers),
                "state": state.value,
                "previous_state": previous_state.value if previous_state else None,
                "evidence_digest": evidence_digest,
                "approval_batch_digest": approval_batch_digest,
                "consumption_digest": consumption_digest,
            }
        )

    @staticmethod
    def _reservation(
        event: Mapping[str, Any], *, disposition: Literal["owner", "reused"]
    ) -> ActionReservationV4:
        return ActionReservationV4(
            fingerprint=str(event["fingerprint"]),
            action_id=str(event["action_id"]),
            action_digest=str(event["action_digest"]),
            owner_task_id=str(event["owner_task_id"]),
            disposition=disposition,
            state=ActionLedgerStateV4(event["state"]),
            candidate_consumers=tuple(event.get("candidate_consumers", ())),
            evidence_digest=event.get("evidence_digest"),
            approval_batch_digest=event.get("approval_batch_digest"),
            consumption_digest=event.get("consumption_digest"),
        )


class BudgetLimitsV4(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    max_prompt_attempts: int = Field(default=64, ge=1, le=64)
    reservation_microusd: int = Field(default=250_000, ge=1)
    max_estimated_cost_microusd: int = Field(default=16_000_000, ge=1, le=16_000_000)


class BudgetReservationV4(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    reservation_id: str
    task_id: str
    role: str
    attempt_kind: Literal["initial", "schema_repair", "reporter"]
    attempt_number: int = Field(ge=1, le=64)
    reserved_microusd: int
    sequence: int


class BudgetSummaryV4(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    reserved_attempts: int
    reserved_microusd: int
    settled_attempts: int
    actual_cost_microusd: int | None
    actual_cost_complete: bool


class BudgetLedgerV4:
    def __init__(
        self,
        context: RunContext,
        *,
        limits: BudgetLimitsV4 | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.context = context
        self.limits = limits or BudgetLimitsV4()
        self.clock = clock
        self.root = context.artifact_path("governance_v4/budget_ledger")
        self.claims = self.root / "claims"
        self.claims.mkdir(parents=True, exist_ok=True)
        self.journal = _HashChainedJournal(self.root / "events.jsonl", ledger="budget_v4")

    def reserve_prompt(
        self,
        *,
        task_id: str,
        role: str,
        attempt_kind: Literal["initial", "schema_repair", "reporter"] = "initial",
        reservation_id: str | None = None,
    ) -> BudgetReservationV4:
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
                "schema_version": "4",
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
            self.context.write_json_exclusive(
                str(claim_path.relative_to(self.context.path)), signed
            )
            event = self.journal.append_locked(
                {
                    "event_id": str(uuid.uuid4()),
                    "event_type": "reserved",
                    "occurred_at": _utc_timestamp(self.clock()),
                    **claim,
                }
            )
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
            return self.journal.append_locked(
                {
                    "schema_version": "4",
                    "event_id": str(uuid.uuid4()),
                    "event_type": "settled",
                    "occurred_at": _utc_timestamp(self.clock()),
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

    def summary(self) -> BudgetSummaryV4:
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
            return BudgetSummaryV4(
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
    def _budget_reservation(event: Mapping[str, Any]) -> BudgetReservationV4:
        return BudgetReservationV4(
            reservation_id=str(event["reservation_id"]),
            task_id=str(event["task_id"]),
            role=str(event["role"]),
            attempt_kind=event["attempt_kind"],
            attempt_number=int(event["attempt_number"]),
            reserved_microusd=int(event["reserved_microusd"]),
            sequence=int(event["sequence"]),
        )


__all__ = [
    "ActionFingerprintV4",
    "ActionLedgerStateV4",
    "ActionLedgerV4",
    "ActionReservationConflict",
    "ActionReservationV4",
    "ActionRetryDenied",
    "ActionRiskV4",
    "BudgetExceeded",
    "BudgetLedgerV4",
    "BudgetLimitsV4",
    "BudgetReservationV4",
    "BudgetSummaryV4",
    "LedgerIntegrityError",
]

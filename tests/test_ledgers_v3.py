from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from hermes.ledgers_v3 import (
    ActionFingerprint,
    ActionLedger,
    ActionLedgerState,
    ActionReservationConflict,
    ActionRetryDenied,
    ActionRisk,
    ActiveTimeExceeded,
    ActiveTimeLedger,
    BudgetExceeded,
    BudgetLedger,
    BudgetLimitsV3,
    LedgerIntegrityError,
)
from hermes.runtime import RunContext

BODY_HASH = "sha256:" + "0" * 64


class Clock:
    def __init__(self, value: float = 1_800_000_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def context(tmp_path: Path, run_id: str = "run-v3") -> RunContext:
    return RunContext(tmp_path / "runs", {"hosts": ["localhost"]}, run_id=run_id)


def action(run: RunContext, *, risk: ActionRisk = ActionRisk.READONLY) -> ActionFingerprint:
    return ActionFingerprint(
        run_id=run.run_id,
        scope_digest=run.scope_digest,
        action_kind="validation_http_get",
        method="get",
        canonical_url="http://localhost:8080/candidate",
        canonical_body_sha256=BODY_HASH,
        identity_binding_digest=None,
        risk=risk,
    )


def test_action_reservation_is_atomic_and_completed_evidence_is_reused(tmp_path: Path) -> None:
    run = context(tmp_path)
    fingerprint = action(run)
    first = ActionLedger(run).reserve(
        fingerprint, owner_task_id="web-1", candidate_consumers=("candidate-web",)
    )

    with pytest.raises(ActionReservationConflict):
        ActionLedger(run).reserve(fingerprint, owner_task_id="infra-1")

    ledger = ActionLedger(run)
    approval_digest = "sha256:" + "a" * 64
    consumption_digest = "sha256:" + "c" * 64
    started = ledger.mark_transport_started(
        first,
        approval_batch_digest=approval_digest,
        consumption_digest=consumption_digest,
    )
    evidence_digest = "sha256:" + "e" * 64
    committed = ledger.mark_evidence_committed(started, evidence_digest=evidence_digest)
    reused = ActionLedger(run).reserve(
        fingerprint, owner_task_id="infra-1", candidate_consumers=("candidate-infra",)
    )

    assert committed.state is ActionLedgerState.EVIDENCE_COMMITTED
    assert reused.disposition == "reused"
    assert reused.evidence_digest == evidence_digest
    assert reused.approval_batch_digest == approval_digest
    assert reused.consumption_digest == consumption_digest
    assert reused.candidate_consumers == ("candidate-infra", "candidate-web")
    assert len(ActionLedger(run).events()) == 5


def test_action_approval_and_consumption_bindings_are_atomic(tmp_path: Path) -> None:
    run = context(tmp_path)
    ledger = ActionLedger(run)
    reservation = ledger.reserve(
        action(run),
        owner_task_id="verifier",
        action_id="readonly-candidate-get",
        action_digest="sha256:" + "3" * 64,
    )
    assert reservation.action_id == "readonly-candidate-get"
    assert reservation.action_digest == "sha256:" + "3" * 64
    with pytest.raises(ValueError, match="together"):
        ledger.mark_transport_started(reservation, approval_batch_digest="sha256:" + "4" * 64)


def test_action_fingerprint_excludes_branch_and_rationale_but_binds_identity_and_body(
    tmp_path: Path,
) -> None:
    run = context(tmp_path)
    base = action(run)
    assert "branch" not in ActionFingerprint.model_fields
    assert "rationale" not in ActionFingerprint.model_fields
    assert base.digest == base.model_copy(update={"method": "GET"}).digest
    assert (
        base.digest
        != base.model_copy(update={"canonical_body_sha256": "sha256:" + "1" * 64}).digest
    )
    assert (
        base.digest
        != base.model_copy(update={"identity_binding_digest": "sha256:" + "2" * 64}).digest
    )


def test_only_pre_transport_failure_can_be_reserved_again(tmp_path: Path) -> None:
    run = context(tmp_path)
    fingerprint = action(run)
    ledger = ActionLedger(run)
    reservation = ledger.reserve(fingerprint, owner_task_id="first")
    ledger.mark_failed_before_transport(reservation)
    retry = ledger.reserve(fingerprint, owner_task_id="second")
    assert retry.owner_task_id == "second"
    assert retry.state is ActionLedgerState.RESERVED

    started = ledger.mark_transport_started(retry)
    ledger.mark_failed_after_transport(started)
    with pytest.raises(ActionRetryDenied, match="retry is forbidden"):
        ledger.reserve(fingerprint, owner_task_id="third")


def test_indeterminate_action_cannot_be_automatically_retried(tmp_path: Path) -> None:
    run = context(tmp_path)
    fingerprint = action(run)
    ledger = ActionLedger(run)
    reservation = ledger.reserve(fingerprint, owner_task_id="first")
    ledger.mark_indeterminate(reservation)

    with pytest.raises(ActionRetryDenied, match="indeterminate"):
        ActionLedger(run).reserve(fingerprint, owner_task_id="resume")


def test_action_journal_and_claim_tampering_are_detected(tmp_path: Path) -> None:
    run = context(tmp_path)
    fingerprint = action(run)
    ledger = ActionLedger(run)
    ledger.reserve(fingerprint, owner_task_id="web")
    journal = run.artifact_path("governance_v3/action_ledger/events.jsonl")
    records = journal.read_text(encoding="utf-8").splitlines()
    first = json.loads(records[0])
    first["owner_task_id"] = "tampered"
    records[0] = json.dumps(first)
    journal.write_text("\n".join(records) + "\n", encoding="utf-8")
    with pytest.raises(LedgerIntegrityError, match="event hash"):
        ledger.events()


def test_action_claim_tampering_is_detected_when_events_are_loaded(tmp_path: Path) -> None:
    run = context(tmp_path)
    fingerprint = action(run)
    ledger = ActionLedger(run)
    ledger.reserve(fingerprint, owner_task_id="web")
    claim = next(run.artifact_path("governance_v3/action_ledger/claims").glob("*.json"))
    value = json.loads(claim.read_text(encoding="utf-8"))
    value["initial_owner_task_id"] = "tampered"
    claim.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(LedgerIntegrityError, match="claim digest"):
        ledger.events()


def test_action_claim_without_journal_is_indeterminate_and_never_replayed(tmp_path: Path) -> None:
    run = context(tmp_path)
    fingerprint = action(run)
    ledger = ActionLedger(run)
    ledger.reserve(fingerprint, owner_task_id="web")
    run.artifact_path("governance_v3/action_ledger/events.jsonl").unlink()
    with pytest.raises(ActionRetryDenied, match="indeterminate"):
        ledger.reserve(fingerprint, owner_task_id="web")
    with pytest.raises(LedgerIntegrityError, match="sets differ"):
        ledger.events()


def test_budget_pre_reservation_does_not_oversell_under_concurrency(tmp_path: Path) -> None:
    run = context(tmp_path)

    def reserve(number: int) -> bool:
        try:
            BudgetLedger(run).reserve_prompt(
                task_id=f"task-{number}", role="web-vuln", reservation_id=f"attempt-{number}"
            )
        except BudgetExceeded:
            return False
        return True

    with ThreadPoolExecutor(max_workers=16) as pool:
        accepted = list(pool.map(reserve, range(60)))

    assert accepted.count(True) == 40
    assert accepted.count(False) == 20
    summary = BudgetLedger(run).summary()
    assert summary.reserved_attempts == 40
    assert summary.reserved_microusd == 10_000_000


def test_budget_counts_repairs_and_reporter_and_rejects_41st_before_reservation(
    tmp_path: Path,
) -> None:
    run = context(tmp_path)
    ledger = BudgetLedger(run)
    initial = ledger.reserve_prompt(task_id="web-1", role="web-vuln", reservation_id="web-initial")
    repair = ledger.reserve_prompt(
        task_id="web-1",
        role="web-vuln",
        attempt_kind="schema_repair",
        reservation_id="web-repair",
    )
    reporter = ledger.reserve_prompt(
        task_id="reporter-1",
        role="reporter",
        attempt_kind="reporter",
        reservation_id="reporter-initial",
    )
    assert {initial.sequence, repair.sequence, reporter.sequence} == {1, 2, 3}
    assert (initial.attempt_number, repair.attempt_number, reporter.attempt_number) == (1, 2, 3)
    for number in range(3, 40):
        ledger.reserve_prompt(
            task_id=f"task-{number}", role="api", reservation_id=f"attempt-{number}"
        )
    with pytest.raises(BudgetExceeded, match="attempt"):
        ledger.reserve_prompt(task_id="overflow", role="api", reservation_id="attempt-41")
    assert not any(
        path.read_text(encoding="utf-8").find("attempt-41") >= 0
        for path in run.artifact_path("governance_v3/budget_ledger/claims").glob("*.json")
    )


def test_budget_reservation_is_idempotent_and_null_actual_cost_is_not_zero(
    tmp_path: Path,
) -> None:
    run = context(tmp_path)
    ledger = BudgetLedger(run)
    first = ledger.reserve_prompt(task_id="web", role="web-vuln", reservation_id="stable")
    again = BudgetLedger(run).reserve_prompt(
        task_id="web", role="web-vuln", reservation_id="stable"
    )
    assert first == again
    ledger.settle("stable", token_usage=None, actual_cost_microusd=None)
    summary = ledger.summary()
    assert summary.settled_attempts == 1
    assert summary.actual_cost_microusd is None
    assert summary.actual_cost_complete is False


def test_budget_claim_without_journal_never_reauthorizes_the_same_attempt(
    tmp_path: Path,
) -> None:
    run = context(tmp_path)
    ledger = BudgetLedger(run)
    ledger.reserve_prompt(task_id="web", role="web-vuln", reservation_id="stable")
    run.artifact_path("governance_v3/budget_ledger/events.jsonl").unlink()
    with pytest.raises(LedgerIntegrityError, match="sets differ"):
        ledger.reserve_prompt(task_id="web", role="web-vuln", reservation_id="stable")


def test_cost_limit_can_bind_before_attempt_limit(tmp_path: Path) -> None:
    run = context(tmp_path)
    ledger = BudgetLedger(
        run,
        limits=BudgetLimitsV3(
            max_prompt_attempts=40,
            reservation_microusd=250_000,
            max_estimated_cost_microusd=500_000,
        ),
    )
    ledger.reserve_prompt(task_id="one", role="api", reservation_id="one")
    ledger.reserve_prompt(task_id="two", role="api", reservation_id="two")
    with pytest.raises(BudgetExceeded, match="cost"):
        ledger.reserve_prompt(task_id="three", role="api", reservation_id="three")


def test_persisted_budget_limits_cannot_be_relaxed_on_reopen(tmp_path: Path) -> None:
    run = context(tmp_path)
    BudgetLedger(run)
    with pytest.raises(LedgerIntegrityError, match="limits changed"):
        BudgetLedger(
            run,
            limits=BudgetLimitsV3(
                max_prompt_attempts=40,
                reservation_microusd=250_000,
                max_estimated_cost_microusd=10_250_000,
            ),
        )


def test_active_time_persists_open_spans_and_excludes_stopped_waits(tmp_path: Path) -> None:
    run = context(tmp_path)
    clock = Clock()
    ledger = ActiveTimeLedger(run, max_active_seconds=30, clock=clock)
    span = ledger.start_span(span_id="assessment", owner="coordinator")
    clock.advance(10)
    assert ledger.stop_span(span) == 10
    clock.advance(100)  # Human approval wait: no active span.
    assert ActiveTimeLedger(run, max_active_seconds=30, clock=clock).active_seconds() == 10

    resumed = ActiveTimeLedger(run, max_active_seconds=30, clock=clock)
    resumed.start_span(span_id="verification", owner="coordinator")
    clock.advance(7)
    # Reopen without stopping: crash time is conservatively counted.
    assert ActiveTimeLedger(run, max_active_seconds=30, clock=clock).active_seconds() == 17


def test_recovery_closes_crashed_span_and_next_human_wait_is_not_charged(
    tmp_path: Path,
) -> None:
    run = context(tmp_path)
    clock = Clock()
    crashed = ActiveTimeLedger(run, max_active_seconds=30, clock=clock)
    crashed.start_span(span_id="crashed-assessment", owner="cli-start")
    clock.advance(8)

    recovered = ActiveTimeLedger(run, max_active_seconds=30, clock=clock)
    closed = recovered.reconcile_open_spans()
    assert tuple(item.span_id for item in closed) == ("crashed-assessment",)
    assert recovered.active_seconds() == 8

    clock.advance(100)
    assert recovered.active_seconds() == 8
    resumed = recovered.start_span(span_id="resume", owner="cli-resume")
    clock.advance(3)
    recovered.stop_span(resumed)
    assert recovered.active_seconds() == 11


def test_coverage_snapshot_is_reproducible_after_later_execution(tmp_path: Path) -> None:
    run = context(tmp_path)
    clock = Clock()
    ledger = ActiveTimeLedger(run, max_active_seconds=30, clock=clock)
    first = ledger.start_span(span_id="verification", owner="cli-resume")
    clock.advance(4)
    snapshot = ledger.record_snapshot("coverage-v3")
    assert snapshot.active_elapsed_ms == 4_000
    clock.advance(2)
    ledger.stop_span(first)
    reporter = ledger.start_span(span_id="reporter", owner="cli-resume")
    clock.advance(3)
    ledger.stop_span(reporter)

    assert ledger.active_seconds() == 9
    assert ledger.snapshot("coverage-v3").active_elapsed_ms == 4_000


def test_overlapping_active_spans_count_wall_time_once_and_enforce_deadline(
    tmp_path: Path,
) -> None:
    run = context(tmp_path)
    clock = Clock()
    ledger = ActiveTimeLedger(run, max_active_seconds=10, clock=clock)
    first = ledger.start_span(span_id="branch-a", owner="coordinator")
    clock.advance(2)
    second = ledger.start_span(span_id="branch-b", owner="coordinator")
    clock.advance(3)
    ledger.stop_span(first)
    clock.advance(2)
    ledger.stop_span(second)
    assert ledger.active_seconds() == 7
    clock.advance(3)
    final = ledger.start_span(span_id="fan-in", owner="coordinator")
    clock.advance(3)
    assert ledger.remaining_seconds() == 0
    with pytest.raises(ActiveTimeExceeded):
        ledger.assert_within_budget()
    assert ledger.stop_span(final) == 3


def test_active_time_journal_tampering_is_fail_closed(tmp_path: Path) -> None:
    run = context(tmp_path)
    clock = Clock()
    ledger = ActiveTimeLedger(run, clock=clock)
    ledger.start_span(span_id="assessment", owner="coordinator")
    journal = run.artifact_path("governance_v3/active_time_ledger/events.jsonl")
    value = json.loads(journal.read_text(encoding="utf-8"))
    value["started_at_epoch"] -= 10
    journal.write_text(json.dumps(value) + "\n", encoding="utf-8")
    with pytest.raises(LedgerIntegrityError, match="event hash"):
        ledger.active_seconds()


def test_persisted_active_deadline_cannot_be_relaxed_on_reopen(tmp_path: Path) -> None:
    run = context(tmp_path)
    ActiveTimeLedger(run, max_active_seconds=1_800)
    with pytest.raises(LedgerIntegrityError, match="limits changed"):
        ActiveTimeLedger(run, max_active_seconds=3_600)

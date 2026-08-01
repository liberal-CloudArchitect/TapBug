from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from hermes.ledgers_v4 import (
    ActionFingerprintV4,
    ActionLedgerStateV4,
    ActionLedgerV4,
    ActionReservationConflict,
    ActionRetryDenied,
    ActionRiskV4,
    BudgetExceeded,
    BudgetLedgerV4,
    LedgerIntegrityError,
)
from hermes.runtime import RunContext

BODY_HASH = "sha256:" + "0" * 64


def context(tmp_path: Path, run_id: str = "run-v4") -> RunContext:
    return RunContext(tmp_path / "runs", {"hosts": ["localhost"]}, run_id=run_id)


def action(
    run: RunContext,
    *,
    risk: ActionRiskV4 = ActionRiskV4.READONLY,
    follow_redirects: bool = True,
) -> ActionFingerprintV4:
    return ActionFingerprintV4(
        run_id=run.run_id,
        scope_digest=run.scope_digest,
        action_kind="validation_http_get",
        method="get",
        canonical_url="https://localhost:8443/candidate",
        canonical_body_sha256=BODY_HASH,
        identity_binding_digest=None,
        follow_redirects=follow_redirects,
        risk=risk,
    )


def test_action_reservation_is_atomic_and_follow_redirects_is_part_of_identity(
    tmp_path: Path,
) -> None:
    run = context(tmp_path)
    first = action(run, follow_redirects=False)
    second = action(run, follow_redirects=True)
    assert first.digest != second.digest

    reservation = ActionLedgerV4(run).reserve(first, owner_task_id="web")
    with pytest.raises(ActionReservationConflict):
        ActionLedgerV4(run).reserve(first, owner_task_id="infra")

    started = ActionLedgerV4(run).mark_transport_started(
        reservation,
        approval_batch_digest="sha256:" + "a" * 64,
        consumption_digest="sha256:" + "b" * 64,
    )
    committed = ActionLedgerV4(run).mark_evidence_committed(
        started, evidence_digest="sha256:" + "c" * 64
    )
    reused = ActionLedgerV4(run).reserve(first, owner_task_id="infra")

    assert committed.state is ActionLedgerStateV4.EVIDENCE_COMMITTED
    assert reused.disposition == "reused"
    assert ActionLedgerV4(run).reserve(second, owner_task_id="redirect").disposition == "owner"


def test_v4_action_claim_and_journal_tampering_are_detected(tmp_path: Path) -> None:
    run = context(tmp_path)
    fingerprint = action(run)
    ledger = ActionLedgerV4(run)
    ledger.reserve(fingerprint, owner_task_id="web")
    journal = run.artifact_path("governance_v4/action_ledger/events.jsonl")
    records = journal.read_text(encoding="utf-8").splitlines()
    first = json.loads(records[0])
    first["owner_task_id"] = "tampered"
    records[0] = json.dumps(first)
    journal.write_text("\n".join(records) + "\n", encoding="utf-8")
    with pytest.raises(LedgerIntegrityError, match="event hash"):
        ledger.events()


def test_v4_action_retry_is_forbidden_after_cleanup_required(tmp_path: Path) -> None:
    run = context(tmp_path)
    fingerprint = action(run, risk=ActionRiskV4.MUTATION)
    ledger = ActionLedgerV4(run)
    reservation = ledger.reserve(fingerprint, owner_task_id="workflow")
    started = ledger.mark_transport_started(
        reservation,
        approval_batch_digest="sha256:" + "a" * 64,
        consumption_digest="sha256:" + "b" * 64,
    )
    ledger.mark_cleanup_required(started)

    with pytest.raises(ActionRetryDenied, match="cleanup_required"):
        ActionLedgerV4(run).reserve(fingerprint, owner_task_id="workflow")


def test_v4_budget_pre_reservation_does_not_oversell_under_concurrency(tmp_path: Path) -> None:
    run = context(tmp_path)

    def reserve(number: int) -> bool:
        try:
            BudgetLedgerV4(run).reserve_prompt(
                task_id=f"task-{number}", role="web-vuln", reservation_id=f"attempt-{number}"
            )
        except BudgetExceeded:
            return False
        return True

    with ThreadPoolExecutor(max_workers=16) as pool:
        accepted = list(pool.map(reserve, range(80)))

    assert accepted.count(True) == 64
    assert accepted.count(False) == 16
    summary = BudgetLedgerV4(run).summary()
    assert summary.reserved_attempts == 64
    assert summary.reserved_microusd == 16_000_000

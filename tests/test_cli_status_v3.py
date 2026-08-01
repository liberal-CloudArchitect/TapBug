from __future__ import annotations

import json
import os
from argparse import Namespace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hermes import cli
from hermes.cli_status_v3 import status_payload_v3
from hermes.domain_contracts_v3 import BranchResult
from hermes.ledgers_v3 import (
    ActionFingerprint,
    ActionLedger,
    ActionRisk,
    BudgetLedger,
    LedgerIntegrityError,
)
from hermes.runtime import RunContext
from hermes.security import (
    KeyUsage,
    TrustedKey,
    TrustStoreV2,
    encode_base64,
    generate_ed25519_private_key,
    public_key_bytes,
)
from hermes.vertical_v3 import ExecutionStateV3, NetworkStateV3, VerticalStateV3

_DIGEST = "sha256:" + "a" * 64
_BODY = "sha256:" + "0" * 64


def _context(tmp_path: Path) -> RunContext:
    return RunContext(
        tmp_path / "runs",
        {"profile": "local-lab"},
        run_id="phase4-status",
    )


def _state(context: RunContext) -> VerticalStateV3:
    return VerticalStateV3(
        run_id=context.run_id,
        execution_state=ExecutionStateV3.AWAITING_MUTATION_APPROVAL,
        network_state=NetworkStateV3.USED,
        requests_planned=15,
        requests_used=1,
        requests_blocked=0,
        next_required_action="approve_or_reject:mutation",
        cleanup_state="not_required",
        last_successful_checkpoint="readonly_decision_completed_v3",
    )


def _tree_snapshot(root: Path) -> tuple[tuple[str, int, int], ...]:
    return tuple(
        (str(path.relative_to(root)), path.stat().st_size, path.stat().st_mtime_ns)
        for path in sorted(root.rglob("*"))
    )


def test_v3_status_recomputes_ledgers_branches_network_and_is_read_only(
    tmp_path: Path,
) -> None:
    context = _context(tmp_path)
    state = _state(context)
    context.write_json("state.json", state.model_dump(mode="json"))
    fingerprint = ActionFingerprint(
        run_id=context.run_id,
        scope_digest=context.scope_digest,
        action_kind="validation_http_get",
        method="GET",
        canonical_url="http://localhost:8080/candidate",
        canonical_body_sha256=_BODY,
        risk=ActionRisk.READONLY,
    )
    ledger = ActionLedger(context)
    reservation = ledger.reserve(
        fingerprint,
        owner_task_id="phase4-verifier-web",
        candidate_consumers=("candidate-web",),
        action_id="web-candidate",
        action_digest=_DIGEST,
    )
    started = ledger.mark_transport_started(
        reservation,
        approval_batch_digest="sha256:" + "b" * 64,
        consumption_digest="sha256:" + "c" * 64,
    )
    ledger.mark_evidence_committed(started, evidence_digest="sha256:" + "d" * 64)
    budget = BudgetLedger(context)
    item = budget.reserve_prompt(
        task_id="phase4-assessment-web",
        role="web-vuln",
        reservation_id="status-budget-1",
    )
    budget.settle(item.reservation_id, token_usage={"total": 12})
    for number in range(2):
        context.write_json(
            f"evidence/status-{number}/manifest.json",
            {"version": "2", "evidence_id": f"status-{number}"},
        )
    now = datetime.now(UTC)
    context.write_json(
        "collaboration_v3/branch-results/web.json",
        BranchResult(
            run_id=context.run_id,
            scope_digest=context.scope_digest,
            generated_by_task_id="phase4-fanin",
            branch="web",
            status="succeeded",
            assessment_digest="sha256:" + "1" * 64,
            provider_metadata_digest="sha256:" + "2" * 64,
            started_at=now,
            finished_at=now,
        ).model_dump(mode="json"),
    )
    for branch in ("api", "authz", "infra"):
        context.write_json(
            f"collaboration_v3/branch-results/{branch}.json",
            BranchResult(
                run_id=context.run_id,
                scope_digest=context.scope_digest,
                generated_by_task_id="phase4-fanin",
                branch=branch,
                status="not_routed",
                reason="not applicable",
            ).model_dump(mode="json"),
        )

    before = _tree_snapshot(context.path)
    payload = status_payload_v3(context, state)
    after = _tree_snapshot(context.path)

    assert before == after
    assert payload["network_state"] == "used"
    assert payload["requests_planned"] == 15
    assert payload["requests_used"] == 2
    assert payload["requests_blocked"] == 0
    assert payload["branches"]["web"]["status"] == "succeeded"
    assert payload["branches"]["api"]["status"] == "not_routed"
    assert payload["budget"] == {
        "attempts_reserved": 1,
        "attempts_settled": 1,
        "estimated_microusd": 250_000,
        "actual_microusd": None,
        "actual_cost_complete": False,
        "remaining_attempts": 39,
        "remaining_estimated_microusd": 9_750_000,
        "latest_event_hash": payload["budget"]["latest_event_hash"],
    }
    assert payload["action_ledger"]["state_counts"]["evidence_committed"] == 1
    assert payload["cleanup"]["status"] == "not_required"
    assert payload["next_required_action"] == "approve_or_reject:mutation"
    assert payload["artifact_paths"]["action_ledger"].endswith("events.jsonl")


def test_v3_status_fails_closed_on_tampered_ledger(tmp_path: Path) -> None:
    context = _context(tmp_path)
    state = _state(context)
    ActionLedger(context).reserve(
        ActionFingerprint(
            run_id=context.run_id,
            scope_digest=context.scope_digest,
            action_kind="validation_http_get",
            method="GET",
            canonical_url="http://localhost:8080/candidate",
            canonical_body_sha256=_BODY,
            risk=ActionRisk.READONLY,
        ),
        owner_task_id="phase4-verifier-web",
    )
    journal = context.artifact_path("governance_v3/action_ledger/events.jsonl")
    records = journal.read_text(encoding="utf-8").splitlines()
    value = json.loads(records[0])
    value["state"] = "evidence_committed"
    records[0] = json.dumps(value)
    journal.write_text("\n".join(records) + "\n", encoding="utf-8")

    with pytest.raises(LedgerIntegrityError, match="hash chain"):
        status_payload_v3(context, state)


def test_v3_status_command_uses_projection_but_v2_still_uses_baseline_emit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    context = _context(tmp_path)
    state = _state(context)
    context.write_json("state.json", state.model_dump(mode="json"))
    monkeypatch.setattr(cli, "_config", lambda _path: {"runs_root": context.runs_root})
    monkeypatch.setattr(cli, "_open_context", lambda _config, _run_id: context)

    result = cli._execute(
        Namespace(
            command="status",
            config=tmp_path / "config.json",
            run_id=context.run_id,
            json=True,
        )
    )

    payload = json.loads(capsys.readouterr().out)
    assert result == cli.EXIT_APPROVAL
    assert "budget" in payload
    assert "action_ledger" in payload


def _trust_store(
    path: Path,
    key_id: str,
    usage: KeyUsage,
    key: Ed25519PrivateKey | None = None,
) -> TrustStoreV2:
    private = key or generate_ed25519_private_key()
    store = TrustStoreV2(
        keys=(
            TrustedKey(
                key_id=key_id,
                public_key=encode_base64(public_key_bytes(private)),
                usages=frozenset({usage}),
                valid_from=datetime(2020, 1, 1, tzinfo=UTC),
                valid_until=datetime(2099, 1, 1, tzinfo=UTC),
            ),
        )
    )
    path.write_text(store.model_dump_json(), encoding="utf-8")
    return store


def test_v3_key_governance_rejects_reused_key_material(tmp_path: Path) -> None:
    shared = generate_ed25519_private_key()
    publisher_path = tmp_path / "publisher.json"
    approval_path = tmp_path / "approval.json"
    review_path = tmp_path / "review.json"
    _trust_store(publisher_path, "publisher", KeyUsage.ROLE_MANIFEST, shared)
    _trust_store(approval_path, "approver", KeyUsage.APPROVAL, shared)
    _trust_store(review_path, "reviewer", KeyUsage.HUMAN_REVIEW)
    config = {
        "role_trust_store": publisher_path,
        "approval_trust_store": approval_path,
        "review_trust_store": review_path,
    }
    manifests = {"web": SimpleNamespace(key_id="publisher")}

    with pytest.raises(cli.CliError, match="distinct key material"):
        cli._validate_v3_key_separation(config, manifests)  # type: ignore[arg-type]


def test_v3_doctor_smokes_are_isolated_and_secret_safe(tmp_path: Path) -> None:
    vault = tmp_path / "identity-vault.json"
    vault.write_text(
        json.dumps(
            {
                "version": "1",
                "identities": {
                    "member": "member-doctor-secret",
                    "fixture-admin": "admin-doctor-secret",
                },
            }
        ),
        encoding="utf-8",
    )
    os.chmod(vault, 0o600)
    config = {
        "identity_vault": vault,
        "runs_root": tmp_path / "runs",
    }
    bridge = Path(__file__).resolve().parents[1] / "scripts/restricted_hermes_acp.py"

    assert cli._task_acp_db_smoke(bridge)
    assert cli._concurrency_smoke()
    assert cli._identity_injection_smoke(config)


def test_config_accepts_v3_only_manifest_bundle(tmp_path: Path) -> None:
    required = {
        "runs_root": "runs",
        "role_manifests_v3": "manifests-v3.json",
        "role_trust_store": "publisher.json",
        "approval_trust_store": "approval.json",
        "review_trust_store": "review.json",
        "prompt_root": "prompts",
        "hermes_cli": "bin/hermes",
        "hermes_python": "bin/python",
        "restricted_bridge": "bridge.py",
        "model": "fixture-model",
    }
    path = tmp_path / "config.json"
    path.write_text(json.dumps(required), encoding="utf-8")

    config = cli._config(path)

    assert "role_manifests" not in config
    assert config["role_manifests_v3"] == tmp_path / "manifests-v3.json"

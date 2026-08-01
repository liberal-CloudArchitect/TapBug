from __future__ import annotations

import json

from hermes import cli
from hermes.vertical_v2 import ExecutionState, NetworkState, VerticalState


def test_json_cli_emits_canonical_failed_state_for_runtime_failure(monkeypatch, capsys) -> None:
    state = VerticalState(
        run_id="run-provider-failure",
        execution_state=ExecutionState.FAILED,
        network_state=NetworkState.ENABLED_IDLE,
        requests_planned=3,
        requests_used=0,
        requests_blocked=0,
        current_role="gatekeeper",
        next_required_action="retry_as_new_run_and_reapprove",
        failure_stage="gatekeeper",
        failure_code="provider_billing_unavailable",
        failure_artifact="failures/provider.json",
    )

    def fail(_args):
        raise cli.CliRunFailure(state, RuntimeError("provider balance exhausted"))

    monkeypatch.setattr(cli, "_execute", fail)

    assert cli.main(["--json", "doctor", "--config", "/unused/config.json"]) == 1
    output = json.loads(capsys.readouterr().out)
    assert output["run_id"] == "run-provider-failure"
    assert output["execution_state"] == "failed"
    assert output["failure_code"] == "provider_billing_unavailable"
    assert output["next_required_action"] == "retry_as_new_run_and_reapprove"

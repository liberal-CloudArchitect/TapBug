from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

from hermes.providers import (
    HermesAcpProvider,
    ProviderBillingError,
    ProviderBudgetError,
    ProviderDenied,
    ProviderProtocolError,
)
from hermes.runtime.agents import ModelRequest, TaskEnvelope

ROOT = Path(__file__).resolve().parents[1]
SCOPE = "sha256:" + "a" * 64


def _task() -> TaskEnvelope:
    return TaskEnvelope(
        run_id="acp-run",
        task_id="recon-1",
        role="recon",
        scope_digest=SCOPE,
        timeout_seconds=5,
    )


def _fake_agent(tmp_path: Path, behavior: str) -> tuple[str, ...]:
    script = tmp_path / "fake_acp.py"
    script.write_text(
        "import json, os, sys\n"
        f"behavior = {behavior!r}\n"
        "assert os.environ['HERMES_ACP_TASK_ID'] == 'recon-1'\n"
        "def send(value): print(json.dumps(value), flush=True)\n"
        "init = json.loads(sys.stdin.readline())\n"
        "send({'jsonrpc':'2.0','id':init['id'],'result':{'protocolVersion':1,'agentCapabilities':{}}})\n"
        "new = json.loads(sys.stdin.readline())\n"
        "assert new['params']['mcpServers'] == []\n"
        "send({'jsonrpc':'2.0','id':new['id'],'result':{'sessionId':'session-1'}})\n"
        "prompt = json.loads(sys.stdin.readline())\n"
        "if behavior == 'permission':\n"
        " send({'jsonrpc':'2.0','id':99,'method':'session/request_permission','params':{}})\n"
        " reply=json.loads(sys.stdin.readline())\n"
        " assert reply['result']['outcome']['outcome'] == 'cancelled'\n"
        "elif behavior == 'tool':\n"
        " send({'jsonrpc':'2.0','method':'session/update','params':"
        "{'sessionId':'session-1','update':{'sessionUpdate':'tool_call',"
        "'toolCallId':'x','title':'bad','kind':'execute'}}})\n"
        "elif behavior == 'billing':\n"
        " print('HTTP 402: Insufficient Balance', file=sys.stderr, flush=True)\n"
        " send({'jsonrpc':'2.0','id':prompt['id'],'result':{'stopReason':'end_turn'}})\n"
        "else:\n"
        " if behavior == 'stderr_noise':\n"
        "  print('diagnostic-' + ('x' * 8192), file=sys.stderr, flush=True)\n"
        " if behavior == 'large_intermediate':\n"
        "  send({'jsonrpc':'2.0','method':'session/update','params':"
        "{'sessionId':'session-1','update':{'sessionUpdate':'agent_thought_chunk',"
        "'content':{'type':'text','text':'x' * 4096}}}})\n"
        " text = ('{\\\"payload\\\":\\\"' + ('x' * 2048) + '\\\"}') "
        "if behavior == 'large_final' else "
        '(\'{\\"label\\":\\"safe\\",\\"score\\":1}\' '
        "if behavior in ('ok', 'stderr_noise', 'large_intermediate') else 'not-json')\n"
        ' if behavior == \'fenced\': text = \'```json\\n{"label":"safe","score":1}\\n```\'\n'
        " send({'jsonrpc':'2.0','method':'session/update','params':"
        "{'sessionId':'session-1','update':{'sessionUpdate':'agent_message_chunk',"
        "'content':{'type':'text','text':text}}}})\n"
        " send({'jsonrpc':'2.0','id':prompt['id'],'result':{'stopReason':'end_turn'}})\n"
        " if behavior in ('text', 'repair'):\n"
        "  repair = json.loads(sys.stdin.readline())\n"
        '  repaired_text = \'{"label":"safe","score":1}\' '
        "if behavior == 'repair' else 'still-not-json'\n"
        "  send({'jsonrpc':'2.0','method':'session/update','params':"
        "{'sessionId':'session-1','update':{'sessionUpdate':'agent_message_chunk',"
        "'content':{'type':'text','text':repaired_text}}}})\n"
        "  send({'jsonrpc':'2.0','id':repair['id'],'result':{'stopReason':'end_turn'}})\n",
        encoding="utf-8",
    )
    return (sys.executable, str(script))


def _provider(tmp_path: Path, behavior: str) -> HermesAcpProvider:
    return HermesAcpProvider(_fake_agent(tmp_path, behavior), run_dir=tmp_path)


def test_acp_provider_returns_only_structured_json_and_advertises_no_mcp(tmp_path: Path) -> None:
    result = _provider(tmp_path, "ok").handle(
        ModelRequest(request_id="model-1", operation="classify", input={"value": "fixture"}),
        _task(),
    )
    assert result == {"label": "safe", "score": 1}
    metadata = (tmp_path / "provider" / "recon-1.json").read_text(encoding="utf-8")
    assert '"prompt_attempts":1' in metadata


def test_acp_provider_counts_schema_repair_as_a_second_prompt(tmp_path: Path) -> None:
    result = _provider(tmp_path, "repair").handle(
        ModelRequest(request_id="model-1", operation="classify", input={}),
        _task(),
    )

    assert result == {"label": "safe", "score": 1}
    metadata = (tmp_path / "provider" / "recon-1.json").read_text(encoding="utf-8")
    assert '"prompt_attempts":2' in metadata


def test_runner_adapter_wraps_domain_json_and_binds_host_evidence(tmp_path: Path) -> None:
    result = _provider(tmp_path, "ok")(
        ModelRequest(
            request_id="model-1",
            operation="extract",
            input={
                "evidence_refs": [
                    {
                        "id": "evidence-1",
                        "kind": "response",
                        "sha256": "sha256:" + "b" * 64,
                        "path": "evidence/evidence-1.json",
                        "redacted": True,
                    }
                ]
            },
        ),
        _task(),
    )

    assert result["result"] == {"label": "safe", "score": 1}
    assert result["evidence_ref_ids"] == ["evidence-1"]


@pytest.mark.parametrize("behavior", ["permission", "tool"])
def test_acp_provider_fails_closed_on_permission_or_tool_requests(
    tmp_path: Path, behavior: str
) -> None:
    with pytest.raises(ProviderDenied):
        _provider(tmp_path, behavior)(
            ModelRequest(request_id="model-1", operation="extract", input={}), _task()
        )


def test_acp_provider_rejects_unstructured_model_output(tmp_path: Path) -> None:
    with pytest.raises(ProviderProtocolError, match="schema-repair"):
        _provider(tmp_path, "text").handle(
            ModelRequest(request_id="model-1", operation="summarize", input={}), _task()
        )


def test_acp_provider_classifies_provider_billing_failure(tmp_path: Path) -> None:
    with pytest.raises(ProviderBillingError, match="insufficient balance"):
        _provider(tmp_path, "billing").handle(
            ModelRequest(request_id="model-1", operation="summarize", input={}), _task()
        )
    failure = tmp_path / "provider" / "failures" / "recon-1.json"
    assert '"error_type":"ProviderBillingError"' in failure.read_text(encoding="utf-8")


def test_acp_provider_does_not_charge_bounded_stderr_to_protocol_output(
    tmp_path: Path,
) -> None:
    provider = HermesAcpProvider(
        _fake_agent(tmp_path, "stderr_noise"),
        run_dir=tmp_path,
        max_output_bytes=4096,
        max_structured_output_bytes=1024,
    )

    result = provider.handle(
        ModelRequest(request_id="model-1", operation="classify", input={}),
        _task(),
    )

    assert result == {"label": "safe", "score": 1}


def test_acp_provider_allows_bounded_non_output_session_updates(tmp_path: Path) -> None:
    provider = HermesAcpProvider(
        _fake_agent(tmp_path, "large_intermediate"),
        run_dir=tmp_path,
        max_output_bytes=8192,
        max_structured_output_bytes=1024,
    )

    result = provider.handle(
        ModelRequest(request_id="model-1", operation="classify", input={}),
        _task(),
    )

    assert result == {"label": "safe", "score": 1}


def test_acp_provider_rejects_large_final_structured_response(tmp_path: Path) -> None:
    provider = HermesAcpProvider(
        _fake_agent(tmp_path, "large_final"),
        run_dir=tmp_path,
        max_output_bytes=8192,
        max_structured_output_bytes=1024,
    )

    with pytest.raises(ProviderProtocolError, match="structured response limit"):
        provider.handle(
            ModelRequest(request_id="model-1", operation="classify", input={}),
            _task(),
        )


def test_acp_provider_accepts_one_fenced_json_document(tmp_path: Path) -> None:
    result = _provider(tmp_path, "fenced").handle(
        ModelRequest(request_id="model-1", operation="classify", input={}), _task()
    )

    assert result == {"label": "safe", "score": 1}


def test_acp_provider_rejects_unsafe_task_id_before_starting_bridge(tmp_path: Path) -> None:
    unsafe_task = _task().model_copy(update={"task_id": "../escape"})

    with pytest.raises(ProviderProtocolError, match="session isolation"):
        _provider(tmp_path, "ok").handle(
            ModelRequest(request_id="model-1", operation="classify", input={}), unsafe_task
        )

    assert not (tmp_path / "provider").exists()


def test_v3_provider_requires_budget_before_starting_acp(tmp_path: Path) -> None:
    task = _task().model_copy(update={"version": "3", "payload": {"operation": "recon"}})
    provider = _provider(tmp_path, "ok")

    with pytest.raises(ProviderBudgetError, match="BudgetLedger"):
        provider.handle(
            ModelRequest(
                request_id="model-1",
                operation="extract",
                input={"prompt_version": "3.0"},
            ),
            task,
        )

    assert not (tmp_path / "provider").exists()


def test_acp_provider_v2_schema_validation_rejects_semantically_invalid_json() -> None:
    request = ModelRequest(
        request_id="model-1",
        operation="extract",
        input={"prompt_version": "2.0"},
    )
    assert HermesAcpProvider._schema_error({}, request, _task()) is not None


def test_acp_provider_keeps_v3_minor_prompt_versions_under_schema_validation() -> None:
    task = _task().model_copy(update={"version": "3", "payload": {"operation": "recon"}})
    request = ModelRequest(
        request_id="model-1",
        operation="extract",
        input={"prompt_version": "3.1"},
    )

    assert HermesAcpProvider._schema_error({}, request, task) is not None


def test_v3_verifier_schema_rebinds_model_outer_authority_before_validation() -> None:
    task = TaskEnvelope(
        version="3",
        run_id="acp-run",
        task_id="phase4-verifier-web-xcto",
        role="verifier",
        scope_digest=SCOPE,
        payload={
            "operation": "verification",
            "campaign_digest": "sha256:" + "b" * 64,
            "approval_batch_digest": "sha256:" + "c" * 64,
        },
    )
    request = ModelRequest(
        request_id="model-1", operation="extract", input={"prompt_version": "3.1"}
    )
    raw = {
        "run_id": "model-controlled",
        "scope_digest": "not-a-digest",
        "generated_by_task_id": "model-controlled",
        "outcome_set_id": "outcome-set-web-xcto",
        "campaign_digest": "not-a-digest",
        "approval_batch_digests": ["not-a-digest"],
        "outcomes": [
            {
                "outcome_id": "outcome-web-xcto",
                "candidate_id": "web-xcto",
                "verifier_task_id": task.task_id,
                "status": "validated",
                "action_digests": ["sha256:" + "d" * 64],
                "action_ledger_entry_digests": ["sha256:" + "e" * 64],
                "evidence": [
                    {
                        "evidence_id": "evidence-web-xcto",
                        "manifest_path": "evidence/evidence-web-xcto/manifest.json",
                        "manifest_sha256": "sha256:" + "f" * 64,
                    }
                ],
                "assertion_summary": "bounded fixture contrast",
            }
        ],
    }

    assert HermesAcpProvider._schema_error(raw, request, task) is None
    normalized = HermesAcpProvider._normalize_result(raw, request, task)
    assert normalized["run_id"] == task.run_id
    assert normalized["scope_digest"] == task.scope_digest
    assert normalized["generated_by_task_id"] == task.task_id
    assert normalized["campaign_digest"] == task.payload["campaign_digest"]
    assert normalized["approval_batch_digests"] == [task.payload["approval_batch_digest"]]


def test_v4_provider_rebinds_model_run_scope_and_task_authority() -> None:
    task = TaskEnvelope(
        version="4",
        run_id="v4-run",
        task_id="phase5-mapper",
        role="mapper",
        scope_digest=SCOPE,
        payload={"operation": "map", "target": "https://localhost:8443/candidate"},
    )
    request = ModelRequest(
        request_id="model-1", operation="extract", input={"prompt_version": "4.0"}
    )
    raw = {
        "run_id": "model-controlled",
        "scope_digest": "sha256:" + "b" * 64,
        "generated_by_task_id": "model-controlled",
        "map_id": "surface-1",
        "passive_posture_digest": "sha256:" + "c" * 64,
        "endpoints": [
            {
                "endpoint_id": "candidate",
                "url": "https://localhost:8443/candidate",
                "method": "GET",
                "route_kind": "candidate",
                "source_evidence": [
                    {
                        "evidence_id": "evidence-1",
                        "manifest_path": "evidence/evidence-1/manifest.json",
                        "manifest_sha256": "sha256:" + "d" * 64,
                    }
                ],
            }
        ],
    }

    assert HermesAcpProvider._schema_error(raw, request, task) is None
    normalized = HermesAcpProvider._normalize_result(raw, request, task)
    assert normalized["run_id"] == task.run_id
    assert normalized["scope_digest"] == task.scope_digest
    assert normalized["generated_by_task_id"] == task.task_id


def test_v4_reporter_requires_parent_injected_provider_authority() -> None:
    task = TaskEnvelope(
        version="4",
        run_id="v4-run",
        task_id="phase5-reporter",
        role="reporter",
        scope_digest=SCOPE,
        payload={
            "operation": "reporting",
            "reporter_launch_receipt_digest": "sha256:" + "b" * 64,
            "quality_gate_digest": "sha256:" + "c" * 64,
            "finding_set_digest": "sha256:" + "d" * 64,
            "coverage_appendix_digest": "sha256:" + "e" * 64,
        },
    )
    request = ModelRequest(
        request_id="model-1", operation="extract", input={"prompt_version": "4.0"}
    )
    bound_request = request.model_copy(
        update={
            "input": {
                **request.input,
                "provider_metadata_authority_digest": "sha256:" + "f" * 64,
            }
        }
    )

    with pytest.raises(ProviderProtocolError, match="metadata authority is missing"):
        HermesAcpProvider._bind_non_authoritative_fields({}, request, task)
    normalized = HermesAcpProvider._bind_non_authoritative_fields({}, bound_request, task)
    assert normalized["provider_metadata_digest"] == "sha256:" + "f" * 64
    assert HermesAcpProvider._schema_error({}, bound_request, task) is None


def test_acp_provider_normalizes_v2_defaults_before_role_runtime_hashing() -> None:
    request = ModelRequest(
        request_id="model-1",
        operation="extract",
        input={"prompt_version": "2.0"},
    )
    raw = {
        "inventory_id": "assets-1",
        "run_id": "acp-run",
        "scope_digest": SCOPE,
        "generated_by_task_id": "recon-1",
        "target": "http://localhost:8080/candidate",
        "assets": [
            {
                "asset_id": "asset-1",
                "kind": "web",
                "canonical_host": "localhost",
                "resolved_ips": ["127.0.0.1"],
                "scheme": "http",
                "port": 8080,
                "service": "http",
                "status_code": 200,
                "header_projection": {},
            }
        ],
        "source_evidence": [
            {
                "evidence_id": "evidence-1",
                "manifest_path": "evidence/evidence-1/manifest.json",
                "manifest_sha256": "sha256:" + "b" * 64,
            }
        ],
    }

    assert HermesAcpProvider._schema_error(raw, request, _task()) is None
    normalized = HermesAcpProvider._normalize_result(raw, request, _task())
    assert normalized["version"] == "2"
    assert normalized["assets"][0]["version"] == "2"


def test_restricted_bridge_uses_run_local_home_and_empty_tool_configuration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = ROOT / "scripts" / "restricted_hermes_acp.py"
    spec = importlib.util.spec_from_file_location("restricted_hermes_acp", path)
    assert spec is not None and spec.loader is not None
    bridge = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bridge)
    for name in (
        "HERMES_HOME",
        "HERMES_TOOLSETS",
        "HERMES_TOOLS",
        "HERMES_ACP_TOOLSETS",
        "HERMES_ACP_TASK_ID",
    ):
        monkeypatch.delenv(name, raising=False)

    state = bridge._prepare_environment(tmp_path)

    assert tmp_path in state.parents
    assert "HERMES_HOME" not in bridge.os.environ
    assert bridge.os.environ["HERMES_TOOLSETS"] == bridge.os.environ["HERMES_TOOLS"] == ""
    assert not (state / "config.yaml").exists()


def test_restricted_bridge_isolates_state_database_directory_per_task(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = ROOT / "scripts" / "restricted_hermes_acp.py"
    spec = importlib.util.spec_from_file_location("restricted_hermes_acp_sessions", path)
    assert spec is not None and spec.loader is not None
    bridge = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bridge)

    monkeypatch.setenv("HERMES_ACP_TASK_ID", "phase4-web-assessment")
    web_state = bridge._prepare_environment(tmp_path)
    monkeypatch.setenv("HERMES_ACP_TASK_ID", "phase4-api-assessment")
    api_state = bridge._prepare_environment(tmp_path)

    assert web_state == tmp_path / "provider" / "sessions" / "phase4-web-assessment"
    assert api_state == tmp_path / "provider" / "sessions" / "phase4-api-assessment"
    assert web_state != api_state


def test_restricted_bridge_rejects_unsafe_task_session_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = ROOT / "scripts" / "restricted_hermes_acp.py"
    spec = importlib.util.spec_from_file_location("restricted_hermes_acp_unsafe", path)
    assert spec is not None and spec.loader is not None
    bridge = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bridge)
    monkeypatch.setenv("HERMES_ACP_TASK_ID", "../escape")

    with pytest.raises(ValueError, match="safe path segment"):
        bridge._prepare_environment(tmp_path)


def test_restricted_bridge_overrides_model_after_loading_operator_environment(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    path = ROOT / "scripts" / "restricted_hermes_acp.py"
    spec = importlib.util.spec_from_file_location("restricted_hermes_acp_model", path)
    assert spec is not None and spec.loader is not None
    bridge = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bridge)
    monkeypatch.setenv("HERMES_MODEL", "operator-default")
    monkeypatch.setenv("HERMES_INFERENCE_MODEL", "operator-default")

    bridge._set_model_override("deepseek-v4-pro")

    assert bridge.os.environ["HERMES_MODEL"] == "deepseek-v4-pro"
    assert bridge.os.environ["HERMES_INFERENCE_MODEL"] == "deepseek-v4-pro"

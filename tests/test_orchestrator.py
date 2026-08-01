import json
from pathlib import Path

import pytest

from hermes.orchestrator import Orchestrator, _gateway_handler, main
from hermes.runtime import (
    ActionKind,
    HttpResponse,
    PolicyEngine,
    ProposedAction,
    RunContext,
    ScopePolicy,
    ScopeRule,
    ToolGateway,
)
from hermes.runtime.agents import GatewayActionRequest, TaskEnvelope


def test_default_orchestrator_creates_an_isolated_zero_egress_plan(tmp_path: Path) -> None:
    policy = ScopePolicy(
        profile="local-lab",
        automation_allowed=False,
        dry_run=True,
        rules=(
            ScopeRule(
                host="127.0.0.1",
                schemes={"http"},
                ports={8080},
                allow_dns=False,
                allow_private=True,
                profile="local-lab",
            ),
        ),
    )
    snapshot = policy.model_dump(mode="json")
    plan = Orchestrator(policy, snapshot, runs_root=tmp_path).plan(["http://127.0.0.1:8080/"])

    assert plan.exists()
    assert (
        '"network_execution":"disabled-until-a-gateway-transport-is-configured"' in plan.read_text()
    )


def test_subprocess_cli_refuses_to_create_a_run_without_all_trust_inputs(tmp_path: Path) -> None:
    scope = tmp_path / "scope.yaml"
    scope.write_text(
        "profile: local-lab\n"
        "automation_allowed: false\n"
        "dry_run: true\n"
        "rules:\n"
        "  - host: 127.0.0.1\n"
        "    schemes: [http]\n"
        "    ports: [8080]\n"
        "    allow_dns: false\n"
        "    allow_private: true\n"
        "    profile: local-lab\n",
        encoding="utf-8",
    )

    with pytest.raises(SystemExit):
        main(
            [
                "--scope",
                str(scope),
                "--runs-root",
                str(tmp_path / "runs"),
                "--target",
                "http://127.0.0.1:8080/",
                "--agent-mode",
                "subprocess",
            ]
        )

    assert not (tmp_path / "runs").exists()


def test_legacy_response_evidence_ref_uses_the_response_hash(tmp_path: Path) -> None:
    policy = ScopePolicy(
        profile="local-lab",
        automation_allowed=True,
        dry_run=False,
        rules=(
            ScopeRule(
                host="localhost",
                schemes={"http"},
                ports={8080},
                allow_dns=True,
                allow_private=True,
                profile="local-lab",
            ),
        ),
    )
    context = RunContext(tmp_path / "runs", policy.model_dump(mode="json"), run_id="hash-run")
    gateway = ToolGateway(
        engine=PolicyEngine(policy, resolver=lambda _host: ["127.0.0.1"]),
        context=context,
        transport=lambda _request: HttpResponse(200, {"Content-Type": "text/plain"}, b"ok"),
    )
    target = "http://localhost:8080/candidate"
    result = _gateway_handler(gateway)(
        GatewayActionRequest(
            request_id="request-1",
            action=ProposedAction(kind=ActionKind.HTTP_GET, target=target, method="GET"),
            url=target,
        ),
        TaskEnvelope(
            run_id=context.run_id,
            task_id="recon-1",
            role="recon",
            scope_digest=context.scope_digest,
        ),
    )
    evidence_ref = result["evidence_ref"]
    evidence = json.loads(
        context.artifact_path(str(evidence_ref["path"])).read_text(encoding="utf-8")
    )
    assert evidence_ref["kind"] == "response"
    assert evidence_ref["sha256"] == evidence["response_hash"]
    assert evidence_ref["sha256"] != evidence["request_hash"]

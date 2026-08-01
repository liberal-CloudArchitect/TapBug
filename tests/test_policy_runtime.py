from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hermes.runtime import (  # noqa: E402
    ActionKind,
    ApprovalAuthority,
    AuditLogger,
    CommandGateway,
    HttpResponse,
    PolicyDenied,
    PolicyEngine,
    ProposedAction,
    RunContext,
    ScopePolicy,
    ScopeRule,
    ToolGateway,
)


def policy(**overrides):
    base = dict(
        profile="local",
        rules=(
            ScopeRule(
                host="localhost",
                schemes={"http"},
                ports={8080},
                allow_dns=True,
                allow_private=True,
                profile="local",
            ),
        ),
        automation_allowed=True,
        dry_run=False,
        max_requests=5,
        rate_limit_rps=1000,
    )
    base.update(overrides)
    return ScopePolicy(**base)


def context(tmp_path: Path, scope: ScopePolicy) -> RunContext:
    return RunContext(tmp_path / "runs", scope.model_dump(mode="json"), run_id="test-run")


def test_run_context_isolated_immutable_and_audited(tmp_path):
    scope = policy()
    run = context(tmp_path, scope)
    assert (run.path / "scope.json").exists()
    with pytest.raises(FileExistsError):
        run.write_json("scope.json", {}, immutable=True)
    run.write_json("handoffs/one.json", {"ok": True}, immutable=True)
    assert json.loads((run.path / "handoffs/one.json").read_text()) == {"ok": True}
    record = AuditLogger(run).record("test", decision="allowed")
    assert record["run_id"] == "test-run"
    assert "test" in run.audit_path.read_text()


def test_scope_is_exact_and_rejects_implicit_subdomain_and_private_resolution():
    scope = policy(
        rules=(
            ScopeRule(
                host="example.test", schemes={"https"}, ports={443}, allow_dns=True, profile="local"
            ),
        )
    )
    engine = PolicyEngine(scope, resolver=lambda _host: ["93.184.216.34"])
    assert engine.resolve_url("https://example.test/").connect_ip == "93.184.216.34"
    with pytest.raises(PolicyDenied):
        engine.resolve_url("https://api.example.test/")
    with pytest.raises(PolicyDenied):
        PolicyEngine(scope, resolver=lambda _host: ["169.254.169.254"]).resolve_url(
            "https://example.test/"
        )
    with pytest.raises(ValueError):
        ScopeRule(
            host="127.0.0.0/8", schemes={"http"}, ports={80}, allow_dns=False, allow_private=True
        )


def test_scope_evidence_limits_are_bounded_and_coherent():
    scope = policy()
    assert scope.evidence_capture_max_bytes == 1_048_576
    assert scope.evidence_analysis_max_bytes == 65_536
    assert not scope.retain_encrypted_raw_evidence

    with pytest.raises(ValueError):
        policy(evidence_capture_max_bytes=10_485_761)
    with pytest.raises(ValueError, match="analysis limit"):
        policy(evidence_capture_max_bytes=1024, evidence_analysis_max_bytes=2048)


def test_scope_supports_explicit_wildcard_cidr_and_exact_ipv6_only():
    wildcard = ScopeRule(
        host="*.example.test",
        schemes={"https"},
        ports={443},
        allow_dns=True,
        profile="local",
    )
    cidr = ScopeRule(
        host="8.8.8.0/24",
        schemes={"https"},
        ports={443},
        allow_dns=False,
        profile="local",
    )
    ipv6 = ScopeRule(
        host="::1",
        schemes={"http"},
        ports={8080},
        allow_dns=False,
        allow_private=True,
        profile="local",
    )
    scope = policy(rules=(wildcard, cidr, ipv6))
    engine = PolicyEngine(scope, resolver=lambda _host: ["93.184.216.34"])

    assert engine.resolve_url("https://api.example.test/").host == "api.example.test"
    assert engine.resolve_url("https://8.8.8.8/").connect_ip == "8.8.8.8"
    assert engine.resolve_url("http://[::1]:8080/").connect_ip == "::1"
    with pytest.raises(PolicyDenied):
        engine.resolve_url("https://example.test/")
    with pytest.raises(PolicyDenied):
        engine.resolve_url("https://user:pass@api.example.test/")


def test_gateway_denies_before_transport_for_dry_run_scope(tmp_path):
    calls = []
    scope = policy(dry_run=True)
    run = context(tmp_path, scope)
    gateway = ToolGateway(
        engine=PolicyEngine(scope, resolver=lambda _host: ["127.0.0.1"]),
        context=run,
        transport=lambda request: calls.append(request) or HttpResponse(200, {}),
    )
    with pytest.raises(PolicyDenied):
        gateway.request("GET", "http://localhost:8080/")
    assert calls == []
    assert '"decision":"denied"' in run.audit_path.read_text()


def test_gateway_enforces_request_budget_before_a_second_connection(tmp_path):
    calls = []
    scope = policy(max_requests=1, rate_limit_rps=1000)
    run = context(tmp_path, scope)
    gateway = ToolGateway(
        engine=PolicyEngine(scope, resolver=lambda _host: ["127.0.0.1"]),
        context=run,
        transport=lambda request: calls.append(request) or HttpResponse(200, {}),
    )

    gateway.request("GET", "http://localhost:8080/")
    with pytest.raises(PolicyDenied, match="request budget"):
        gateway.request("GET", "http://localhost:8080/")
    assert len(calls) == 1


def test_request_budget_survives_gateway_reconstruction(tmp_path):
    calls = []
    scope = policy(max_requests=1, rate_limit_rps=1000)
    run = context(tmp_path, scope)
    first = ToolGateway(
        engine=PolicyEngine(scope, resolver=lambda _host: ["127.0.0.1"]),
        context=run,
        transport=lambda request: calls.append(request) or HttpResponse(200, {}),
    )
    second = ToolGateway(
        engine=PolicyEngine(scope, resolver=lambda _host: ["127.0.0.1"]),
        context=run,
        transport=lambda request: calls.append(request) or HttpResponse(200, {}),
    )

    first.request("GET", "http://localhost:8080/candidate")
    with pytest.raises(PolicyDenied, match="request budget"):
        second.request("GET", "http://localhost:8080/control")

    assert len(calls) == 1
    assert len(list((run.path / "network" / "reservations").glob("*.json"))) == 1


def test_repeated_identical_gets_keep_distinct_evidence_records(tmp_path):
    scope = policy(rate_limit_rps=1000)
    run = context(tmp_path, scope)
    gateway = ToolGateway(
        engine=PolicyEngine(scope, resolver=lambda _host: ["127.0.0.1"]),
        context=run,
        transport=lambda _request: HttpResponse(200, {"Content-Type": "text/html"}, b"same"),
    )

    _, first = gateway.request("GET", "http://localhost:8080/candidate")
    _, second = gateway.request("GET", "http://localhost:8080/candidate")

    assert first.request_hash == second.request_hash
    assert first.evidence_id != second.evidence_id
    assert len(list((run.path / "evidence").glob("*.json"))) == 2


def test_gateway_waits_for_rate_limit_instead_of_rejecting_second_request(tmp_path, monkeypatch):
    clock = [100.0]
    sleeps = []

    def sleep(seconds):
        sleeps.append(seconds)
        clock[0] += seconds

    monkeypatch.setattr("hermes.runtime.gateway.time.monotonic", lambda: clock[0])
    monkeypatch.setattr("hermes.runtime.gateway.time.sleep", sleep)
    scope = policy(rate_limit_rps=2)
    run = context(tmp_path, scope)
    calls = []
    gateway = ToolGateway(
        engine=PolicyEngine(scope, resolver=lambda _host: ["127.0.0.1"]),
        context=run,
        transport=lambda request: calls.append(request) or HttpResponse(200, {}),
    )

    gateway.request("GET", "http://localhost:8080/candidate")
    gateway.request("GET", "http://localhost:8080/control")

    assert len(calls) == 2
    assert sleeps == [0.5]


def test_post_requires_single_use_bound_ed25519_approval_and_pins_connection(tmp_path):
    scope = policy()
    run = context(tmp_path, scope)
    captured = []
    authority = ApprovalAuthority()
    gateway = ToolGateway(
        engine=PolicyEngine(scope, resolver=lambda _host: ["127.0.0.1"]),
        context=run,
        approval_authority=authority,
        transport=lambda request: (
            captured.append(request) or HttpResponse(201, {"x": "ok"}, b"safe")
        ),
    )
    action = ProposedAction(
        kind=ActionKind.HTTP_POST, target="http://localhost:8080/write", method="POST"
    )
    token = authority.approve(
        authority.challenge(run_id=run.run_id, scope_digest=run.scope_digest, action=action), action
    )
    response, evidence = gateway.request("POST", "http://localhost:8080/write", approval=token)
    assert response.status_code == 201 and evidence.request_hash.startswith("sha256:")
    assert captured[0].connect_ip == "127.0.0.1" and captured[0].host_header == "localhost:8080"
    with pytest.raises(PolicyDenied):
        gateway.request("POST", "http://localhost:8080/write", approval=token)


def test_approval_consumption_is_persisted_across_gateway_instances(tmp_path):
    scope = policy()
    run = context(tmp_path, scope)
    issuer = ApprovalAuthority()
    action = ProposedAction(
        kind=ActionKind.HTTP_POST, target="http://localhost:8080/write", method="POST"
    )
    token = issuer.approve(
        issuer.challenge(run_id=run.run_id, scope_digest=run.scope_digest, action=action), action
    )
    first = ToolGateway(
        engine=PolicyEngine(scope, resolver=lambda _host: ["127.0.0.1"]),
        context=run,
        approval_authority=issuer,
        transport=lambda _request: HttpResponse(201, {}),
    )
    first.request("POST", action.target, approval=token)

    restarted_verifier = ApprovalAuthority(public_key=issuer.public_key_bytes)
    replay = ToolGateway(
        engine=PolicyEngine(scope, resolver=lambda _host: ["127.0.0.1"]),
        context=run,
        approval_authority=restarted_verifier,
        transport=lambda _request: pytest.fail("replayed approval reached transport"),
    )
    with pytest.raises(PolicyDenied, match="already consumed"):
        replay.request("POST", action.target, approval=token)
    assert len(list((run.path / "approvals" / "consumed").glob("*.json"))) == 1


def test_approval_challenge_and_grant_are_audited_without_storing_raw_token(tmp_path):
    scope = policy()
    run = context(tmp_path, scope)
    authority = ApprovalAuthority()
    gateway = ToolGateway(
        engine=PolicyEngine(scope, resolver=lambda _host: ["127.0.0.1"]),
        context=run,
        approval_authority=authority,
    )
    action = ProposedAction(
        kind=ActionKind.HTTP_POST,
        target="http://localhost:8080/write",
        method="POST",
    )

    challenge = gateway.request_approval(action)
    token = gateway.grant_approval(challenge, action)

    assert (run.path / "approvals" / "challenges" / f"{challenge.challenge_id}.json").exists()
    granted = list((run.path / "approvals" / "granted").glob("*.json"))
    assert len(granted) == 1
    assert token.encoded not in granted[0].read_text()


def test_post_cannot_be_mislabeled_as_safe_get_to_bypass_approval(tmp_path):
    scope = policy()
    run = context(tmp_path, scope)
    calls = []
    gateway = ToolGateway(
        engine=PolicyEngine(scope, resolver=lambda _host: ["127.0.0.1"]),
        context=run,
        transport=lambda request: calls.append(request) or HttpResponse(200, {}),
    )

    with pytest.raises(PolicyDenied, match="safe read action"):
        gateway.request(
            "POST",
            "http://localhost:8080/write",
            action_kind=ActionKind.HTTP_GET,
        )
    assert calls == []


def test_out_of_scope_redirect_is_rejected_without_a_second_transport_call(tmp_path):
    scope = policy()
    run = context(tmp_path, scope)
    calls = []
    gateway = ToolGateway(
        engine=PolicyEngine(scope, resolver=lambda _host: ["127.0.0.1"]),
        context=run,
        transport=lambda request: (
            calls.append(request) or HttpResponse(302, {"Location": "http://evil.test/"})
        ),
    )

    with pytest.raises(PolicyDenied):
        gateway.request("GET", "http://localhost:8080/", follow_redirects=True, max_redirects=1)
    assert len(calls) == 1


def test_command_needs_scope_allowlist_and_approval_without_subprocess(tmp_path):
    scope = policy(allowed_commands={"echo"})
    run = context(tmp_path, scope)
    authority = ApprovalAuthority()
    gateway = ToolGateway(
        engine=PolicyEngine(scope, resolver=lambda _host: ["127.0.0.1"]),
        context=run,
        approval_authority=authority,
    )
    command = CommandGateway(gateway=gateway, executor=lambda argv: (0, " ".join(argv[1:]), ""))
    action = ProposedAction(kind=ActionKind.COMMAND, target="command:echo", detail="echo hello")
    token = authority.approve(
        authority.challenge(run_id=run.run_id, scope_digest=run.scope_digest, action=action), action
    )
    assert command.run(["echo", "hello"], approval=token) == (0, "hello", "")
    with pytest.raises(PolicyDenied):
        command.run(["curl", "example.test"])

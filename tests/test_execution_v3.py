from __future__ import annotations

import hashlib
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hermes.campaign_v3 import materialized_body_digest
from hermes.domain_contracts import canonical_digest
from hermes.domain_contracts_v3 import (
    ApprovalBatchV3,
    VerificationActionV3,
    VerificationCampaignPlan,
)
from hermes.evidence import EvidenceStore
from hermes.execution_v3 import (
    ApprovalConsumptionStoreV3,
    CompensationManagerV3,
    GovernedExecutionError,
    GovernedGatewayV3,
)
from hermes.ledgers_v3 import ActionLedger, ActionReservationConflict, ActionRetryDenied
from hermes.runtime.actions import ActionKind, ProposedAction
from hermes.runtime.agents.contracts import GatewayActionRequest, TaskEnvelope
from hermes.runtime.context import RunContext
from hermes.runtime.gateway import HttpRequest, HttpResponse, Transport
from hermes.runtime.policy import PolicyEngine, ScopePolicy, ScopeRule
from hermes.security import (
    KeyUsage,
    TrustedKey,
    TrustStoreV2,
    encode_base64,
    public_key_bytes,
)
from hermes.security_v3 import (
    IdentityCredentialV3,
    IdentityVaultV3,
    approval_actions_v3,
    sign_approval_batch_v3,
)

NOW = datetime(2026, 7, 14, 12, tzinfo=UTC)
EMPTY = "sha256:" + hashlib.sha256(b"").hexdigest()


def _scope() -> ScopePolicy:
    return ScopePolicy(
        profile="local",
        rules=(
            ScopeRule(
                host="localhost",
                schemes=frozenset({"http"}),
                ports=frozenset({8080}),
                allow_dns=True,
                allow_private=True,
                profile="local",
            ),
        ),
        automation_allowed=True,
        dry_run=False,
        max_requests=15,
        max_concurrency=4,
        rate_limit_rps=1000,
    )


def _context(tmp_path: Path) -> tuple[RunContext, ScopePolicy]:
    scope = _scope()
    return RunContext(tmp_path / "runs", scope.model_dump(mode="json"), "run-v3"), scope


def _action(
    context: RunContext,
    action_id: str,
    candidate_id: str,
    *,
    purpose: Literal[
        "baseline", "candidate", "negative_control", "cleanup", "cleanup_check"
    ] = "candidate",
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"] = "GET",
    path: str = "/candidate",
    risk: Literal["readonly", "mutation", "cleanup"] = "readonly",
    body_sha256: str | None = None,
    identity: str | None = None,
    cleanup_of: str | None = None,
    depends_on: tuple[str, ...] = (),
) -> VerificationActionV3:
    authority = {
        "run_id": context.run_id,
        "scope_digest": context.scope_digest,
        "candidate_consumers": (candidate_id,),
        "purpose": purpose,
        "risk_group": risk,
        "method": method,
        "target_url": f"http://localhost:8080{path}",
        "body_sha256": body_sha256,
        "identity_binding_digest": identity,
        "depends_on": depends_on,
        "cleanup_of": cleanup_of,
    }
    return VerificationActionV3(
        action_id=action_id,
        candidate_id=candidate_id,
        candidate_consumers=(candidate_id,),
        purpose=purpose,
        risk_group=risk,
        action_kind="validation_http_get" if method == "GET" else "validation_http_request",
        method=method,
        target_url=f"http://localhost:8080{path}",
        body_sha256=body_sha256,
        identity_binding_digest=identity,
        action_digest=canonical_digest(authority),
        depends_on=depends_on,
        cleanup_of=cleanup_of,
    )


def _campaign(
    context: RunContext, actions: tuple[VerificationActionV3, ...]
) -> VerificationCampaignPlan:
    return VerificationCampaignPlan(
        run_id=context.run_id,
        scope_digest=context.scope_digest,
        generated_by_task_id="planner-v3",
        campaign_id="campaign-v3",
        candidate_collection_digest="sha256:" + "a" * 64,
        cross_review_set_digest="sha256:" + "b" * 64,
        actions=actions,
        request_budget=len(actions),
        created_at=NOW,
        expires_at=NOW + timedelta(minutes=15),
    )


def _approval(
    campaign: VerificationCampaignPlan,
    private: Ed25519PrivateKey,
    *,
    risk: Literal["readonly", "mutation", "cleanup"],
) -> tuple[ApprovalBatchV3, TrustStoreV2]:
    eligible = approval_actions_v3(campaign, risk)
    candidates = tuple(dict.fromkeys(item.candidate_id for item in eligible))
    unsigned = ApprovalBatchV3(
        run_id=campaign.run_id,
        scope_digest=campaign.scope_digest,
        generated_by_task_id="approver-v3",
        approval_id=f"approval-{risk}",
        campaign_digest=campaign.digest,
        risk_group=risk,
        verdict="approved",
        candidate_ids=candidates,
        action_digests=tuple(item.action_digest for item in eligible),
        key_id="approver-key",
        signed_at=NOW + timedelta(seconds=1),
        expires_at=NOW + timedelta(minutes=10),
        rationale="Approve the complete exact local fixture action graph.",
        signature_b64="unsigned-signature",
    )
    batch = sign_approval_batch_v3(unsigned, private)
    store = TrustStoreV2(
        keys=(
            TrustedKey(
                key_id="approver-key",
                public_key=encode_base64(public_key_bytes(private)),
                usages=frozenset({KeyUsage.APPROVAL}),
                valid_from=NOW - timedelta(days=1),
                valid_until=NOW + timedelta(days=1),
            ),
        )
    )
    return batch, store


def _task(
    context: RunContext,
    actions: tuple[VerificationActionV3, ...],
    approval: ApprovalBatchV3,
    *,
    task_id: str = "verify-web",
) -> TaskEnvelope:
    return TaskEnvelope(
        version="3",
        run_id=context.run_id,
        task_id=task_id,
        role="verifier",
        scope_digest=context.scope_digest,
        payload={
            "actions": [item.model_dump(mode="json") for item in actions],
            "approval_id": approval.approval_id,
        },
        allowed_actions=("validation_http_get", "http_post"),
        request_budget=len(actions),
        evidence_required=True,
    )


def _request(
    task: TaskEnvelope, action: VerificationActionV3, index: int = 0
) -> GatewayActionRequest:
    kind = ActionKind.VALIDATION_HTTP_GET if action.method == "GET" else ActionKind.HTTP_POST
    return GatewayActionRequest(
        request_id=f"{task.task_id}:gateway:{index}",
        action=ProposedAction(
            kind=kind,
            target=action.target_url,
            method=action.method,
            max_requests=1,
            detail=action.action_digest,
        ),
        url=action.target_url,
        approval_token=str(task.payload["approval_id"]),
    )


def _gateway(
    context: RunContext,
    scope: ScopePolicy,
    campaign: VerificationCampaignPlan,
    batch: ApprovalBatchV3,
    trust: TrustStoreV2,
    transport: Transport,
    *,
    candidate_types: dict[str, str] | None = None,
    vault: IdentityVaultV3 | None = None,
) -> GovernedGatewayV3:
    return GovernedGatewayV3(
        context=context,
        campaign=campaign,
        approval_batches=(batch,),
        consumption_store=ApprovalConsumptionStoreV3(
            context,
            campaign,
            trust,
            clock=lambda: NOW + timedelta(minutes=1),
        ),
        action_ledger=ActionLedger(context),
        policy_engine=PolicyEngine(scope, resolver=lambda _host: ("127.0.0.1",)),
        evidence_store=EvidenceStore(context.path),
        transport=transport,
        candidate_types=candidate_types
        or {item.candidate_id: "missing_x_content_type_options" for item in campaign.actions},
        identity_vault=vault,
    )


def test_exact_task_action_consumes_signed_approval_and_commits_evidence(
    tmp_path: Path,
) -> None:
    context, scope = _context(tmp_path)
    action = _action(context, "web-candidate", "web-xcto")
    campaign = _campaign(context, (action,))
    batch, trust = _approval(campaign, Ed25519PrivateKey.generate(), risk="readonly")
    seen: list[HttpRequest] = []

    def transport(request: HttpRequest) -> HttpResponse:
        seen.append(request)
        return HttpResponse(200, {"Content-Type": "text/html"}, b"ok")

    gateway = _gateway(context, scope, campaign, batch, trust, transport)
    task = _task(context, (action,), batch)
    first = gateway.execute_task_action(task=task, request=_request(task, action), action_index=0)

    assert len(seen) == 1
    assert first.action_digest == action.action_digest
    manifest = gateway.evidence_store.verify(first.evidence_artifact_ref)
    second = gateway.execute_task_action(task=task, request=_request(task, action), action_index=0)
    assert len(seen) == 1  # second call reused committed evidence; no new transport
    assert second.reused is True
    assert manifest.binding.action_digest == action.action_digest
    assert manifest.binding.approval_bundle_digest == batch.digest
    assert first.evidence_artifact_ref.manifest_sha256.startswith("sha256:")


def test_agent_cannot_choose_url_body_headers_or_action_index(tmp_path: Path) -> None:
    context, scope = _context(tmp_path)
    action = _action(context, "web-candidate", "web-xcto")
    campaign = _campaign(context, (action,))
    batch, trust = _approval(campaign, Ed25519PrivateKey.generate(), risk="readonly")
    calls = 0

    def transport(_request: HttpRequest) -> HttpResponse:
        nonlocal calls
        calls += 1
        return HttpResponse(200, {}, b"ok")

    gateway = _gateway(context, scope, campaign, batch, trust, transport)
    task = _task(context, (action,), batch)
    request = _request(task, action).model_copy(update={"headers": {"X-Evil": "1"}})
    with pytest.raises(GovernedExecutionError, match="differs"):
        gateway(request, task)
    with pytest.raises(GovernedExecutionError, match="outside"):
        gateway.execute_task_action(task=task, request=_request(task, action), action_index=1)
    assert calls == 0


def test_concurrent_duplicate_claim_allows_only_one_transport(tmp_path: Path) -> None:
    context, scope = _context(tmp_path)
    action = _action(context, "web-candidate", "web-xcto")
    campaign = _campaign(context, (action,))
    batch, trust = _approval(campaign, Ed25519PrivateKey.generate(), risk="readonly")
    entered = threading.Event()
    release = threading.Event()
    calls = 0

    def transport(_request: HttpRequest) -> HttpResponse:
        nonlocal calls
        calls += 1
        entered.set()
        release.wait(2)
        return HttpResponse(200, {}, b"ok")

    gateway = _gateway(context, scope, campaign, batch, trust, transport)
    task = _task(context, (action,), batch)
    failures: list[Exception] = []

    def execute() -> None:
        try:
            gateway(_request(task, action), task)
        except Exception as exc:  # expected for the losing concurrent owner
            failures.append(exc)

    first = threading.Thread(target=execute)
    second = threading.Thread(target=execute)
    first.start()
    assert entered.wait(2)
    second.start()
    second.join(2)
    release.set()
    first.join(2)

    assert calls == 1
    assert len(failures) == 1
    assert isinstance(failures[0], ActionReservationConflict)


def test_failure_after_transport_is_never_retried(tmp_path: Path) -> None:
    context, scope = _context(tmp_path)
    action = _action(context, "web-candidate", "web-xcto")
    campaign = _campaign(context, (action,))
    batch, trust = _approval(campaign, Ed25519PrivateKey.generate(), risk="readonly")
    calls = 0

    def transport(_request: HttpRequest) -> HttpResponse:
        nonlocal calls
        calls += 1
        raise OSError("connection outcome unknown")

    gateway = _gateway(context, scope, campaign, batch, trust, transport)
    task = _task(context, (action,), batch)
    with pytest.raises(OSError, match="unknown"):
        gateway(_request(task, action), task)
    with pytest.raises(ActionRetryDenied, match="retry is forbidden"):
        gateway(_request(task, action), task)
    assert calls == 1


def test_parent_injects_identity_and_compensation_restores_mutation(tmp_path: Path) -> None:
    context, scope = _context(tmp_path)
    member_secret = "phase4-member-token"
    admin_secret = "phase4-fixture-admin-token"
    member_binding = canonical_digest({"test": "member"})
    admin_binding = canonical_digest({"test": "admin"})
    vault = IdentityVaultV3(
        Path("/external/identity-vault.json"),
        {
            "member": IdentityCredentialV3("member", member_secret, member_binding),
            "fixture-admin": IdentityCredentialV3("fixture-admin", admin_secret, admin_binding),
        },
    )
    candidate = "api-graphql"
    baseline = _action(
        context,
        "api-baseline",
        candidate,
        purpose="baseline",
        path="/graphql",
        risk="mutation",
        identity=member_binding,
    )
    forward = _action(
        context,
        "api-forward",
        candidate,
        method="POST",
        path="/graphql/mutate",
        risk="mutation",
        body_sha256=materialized_body_digest("unauthorized_graphql_mutation", "candidate"),
        identity=member_binding,
    )
    cleanup = _action(
        context,
        "api-cleanup",
        candidate,
        purpose="cleanup",
        method="POST",
        path="/graphql/cleanup",
        risk="mutation",
        body_sha256=materialized_body_digest("unauthorized_graphql_mutation", "cleanup"),
        identity=admin_binding,
        cleanup_of=forward.action_id,
        depends_on=(forward.action_id,),
    )
    check = _action(
        context,
        "api-cleanup-check",
        candidate,
        purpose="cleanup_check",
        path="/graphql",
        risk="mutation",
        identity=member_binding,
        depends_on=(cleanup.action_id,),
    )
    campaign = _campaign(context, (baseline, forward, cleanup, check))
    batch, trust = _approval(campaign, Ed25519PrivateKey.generate(), risk="mutation")
    state = {"value": "initial"}
    auth_seen: list[str] = []

    def transport(request: HttpRequest) -> HttpResponse:
        auth_seen.append(str(request.headers.get("Authorization")))
        if request.url.endswith("/mutate"):
            state["value"] = "mutated"
        elif request.url.endswith("/cleanup"):
            state["value"] = "initial"
        return HttpResponse(200, {"Content-Type": "application/json"}, b"{}")

    gateway = _gateway(
        context,
        scope,
        campaign,
        batch,
        trust,
        transport,
        candidate_types={candidate: "unauthorized_graphql_mutation"},
        vault=vault,
    )
    task = _task(context, (baseline, forward), batch, task_id="verify-api")
    gateway(_request(task, baseline, index=0), task)
    gateway(_request(task, forward, index=1), task)
    assert state["value"] == "mutated"
    initial = canonical_digest({"value": "initial"})
    manager = CompensationManagerV3(
        context=context,
        campaign=campaign,
        gateway=gateway,
        action_ledger=gateway.action_ledger,
        mutation_approval=batch,
        initial_state_sha256=initial,
        state_hash_reader=lambda: canonical_digest(state),
        clock=lambda: NOW + timedelta(minutes=2),
    )
    receipt = manager.run()

    assert receipt.state_restored is True
    assert receipt.results[0].status == "cleaned"
    assert len(receipt.results[0].evidence) == 2
    assert auth_seen == [
        f"Bearer {member_secret}",
        f"Bearer {member_secret}",
        f"Bearer {admin_secret}",
        f"Bearer {member_secret}",
    ]
    latest = {item["action_id"]: item["state"] for item in gateway.action_ledger.events()}
    assert latest[forward.action_id] == "cleaned"


def test_cleanup_only_gateway_consumes_only_cleanup_projection(tmp_path: Path) -> None:
    context, scope = _context(tmp_path)
    admin_binding = canonical_digest({"test": "admin"})
    vault = IdentityVaultV3(
        Path("/external/identity-vault.json"),
        {
            "fixture-admin": IdentityCredentialV3("fixture-admin", "admin-secret", admin_binding),
        },
    )
    forward = _action(
        context,
        "api-forward",
        "api-graphql",
        method="POST",
        path="/graphql/mutate",
        risk="mutation",
        body_sha256=materialized_body_digest("unauthorized_graphql_mutation", "candidate"),
        identity=admin_binding,
    )
    cleanup = _action(
        context,
        "api-cleanup",
        "api-graphql",
        purpose="cleanup",
        method="POST",
        path="/graphql/cleanup",
        risk="mutation",
        body_sha256=materialized_body_digest("unauthorized_graphql_mutation", "cleanup"),
        identity=admin_binding,
        cleanup_of=forward.action_id,
        depends_on=(forward.action_id,),
    )
    check = _action(
        context,
        "api-cleanup-check",
        "api-graphql",
        purpose="cleanup_check",
        path="/graphql",
        risk="mutation",
        identity=admin_binding,
        depends_on=(cleanup.action_id,),
    )
    campaign = _campaign(context, (forward, cleanup, check))
    batch, trust = _approval(campaign, Ed25519PrivateKey.generate(), risk="cleanup")
    seen: list[str] = []

    def transport(request: HttpRequest) -> HttpResponse:
        seen.append(request.url)
        return HttpResponse(200, {"Content-Type": "application/json"}, b"{}")

    gateway = _gateway(
        context,
        scope,
        campaign,
        batch,
        trust,
        transport,
        candidate_types={"api-graphql": "unauthorized_graphql_mutation"},
        vault=vault,
    )
    gateway.execute_parent_action(action=cleanup, batch=batch, task_id="cleanup-only-api")
    gateway.execute_parent_action(action=check, batch=batch, task_id="cleanup-only-api-check")

    assert seen == [cleanup.target_url, check.target_url]
    assert forward.target_url not in seen
    consumptions = tuple(context.artifact_path("approvals_v3/consumptions").glob("*.json"))
    assert len(consumptions) == 2


def test_failed_compensation_is_cleanup_required_and_never_reports_restored(
    tmp_path: Path,
) -> None:
    context, scope = _context(tmp_path)
    member_binding = canonical_digest({"test": "member"})
    admin_binding = canonical_digest({"test": "admin"})
    vault = IdentityVaultV3(
        Path("/external/identity-vault.json"),
        {
            "member": IdentityCredentialV3("member", "member-secret", member_binding),
            "fixture-admin": IdentityCredentialV3("fixture-admin", "admin-secret", admin_binding),
        },
    )
    candidate = "api-graphql"
    forward = _action(
        context,
        "api-forward",
        candidate,
        method="POST",
        path="/graphql/mutate",
        risk="mutation",
        body_sha256=materialized_body_digest("unauthorized_graphql_mutation", "candidate"),
        identity=member_binding,
    )
    cleanup = _action(
        context,
        "api-cleanup",
        candidate,
        purpose="cleanup",
        method="POST",
        path="/graphql/cleanup",
        risk="mutation",
        body_sha256=materialized_body_digest("unauthorized_graphql_mutation", "cleanup"),
        identity=admin_binding,
        cleanup_of=forward.action_id,
        depends_on=(forward.action_id,),
    )
    check = _action(
        context,
        "api-cleanup-check",
        candidate,
        purpose="cleanup_check",
        path="/graphql",
        risk="mutation",
        identity=admin_binding,
        depends_on=(cleanup.action_id,),
    )
    campaign = _campaign(context, (forward, cleanup, check))
    batch, trust = _approval(campaign, Ed25519PrivateKey.generate(), risk="mutation")
    state = {"value": "initial"}

    calls = 0

    def transport(request: HttpRequest) -> HttpResponse:
        nonlocal calls
        calls += 1
        if request.url.endswith("/mutate"):
            state["value"] = "mutated"
            return HttpResponse(200, {}, b"{}")
        raise OSError("cleanup transport failed")

    gateway = _gateway(
        context,
        scope,
        campaign,
        batch,
        trust,
        transport,
        candidate_types={candidate: "unauthorized_graphql_mutation"},
        vault=vault,
    )
    task = _task(context, (forward,), batch, task_id="verify-api")
    gateway(_request(task, forward), task)
    manager = CompensationManagerV3(
        context=context,
        campaign=campaign,
        gateway=gateway,
        action_ledger=gateway.action_ledger,
        mutation_approval=batch,
        initial_state_sha256=canonical_digest({"value": "initial"}),
        state_hash_reader=lambda: canonical_digest(state),
        clock=lambda: NOW + timedelta(minutes=2),
    )

    receipt = manager.run()

    assert receipt.state_restored is False
    assert receipt.results[0].status == "cleanup_required"
    latest = {item["action_id"]: item["state"] for item in gateway.action_ledger.events()}
    assert latest[forward.action_id] == "cleanup_required"
    assert latest[cleanup.action_id] == "failed_after_transport"
    second = manager.run()
    assert second.state_restored is False
    assert calls == 2  # forward + first cleanup; failed-after-transport is never replayed
    assert not context.artifact_path("verification_v3/cleanup.json").exists()
    assert not context.artifact_path("report/reporter-launch-v3.json").exists()
    assert not context.artifact_path("report/reporter-ack-v3.json").exists()
    assert not context.artifact_path("report/report-v3.md").exists()
    assert not context.artifact_path("report/findings-v3.json").exists()
    assert not context.artifact_path("report/report-write-receipt-v3.json").exists()


def test_compensation_state_reader_failure_is_fail_closed(tmp_path: Path) -> None:
    """A missing cleanup-check artifact must become cleanup_required, not a CLI crash."""

    context, scope = _context(tmp_path)
    member_binding = canonical_digest({"test": "member"})
    admin_binding = canonical_digest({"test": "admin"})
    vault = IdentityVaultV3(
        Path("/external/identity-vault.json"),
        {
            "member": IdentityCredentialV3("member", "member-secret", member_binding),
            "fixture-admin": IdentityCredentialV3("fixture-admin", "admin-secret", admin_binding),
        },
    )
    candidate = "api-graphql"
    forward = _action(
        context,
        "api-forward",
        candidate,
        method="POST",
        path="/graphql/mutate",
        risk="mutation",
        body_sha256=materialized_body_digest("unauthorized_graphql_mutation", "candidate"),
        identity=member_binding,
    )
    cleanup = _action(
        context,
        "api-cleanup",
        candidate,
        purpose="cleanup",
        method="POST",
        path="/graphql/cleanup",
        risk="mutation",
        body_sha256=materialized_body_digest("unauthorized_graphql_mutation", "cleanup"),
        identity=admin_binding,
        cleanup_of=forward.action_id,
        depends_on=(forward.action_id,),
    )
    check = _action(
        context,
        "api-cleanup-check",
        candidate,
        purpose="cleanup_check",
        path="/graphql",
        risk="mutation",
        identity=member_binding,
        depends_on=(cleanup.action_id,),
    )
    campaign = _campaign(context, (forward, cleanup, check))
    batch, trust = _approval(campaign, Ed25519PrivateKey.generate(), risk="mutation")

    gateway = _gateway(
        context,
        scope,
        campaign,
        batch,
        trust,
        lambda _request: HttpResponse(200, {"Content-Type": "application/json"}, b"{}"),
        candidate_types={candidate: "unauthorized_graphql_mutation"},
        vault=vault,
    )
    task = _task(context, (forward,), batch, task_id="verify-api")
    gateway(_request(task, forward), task)
    manager = CompensationManagerV3(
        context=context,
        campaign=campaign,
        gateway=gateway,
        action_ledger=gateway.action_ledger,
        mutation_approval=batch,
        initial_state_sha256=canonical_digest({"value": "initial"}),
        state_hash_reader=lambda: (_ for _ in ()).throw(
            RuntimeError("cleanup check evidence unavailable")
        ),
        clock=lambda: NOW + timedelta(minutes=2),
    )

    receipt = manager.run()

    assert receipt.state_restored is False
    assert receipt.final_state_sha256 is None
    assert receipt.results[0].status == "cleanup_required"
    assert not context.artifact_path("verification_v3/cleanup.json").exists()

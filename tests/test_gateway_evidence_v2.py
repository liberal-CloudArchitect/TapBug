from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from hermes.evidence import EvidencePolicy, EvidenceStore
from hermes.runtime.actions import ActionKind
from hermes.runtime.context import RunContext
from hermes.runtime.errors import ApprovalDenied
from hermes.runtime.gateway import (
    GatewayExecutionContext,
    HttpRequest,
    HttpResponse,
    ToolGateway,
)
from hermes.runtime.policy import PolicyEngine, ScopePolicy, ScopeRule
from hermes.runtime.transport import PinnedHttpTransport
from hermes.vertical_contracts import (
    ApprovalConsumptionV2,
    RunPlan,
    SignedHumanReview,
)

DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64


def policy() -> ScopePolicy:
    return ScopePolicy(
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
        max_requests=3,
        rate_limit_rps=1000,
    )


def run_context(tmp_path: Path, scope: ScopePolicy) -> RunContext:
    return RunContext(tmp_path / "runs", scope.model_dump(mode="json"), run_id="run-1")


def recon_execution() -> GatewayExecutionContext:
    return GatewayExecutionContext(
        task_id="task-recon",
        task_input_sha256=DIGEST_A,
        role="recon",
        request_id="request-recon",
        action_id="recon-get",
    )


def verifier_execution() -> GatewayExecutionContext:
    return GatewayExecutionContext(
        task_id="task-verifier",
        task_input_sha256=DIGEST_A,
        role="verifier",
        request_id="request-verifier",
        action_id="verify-target",
        plan_digest=DIGEST_B,
        approval_bundle_id="bundle-1",
        approval_bundle_digest=DIGEST_C,
    )


def gateway(
    tmp_path: Path,
    *,
    validator=None,
    transport=None,
) -> tuple[ToolGateway, EvidenceStore]:
    scope = policy()
    context = run_context(tmp_path, scope)
    store = EvidenceStore(
        context.path,
        policy=EvidencePolicy(
            capture_limit_bytes=scope.evidence_capture_max_bytes,
            analysis_limit_bytes=scope.evidence_analysis_max_bytes,
        ),
    )
    return (
        ToolGateway(
            engine=PolicyEngine(scope, resolver=lambda _host: ("127.0.0.1",)),
            context=context,
            evidence_store=store,
            external_approval_validator_v2=validator,
            transport=transport
            or (
                lambda _request: HttpResponse(
                    200,
                    {"Content-Type": "text/plain", "X-Repeat": "two"},
                    b"ok",
                    header_fields=(
                        ("Content-Type", "text/plain"),
                        ("X-Repeat", "one"),
                        ("X-Repeat", "two"),
                    ),
                    original_body_bytes=2,
                )
            ),
        ),
        store,
    )


def test_recon_v2_evidence_has_task_action_run_scope_without_approval(tmp_path: Path) -> None:
    tool, store = gateway(tmp_path)
    response, ref = tool.request_v2(
        "GET", "http://localhost:8080/candidate?token=secret", execution=recon_execution()
    )

    assert response.status_code == 200
    manifest = store.verify(ref)
    assert manifest.binding.run_id == "run-1"
    assert manifest.binding.scope_digest == tool.context.scope_digest
    assert manifest.binding.task_id == "task-recon"
    assert manifest.binding.action_id == "recon-get"
    assert manifest.binding.plan_digest is None
    assert manifest.binding.approval_bundle_id is None
    assert manifest.binding.approval_consumption_digest is None
    assert manifest.response_hash != manifest.request_hash
    analysis = json.loads((tool.context.path / manifest.analysis.path).read_text())
    assert analysis["request"]["url"].endswith("token=%5BREDACTED%5D")
    assert analysis["response"]["headers"][-2:] == [
        {"name": "X-Repeat", "value": "one"},
        {"name": "X-Repeat", "value": "two"},
    ]


def test_verifier_consumption_is_bound_to_preallocated_evidence_id(tmp_path: Path) -> None:
    seen: list[tuple[str, str]] = []

    def validate(action, token, execution, evidence_id):
        seen.append((evidence_id, action.digest))
        assert token == "bundle-1"
        return ApprovalConsumptionV2(
            bundle_id="bundle-1",
            bundle_digest=DIGEST_C,
            plan_digest=DIGEST_B,
            run_id="run-1",
            scope_digest=tool.context.scope_digest,
            task_id=execution.task_id,
            request_id=execution.request_id,
            evidence_id=evidence_id,
            action_id=execution.action_id,
            action_digest=action.digest,
            consumed_at=datetime.now(UTC),
        )

    tool, store = gateway(tmp_path, validator=validate)
    _, ref = tool.request_v2(
        "GET",
        "http://localhost:8080/candidate",
        execution=verifier_execution(),
        action_kind=ActionKind.VALIDATION_HTTP_GET,
        approval="bundle-1",
    )

    manifest = store.verify(ref)
    assert seen == [(ref.evidence_id, manifest.binding.action_digest)]
    assert manifest.binding.evidence_id == ref.evidence_id
    assert manifest.binding.plan_digest == DIGEST_B
    assert manifest.binding.approval_bundle_id == "bundle-1"
    assert manifest.binding.approval_bundle_digest == DIGEST_C
    assert manifest.binding.approval_consumption_digest is not None


@pytest.mark.parametrize(
    "changed",
    ["evidence_id", "action_digest", "task_id", "run_id", "plan_digest", "bundle_digest"],
)
def test_gateway_rejects_misbound_v2_consumption_before_transport(
    tmp_path: Path, changed: str
) -> None:
    calls: list[object] = []

    def validate(action, _token, execution, evidence_id):
        values = {
            "bundle_id": "bundle-1",
            "bundle_digest": DIGEST_C,
            "plan_digest": DIGEST_B,
            "run_id": "run-1",
            "scope_digest": tool.context.scope_digest,
            "task_id": execution.task_id,
            "request_id": execution.request_id,
            "evidence_id": evidence_id,
            "action_id": execution.action_id,
            "action_digest": action.digest,
            "consumed_at": datetime.now(UTC),
        }
        replacements = {
            "evidence_id": "other-evidence",
            "action_digest": DIGEST_A,
            "task_id": "other-task",
            "run_id": "other-run",
            "plan_digest": DIGEST_A,
            "bundle_digest": DIGEST_A,
        }
        values[changed] = replacements[changed]
        return ApprovalConsumptionV2(**values)

    tool, _ = gateway(
        tmp_path,
        validator=validate,
        transport=lambda request: calls.append(request) or HttpResponse(200, {}),
    )
    with pytest.raises(ApprovalDenied, match="consumption is not bound"):
        tool.request_v2(
            "GET",
            "http://localhost:8080/candidate",
            execution=verifier_execution(),
            action_kind=ActionKind.VALIDATION_HTTP_GET,
            approval="bundle-1",
        )
    assert calls == []


def test_v2_rejects_missing_approval_context_or_store(tmp_path: Path) -> None:
    tool, _ = gateway(tmp_path)
    with pytest.raises(ApprovalDenied, match="approval context"):
        tool.request_v2(
            "GET",
            "http://localhost:8080/candidate",
            execution=recon_execution(),
            action_kind=ActionKind.VALIDATION_HTTP_GET,
            approval="bundle-1",
        )

    scope = policy()
    no_store = ToolGateway(
        engine=PolicyEngine(scope, resolver=lambda _host: ("127.0.0.1",)),
        context=run_context(tmp_path / "other", scope),
        transport=lambda _request: HttpResponse(200, {}),
    )
    with pytest.raises(ValueError, match="EvidenceStore"):
        no_store.request_v2("GET", "http://localhost:8080/candidate", execution=recon_execution())


def test_transport_truncation_metadata_reaches_manifest(tmp_path: Path) -> None:
    tool, store = gateway(
        tmp_path,
        transport=lambda _request: HttpResponse(
            200,
            {"Content-Type": "text/plain"},
            b"captured",
            header_fields=(("Content-Type", "text/plain"),),
            original_body_bytes=None,
            truncated=True,
        ),
    )
    _, ref = tool.request_v2("GET", "http://localhost:8080/candidate", execution=recon_execution())
    manifest = store.verify(ref)
    assert manifest.response_captured_bytes == len(b"captured")
    assert manifest.response_truncated is True


def test_pinned_transport_stops_at_limit_and_preserves_ordered_headers(monkeypatch) -> None:
    read_sizes: list[int] = []

    class Response:
        status = 200

        def getheaders(self):
            return [("X-Repeat", "one"), ("X-Repeat", "two")]

        def getheader(self, _name):
            return None

        def read(self, amount):
            read_sizes.append(amount)
            return b"x" * amount

    class Connection:
        def request(self, *_args, **_kwargs):
            return None

        def getresponse(self):
            return Response()

        def close(self):
            return None

    monkeypatch.setattr(
        "hermes.runtime.transport._PinnedHttpConnection",
        lambda *_args, **_kwargs: Connection(),
    )
    response = PinnedHttpTransport()(
        HttpRequest(
            method="GET",
            url="http://localhost:8080/candidate",
            connect_ip="127.0.0.1",
            host_header="localhost:8080",
            tls_server_name=None,
            headers={"Host": "localhost:8080"},
            response_body_limit=8,
        )
    )
    assert read_sizes == [9]
    assert response.body == b"x" * 8
    assert response.truncated is True
    assert response.original_body_bytes is None
    assert response.header_fields == (("X-Repeat", "one"), ("X-Repeat", "two"))


def test_run_plan_defaults_v2_and_review_v2_requires_both_digests() -> None:
    plan = RunPlan(
        run_id="run-1",
        target="http://localhost:8080/candidate",
        scope_digest=DIGEST_A,
        provider="hermes-acp",
        model="test-model",
        roles=("gatekeeper", "recon", "mapper", "web-vuln", "verifier", "reporter"),
        prompt_registry_digest=DIGEST_B,
    )
    assert plan.version == "2"

    base = {
        "version": "2",
        "review_id": "review-1",
        "finding_id": "finding-1",
        "run_id": "run-1",
        "scope_digest": DIGEST_A,
        "evidence_digest": DIGEST_B,
        "reviewer": "reviewer",
        "verdict": "accepted",
        "rationale": "Evidence and differential were reviewed.",
        "reviewed_at": datetime.now(UTC),
        "key_id": "reviewer-key",
        "signature": "placeholder",
    }
    with pytest.raises(ValidationError, match="outcome and report draft"):
        SignedHumanReview(**base)
    review = SignedHumanReview(**base, outcome_digest=DIGEST_B, report_draft_digest=DIGEST_C)
    assert review.digest.startswith("sha256:")

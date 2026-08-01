from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from hermes.domain_contracts import (
    AssetInventory,
    AssetRecord,
    CandidateRecord,
    CandidateSet,
    CoverageReport,
    EndpointInventory,
    EndpointRecord,
    ValidatedFinding,
    VerificationOutcome,
    VerificationPlan,
    VerificationStep,
    VerificationStepOutcome,
    canonical_digest,
)
from hermes.evidence import EvidenceBinding, EvidenceStore, HeaderField
from hermes.metrics import collect_pre_report_metrics
from hermes.preflight import ReportPreflightError, ReportPreflightVerifier
from hermes.prompts import PromptRegistry
from hermes.runtime import RunContext
from hermes.runtime.agents import (
    RoleManifest,
    RoleTrustStore,
    TaskEnvelope,
    TaskResult,
    role_manifest_signing_payload,
)
from hermes.security import (
    KeyUsage,
    TrustedKey,
    TrustStoreV2,
    encode_base64,
    generate_ed25519_private_key,
    public_key_bytes,
)
from hermes.vertical_contracts import (
    ActionDecision,
    ApprovalBundle,
    ApprovalConsumptionV2,
    RunPlan,
    SignedHumanReview,
    sign_approval_bundle,
    sign_human_review,
)

ROOT = Path(__file__).resolve().parents[1]
ROLE_ORDER = ("gatekeeper", "recon", "mapper", "web-vuln", "verifier", "reporter")


@dataclass(frozen=True)
class Fixture:
    context: RunContext
    verifier: ReportPreflightVerifier
    approval: ApprovalBundle
    plan: VerificationPlan


def _trust(usage: KeyUsage, key_id: str, now: datetime):
    private = generate_ed25519_private_key()
    store = TrustStoreV2(
        keys=(
            TrustedKey(
                key_id=key_id,
                public_key=encode_base64(public_key_bytes(private)),
                usages=frozenset({usage}),
                valid_from=now - timedelta(days=1),
                valid_until=now + timedelta(days=1),
            ),
        )
    )
    return private, store


def _write(context: RunContext, relative: str, value: object) -> None:
    assert hasattr(value, "model_dump")
    context.write_json(relative, value.model_dump(mode="json"), immutable=True)  # type: ignore[attr-defined]


def _fixture(
    tmp_path: Path,
    *,
    recon_link: str | None = '</control>; rel="negative-control"',
    candidate_nosniff: str | None = None,
    control_nosniff: str | None = "nosniff",
    control_body: bytes = b"fixture",
    control_truncated: bool = False,
    candidate_mime: str = "text/html",
    control_mime: str = "text/html",
    recon_mime: str = "text/html",
) -> Fixture:
    context = RunContext(
        tmp_path / "runs",
        {"profile": "local-lab", "max_requests": 3},
        run_id="preflight-run",
    )
    now = datetime.now(UTC)
    approval_private, approval_store = _trust(KeyUsage.APPROVAL, "approver-1", now)
    review_private, review_store = _trust(KeyUsage.HUMAN_REVIEW, "reviewer-1", now)
    publisher_private = generate_ed25519_private_key()
    publisher_store = RoleTrustStore({"publisher-1": public_key_bytes(publisher_private)})
    prompt_registry = PromptRegistry(ROOT)
    manifests: list[RoleManifest] = []
    for role in ROLE_ORDER:
        entry = prompt_registry.roles[role]
        unsigned = RoleManifest(
            role=role,
            prompt_id=f"hermes.{role}",
            prompt_version=str(entry["prompt_version"]),
            prompt_sha256=str(entry["prompt_sha256"]),
            output_contract_id=str(entry["output_contract_id"]),
            image="sha256:" + "b" * 64,
            command=("/opt/hermes/agent",),
            allowed_ipc=tuple(entry["allowed_ipc"]),
            key_id="publisher-1",
            signature="unsigned",
        )
        manifests.append(
            unsigned.model_copy(
                update={
                    "signature": publisher_private.sign(
                        role_manifest_signing_payload(unsigned)
                    ).hex()
                }
            )
        )
    context.write_json(
        "plan/role-manifests.json",
        {"version": "1", "roles": [item.model_dump(mode="json") for item in manifests]},
        immutable=True,
    )
    context.write_json(
        "plan/prompt-registry.json",
        json.loads((ROOT / "prompts" / "registry.json").read_text(encoding="utf-8")),
        immutable=True,
    )
    context.write_json(
        "plan/run-plan.json",
        RunPlan(
            run_id=context.run_id,
            target="http://localhost:8080/candidate",
            scope_digest=context.scope_digest,
            provider="hermes-acp-restricted",
            model="fixture",
            roles=ROLE_ORDER,
            prompt_registry_digest=prompt_registry.digest,
        ).model_dump(mode="json"),
        immutable=True,
    )
    tasks: dict[str, TaskEnvelope] = {}
    for index, role in enumerate(ROLE_ORDER[:-1]):
        task_id = f"phase3-{role}"
        task = TaskEnvelope(
            run_id=context.run_id,
            task_id=task_id,
            role=role,
            scope_digest=context.scope_digest,
            created_at=now + timedelta(seconds=index),
        )
        result = TaskResult(
            task=task,
            lifecycle="completed",
            input_sha256=task.input_hash(),
            started_at=now + timedelta(seconds=index),
            finished_at=now + timedelta(seconds=index, milliseconds=500),
        )
        context.write_json(
            f"handoffs/{task_id}.json",
            {"task": task.model_dump(mode="json"), "result": result.model_dump(mode="json")},
            immutable=True,
        )
        context.write_json(
            f"provider/{task_id}.json",
            {
                "run_id": context.run_id,
                "task_id": task_id,
                "prompt_attempts": 1,
                "token_usage": None,
            },
            immutable=True,
        )
        tasks[role] = task
    recon_task = tasks["recon"]
    verifier_task = tasks["verifier"]
    store = EvidenceStore(context.path)

    recon_ref = store.capture(
        binding=EvidenceBinding(
            evidence_id="recon-evidence",
            run_id=context.run_id,
            scope_digest=context.scope_digest,
            task_id=recon_task.task_id,
            task_input_sha256=recon_task.input_hash(),
            role="recon",
            request_id="recon-request",
            action_id="recon-get",
            action_digest="sha256:" + "2" * 64,
            captured_at=now,
        ),
        request_method="GET",
        request_url="http://localhost:8080/candidate",
        request_headers=(),
        request_body=b"",
        response_status=200,
        response_headers=(
            HeaderField(name="content-type", value=recon_mime),
            *((HeaderField(name="link", value=recon_link),) if recon_link is not None else ()),
        ),
        response_body=b"candidate",
    )
    assets = AssetInventory(
        inventory_id="assets-1",
        run_id=context.run_id,
        scope_digest=context.scope_digest,
        generated_by_task_id=recon_task.task_id,
        target="http://localhost:8080/candidate",
        assets=(
            AssetRecord(
                asset_id="asset-1",
                resolved_ips=("127.0.0.1",),
                scheme="http",
                port=8080,
                service="http",
                status_code=200,
                header_projection={
                    "content-type": recon_mime,
                    **({"link": recon_link} if recon_link is not None else {}),
                },
            ),
        ),
        source_evidence=(recon_ref,),
    )
    endpoints = EndpointInventory(
        inventory_id="endpoints-1",
        run_id=context.run_id,
        scope_digest=context.scope_digest,
        generated_by_task_id="mapper-1",
        asset_inventory_digest=assets.digest,
        endpoints=(
            EndpointRecord(
                endpoint_id="endpoint-candidate",
                asset_id="asset-1",
                canonical_url="http://localhost:8080/candidate",
                relation="candidate",
                evidence=(recon_ref,),
            ),
            EndpointRecord(
                endpoint_id="endpoint-control",
                asset_id="asset-1",
                canonical_url="http://localhost:8080/control",
                relation="negative_control",
                evidence=(recon_ref,),
            ),
        ),
    )
    candidates = CandidateSet(
        set_id="candidates-1",
        run_id=context.run_id,
        scope_digest=context.scope_digest,
        generated_by_task_id="web-vuln-1",
        endpoint_inventory_digest=endpoints.digest,
        prompt_id="web-vuln",
        prompt_sha256="sha256:" + "3" * 64,
        candidates=(
            CandidateRecord(
                candidate_id="missing-x-content-type-options",
                target_endpoint_id="endpoint-candidate",
                control_endpoint_id="endpoint-control",
                rationale="candidate lacks nosniff while its control supplies it",
                counterexamples=("an upstream proxy could inject the header",),
                required_evidence=(recon_ref,),
            ),
        ),
    )
    plan = VerificationPlan(
        plan_id="verification-1",
        run_id=context.run_id,
        scope_digest=context.scope_digest,
        generated_by_task_id="planner-1",
        candidate_set_digest=candidates.digest,
        endpoint_inventory_digest=endpoints.digest,
        candidate_id="missing-x-content-type-options",
        steps=(
            VerificationStep(
                action_id="target-get",
                endpoint_id="endpoint-candidate",
                purpose="candidate",
                target_url="http://localhost:8080/candidate",
                expected_assertion="nosniff is absent",
                evidence_prerequisites=(recon_ref,),
            ),
            VerificationStep(
                action_id="control-get",
                endpoint_id="endpoint-control",
                purpose="negative_control",
                target_url="http://localhost:8080/control",
                expected_assertion="nosniff is present",
                evidence_prerequisites=(recon_ref,),
            ),
        ),
        created_at=now - timedelta(seconds=1),
        expires_at=now + timedelta(minutes=10),
    )
    approval = sign_approval_bundle(
        ApprovalBundle(
            version="2",
            bundle_id="approval-1",
            plan_digest=plan.digest,
            run_id=context.run_id,
            scope_digest=context.scope_digest,
            candidate_id=plan.candidate_id,
            total_requests=2,
            approver="approver@example.test",
            reviewer="approver@example.test",
            decisions=tuple(
                ActionDecision(
                    action_id=step.action_id,
                    decision="approved",
                    rationale="approved for the local fixture",
                )
                for step in plan.steps
            ),
            issued_at=now,
            expires_at=now + timedelta(minutes=5),
            key_id="approver-1",
            signature="unsigned",
        ),
        approval_private,
    )

    consumptions = tuple(
        ApprovalConsumptionV2(
            bundle_id=approval.bundle_id,
            bundle_digest=approval.digest,
            plan_digest=plan.digest,
            run_id=context.run_id,
            scope_digest=context.scope_digest,
            task_id=verifier_task.task_id,
            request_id=f"request-{index}",
            evidence_id=f"verification-evidence-{index}",
            action_id=step.action_id,
            action_digest=step.action_digest,
            consumed_at=now + timedelta(seconds=index),
        )
        for index, step in enumerate(plan.steps, start=1)
    )
    verification_refs = tuple(
        store.capture(
            binding=EvidenceBinding(
                evidence_id=consumption.evidence_id,
                run_id=context.run_id,
                scope_digest=context.scope_digest,
                task_id=verifier_task.task_id,
                task_input_sha256=verifier_task.input_hash(),
                role="verifier",
                request_id=consumption.request_id,
                action_id=step.action_id,
                action_digest=step.action_digest,
                plan_digest=plan.digest,
                approval_bundle_id=approval.bundle_id,
                approval_bundle_digest=approval.digest,
                approval_consumption_digest=consumption.digest,
                captured_at=now + timedelta(seconds=index + 2),
            ),
            request_method="GET",
            request_url=step.target_url,
            request_headers=(),
            request_body=b"",
            response_status=200,
            response_headers=(
                HeaderField(
                    name="content-type",
                    value=(control_mime if step.purpose == "negative_control" else candidate_mime),
                ),
                *(
                    (HeaderField(name="x-content-type-options", value=value),)
                    if (
                        value := (
                            control_nosniff
                            if step.purpose == "negative_control"
                            else candidate_nosniff
                        )
                    )
                    is not None
                    else ()
                ),
            ),
            response_body=(control_body if step.purpose == "negative_control" else b"fixture"),
            response_original_bytes=(
                10_000 if step.purpose == "negative_control" and control_truncated else None
            ),
            response_was_truncated=(step.purpose == "negative_control" and control_truncated),
        )
        for index, (step, consumption) in enumerate(
            zip(plan.steps, consumptions, strict=True), start=1
        )
    )
    outcome = VerificationOutcome(
        outcome_id="outcome-1",
        run_id=context.run_id,
        scope_digest=context.scope_digest,
        generated_by_task_id=verifier_task.task_id,
        candidate_id=plan.candidate_id,
        verification_plan_digest=plan.digest,
        approval_bundle_id=approval.bundle_id,
        approval_bundle_digest=approval.digest,
        step_outcomes=tuple(
            VerificationStepOutcome(
                action_id=step.action_id,
                action_digest=step.action_digest,
                consumption_digest=consumption.digest,
                evidence=ref,
                status="passed",
                assertion=step.expected_assertion,
            )
            for step, consumption, ref in zip(
                plan.steps, consumptions, verification_refs, strict=True
            )
        ),
        status="validated",
        differential_assertion=True,
        assertion_summary="candidate omits nosniff while control supplies it",
    )
    draft = b"# Review draft\n\nLocal teaching fixture only.\n"
    context.write_text(ReportPreflightVerifier.DRAFT, draft.decode(), immutable=True)
    review = sign_human_review(
        SignedHumanReview(
            version="2",
            review_id="review-1",
            finding_id=plan.candidate_id,
            run_id=context.run_id,
            scope_digest=context.scope_digest,
            evidence_digest=outcome.digest,
            outcome_digest=outcome.digest,
            report_draft_digest="sha256:" + hashlib.sha256(draft).hexdigest(),
            reviewer="reviewer@example.test",
            verdict="accepted",
            rationale="the approved target/control evidence supports the local finding",
            reviewed_at=now + timedelta(seconds=10),
            key_id="reviewer-1",
            signature="unsigned",
        ),
        review_private,
    )
    finding = ValidatedFinding(
        finding_id=plan.candidate_id,
        candidate_id=plan.candidate_id,
        run_id=context.run_id,
        scope_digest=context.scope_digest,
        generated_by_task_id="promotion-1",
        candidate_set_digest=candidates.digest,
        verification_plan_digest=plan.digest,
        verification_outcome_digest=outcome.digest,
        approval_bundle_id=approval.bundle_id,
        approval_bundle_digest=approval.digest,
        approval_consumption_digests=tuple(item.digest for item in consumptions),
        signed_review_id=review.review_id,
        signed_review_digest=canonical_digest(review),
        evidence=(recon_ref, *verification_refs),
        title="Missing X-Content-Type-Options",
        target="http://localhost:8080/candidate",
        summary="The teaching candidate lacks nosniff while its control supplies it.",
        reproduction_steps=("GET the candidate and negative control",),
        impact="Local teaching demonstration only.",
        remediation="Return X-Content-Type-Options: nosniff.",
        severity="informational",
    )
    metrics = collect_pre_report_metrics(context)
    coverage = CoverageReport(
        report_id="coverage-1",
        run_id=context.run_id,
        scope_digest=context.scope_digest,
        generated_by_task_id="coverage-1",
        asset_inventory_digest=assets.digest,
        endpoint_inventory_digest=endpoints.digest,
        candidate_set_digest=candidates.digest,
        verification_plan_digest=plan.digest,
        verification_outcome_digest=outcome.digest,
        validated_finding_digest=finding.digest,
        steps_planned=2,
        steps_tested=2,
        steps_blocked=0,
        steps_skipped=0,
        findings_validated=1,
        candidates_inconclusive=0,
        candidates_disproved=0,
        model_calls=metrics.model_calls,
        elapsed_ms=metrics.elapsed_ms,
        cost_microusd=metrics.cost_microusd,
    )

    for path, value in (
        (ReportPreflightVerifier.ASSETS, assets),
        (ReportPreflightVerifier.ENDPOINTS, endpoints),
        (ReportPreflightVerifier.CANDIDATES, candidates),
        (ReportPreflightVerifier.PLAN, plan),
        (ReportPreflightVerifier.OUTCOME, outcome),
        (ReportPreflightVerifier.FINDING, finding),
        (ReportPreflightVerifier.COVERAGE, coverage),
        (ReportPreflightVerifier.APPROVAL, approval),
        (ReportPreflightVerifier.REVIEW, review),
    ):
        _write(context, path, value)
    for consumption in consumptions:
        _write(
            context,
            f"approvals/consumed/{approval.bundle_id}/{consumption.action_id}.json",
            consumption,
        )
    return Fixture(
        context=context,
        verifier=ReportPreflightVerifier(
            context,
            approval_store=approval_store,
            review_store=review_store,
            publisher_store=publisher_store,
            prompt_registry=prompt_registry,
        ),
        approval=approval,
        plan=plan,
    )


def _replace_json(path: Path, **updates: object) -> None:
    document = json.loads(path.read_text(encoding="utf-8"))
    document.update(updates)
    path.write_text(json.dumps(document), encoding="utf-8")


def test_preflight_authorizes_only_the_complete_canonical_chain(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    bundle = fixture.verifier.verify()

    assert bundle.authorization.run_id == fixture.context.run_id
    assert bundle.authorization.validated_finding_digest == bundle.finding.digest
    assert bundle.authorization.approval_bundle_digest == fixture.approval.digest
    assert len(bundle.evidence_manifests) == 3
    assert (
        bundle.authorization.authorization_input_digest
        == fixture.verifier.authorize().authorization_input_digest
    )


@pytest.mark.parametrize(
    (
        "recon_link",
        "candidate_nosniff",
        "control_nosniff",
        "control_body",
        "control_truncated",
        "candidate_mime",
        "control_mime",
    ),
    (
        (None, None, "nosniff", b"fixture", False, "text/html", "text/html"),
        (
            '</wrong>; rel="negative-control"',
            None,
            "nosniff",
            b"fixture",
            False,
            "text/html",
            "text/html",
        ),
        (
            '</control>; rel="negative-control"',
            "nosniff",
            "nosniff",
            b"fixture",
            False,
            "text/html",
            "text/html",
        ),
        (
            '</control>; rel="negative-control"',
            None,
            None,
            b"fixture",
            False,
            "text/html",
            "text/html",
        ),
        (
            '</control>; rel="negative-control"',
            None,
            "nosniff",
            b"different",
            False,
            "text/html",
            "text/html",
        ),
        (
            '</control>; rel="negative-control"',
            None,
            "nosniff",
            b"fixture",
            True,
            "text/html",
            "text/html",
        ),
        (
            '</control>; rel="negative-control"',
            None,
            "nosniff",
            b"fixture",
            False,
            "image/png",
            "text/html",
        ),
        (
            '</control>; rel="negative-control"',
            None,
            "nosniff",
            b"fixture",
            False,
            "application/octet-stream",
            "application/octet-stream",
        ),
    ),
)
def test_preflight_recomputes_http_header_semantics(
    tmp_path: Path,
    recon_link: str | None,
    candidate_nosniff: str | None,
    control_nosniff: str | None,
    control_body: bytes,
    control_truncated: bool,
    candidate_mime: str,
    control_mime: str,
) -> None:
    fixture = _fixture(
        tmp_path,
        recon_link=recon_link,
        candidate_nosniff=candidate_nosniff,
        control_nosniff=control_nosniff,
        control_body=control_body,
        control_truncated=control_truncated,
        candidate_mime=candidate_mime,
        control_mime=control_mime,
    )

    with pytest.raises(ReportPreflightError):
        fixture.verifier.verify()


def test_preflight_requires_html_recon_evidence(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path, recon_mime="image/png")

    with pytest.raises(ReportPreflightError):
        fixture.verifier.verify()


def test_preflight_rejects_legacy_run_and_tampered_review_draft(tmp_path: Path) -> None:
    legacy = _fixture(tmp_path / "legacy")
    _replace_json(legacy.context.artifact_path("plan/run-plan.json"), version="1")
    with pytest.raises(ReportPreflightError):
        legacy.verifier.verify()

    changed = _fixture(tmp_path / "draft")
    changed.context.artifact_path(ReportPreflightVerifier.DRAFT).write_text(
        "changed after review", encoding="utf-8"
    )
    with pytest.raises(ReportPreflightError, match="outcome and draft"):
        changed.verifier.verify()


@pytest.mark.parametrize("mutation", ["path", "hash"])
def test_preflight_rejects_forged_evidence_path_or_hash(tmp_path: Path, mutation: str) -> None:
    fixture = _fixture(tmp_path)
    finding_path = fixture.context.artifact_path(ReportPreflightVerifier.FINDING)
    finding = json.loads(finding_path.read_text(encoding="utf-8"))
    if mutation == "path":
        finding["evidence"][0]["manifest_path"] = "evidence/forged/manifest.json"
    else:
        finding["evidence"][0]["manifest_sha256"] = "sha256:" + "f" * 64
    finding_path.write_text(json.dumps(finding), encoding="utf-8")

    with pytest.raises(ReportPreflightError):
        fixture.verifier.verify()


def test_preflight_rejects_cross_run_or_cross_binding_artifacts(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    assets = fixture.context.artifact_path(ReportPreflightVerifier.ASSETS)
    _replace_json(assets, run_id="another-run")
    with pytest.raises(ReportPreflightError, match="run or scope"):
        fixture.verifier.verify()


def test_preflight_rejects_tampered_approval_or_review(tmp_path: Path) -> None:
    approval_fixture = _fixture(tmp_path / "approval")
    _replace_json(
        approval_fixture.context.artifact_path(ReportPreflightVerifier.APPROVAL),
        signature="AAAA",
    )
    with pytest.raises(ReportPreflightError):
        approval_fixture.verifier.verify()

    review_fixture = _fixture(tmp_path / "review")
    _replace_json(
        review_fixture.context.artifact_path(ReportPreflightVerifier.REVIEW),
        signature="AAAA",
    )
    with pytest.raises(ReportPreflightError):
        review_fixture.verifier.verify()


@pytest.mark.parametrize("kind", ["missing", "extra"])
def test_preflight_rejects_missing_or_extra_evidence(tmp_path: Path, kind: str) -> None:
    fixture = _fixture(tmp_path)
    evidence_root = fixture.context.artifact_path("evidence")
    if kind == "missing":
        (evidence_root / "recon-evidence" / "manifest.json").unlink()
    else:
        extra = evidence_root / "extra"
        extra.mkdir()
        (extra / "manifest.json").write_text("{}", encoding="utf-8")
    with pytest.raises(ReportPreflightError):
        fixture.verifier.verify()


@pytest.mark.parametrize("kind", ["missing", "extra"])
def test_preflight_rejects_missing_or_extra_consumption(tmp_path: Path, kind: str) -> None:
    fixture = _fixture(tmp_path)
    root = fixture.context.artifact_path(f"approvals/consumed/{fixture.approval.bundle_id}")
    if kind == "missing":
        (root / f"{fixture.plan.steps[0].action_id}.json").unlink()
    else:
        (root / "extra.json").write_text("{}", encoding="utf-8")
    with pytest.raises(ReportPreflightError, match="consumption set"):
        fixture.verifier.verify()


def test_preflight_rejects_incomplete_or_cross_bound_coverage(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    coverage = fixture.context.artifact_path(ReportPreflightVerifier.COVERAGE)
    _replace_json(coverage, asset_inventory_digest="sha256:" + "f" * 64)
    with pytest.raises(ReportPreflightError, match="coverage"):
        fixture.verifier.verify()


def test_preflight_recomputes_coverage_provider_metrics(tmp_path: Path) -> None:
    coverage_fixture = _fixture(tmp_path / "coverage")
    coverage_path = coverage_fixture.context.artifact_path(ReportPreflightVerifier.COVERAGE)
    _replace_json(coverage_path, model_calls=4)
    with pytest.raises(ReportPreflightError, match="provider metrics"):
        coverage_fixture.verifier.verify()

    provider_fixture = _fixture(tmp_path / "provider")
    provider_path = provider_fixture.context.artifact_path("provider/phase3-mapper.json")
    _replace_json(provider_path, run_id="another-run")
    with pytest.raises(ReportPreflightError, match="provider metrics"):
        provider_fixture.verifier.verify()

    repair_fixture = _fixture(tmp_path / "repair")
    repair_provider = repair_fixture.context.artifact_path("provider/phase3-mapper.json")
    _replace_json(repair_provider, prompt_attempts=2)
    repair_coverage = repair_fixture.context.artifact_path(ReportPreflightVerifier.COVERAGE)
    _replace_json(repair_coverage, model_calls=6)
    assert repair_fixture.verifier.verify().coverage.model_calls == 6


@pytest.mark.parametrize("prompt_attempts", [None, True, False, 0, 3])
def test_preflight_rejects_invalid_provider_prompt_attempts(
    tmp_path: Path, prompt_attempts: object
) -> None:
    fixture = _fixture(tmp_path)
    provider_path = fixture.context.artifact_path("provider/phase3-mapper.json")
    provider = json.loads(provider_path.read_text(encoding="utf-8"))
    if prompt_attempts is None:
        provider.pop("prompt_attempts")
    else:
        provider["prompt_attempts"] = prompt_attempts
    provider_path.write_text(json.dumps(provider), encoding="utf-8")
    with pytest.raises(ReportPreflightError, match="provider metrics"):
        fixture.verifier.verify()


def test_preflight_rejects_tampered_supply_chain_and_task_binding(tmp_path: Path) -> None:
    registry_fixture = _fixture(tmp_path / "registry")
    registry_path = registry_fixture.context.artifact_path("plan/prompt-registry.json")
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    registry["roles"]["recon"]["prompt_sha256"] = "sha256:" + "f" * 64
    registry_path.write_text(json.dumps(registry), encoding="utf-8")
    with pytest.raises(ReportPreflightError, match="registry snapshot"):
        registry_fixture.verifier.verify()

    task_fixture = _fixture(tmp_path / "task")
    task_path = task_fixture.context.artifact_path("handoffs/phase3-recon.json")
    task = json.loads(task_path.read_text(encoding="utf-8"))
    task["task"]["payload"] = {"tampered": True}
    task_path.write_text(json.dumps(task), encoding="utf-8")
    with pytest.raises(ReportPreflightError, match="producer TaskEnvelope"):
        task_fixture.verifier.verify()


def test_preflight_rejects_orphan_evidence_directory_or_report_json(tmp_path: Path) -> None:
    evidence_fixture = _fixture(tmp_path / "evidence")
    orphan = evidence_fixture.context.artifact_path("evidence/orphan")
    orphan.mkdir()
    (orphan / "analysis.json").write_text("{}", encoding="utf-8")
    with pytest.raises(ReportPreflightError, match="orphan artifact"):
        evidence_fixture.verifier.verify()

    report_fixture = _fixture(tmp_path / "report")
    report_fixture.context.artifact_path("report/forged-finding.json").write_text(
        "{}", encoding="utf-8"
    )
    with pytest.raises(ReportPreflightError, match="orphan formal"):
        report_fixture.verifier.verify()

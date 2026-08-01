"""Real Docker + Hermes ACP acceptance gates for the V2 localhost vertical."""

from __future__ import annotations

import json
from collections import Counter
from typing import Any

from .domain_contracts import ReporterAcknowledgement, VerificationPlan
from .evidence import EvidenceStore
from .preflight import ReportAuthorizationReceipt, ReportPreflightVerifier
from .prompts import PromptRegistry
from .runtime import RunContext
from .runtime.agents import RoleManifest, RoleTrustStore, TaskResult
from .security import TrustStoreV2
from .vertical_contracts import ApprovalBundle, RunPlan, verify_approval_bundle
from .vertical_v2 import ROLE_ORDER, ExecutionState, NetworkState, VerticalState


class AcceptanceError(RuntimeError):
    pass


def verify_phase2_rejected_run(
    context: RunContext,
    *,
    approval_store: TrustStoreV2,
) -> dict[str, Any]:
    state = VerticalState.model_validate_json(context.artifact_path("state.json").read_bytes())
    if (
        state.execution_state is not ExecutionState.REJECTED
        or state.network_state is not NetworkState.USED
        or state.requests_used != 1
    ):
        raise AcceptanceError("rejected V2 run does not retain its one-request terminal state")
    plan = VerificationPlan.model_validate_json(
        context.artifact_path("plan/verification.json").read_bytes()
    )
    bundle = ApprovalBundle.model_validate_json(
        context.artifact_path("approvals/decision.json").read_bytes()
    )
    verify_approval_bundle(bundle, plan, approval_store, at=bundle.issued_at)
    if bundle.version != "2" or any(item.decision != "rejected" for item in bundle.decisions):
        raise AcceptanceError("reject path does not contain an exact signed V2 rejection")
    evidence = list(context.artifact_path("evidence").glob("*/manifest.json"))
    if len(evidence) != 1:
        raise AcceptanceError("reject path must retain exactly one Recon EvidenceArtifact")
    forbidden = (
        "handoffs/phase3-verifier.json",
        "handoffs/phase3-reporter.json",
        "provider/phase3-verifier.json",
        "provider/phase3-reporter.json",
        "report/outcome.json",
        "report/finding.json",
        "report/coverage.json",
        "report/authorization.json",
        "report/reporter-acknowledgement.json",
        "report/report.md",
        "report/findings.json",
    )
    if any(context.artifact_path(relative).exists() for relative in forbidden):
        raise AcceptanceError("reject path executed validation, promotion, or reporting")
    if list(context.artifact_path("approvals/consumed").glob("*/*.json")):
        raise AcceptanceError("reject path consumed an approval")
    return {"run_id": context.run_id, "http_evidence": 1, "state": "rejected"}


def verify_phase2_run(
    context: RunContext,
    *,
    publisher_store: RoleTrustStore,
    approval_store: TrustStoreV2,
    review_store: TrustStoreV2,
    prompt_registry: PromptRegistry,
) -> dict[str, Any]:
    state = VerticalState.model_validate_json(context.artifact_path("state.json").read_bytes())
    if state.execution_state is not ExecutionState.COMPLETED:
        raise AcceptanceError("V2 run is not completed")
    if state.network_state is not NetworkState.USED or state.requests_used != 3:
        raise AcceptanceError("completed V2 run did not use exactly three requests")
    plan = RunPlan.model_validate_json(context.artifact_path("plan/run-plan.json").read_bytes())
    if plan.version != "2" or plan.prompt_registry_digest != prompt_registry.digest:
        raise AcceptanceError("run plan is not bound to the trusted V2 prompt registry")

    manifest_document = json.loads(
        context.artifact_path("plan/role-manifests.json").read_text(encoding="utf-8")
    )
    manifests = [RoleManifest.model_validate(item) for item in manifest_document["roles"]]
    if {item.role for item in manifests} != set(ROLE_ORDER):
        raise AcceptanceError("manifest snapshot does not contain the exact six roles")
    for manifest in manifests:
        # Acceptance reads retained run artifacts.  A publisher key may validly
        # expire after the manifest was signed, so evaluate the signature at the
        # recorded signing time rather than treating a historical run as a new
        # launch.  Runtime role launches intentionally continue to use verify().
        publisher_store.verify_historical(manifest)
        prompt_registry.verify_manifest(manifest)

    results: list[TaskResult] = []
    for role in ROLE_ORDER:
        document = json.loads(
            context.artifact_path(f"handoffs/phase3-{role}.json").read_text(encoding="utf-8")
        )
        result = TaskResult.model_validate(document["result"])
        if (
            result.lifecycle != "completed"
            or result.handoff is None
            or result.handoff.version != "2"
        ):
            raise AcceptanceError(f"V2 role {role} did not complete")
        results.append(result)
    containers = {item.handoff.container_id for item in results if item.handoff is not None}
    host_pids = {item.host_process_id for item in results}
    if None in containers or len(containers) != 6 or None in host_pids or len(host_pids) != 6:
        raise AcceptanceError("the six roles were not independent container processes")

    provider_records = [
        json.loads(
            context.artifact_path(f"provider/phase3-{role}.json").read_text(encoding="utf-8")
        )
        for role in ROLE_ORDER
    ]
    sessions = {record.get("session_id") for record in provider_records}
    if None in sessions or len(sessions) != 6:
        raise AcceptanceError("the six roles did not use independent ACP sessions")
    for role, record in zip(ROLE_ORDER, provider_records, strict=True):
        if record.get("prompt_sha256") != prompt_registry.roles[role]["prompt_sha256"]:
            raise AcceptanceError(f"provider prompt digest mismatch for {role}")

    preflight = ReportPreflightVerifier(
        context,
        approval_store=approval_store,
        review_store=review_store,
        publisher_store=publisher_store,
        prompt_registry=prompt_registry,
        evidence_store=EvidenceStore(context.path),
        historical_manifest_verification=True,
    )
    verified = preflight.verify()
    stored_receipt = ReportAuthorizationReceipt.model_validate_json(
        context.artifact_path("report/authorization.json").read_bytes()
    )
    if (
        stored_receipt.authorization_input_digest
        != verified.authorization.authorization_input_digest
    ):
        raise AcceptanceError("stored report authorization differs from fresh preflight")
    acknowledgement = ReporterAcknowledgement.model_validate_json(
        context.artifact_path("report/reporter-acknowledgement.json").read_bytes()
    )
    if (
        acknowledgement.finding_id != verified.finding.finding_id
        or acknowledgement.coverage_report_digest != verified.coverage.digest
        or acknowledgement.authorization_receipt_digest != stored_receipt.digest
    ):
        raise AcceptanceError("Reporter acknowledgement is not bound to authorization")

    manifests_on_disk = list(context.artifact_path("evidence").glob("*/manifest.json"))
    analysis_on_disk = list(context.artifact_path("evidence").glob("*/analysis.json"))
    if len(manifests_on_disk) != 3 or len(analysis_on_disk) != 3:
        raise AcceptanceError("V2 run requires three manifests and three analysis copies")
    targets = Counter(item.target for item in verified.evidence_manifests)
    candidate_target = verified.finding.target
    control_target = verified.verification_plan.steps[1].target_url
    if targets != Counter({candidate_target: 2, control_target: 1}):
        raise AcceptanceError("evidence request distribution is not Recon=1 and Verifier=2")
    audit = [
        json.loads(line)
        for line in context.audit_path.read_text(encoding="utf-8").splitlines()
        if line
    ]
    allowed_http = [
        item for item in audit if item.get("event") == "http" and item.get("decision") == "allowed"
    ]
    if Counter(item.get("target") for item in allowed_http) != targets:
        raise AcceptanceError("audit HTTP events do not match the evidence request set")
    for required in ("report/report.md", "report/findings.json"):
        if not context.artifact_path(required).is_file():
            raise AcceptanceError(f"completed V2 run is missing {required}")
    report = context.artifact_path("report/report.md").read_text(encoding="utf-8")
    if verified.finding.finding_id not in report or "not a Bugcrowd submission" not in report:
        raise AcceptanceError("formal report omits finding identity or local-lab disclaimer")
    return {
        "run_id": context.run_id,
        "roles": len(results),
        "containers": len(containers),
        "acp_sessions": len(sessions),
        "http_evidence": len(manifests_on_disk),
        "analysis_copies": len(analysis_on_disk),
        "approval_consumptions": len(verified.consumptions),
        "authorization_receipt": "report/authorization.json",
        "report": "report/report.md",
    }

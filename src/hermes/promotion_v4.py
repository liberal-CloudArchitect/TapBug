"""Deterministic promotion and coverage for verified V4 localhost observations."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

from .campaign_v4 import CandidateTypeV4, VerificationCampaignPlanV4, campaign_candidate_ids
from .domain_contracts_v3 import CleanupReceipt
from .domain_contracts_v4 import (
    CoverageAppendixV4,
    CoverageFamilySummaryV4,
    FindingSetV4,
    FindingV4,
    QualityGateReceiptV4,
    VerificationOutcomeSetV4,
)
from .evidence import EvidenceArtifactRef
from .execution_v4 import ExecutionResultV4
from .quality_v4 import (
    evaluate_quality_dataset_v4,
    load_quality_dataset_v4,
    operational_metrics_v4,
    quality_dataset_payload_v4,
)
from .runtime import RunContext
from .security_v4 import ApprovalBatchV4


class PromotionV4Error(ValueError):
    """V4 execution facts cannot become a local teaching finding."""


_FAMILY: dict[CandidateTypeV4, str] = {
    "missing_x_content_type_options": "web",
    "insecure_session_cookie": "web",
    "unvalidated_redirect": "web",
    "exposed_debug_endpoint": "infra",
    "unauthorized_graphql_mutation": "api",
    "privilege_escalation": "authz",
    "cross_tenant_object_read": "authz",
    "workflow_transition_bypass": "workflow",
}
_PRESENTATION: dict[CandidateTypeV4, tuple[str, str, str, str, str, str]] = {
    "missing_x_content_type_options": (
        "Missing X-Content-Type-Options response header",
        "low",
        "A browser may MIME-sniff an unsafe response.",
        "Set X-Content-Type-Options: nosniff on the affected response.",
        "Server Security Misconfiguration",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    ),
    "insecure_session_cookie": (
        "Session cookie lacks required security attributes",
        "medium",
        "A session identifier may be exposed to script or an insecure transport.",
        "Set Secure, HttpOnly and an appropriate SameSite value on the session cookie.",
        "Cookie Security",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
    ),
    "exposed_debug_endpoint": (
        "Diagnostic endpoint exposed",
        "medium",
        "Diagnostic output can disclose implementation details to an unauthenticated user.",
        "Disable the endpoint outside development or require administrator authorization.",
        "Server Security Misconfiguration",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
    ),
    "unvalidated_redirect": (
        "Unvalidated external redirect",
        "medium",
        "An attacker can use the trusted local origin in a phishing redirect chain.",
        "Allow only relative destinations or an explicit destination allowlist.",
        "Unvalidated Redirects and Forwards",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    ),
    "cross_tenant_object_read": (
        "Cross-tenant object read",
        "high",
        "One tenant identity can read an object owned by another tenant.",
        "Enforce owner and tenant checks on every object read before serialization.",
        "Insecure Direct Object Reference",
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    ),
    "unauthorized_graphql_mutation": (
        "Unauthorized GraphQL state change",
        "high",
        (
            "A lower-privileged identity can change fixture state without the strict "
            "authorization path."
        ),
        "Apply authorization checks to every mutation resolver before state changes.",
        "GraphQL Authorization",
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:L",
    ),
    "privilege_escalation": (
        "Privilege escalation accepted",
        "high",
        "A non-administrator identity can grant itself elevated access.",
        "Require server-side role authorization for any role-change action.",
        "Privilege Escalation",
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    ),
    "workflow_transition_bypass": (
        "Workflow transition bypass",
        "high",
        "A draft item can move directly to approved without the required intermediate control.",
        "Enforce allowed transition edges in a transaction on the server.",
        "Business Logic Errors",
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N",
    ),
}


def build_quality_receipt_v4(
    *,
    context: RunContext,
    dataset_path: Path,
    campaign: VerificationCampaignPlanV4,
    results: Iterable[ExecutionResultV4],
) -> QualityGateReceiptV4:
    """Evaluate and freeze an explicit ground-truth dataset for this run.

    The fixture data is copied into the run before the receipt is produced, so
    later edits to a configured source path cannot silently change what the
    report gate means.  Live requests only supply operational accounting; they
    never supply labels for the independent quality ground truth.
    """

    if (campaign.run_id, campaign.scope_digest) != (context.run_id, context.scope_digest):
        raise PromotionV4Error("quality campaign crosses the canonical run or scope")
    dataset = load_quality_dataset_v4(dataset_path)
    context.write_json(
        "quality/dataset-v4.json", quality_dataset_payload_v4(dataset), immutable=True
    )
    values = tuple(results)
    families = evaluate_quality_dataset_v4(
        dataset,
        operational=operational_metrics_v4(context, campaign, values),
    )
    return QualityGateReceiptV4(
        run_id=context.run_id,
        scope_digest=context.scope_digest,
        generated_by_task_id="phase5-quality-gate",
        receipt_id="phase5-quality-v2",
        families=families,
        overall_passed=all(item.passed for item in families),
        recorded_at=datetime.now(UTC),
    )


def promote_v4(
    campaign: VerificationCampaignPlanV4,
    results: Iterable[ExecutionResultV4],
    approvals: Iterable[ApprovalBatchV4],
    quality: QualityGateReceiptV4,
    discovery_evidence: tuple[EvidenceArtifactRef, ...] = (),
    outcomes: dict[str, VerificationOutcomeSetV4] | None = None,
    cleanup: CleanupReceipt | None = None,
    gaps: tuple[str, ...] = (),
) -> tuple[FindingSetV4, CoverageAppendixV4]:
    values = tuple(results)
    by_candidate: dict[str, list[ExecutionResultV4]] = {}
    for result in values:
        by_candidate.setdefault(result.candidate_id, []).append(result)
    types = {item.candidate_id: item.candidate_type for item in campaign.actions}
    if set(by_candidate) != set(campaign_candidate_ids(campaign)):
        raise PromotionV4Error("promotion requires results for every canonical V4 candidate")
    if outcomes is None or set(outcomes) != set(campaign_candidate_ids(campaign)):
        raise PromotionV4Error("promotion requires one independent verifier outcome per candidate")
    mutation_types = {
        "unauthorized_graphql_mutation",
        "privilege_escalation",
        "workflow_transition_bypass",
    }
    campaign_has_mutation = any(item.candidate_type in mutation_types for item in campaign.actions)
    if campaign_has_mutation and (
        cleanup is None or not cleanup.state_restored or cleanup.campaign_digest != campaign.digest
    ):
        raise PromotionV4Error("mutation findings require a restored cleanup receipt")
    if not campaign_has_mutation and cleanup is not None:
        raise PromotionV4Error("read-only V4 campaign must not carry a cleanup receipt")
    approval_by_candidate: dict[str, list[ApprovalBatchV4]] = {}
    for batch in approvals:
        for candidate in batch.candidate_ids:
            approval_by_candidate.setdefault(candidate, []).append(batch)
    findings: list[FindingV4] = []
    for candidate_id in campaign_candidate_ids(campaign):
        candidate_type = types[candidate_id]
        executions = tuple(by_candidate[candidate_id])
        if not _validated(candidate_type, executions):
            raise PromotionV4Error(f"fixed fixture assertion was not validated: {candidate_id}")
        outcome = outcomes[candidate_id]
        if (
            outcome.run_id != campaign.run_id
            or outcome.scope_digest != campaign.scope_digest
            or outcome.campaign_digest != campaign.digest
            or len(outcome.outcomes) != 1
            or outcome.outcomes[0].candidate_id != candidate_id
            or outcome.outcomes[0].status != "validated"
        ):
            raise PromotionV4Error("independent verifier outcome does not bind the candidate")
        batches = tuple(approval_by_candidate.get(candidate_id, ()))
        if not batches:
            raise PromotionV4Error("validated V4 candidate has no signed approval batch")
        title, severity, impact, remediation, vrt, cvss = _PRESENTATION[candidate_type]
        evidence = tuple(item.evidence for item in executions)
        if candidate_id == "web-xcto":
            evidence = (*discovery_evidence, *evidence)
        findings.append(
            FindingV4(
                finding_id=candidate_id,
                candidate_id=candidate_id,
                candidate_type=candidate_type,
                family=_FAMILY[candidate_type],  # type: ignore[arg-type]
                title=title,
                summary=(
                    "Parent evidence oracle validated "
                    f"{candidate_type} in the localhost teaching fixture."
                ),
                reproduction_steps=tuple(
                    f"{item.action_id}: observe HTTP {item.status_code} from the approved action."
                    for item in executions
                ),
                prerequisites=("Docker localhost teaching fixture", "signed V4 approval"),
                impact=impact,
                remediation=remediation,
                severity=severity,  # type: ignore[arg-type]
                severity_rationale=(
                    "Fixed local teaching-fixture assertion and bounded approved proof."
                ),
                vrt_category=vrt,
                cvss_vector=cvss,
                verification_outcome_digest=outcome.digest,
                approval_batch_digests=tuple(batch.digest for batch in batches),
                approval_consumption_digests=tuple(
                    item.approval_consumption_digest for item in executions
                ),
                evidence=evidence,
                review_digest="sha256:" + "0" * 64,
            )
        )
    finding_set = FindingSetV4(
        run_id=campaign.run_id,
        scope_digest=campaign.scope_digest,
        generated_by_task_id="phase5-promotion",
        finding_set_id="phase5-findings",
        quality_gate_digest=quality.digest,
        cleanup_receipt_digest=None if cleanup is None else cleanup.digest,
        findings=tuple(findings),
    )
    summaries = []
    gap_by_family = {
        "web": tuple(item for item in gaps if ":web:" in item or ":web-" in item),
        "api": tuple(item for item in gaps if ":api:" in item or ":api-" in item),
        "authz": tuple(item for item in gaps if ":authz:" in item or ":authz-" in item),
        "infra": tuple(item for item in gaps if ":infra:" in item or ":infra-" in item),
        "workflow": tuple(item for item in gaps if ":workflow:" in item),
    }
    for family in ("web", "api", "authz", "infra", "workflow"):
        found = [item for item in findings if item.family == family]
        routed = [
            candidate_id
            for candidate_id in campaign_candidate_ids(campaign)
            if _FAMILY[types[candidate_id]] == family
        ]
        requests = sum(len(by_candidate[item.candidate_id]) for item in found)
        summaries.append(
            CoverageFamilySummaryV4(
                family=family,
                routed=len(routed),
                tested=len(found),
                validated=len(found),
                requests_used=requests,
                not_tested_reasons=gap_by_family[family],
            )
        )
    coverage = CoverageAppendixV4(
        run_id=campaign.run_id,
        scope_digest=campaign.scope_digest,
        generated_by_task_id="phase5-coverage",
        appendix_id="phase5-coverage",
        quality_gate_digest=quality.digest,
        finding_set_digest=finding_set.digest,
        cleanup_receipt_digest=None if cleanup is None else cleanup.digest,
        families=tuple(summaries),
        requests_planned=campaign.total_request_budget,
        requests_used=campaign.total_request_budget,
        model_attempts_reserved=0,
        model_attempts_used=0,
        estimated_cost_microusd=0,
        active_elapsed_ms=0,
        completion="completed_with_gaps" if gaps else "completed",
        gaps=tuple(sorted(set(gaps))),
    )
    return finding_set, coverage


def _validated(candidate_type: CandidateTypeV4, values: tuple[ExecutionResultV4, ...]) -> bool:
    by_purpose = {item.action_id: item for item in values}
    statuses = {item.action_id: item.status_code for item in values}
    if candidate_type == "missing_x_content_type_options":
        target = by_purpose["web-xcto-target"].headers
        control = by_purpose["web-xcto-control"].headers
        return (
            "x-content-type-options" not in target
            and control.get("x-content-type-options") == "nosniff"
        )
    if candidate_type == "exposed_debug_endpoint":
        return statuses["infra-debug-target"] == 200 and statuses["infra-debug-control"] == 404
    if candidate_type == "insecure_session_cookie":
        cookie_target = by_purpose["web-cookie-target"].headers.get("set-cookie", "").lower()
        cookie_control = by_purpose["web-cookie-control"].headers.get("set-cookie", "").lower()
        target_attributes = _cookie_attributes(cookie_target)
        control_attributes = _cookie_attributes(cookie_control)
        return (
            "secure" not in target_attributes
            and "httponly" not in target_attributes
            and {"secure", "httponly"} <= control_attributes
        )
    if candidate_type == "unvalidated_redirect":
        location = by_purpose["web-redirect-target"].headers.get("location", "")
        return (
            location.startswith("https://redirect.invalid")
            and statuses["web-redirect-control"] == 400
        )
    if candidate_type == "cross_tenant_object_read":
        return [item.status_code for item in values] == [200, 200, 403]
    if candidate_type == "unauthorized_graphql_mutation":
        return (
            statuses["api-graphql-baseline"] == 200
            and statuses["api-graphql-forward"] == 200
            and statuses["api-graphql-control"] == 403
        )
    if candidate_type == "privilege_escalation":
        return (
            statuses["authz-privilege-baseline"] == 200
            and statuses["authz-privilege-forward"] == 200
            and statuses["authz-privilege-control"] == 200
        )
    if candidate_type == "workflow_transition_bypass":
        return (
            statuses["workflow-baseline"] == 200
            and statuses["workflow-forward"] == 200
            and statuses["workflow-control"] == 403
        )
    return False


def _cookie_attributes(value: str) -> set[str]:
    """Return exact, lower-case Set-Cookie attribute names.

    Attribute matching must not use substrings: a cookie value such as
    ``sessionid=insecure`` is evidence of the absence of the ``Secure`` flag,
    not evidence that the flag is present.
    """

    parts = [part.strip().lower() for part in value.split(";")]
    attributes: set[str] = set()
    for part in parts[1:]:
        if not part:
            continue
        attributes.add(part.split("=", 1)[0].strip())
    return attributes


__all__ = ["PromotionV4Error", "build_quality_receipt_v4", "promote_v4"]

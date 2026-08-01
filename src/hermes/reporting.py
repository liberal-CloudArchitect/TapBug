"""Formal reporting behind the unified V2 preflight authorization gate."""

from __future__ import annotations

from pathlib import Path

from .domain_contracts import ReporterAcknowledgement, ValidatedFinding
from .legacy import require_v2_run
from .preflight import ReportAuthorizationReceipt, ReportPreflightVerifier
from .runtime import RunContext


class ReportWriteError(ValueError):
    """Reporter acknowledgement or authorization receipt is not current."""


def build_report(finding: ValidatedFinding) -> str:
    """Render the single, preflight-verified local teaching finding."""

    refs = ", ".join(item.manifest_path for item in finding.evidence)
    return "\n".join(
        (
            "# Hermes evidence report",
            "",
            f"## {finding.title}",
            f"- ID: `{finding.finding_id}`",
            f"- Run: `{finding.run_id}`",
            f"- Target: `{finding.target}`",
            f"- Scope: `{finding.scope_digest}`",
            f"- Approval bundle: `{finding.approval_bundle_id}`",
            f"- Signed review: `{finding.signed_review_id}`",
            f"- Evidence manifests: {refs}",
            f"- Summary: {finding.summary}",
            f"- Preconditions: {', '.join(finding.prerequisites) or 'none'}",
            f"- Reproduction: {'; '.join(finding.reproduction_steps)}",
            f"- Impact: {finding.impact}",
            f"- Remediation: {finding.remediation}",
            f"- Severity: `{finding.severity}`",
            "- Environment: local teaching fixture; not a Bugcrowd submission",
            f"- VRT snapshot: `{finding.vrt_snapshot or 'pending human classification'}`",
            f"- CVSS: `{finding.cvss_vector or 'pending complete impact inputs'}`",
            "",
        )
    )


def persist_authorization_receipt(context: RunContext, receipt: ReportAuthorizationReceipt) -> Path:
    """Persist the recomputable receipt before Reporter is allowed to run."""

    require_v2_run(context)
    if receipt.run_id != context.run_id or receipt.scope_digest != context.scope_digest:
        raise ReportWriteError("authorization receipt belongs to another run or scope")
    return context.write_json(
        "report/authorization.json", receipt.model_dump(mode="json"), immutable=True
    )


def write_report(
    context: RunContext,
    verifier: ReportPreflightVerifier,
    reporter_ack: ReporterAcknowledgement,
) -> Path:
    """Re-run preflight, verify Reporter acknowledgement, then write formal output.

    Neither a caller-provided Finding nor a previously computed boolean is accepted.
    The canonical run directory is reloaded and checked before either formal output
    path is created.
    """

    require_v2_run(context)
    bundle = verifier.verify()
    receipt_path = context.artifact_path("report/authorization.json")
    try:
        stored_receipt = ReportAuthorizationReceipt.model_validate_json(
            receipt_path.read_text(encoding="utf-8")
        )
    except (OSError, ValueError) as exc:
        raise ReportWriteError("the canonical authorization receipt is missing or invalid") from exc
    if stored_receipt.authorization_input_digest != bundle.authorization.authorization_input_digest:
        raise ReportWriteError("authorization receipt no longer matches a fresh preflight")
    finding = bundle.finding
    coverage = bundle.coverage
    expected = (
        context.run_id,
        context.scope_digest,
        "phase3-reporter",
        finding.finding_id,
        coverage.digest,
        stored_receipt.digest,
        True,
    )
    actual = (
        reporter_ack.run_id,
        reporter_ack.scope_digest,
        reporter_ack.generated_by_task_id,
        reporter_ack.finding_id,
        reporter_ack.coverage_report_digest,
        reporter_ack.authorization_receipt_digest,
        reporter_ack.accepted,
    )
    if actual != expected:
        raise ReportWriteError("Reporter acknowledgement is not bound to fresh authorization")

    rendered = build_report(finding)
    context.write_json("report/findings.json", [finding.model_dump(mode="json")], immutable=True)
    return context.write_text("report/report.md", rendered, immutable=True)


__all__ = [
    "ReportWriteError",
    "build_report",
    "persist_authorization_receipt",
    "write_report",
]

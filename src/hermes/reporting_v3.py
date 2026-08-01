"""Fail-closed, parent-owned publication of V3 formal report artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from .domain_contracts_v3 import (
    CoverageReportV3,
    FindingSet,
    ReporterAckV3,
    ReporterLaunchReceiptV3,
    ReportWriteReceiptV3,
)
from .runtime import RunContext


class ReportWriteV3Error(ValueError):
    """Fresh preflight or atomic formal publication failed."""


@dataclass(frozen=True, slots=True)
class VerifiedReportWriteV3:
    """Minimal result a V3 preflight must recompute immediately before write."""

    launch_receipt: ReporterLaunchReceiptV3
    finding_set: FindingSet
    coverage: CoverageReportV3
    provider_metadata_digest: str
    final_budget_ledger_head_digest: str


class ReportPreflightVerifierV3Protocol(Protocol):
    """Decouples formal output from the concrete, evolving preflight loader."""

    def verify_for_write(self, reporter_ack: ReporterAckV3) -> VerifiedReportWriteV3:
        """Reload and verify the complete authority graph without trusting the caller."""


def build_report_v3(findings: FindingSet, coverage: CoverageReportV3) -> str:
    """Render a deterministic local-fixture report from promoted parent records."""

    lines = [
        "# Hermes parallel security assessment",
        "",
        "- Environment: local teaching fixture; not a Bugcrowd submission",
        f"- Run: `{findings.run_id}`",
        f"- Scope: `{findings.scope_digest}`",
        f"- Completion: `{coverage.completion}`",
        f"- Validated findings: `{len(findings.findings)}`",
        "",
    ]
    if coverage.gaps:
        lines.extend(("## Coverage gaps", "", *(f"- {gap}" for gap in coverage.gaps), ""))
    for finding in findings.findings:
        evidence = ", ".join(item.manifest_path for item in finding.evidence)
        lines.extend(
            (
                f"## {finding.title}",
                "",
                f"- ID: `{finding.finding_id}`",
                f"- Type: `{finding.candidate_type}`",
                f"- Severity: `{finding.severity}`",
                f"- Outcome: `{finding.verification_outcome_digest}`",
                f"- Independent review: `{finding.cross_review_digest}`",
                f"- Evidence manifests: {evidence}",
                f"- Summary: {finding.summary}",
                "",
            )
        )
    return "\n".join(lines)


def write_report_v3(
    context: RunContext,
    verifier: ReportPreflightVerifierV3Protocol,
    reporter_ack: ReporterAckV3,
) -> Path:
    """Re-run preflight and publish all three formal artifacts as one transaction.

    The API deliberately accepts neither a caller-provided finding nor a cached
    authorization boolean.  On every ordinary failure, all final paths are rolled
    back; exclusive hard links prevent overwriting an earlier formal report.
    """

    finals = (
        context.artifact_path("report/report-v3.md"),
        context.artifact_path("report/findings-v3.json"),
        context.artifact_path("report/report-write-receipt-v3.json"),
    )
    try:
        verified = verifier.verify_for_write(reporter_ack)
        _verify_ack(context, reporter_ack, verified)
        report_bytes = build_report_v3(verified.finding_set, verified.coverage).encode("utf-8")
        findings_bytes = _canonical_bytes(verified.finding_set.model_dump(mode="json"))
        receipt = ReportWriteReceiptV3(
            run_id=context.run_id,
            scope_digest=context.scope_digest,
            generated_by_task_id="phase4-report-writer",
            receipt_id="phase4-report-write",
            launch_receipt_digest=verified.launch_receipt.digest,
            reporter_ack_digest=reporter_ack.digest,
            final_budget_ledger_head_digest=verified.final_budget_ledger_head_digest,
            report_sha256=_sha256(report_bytes),
            findings_sha256=_sha256(findings_bytes),
            written_at=datetime.now(UTC),
        )
        receipt_bytes = _canonical_bytes(receipt.model_dump(mode="json"))
        _commit_exclusive_group(context, finals, (report_bytes, findings_bytes, receipt_bytes))
        return finals[0]
    except ReportWriteV3Error:
        raise
    except (OSError, ValueError, TypeError) as exc:
        raise ReportWriteV3Error(f"V3 formal report publication failed: {exc}") from exc


def _verify_ack(
    context: RunContext,
    ack: ReporterAckV3,
    verified: VerifiedReportWriteV3,
) -> None:
    if (ack.run_id, ack.scope_digest) != (context.run_id, context.scope_digest):
        raise ReportWriteV3Error("Reporter acknowledgement crosses a run or scope boundary")
    if ack.generated_by_task_id != "phase4-reporter":
        raise ReportWriteV3Error("Reporter acknowledgement was not produced by the Reporter task")
    expected = (
        verified.launch_receipt.digest,
        verified.finding_set.digest,
        verified.coverage.digest,
        verified.provider_metadata_digest,
        True,
    )
    actual = (
        ack.launch_receipt_digest,
        ack.finding_set_digest,
        ack.coverage_report_digest,
        ack.provider_metadata_digest,
        ack.accepted,
    )
    if actual != expected:
        raise ReportWriteV3Error(
            "Reporter acknowledgement is not bound to fresh preflight artifacts"
        )
    if (
        verified.launch_receipt.run_id,
        verified.launch_receipt.scope_digest,
        verified.finding_set.run_id,
        verified.finding_set.scope_digest,
        verified.coverage.run_id,
        verified.coverage.scope_digest,
    ) != (
        context.run_id,
        context.scope_digest,
        context.run_id,
        context.scope_digest,
        context.run_id,
        context.scope_digest,
    ):
        raise ReportWriteV3Error("fresh preflight returned cross-context artifacts")
    if (
        verified.launch_receipt.finding_set_digest != verified.finding_set.digest
        or verified.launch_receipt.coverage_report_digest != verified.coverage.digest
        or verified.coverage.finding_set_digest != verified.finding_set.digest
    ):
        raise ReportWriteV3Error("fresh preflight returned a discontinuous report chain")


def _commit_exclusive_group(
    context: RunContext,
    finals: tuple[Path, Path, Path],
    payloads: tuple[bytes, bytes, bytes],
) -> None:
    report_dir = context.artifact_path("report")
    report_dir.mkdir(parents=True, exist_ok=True)
    created: list[Path] = []
    stage = Path(tempfile.mkdtemp(prefix=".formal-v3-", dir=report_dir))
    try:
        staged: list[Path] = []
        for index, payload in enumerate(payloads):
            path = stage / str(index)
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            staged.append(path)
        with context.lock():
            if any(path.exists() for path in finals):
                raise ReportWriteV3Error("formal V3 report artifacts already exist")
            try:
                for source, destination in zip(staged, finals, strict=True):
                    os.link(source, destination)
                    created.append(destination)
                directory_fd = os.open(report_dir, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            except Exception:
                for path in reversed(created):
                    path.unlink(missing_ok=True)
                raise
    finally:
        shutil.rmtree(stage, ignore_errors=True)


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


__all__ = [
    "ReportPreflightVerifierV3Protocol",
    "ReportWriteV3Error",
    "VerifiedReportWriteV3",
    "build_report_v3",
    "write_report_v3",
]

"""Fail-closed publication of V4 formal report artifacts."""

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

from .domain_contracts_v4 import (
    CoverageAppendixV4,
    FindingSetV4,
    QualityGateReceiptV4,
    ReporterAckV4,
    ReporterLaunchReceiptV4,
    ReportWriteReceiptV4,
)
from .runtime import RunContext


class ReportWriteV4Error(ValueError):
    """Fresh preflight or atomic formal publication failed."""


@dataclass(frozen=True, slots=True)
class VerifiedReportWriteV4:
    launch_receipt: ReporterLaunchReceiptV4
    quality: QualityGateReceiptV4
    finding_set: FindingSetV4
    coverage: CoverageAppendixV4
    provider_metadata_digest: str


class ReportPreflightVerifierV4Protocol(Protocol):
    def verify_for_write(self, reporter_ack: ReporterAckV4) -> VerifiedReportWriteV4: ...


def build_report_v4(
    quality: QualityGateReceiptV4,
    findings: FindingSetV4,
    coverage: CoverageAppendixV4,
) -> str:
    lines = [
        "# Hermes V4 security assessment",
        "",
        "- Environment: local teaching fixture; not a Bugcrowd submission",
        f"- Run: `{findings.run_id}`",
        f"- Scope: `{findings.scope_digest}`",
        f"- Completion: `{coverage.completion}`",
        f"- Validated findings: `{len(findings.findings)}`",
        "",
        "## Quality gate",
        "",
    ]
    for quality_family in quality.families:
        lines.append(
            "- "
            f"{quality_family.family}: recall={quality_family.candidate_recall!r}, "
            f"precision={quality_family.verified_precision!r}, "
            f"blocked={quality_family.blocked_count}, "
            f"inconclusive={quality_family.inconclusive_count}, "
            f"requests={quality_family.requests_used}, "
            f"elapsed_ms={quality_family.elapsed_ms}, "
            f"cost_microusd={quality_family.estimated_cost_microusd}"
        )
    lines.append("")
    for finding in findings.findings:
        evidence = ", ".join(ref.manifest_path for ref in finding.evidence)
        lines.extend(
            (
                f"## {finding.title}",
                "",
                f"- ID: `{finding.finding_id}`",
                f"- Type: `{finding.candidate_type}`",
                f"- Family: `{finding.family}`",
                f"- Severity: `{finding.severity}`",
                f"- Severity rationale: {finding.severity_rationale}",
                f"- VRT: `{finding.vrt_category}`",
                f"- CVSS: `{finding.cvss_vector}`",
                f"- Outcome digest: `{finding.verification_outcome_digest}`",
                f"- Evidence manifests: {evidence}",
                "",
                "### Summary",
                "",
                finding.summary,
                "",
                "### Preconditions",
                "",
                *(f"- {item}" for item in finding.prerequisites),
                *(() if finding.prerequisites else ("- None",)),
                "",
                "### Reproduction",
                "",
                *(
                    f"1. {step}" if index == 0 else f"{index + 1}. {step}"
                    for index, step in enumerate(finding.reproduction_steps)
                ),
                "",
                "### Impact",
                "",
                finding.impact,
                "",
                "### Remediation",
                "",
                finding.remediation,
                "",
            )
        )
    lines.extend(
        (
            "## Coverage appendix",
            "",
        )
    )
    for coverage_family in coverage.families:
        reasons = (
            ", ".join(coverage_family.not_tested_reasons)
            if coverage_family.not_tested_reasons
            else "none"
        )
        lines.append(
            "- "
            f"{coverage_family.family}: routed={coverage_family.routed}, "
            f"tested={coverage_family.tested}, validated={coverage_family.validated}, "
            f"disproved={coverage_family.disproved}, blocked={coverage_family.blocked}, "
            f"inconclusive={coverage_family.inconclusive}, "
            f"requests={coverage_family.requests_used}, "
            f"elapsed_ms={coverage_family.elapsed_ms}, "
            f"cost_microusd={coverage_family.estimated_cost_microusd}, "
            f"not_tested={reasons}"
        )
    if coverage.gaps:
        lines.extend(("", "### Coverage gaps", "", *(f"- {gap}" for gap in coverage.gaps)))
    return "\n".join(lines) + "\n"


def write_report_v4(
    context: RunContext,
    verifier: ReportPreflightVerifierV4Protocol,
    reporter_ack: ReporterAckV4,
) -> Path:
    finals = (
        context.artifact_path("report/report-v4.md"),
        context.artifact_path("report/findings-v4.json"),
        context.artifact_path("report/report-write-receipt-v4.json"),
    )
    try:
        verified = verifier.verify_for_write(reporter_ack)
        _verify_ack(context, reporter_ack, verified)
        report_bytes = build_report_v4(
            verified.quality,
            verified.finding_set,
            verified.coverage,
        ).encode("utf-8")
        findings_bytes = _canonical_bytes(
            {
                "quality": verified.quality.model_dump(mode="json"),
                "finding_set": verified.finding_set.model_dump(mode="json"),
                "coverage": verified.coverage.model_dump(mode="json"),
            }
        )
        receipt = ReportWriteReceiptV4(
            run_id=context.run_id,
            scope_digest=context.scope_digest,
            generated_by_task_id="phase5-report-writer",
            receipt_id="phase5-report-write",
            launch_receipt_digest=verified.launch_receipt.digest,
            reporter_ack_digest=reporter_ack.digest,
            report_sha256=_sha256(report_bytes),
            findings_sha256=_sha256(findings_bytes),
            written_at=datetime.now(UTC),
        )
        receipt_bytes = _canonical_bytes(receipt.model_dump(mode="json"))
        _commit_exclusive_group(context, finals, (report_bytes, findings_bytes, receipt_bytes))
        return finals[0]
    except ReportWriteV4Error:
        raise
    except (OSError, ValueError, TypeError) as exc:
        raise ReportWriteV4Error(f"V4 formal report publication failed: {exc}") from exc


def _verify_ack(
    context: RunContext,
    ack: ReporterAckV4,
    verified: VerifiedReportWriteV4,
) -> None:
    if (ack.run_id, ack.scope_digest) != (context.run_id, context.scope_digest):
        raise ReportWriteV4Error("Reporter acknowledgement crosses a run or scope boundary")
    if ack.generated_by_task_id != "phase5-reporter":
        raise ReportWriteV4Error("Reporter acknowledgement was not produced by the Reporter task")
    expected = (
        verified.launch_receipt.digest,
        verified.quality.digest,
        verified.finding_set.digest,
        verified.coverage.digest,
        verified.provider_metadata_digest,
        True,
    )
    actual = (
        ack.launch_receipt_digest,
        ack.quality_gate_digest,
        ack.finding_set_digest,
        ack.coverage_appendix_digest,
        ack.provider_metadata_digest,
        ack.accepted,
    )
    if actual != expected:
        raise ReportWriteV4Error(
            "Reporter acknowledgement is not bound to fresh V4 preflight artifacts"
        )


def _commit_exclusive_group(
    context: RunContext,
    finals: tuple[Path, Path, Path],
    payloads: tuple[bytes, bytes, bytes],
) -> None:
    report_dir = context.artifact_path("report")
    report_dir.mkdir(parents=True, exist_ok=True)
    created: list[Path] = []
    stage = Path(tempfile.mkdtemp(prefix=".formal-v4-", dir=report_dir))
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
                raise ReportWriteV4Error("formal V4 report artifacts already exist")
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
    "ReportPreflightVerifierV4Protocol",
    "ReportWriteV4Error",
    "VerifiedReportWriteV4",
    "build_report_v4",
    "write_report_v4",
]

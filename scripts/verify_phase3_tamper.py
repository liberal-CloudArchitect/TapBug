#!/usr/bin/env python3
"""Replay tampered copies of a successful V2 run through the formal report boundary."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from hermes.cli import _config  # noqa: E402
from hermes.domain_contracts import ReporterAcknowledgement  # noqa: E402
from hermes.evidence import EvidenceStore  # noqa: E402
from hermes.preflight import ReportPreflightError, ReportPreflightVerifier  # noqa: E402
from hermes.prompts import PromptRegistry  # noqa: E402
from hermes.reporting import ReportWriteError, write_report  # noqa: E402
from hermes.runtime import RunContext  # noqa: E402
from hermes.runtime.agents import RoleTrustStore  # noqa: E402
from hermes.security import TrustStoreV2  # noqa: E402


class TamperAcceptanceError(RuntimeError):
    pass


def _json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TamperAcceptanceError(f"expected JSON object: {path}")
    return value


def _replace(path: Path, update: Callable[[dict[str, Any]], None]) -> None:
    value = _json(path)
    update(value)
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")


def _mutations(run: Path) -> dict[str, Callable[[], None]]:
    consumption = sorted((run / "approvals" / "consumed").glob("*/*.json"))[0]
    manifest = sorted((run / "evidence").glob("*/manifest.json"))[0]
    analysis = sorted((run / "evidence").glob("*/analysis.json"))[0]
    return {
        "approval_signature": lambda: _replace(
            run / "approvals" / "decision.json",
            lambda value: value.__setitem__("signature", "AAAA"),
        ),
        "review_signature": lambda: _replace(
            run / "reviews" / "signed.json",
            lambda value: value.__setitem__("signature", "AAAA"),
        ),
        "consumption_binding": lambda: _replace(
            consumption,
            lambda value: value.__setitem__("evidence_id", "tampered-evidence"),
        ),
        "evidence_manifest": lambda: manifest.write_bytes(manifest.read_bytes() + b"\n"),
        "evidence_analysis": lambda: analysis.write_bytes(analysis.read_bytes() + b"\n"),
        "coverage_chain": lambda: _replace(
            run / "report" / "coverage.json",
            lambda value: value.__setitem__("asset_inventory_digest", "sha256:" + "f" * 64),
        ),
        "cross_run_finding": lambda: _replace(
            run / "report" / "finding.json",
            lambda value: value.__setitem__("run_id", "another-run"),
        ),
    }


def _remove_formal_outputs(run: Path) -> None:
    for relative in (
        "report/authorization.json",
        "report/reporter-acknowledgement.json",
        "report/findings.json",
        "report/report.md",
        "handoffs/phase3-reporter.json",
        "provider/phase3-reporter.json",
    ):
        (run / relative).unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs-root", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    source = (args.runs_root / args.run_id).resolve(strict=True)
    output = args.output_root.resolve()
    if output.exists():
        raise TamperAcceptanceError("output root must not already exist")
    output.mkdir(parents=True)

    config = _config(args.config)
    approval_store = TrustStoreV2.from_file(Path(config["approval_trust_store"]))
    review_store = TrustStoreV2.from_file(Path(config["review_trust_store"]))
    publisher_store = RoleTrustStore.from_file(Path(config["role_trust_store"]))
    prompt_registry = PromptRegistry(Path(config["prompt_root"]))
    acknowledgement = ReporterAcknowledgement.model_validate_json(
        (source / "report" / "reporter-acknowledgement.json").read_bytes()
    )

    blocked: list[str] = []
    failures: dict[str, str] = {}
    for name in (
        "approval_signature",
        "review_signature",
        "consumption_binding",
        "evidence_manifest",
        "evidence_analysis",
        "coverage_chain",
        "cross_run_finding",
    ):
        runs = output / name / "runs"
        copied = runs / args.run_id
        copied.parent.mkdir(parents=True)
        shutil.copytree(source, copied)
        _remove_formal_outputs(copied)
        _mutations(copied)[name]()
        scope = _json(copied / "scope.json")
        context = RunContext.open_existing(runs, scope, args.run_id)
        verifier = ReportPreflightVerifier(
            context,
            approval_store=approval_store,
            review_store=review_store,
            publisher_store=publisher_store,
            prompt_registry=prompt_registry,
            evidence_store=EvidenceStore(context.path),
        )
        try:
            write_report(context, verifier, acknowledgement)
        except (ReportPreflightError, ReportWriteError) as exc:
            blocked.append(name)
            failures[name] = f"{type(exc).__name__}: {exc}"
        else:
            raise TamperAcceptanceError(f"tamper case reached formal reporting: {name}")
        for relative in (
            "report/authorization.json",
            "report/reporter-acknowledgement.json",
            "report/findings.json",
            "report/report.md",
        ):
            if (copied / relative).exists():
                raise TamperAcceptanceError(f"tamper case created {relative}: {name}")

    summary = {
        "source_run_id": args.run_id,
        "tamper_cases": blocked,
        "failures": failures,
        "blocked_count": len(blocked),
        "formal_reports_created": 0,
        "output_root": str(output),
    }
    (output / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

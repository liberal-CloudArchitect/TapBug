#!/usr/bin/env python3
"""CAP-07 full-campaign resume E2E: re-run a real V4 assessment as the resume.

Extends ``run_cap07_e2e`` from "recovery composed" to "recovery resumed by a full
assessment campaign". It:

  1. runs the real CAP-07 recovery over a real R2.5 learning run (via
     ``run_cap07_e2e``), producing a verified ``Cap07RecoveryBundle`` (paused
     assessment -> approved Wheel -> bound resume -> feedback); then
  2. runs a real V4 assessment campaign (via ``run_phase5_e2e``) as the resume of
     that recovery — a NEW run, never in place; then
  3. binds that campaign run to the recovery (``bind_campaign_resume``) so the
     chain paused-assessment -> recovery -> resumed-campaign is one governed,
     auditable record.

Honest scope boundary: the V4 campaign here does not yet *invoke* the approved
Wheel to resolve the specific gap — that needs a purpose-built fixture whose
assessment cannot proceed without the Wheel plus a governed Wheel-invocation hook
in the assessment roles (still open; docs/15 §11.7). This driver proves the
governed structure: a real full campaign run as the non-in-place bound resume.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from hermes.cap07 import Cap07Error, Cap07RecoveryBundle, bind_campaign_resume  # noqa: E402


class Cap07ResumeFailure(RuntimeError):
    pass


def _run_json(cmd: list[str]) -> dict[str, Any]:
    completed = subprocess.run(cmd, cwd=PROJECT_ROOT, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        sys.stderr.write(completed.stdout + "\n" + completed.stderr + "\n")
        raise Cap07ResumeFailure(f"{Path(cmd[1]).name} returned {completed.returncode}")
    return json.loads(completed.stdout.strip().splitlines()[-1])


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--hermes-cli", type=Path, required=True)
    ap.add_argument("--hermes-python", type=Path, required=True)
    ap.add_argument("--model", required=True)
    ap.add_argument(
        "--artifact-root", type=Path, default=PROJECT_ROOT / "artifacts" / "cap07-campaign-resume"
    )
    args = ap.parse_args(argv)

    common = [
        "--hermes-cli",
        str(args.hermes_cli),
        "--hermes-python",
        str(args.hermes_python),
        "--model",
        args.model,
    ]

    # 1. Real CAP-07 recovery (runs R2.5 inside) -> verified recovery bundle.
    recovery = _run_json(
        [sys.executable, str(PROJECT_ROOT / "scripts" / "run_cap07_e2e.py"), *common]
    )
    bundle_path = Path(recovery["artifact_root"]) / "cap07-recovery.json"
    bundle = Cap07RecoveryBundle.model_validate_json(bundle_path.read_text("utf-8"))

    # 2. Real V4 assessment campaign as the resume (a new run).
    phase5 = _run_json(
        [sys.executable, str(PROJECT_ROOT / "scripts" / "run_phase5_e2e.py"), *common]
    )
    accepted = phase5["accepted"]
    resume_run_id = str(accepted["run_id"])
    findings = int(accepted["verification"]["findings"])

    # 3. Bind the campaign run as the governed, non-in-place resume of the recovery.
    now = datetime.now(UTC)
    record = bind_campaign_resume(
        bundle,
        resume_run_id=resume_run_id,
        resume_workflow="v4",
        resume_execution_state="completed",
        resume_findings=findings,
        now=now,
    )

    out_root = args.artifact_root.resolve()
    out_root.mkdir(parents=True, exist_ok=True)
    out = out_root / f"{now.strftime('%Y%m%dT%H%M%SZ')}-cap07-campaign-resume"
    out.mkdir(parents=True, exist_ok=True)
    (out / "campaign-resume.json").write_text(
        record.model_dump_json(indent=2) + "\n", encoding="utf-8"
    )
    summary = {
        "cap07_campaign_resume": "verified",
        "paused_run_id": record.paused_run_id,
        "resume_run_id": record.resume_run_id,
        "in_place_resume": record.resume_run_id == record.paused_run_id,
        "resume_workflow": record.resume_workflow,
        "resume_execution_state": record.resume_execution_state,
        "resume_findings": record.resume_findings,
        "recovery_bundle_digest": record.recovery_bundle_digest,
        "recovery_root": recovery["artifact_root"],
        "campaign_root": phase5["artifact_root"],
        "artifact_root": str(out),
    }
    (out / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (Cap07ResumeFailure, Cap07Error, OSError, ValueError, KeyError) as exc:
        print(f"cap07-campaign-resume: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

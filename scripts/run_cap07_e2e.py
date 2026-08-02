#!/usr/bin/env python3
"""CAP-07 governed assessment-recovery E2E over a real R2.5 learning run.

This driver runs the real ``run_r25_e2e`` flow (real Hermes ACP + Docker: the
Researcher/Planner roles, signed Wheel registry, and the zero-network Wheel
sandbox continuation), then composes its genuine outputs into a governed
CAP-07 recovery and re-verifies the linkage:

    paused assessment (frozen parent V3 run) + a knowledge-gap ProblemCard
      -> the real signed, ACTIVE Wheel + real ContinuationOutcomeV1
      -> a resume BOUND to the frozen input + approved Wheel as a NEW run
      -> registry effect feedback

Nothing here re-implements learning or verification; it binds real R2.5 artifacts
through ``hermes.cap07``/``hermes.learning_recovery`` and checks the result. A
missing active Wheel, an in-place resume, a mismatched continuation, or a broken
pause<->resume<->feedback link all fail closed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from hermes.cap07 import Cap07Error, orchestrate_recovery, verify_recovery_bundle  # noqa: E402
from hermes.learning_recovery import ActiveWheelView, AssessmentPauseRecordV1  # noqa: E402
from hermes.r25_contracts import ContinuationOutcomeV1  # noqa: E402


class Cap07E2EFailure(RuntimeError):
    pass


def _json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise Cap07E2EFailure(f"not a JSON object: {path}")
    return value


def _sha256_file(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _run_r25(args: argparse.Namespace) -> dict[str, Any]:
    """Run the real R2.5 E2E and return its JSON summary."""
    cmd = [
        sys.executable,
        str(PROJECT_ROOT / "scripts" / "run_r25_e2e.py"),
        "--hermes-cli",
        str(args.hermes_cli),
        "--hermes-python",
        str(args.hermes_python),
        "--model",
        args.model,
        "--artifact-root",
        str(args.r25_artifact_root),
    ]
    completed = subprocess.run(cmd, cwd=PROJECT_ROOT, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        sys.stderr.write(completed.stdout + "\n" + completed.stderr + "\n")
        raise Cap07E2EFailure(f"run_r25_e2e returned {completed.returncode}")
    line = completed.stdout.strip().splitlines()[-1]
    return json.loads(line)


def _active_wheel_from_run(
    root: Path,
    learning_run_id: str,
    continuation: ContinuationOutcomeV1,
    problem_card_id: str,
) -> ActiveWheelView:
    learning = root / "runs" / "learning" / learning_run_id
    activation_path = learning / "wheels" / "activation.json"
    activation = _json(activation_path)
    # The signed activation and the continuation must name the same Wheel manifest;
    # the continuation only runs once the registry has an active, signed Wheel.
    if activation.get("wheel_manifest_digest") != continuation.wheel_manifest_digest:
        raise Cap07E2EFailure("activation Wheel manifest disagrees with the continuation outcome")
    manifests = sorted((learning / "wheels").glob("*/wheel-manifest.json"))
    if not manifests:
        raise Cap07E2EFailure("no wheel manifest under the learning run")
    manifest = _json(manifests[0])
    return ActiveWheelView(
        wheel_id=str(manifest["wheel_id"]),
        # Bind to the exact manifest the continuation ran against.
        wheel_manifest_digest=continuation.wheel_manifest_digest,
        activation_digest=_sha256_file(activation_path),
        status="active",
        problem_card_ids=(problem_card_id,),
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--hermes-cli", type=Path, required=True)
    ap.add_argument("--hermes-python", type=Path, required=True)
    ap.add_argument("--model", required=True)
    ap.add_argument(
        "--artifact-root", type=Path, default=PROJECT_ROOT / "artifacts" / "cap07-e2e"
    )
    ap.add_argument(
        "--r25-artifact-root", type=Path, default=PROJECT_ROOT / "artifacts" / "r25-e2e"
    )
    ap.add_argument(
        "--problem-card-id",
        default="gap-line-kv-unparsed-field",
        help="The knowledge gap the paused assessment could not resolve.",
    )
    args = ap.parse_args(argv)

    # 1. Real R2.5 learning (real ACP + Docker).
    r25 = _run_r25(args)
    root = Path(r25["artifact_root"])
    parent_run_id = str(r25["parent_run_id"])
    continuation_run_id = str(r25["continuation_run_id"])
    learning_run_id = str(r25["learning_run_id"])

    # 2. Load the real continuation outcome and the frozen input it bound.
    outcome_path = (
        root / "runs" / "learning" / continuation_run_id / "continuation" / "outcome.json"
    )
    continuation = ContinuationOutcomeV1.model_validate_json(outcome_path.read_text("utf-8"))
    if continuation.parent_run_id != parent_run_id:
        raise Cap07E2EFailure("continuation outcome parent run id disagrees with the R2.5 summary")
    frozen = root / "runs" / "learning" / learning_run_id / "research" / "frozen-analysis.json"
    frozen_input_sha256 = _sha256_file(frozen)

    # 3. The real active Wheel view from the signed registry artifacts.
    wheel = _active_wheel_from_run(root, learning_run_id, continuation, args.problem_card_id)

    # 4. Record the pause on the frozen parent assessment.
    now = datetime.now(UTC)
    pause = AssessmentPauseRecordV1(
        paused_run_id=parent_run_id,
        scope_digest=continuation.scope_digest,
        paused_task_id="phase4-verify-line-kv",
        problem_card_id=args.problem_card_id,
        problem_card_digest=_sha256_file(outcome_path),
        frozen_input_sha256=frozen_input_sha256,
        reason="assessment paused: unparsed line_kv field needs a governed Wheel",
        paused_at=now,
    )

    # 5. Compose + verify the governed recovery (new bound run; never in place).
    resume_run_id = f"cap07-resume-{continuation_run_id}"
    bundle = orchestrate_recovery(
        pause,
        continuation,
        [wheel],
        resume_run_id=resume_run_id,
        summary="knowledge gap resolved by the governed passive-parser Wheel continuation",
        now=now,
    )
    verify_recovery_bundle(bundle)  # defence in depth; orchestrate_recovery already verified

    # 6. Persist and report.
    out_root = args.artifact_root.resolve()
    out_root.mkdir(parents=True, exist_ok=True)
    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    out = out_root / f"{stamp}-cap07-{continuation_run_id[:12]}"
    out.mkdir(parents=True, exist_ok=True)
    (out / "cap07-recovery.json").write_text(
        bundle.model_dump_json(indent=2) + "\n", encoding="utf-8"
    )
    summary = {
        "cap07_recovery": "verified",
        "paused_run_id": pause.paused_run_id,
        "problem_card_id": pause.problem_card_id,
        "resume_run_id": bundle.binding.resume_run_id,
        "in_place_resume": bundle.binding.resume_run_id == pause.paused_run_id,
        "frozen_input_bound": bundle.binding.frozen_input_sha256 == pause.frozen_input_sha256,
        "wheel_id": wheel.wheel_id,
        "effect": bundle.feedback.effect,
        "r25_root": str(root),
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
    except (Cap07E2EFailure, Cap07Error, OSError, ValueError) as exc:
        print(f"cap07-e2e: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

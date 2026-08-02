#!/usr/bin/env python3
"""CAP-07 gap-resolution E2E: a resumed assessment invokes the Wheel to resolve.

This closes the loop CAP-07 opened. It runs a real R2.5 learning run to produce a
signed, active Wheel, then acts as the resumed assessment reaching the gap that
paused it: it invokes that exact Wheel through the real, no-network, non-root,
digest-pinned Docker sandbox (``hermes.wheel_consumption.resolve_gap_with_wheel``)
on the gap input, and checks the Wheel produced a bound, matched structured
observation. Every governance edge fails closed (only an active Wheel that
addresses the gap, input bound by digest, sandbox must pass).

The gap input is the Wheel's own positive fixture — the exact ``line_kv`` shape the
assessment could not parse without the Wheel — so a match proves the resumed
assessment genuinely *used* the learned capability, not merely re-ran.
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

from hermes.learning_recovery import ActiveWheelView  # noqa: E402
from hermes.wheel_consumption import (  # noqa: E402
    GapResolutionRequestV1,
    WheelConsumptionError,
    gap_input_digest,
    resolve_gap_with_wheel,
)
from hermes.wheels.sandbox import DockerSandbox  # noqa: E402

# python+pytest image pushed to ghcr for a reviewed @sha256 digest (docs/15 §11.5).
_DEFAULT_SANDBOX = (
    "ghcr.io/liberal-cloudarchitect/hermes-wheel-sandbox@sha256:"
    "7368b888d7110869c311bd70a0320f138b39e48c6ef924909317ccbdc6a1f05e"
)


class GapE2EFailure(RuntimeError):
    pass


def _json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise GapE2EFailure(f"not a JSON object: {path}")
    return value


def _sha256_file(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _run_r25(args: argparse.Namespace) -> dict[str, Any]:
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
        raise GapE2EFailure(f"run_r25_e2e returned {completed.returncode}")
    return json.loads(completed.stdout.strip().splitlines()[-1])


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--hermes-cli", type=Path, required=True)
    ap.add_argument("--hermes-python", type=Path, required=True)
    ap.add_argument("--model", required=True)
    ap.add_argument("--sandbox-image", default=_DEFAULT_SANDBOX)
    ap.add_argument("--problem-card-id", default="gap-line-kv-unparsed-field")
    ap.add_argument(
        "--artifact-root", type=Path, default=PROJECT_ROOT / "artifacts" / "cap07-gap-resolution"
    )
    ap.add_argument(
        "--r25-artifact-root", type=Path, default=PROJECT_ROOT / "artifacts" / "r25-e2e"
    )
    args = ap.parse_args(argv)

    # 1. Real R2.5 learning -> signed, active Wheel.
    r25 = _run_r25(args)
    root = Path(r25["artifact_root"])
    learning = root / "runs" / "learning" / str(r25["learning_run_id"])

    manifest_paths = sorted(learning.glob("wheels/*/wheel-manifest.json"))
    if not manifest_paths:
        raise GapE2EFailure("no wheel manifest in the R2.5 learning run")
    wheel_dir = manifest_paths[0].parent
    manifest = _json(manifest_paths[0])
    activation = _json(learning / "wheels" / "activation.json")
    entrypoint = str(manifest["entrypoint"])
    wheel_manifest_digest = str(activation["wheel_manifest_digest"])
    activation_digest = _sha256_file(learning / "wheels" / "activation.json")

    # 2. The gap: the Wheel's own positive fixture — the exact line_kv shape the
    #    assessment could not parse without the Wheel.
    gap_input = _json(wheel_dir / "fixtures" / "positive.json")

    # 3. The active Wheel view + the bound resolution request.
    active_wheel = ActiveWheelView(
        wheel_id=str(manifest["wheel_id"]),
        wheel_manifest_digest=wheel_manifest_digest,
        activation_digest=activation_digest,
        status="active",
        problem_card_ids=(args.problem_card_id,),
    )
    request = GapResolutionRequestV1(
        resume_run_id=f"cap07-resume-{root.name[-12:]}",
        paused_run_id=str(r25["parent_run_id"]),
        scope_digest=_sha256_file(manifest_paths[0]),
        problem_card_id=args.problem_card_id,
        wheel_manifest_digest=wheel_manifest_digest,
        wheel_activation_digest=activation_digest,
        gap_input_sha256=gap_input_digest(gap_input),
    )

    # 4. Invoke the Wheel in the real governed sandbox to resolve the gap.
    sandbox = DockerSandbox(args.sandbox_image)
    now = datetime.now(UTC)
    observation = resolve_gap_with_wheel(
        request,
        active_wheel,
        sandbox,
        wheel_artifact_root=wheel_dir,
        entrypoint=entrypoint,
        gap_input=gap_input,
        now=now,
    )
    if not observation.matched or observation.status != "resolved":
        raise GapE2EFailure(
            f"Wheel did not resolve the gap: matched={observation.matched} "
            f"status={observation.status}"
        )

    out_root = args.artifact_root.resolve()
    out_root.mkdir(parents=True, exist_ok=True)
    out = out_root / f"{now.strftime('%Y%m%dT%H%M%SZ')}-cap07-gap-resolution"
    out.mkdir(parents=True, exist_ok=True)
    (out / "resolved-observation.json").write_text(
        observation.model_dump_json(indent=2) + "\n", encoding="utf-8"
    )
    summary = {
        "cap07_gap_resolution": "resolved",
        "problem_card_id": observation.problem_card_id,
        "wheel_id": active_wheel.wheel_id,
        "wheel_invoked_in_sandbox": True,
        "sandbox_image": sandbox.image,
        "matched": observation.matched,
        "resolved_fields": observation.fields,
        "resume_run_id": observation.resume_run_id,
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
    except (GapE2EFailure, WheelConsumptionError, OSError, ValueError, KeyError) as exc:
        print(f"cap07-gap-resolution: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

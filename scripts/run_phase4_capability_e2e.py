#!/usr/bin/env python3
"""ACP-driven Phase 4 capability E2E: a real Wheel resolves a real V3 candidate.

This is the end-to-end closure of the CAP-07 consumption path. Where
``run_cap07_gap_resolution_e2e.py`` invokes the Wheel directly, this driver proves
the same resolution happens *inside a real V3 collaboration campaign*: the
localhost Phase 4 fixture advertises a ``line_kv`` capability artifact the
assessment cannot parse unaided, the campaign produces an ``infra-capability-gap``
candidate for it, and the isolated Verifier resolves that candidate's verdict by
running an active, approved Wheel through the governed sandbox.

Steps:
  1. Run a real R2.5 learning cycle to mint a signed, active Wheel.
  2. Read the Wheel's manifest / activation / positive fixture for its identity,
     digests, entrypoint, artifact root, and the exact ``line_kv`` gap text.
  3. Invoke ``run_phase4_e2e.py --scenario capability`` with that Wheel, so the
     live campaign's Verifier consumes it and validates the candidate end-to-end.

Every governance edge from ``resolve_gap_with_wheel`` still applies inside the
campaign (active Wheel, addressed problem card, input bound by digest, sandbox
pass); the driver asserts the Verifier wrote a bound, matched observation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]

# The reviewed python+pytest sandbox image (docs/15 §11.5), shared with the
# direct gap-resolution driver so both consume the identical governed sandbox.
_DEFAULT_SANDBOX = (
    "ghcr.io/liberal-cloudarchitect/hermes-wheel-sandbox@sha256:"
    "7368b888d7110869c311bd70a0320f138b39e48c6ef924909317ccbdc6a1f05e"
)


class CapabilityE2EFailure(RuntimeError):
    pass


def _json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise CapabilityE2EFailure(f"not a JSON object: {path}")
    return value


def _sha256_file(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _run(cmd: list[str]) -> dict[str, Any]:
    completed = subprocess.run(cmd, cwd=PROJECT_ROOT, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        sys.stderr.write(completed.stdout + "\n" + completed.stderr + "\n")
        raise CapabilityE2EFailure(f"{Path(cmd[1]).name} returned {completed.returncode}")
    return json.loads(completed.stdout.strip().splitlines()[-1])


def _mint_wheel(args: argparse.Namespace) -> dict[str, str]:
    """Run a real R2.5 learning cycle and read back the active Wheel's identity."""
    r25 = _run(
        [
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
    )
    root = Path(r25["artifact_root"])
    learning = root / "runs" / "learning" / str(r25["learning_run_id"])

    manifest_paths = sorted(learning.glob("wheels/*/wheel-manifest.json"))
    if not manifest_paths:
        raise CapabilityE2EFailure("no wheel manifest in the R2.5 learning run")
    wheel_dir = manifest_paths[0].parent
    manifest = _json(manifest_paths[0])
    activation = _json(learning / "wheels" / "activation.json")

    gap_fixture = _json(wheel_dir / "fixtures" / "positive.json")
    gap_text = gap_fixture.get("text")
    if not isinstance(gap_text, str) or not gap_text:
        raise CapabilityE2EFailure("wheel positive fixture has no 'text' gap input")

    return {
        "wheel_id": str(manifest["wheel_id"]),
        "wheel_manifest_digest": str(activation["wheel_manifest_digest"]),
        "wheel_activation_digest": _sha256_file(learning / "wheels" / "activation.json"),
        "entrypoint": str(manifest["entrypoint"]),
        "wheel_artifact_root": str(wheel_dir),
        "gap_text": gap_text,
        "r25_root": str(root),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--hermes-cli", type=Path, required=True)
    ap.add_argument("--hermes-python", type=Path, required=True)
    ap.add_argument("--model", required=True)
    ap.add_argument("--sandbox-image", default=_DEFAULT_SANDBOX)
    ap.add_argument("--problem-card-id", default="gap-line-kv-unparsed-field")
    ap.add_argument("--base-image")
    ap.add_argument(
        "--artifact-root", type=Path, default=PROJECT_ROOT / "artifacts" / "phase4-capability-e2e"
    )
    ap.add_argument(
        "--r25-artifact-root", type=Path, default=PROJECT_ROOT / "artifacts" / "r25-e2e"
    )
    args = ap.parse_args(argv)

    wheel = _mint_wheel(args)

    phase4_cmd = [
        sys.executable,
        str(PROJECT_ROOT / "scripts" / "run_phase4_e2e.py"),
        "--hermes-cli",
        str(args.hermes_cli),
        "--hermes-python",
        str(args.hermes_python),
        "--model",
        args.model,
        "--scenario",
        "capability",
        "--artifact-root",
        str(args.artifact_root),
        "--wheel-id",
        wheel["wheel_id"],
        "--wheel-manifest-digest",
        wheel["wheel_manifest_digest"],
        "--wheel-activation-digest",
        wheel["wheel_activation_digest"],
        "--sandbox-image",
        args.sandbox_image,
        "--wheel-artifact-root",
        wheel["wheel_artifact_root"],
        "--wheel-entrypoint",
        wheel["entrypoint"],
        "--problem-card-id",
        args.problem_card_id,
        "--gap-text",
        wheel["gap_text"],
    ]
    if args.base_image:
        phase4_cmd += ["--base-image", args.base_image]

    phase4 = _run(phase4_cmd)

    summary = {
        "phase4_capability": "resolved",
        "wheel_id": wheel["wheel_id"],
        "wheel_manifest_digest": wheel["wheel_manifest_digest"],
        "problem_card_id": args.problem_card_id,
        "sandbox_image": args.sandbox_image,
        "r25_root": wheel["r25_root"],
        "phase4_run_id": phase4.get("run_id"),
        "phase4_verification": phase4.get("verification"),
        "phase4_artifact_root": phase4.get("artifact_root"),
    }
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (CapabilityE2EFailure, OSError, ValueError, KeyError) as exc:
        print(f"phase4-capability: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

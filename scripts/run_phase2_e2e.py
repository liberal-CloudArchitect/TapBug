#!/usr/bin/env python3
"""Build and execute the real accepted/rejected Phase 2 local-lab gates."""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import urllib.request
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))
DEFAULT_BASE = (
    "python:3.11-slim@sha256:cdbd05fb6f457ca275ff51ce00d93d865ca0b6a25f5ffb08262d94f6835771e5"
)


class E2EFailure(RuntimeError):
    pass


def executable_path(path: Path) -> Path:
    """Make an executable path absolute without resolving its virtualenv symlink."""
    return Path(os.path.abspath(os.path.expanduser(path)))


class Driver:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.e2e_id = f"phase2-{uuid.uuid4().hex[:12]}"
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        self.root = args.artifact_root.resolve() / f"{stamp}-{self.e2e_id}"
        self.root.mkdir(parents=True)
        self.logs = self.root / "logs"
        self.logs.mkdir()
        self.runs = self.root / "runs"
        self.runs.mkdir()
        self.sequence = 0
        self.lab_container: str | None = None
        self.run_ids: list[str] = []
        self.temp = tempfile.TemporaryDirectory(prefix="hermes-phase2-keys-")
        self.private_root = Path(self.temp.name)
        self.env = dict(os.environ)
        current = self.env.get("PYTHONPATH")
        source = str(PROJECT_ROOT / "src")
        self.env["PYTHONPATH"] = source if not current else f"{source}{os.pathsep}{current}"

    def command(
        self,
        argv: list[str],
        *,
        expected: set[int] = {0},
        timeout: int = 600,
    ) -> subprocess.CompletedProcess[str]:
        self.sequence += 1
        result = subprocess.run(
            argv,
            cwd=PROJECT_ROOT,
            env=self.env,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
        log = {
            "argv": argv,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
        (self.logs / f"{self.sequence:03d}.json").write_text(
            json.dumps(log, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        if result.returncode not in expected:
            raise E2EFailure(
                f"command {argv[0]!r} returned {result.returncode}; see log {self.sequence:03d}"
            )
        return result

    def cli(self, arguments: list[str], *, expected: set[int]) -> dict[str, Any]:
        result = self.command(
            [sys.executable, "-m", "hermes", "--json", *arguments], expected=expected
        )
        try:
            value = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise E2EFailure("CLI did not return its promised JSON state") from exc
        if not isinstance(value, dict):
            raise E2EFailure("CLI JSON state is not an object")
        return value

    def generate_key(self, usage: str, key_id: str) -> tuple[Path, dict[str, Any]]:
        from hermes.security import encode_base64, generate_ed25519_private_key, public_key_bytes

        key = generate_ed25519_private_key()
        path = self.private_root / f"{usage}.pem"
        path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        path.chmod(0o600)
        now = datetime.now(UTC)
        record = {
            "key_id": key_id,
            "public_key": encode_base64(public_key_bytes(key)),
            "usages": [usage],
            "status": "active",
            "valid_from": (now - timedelta(minutes=5)).isoformat(),
            "valid_until": (now + timedelta(days=1)).isoformat(),
            "revoked_at": None,
        }
        return path, record

    def prepare(self) -> tuple[Path, int, Path, Path, Path]:
        role_tag = f"hermes-role-runtime:{self.e2e_id}"
        lab_tag = f"hermes-phase2-lab:{self.e2e_id}"
        self.command(
            [
                sys.executable,
                "scripts/build_role_image.py",
                "build",
                "--base-image",
                self.args.base_image,
                "--tag",
                role_tag,
            ],
            timeout=1200,
        )
        role_image = self.command(
            ["docker", "image", "inspect", "--format", "{{.Id}}", role_tag]
        ).stdout.strip()
        self.command(
            [
                "docker",
                "build",
                "--tag",
                lab_tag,
                str(PROJECT_ROOT / "tests" / "e2e_lab"),
            ],
            timeout=1200,
        )
        publisher_key, publisher = self.generate_key("role_manifest", "publisher-e2e")
        approver_key, approver = self.generate_key("approval", "approver-e2e")
        reviewer_key, reviewer = self.generate_key("human_review", "reviewer-e2e")
        stores = {
            "publisher-trust.json": publisher,
            "approval-trust.json": approver,
            "review-trust.json": reviewer,
        }
        for name, record in stores.items():
            (self.root / name).write_text(
                json.dumps({"version": "2", "keys": [record]}, indent=2) + "\n",
                encoding="utf-8",
            )
        manifests = self.root / "role-manifests.json"
        self.command(
            [
                sys.executable,
                "scripts/build_role_image.py",
                "manifest",
                "--image",
                role_image,
                "--key-id",
                "publisher-e2e",
                "--private-key",
                str(publisher_key),
                "--output",
                str(manifests),
            ]
        )
        self.lab_container = self.command(
            [
                "docker",
                "run",
                "--detach",
                "--rm",
                "--pull",
                "never",
                "--publish",
                "127.0.0.1::8080",
                "--label",
                f"com.hermes.e2e_id={self.e2e_id}",
                lab_tag,
            ]
        ).stdout.strip()
        binding = self.command(["docker", "port", self.lab_container, "8080/tcp"]).stdout.strip()
        port = int(binding.rsplit(":", 1)[1])
        self.wait_for_fixture(port)
        scope = self.root / "scope.yaml"
        scope.write_text(
            "\n".join(
                [
                    "profile: local-lab",
                    "automation_allowed: true",
                    "dry_run: false",
                    "rate_limit_rps: 10",
                    "max_requests: 3",
                    "max_duration_seconds: 180",
                    "max_concurrency: 1",
                    "allowed_commands: []",
                    "rules:",
                    "  - host: localhost",
                    "    schemes: [http]",
                    f"    ports: [{port}]",
                    "    allow_dns: true",
                    "    allow_private: true",
                    "    profile: local-lab",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        config = self.root / "config.json"
        config.write_text(
            json.dumps(
                {
                    "runs_root": str(self.runs),
                    "role_manifests": str(manifests),
                    "role_trust_store": str(self.root / "publisher-trust.json"),
                    "approval_trust_store": str(self.root / "approval-trust.json"),
                    "review_trust_store": str(self.root / "review-trust.json"),
                    "prompt_root": str(PROJECT_ROOT),
                    "hermes_cli": str(executable_path(self.args.hermes_cli)),
                    "hermes_python": str(executable_path(self.args.hermes_python)),
                    "restricted_bridge": str(PROJECT_ROOT / "scripts/restricted_hermes_acp.py"),
                    "model": self.args.model,
                    "docker_binary": "docker",
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        return config, port, scope, approver_key, reviewer_key

    def wait_for_fixture(self, port: int) -> None:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            try:
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/healthz", timeout=1
                ) as response:
                    if response.status == 204:
                        return
            except OSError:
                time.sleep(0.2)
        raise E2EFailure("local fixture did not become healthy within 15 seconds")

    def fixture_json(self, port: int, path: str) -> dict[str, Any]:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=3) as response:
            return json.loads(response.read())

    def execute(self) -> dict[str, Any]:
        config, port, scope, approver_key, reviewer_key = self.prepare()
        target = f"http://localhost:{port}/candidate"
        self.command(
            [
                sys.executable,
                "-m",
                "hermes",
                "validate-config",
                "--config",
                str(config),
                "--scope",
                str(scope),
            ]
        )
        self.command([sys.executable, "-m", "hermes", "doctor", "--config", str(config)])
        accepted = self.cli(
            ["run", "--config", str(config), "--scope", str(scope), "--target", target],
            expected={20},
        )
        accepted_id = str(accepted["run_id"])
        self.run_ids.append(accepted_id)
        challenge = json.loads(
            (self.runs / accepted_id / "approvals" / "challenge.json").read_text()
        )
        self.cli(
            [
                "approve",
                "--config",
                str(config),
                "--run-id",
                accepted_id,
                "--challenge-id",
                str(challenge["challenge_id"]),
                "--key",
                str(approver_key),
            ],
            expected={20},
        )
        self.cli(["resume", "--config", str(config), "--run-id", accepted_id], expected={21})
        outcome = json.loads((self.runs / accepted_id / "report" / "outcome.json").read_text())
        self.cli(
            [
                "review",
                "sign",
                "--config",
                str(config),
                "--run-id",
                accepted_id,
                "--outcome-id",
                str(outcome["outcome_id"]),
                "--verdict",
                "accepted",
                "--key",
                str(reviewer_key),
                "--rationale",
                "Independent local E2E review accepted.",
            ],
            expected={21},
        )
        self.cli(["resume", "--config", str(config), "--run-id", accepted_id], expected={0})
        verified = json.loads(
            self.command(
                [
                    sys.executable,
                    "scripts/verify_phase2_run.py",
                    "--runs-root",
                    str(self.runs),
                    "--run-id",
                    accepted_id,
                    "--config",
                    str(config),
                ]
            ).stdout
        )
        accepted_stats = self.fixture_json(port, "/__stats")
        if accepted_stats != {"candidate": 2, "control": 1}:
            raise E2EFailure(f"unexpected accepted request counts: {accepted_stats}")
        rejected = self.cli(
            ["run", "--config", str(config), "--scope", str(scope), "--target", target],
            expected={20},
        )
        rejected_id = str(rejected["run_id"])
        self.run_ids.append(rejected_id)
        rejected_challenge = json.loads(
            (self.runs / rejected_id / "approvals" / "challenge.json").read_text()
        )
        rejected_state = self.cli(
            [
                "reject",
                "--config",
                str(config),
                "--run-id",
                rejected_id,
                "--challenge-id",
                str(rejected_challenge["challenge_id"]),
                "--key",
                str(approver_key),
                "--reason",
                "Reject-path E2E gate.",
            ],
            expected={22},
        )
        rejected_root = self.runs / rejected_id
        if (rejected_root / "handoffs" / "phase3-verifier.json").exists() or (
            rejected_root / "report" / "report.md"
        ).exists():
            raise E2EFailure("rejected run produced verifier or formal report artifacts")
        rejected_verification = json.loads(
            self.command(
                [
                    sys.executable,
                    "scripts/verify_phase2_run.py",
                    "--runs-root",
                    str(self.runs),
                    "--run-id",
                    rejected_id,
                    "--config",
                    str(config),
                    "--rejected",
                ]
            ).stdout
        )
        return {
            "e2e_id": self.e2e_id,
            "accepted_run_id": accepted_id,
            "rejected_run_id": rejected_id,
            "accepted_stats": accepted_stats,
            "accepted_verification": verified,
            "rejected_state": rejected_state["execution_state"],
            "rejected_verification": rejected_verification,
            "artifact_root": str(self.root),
        }

    def execute_rejected_only(self) -> dict[str, Any]:
        """Run the independent reject gate without spending six accepted-path model calls."""

        config, port, scope, approver_key, _reviewer_key = self.prepare()
        target = f"http://localhost:{port}/candidate"
        self.command(
            [
                sys.executable,
                "-m",
                "hermes",
                "validate-config",
                "--config",
                str(config),
                "--scope",
                str(scope),
            ]
        )
        self.command([sys.executable, "-m", "hermes", "doctor", "--config", str(config)])
        rejected = self.cli(
            ["run", "--config", str(config), "--scope", str(scope), "--target", target],
            expected={20},
        )
        rejected_id = str(rejected["run_id"])
        self.run_ids.append(rejected_id)
        challenge = json.loads(
            (self.runs / rejected_id / "approvals" / "challenge.json").read_text()
        )
        rejected_state = self.cli(
            [
                "reject",
                "--config",
                str(config),
                "--run-id",
                rejected_id,
                "--challenge-id",
                str(challenge["challenge_id"]),
                "--key",
                str(approver_key),
                "--reason",
                "Reject-path E2E gate.",
            ],
            expected={22},
        )
        rejected_verification = json.loads(
            self.command(
                [
                    sys.executable,
                    "scripts/verify_phase2_run.py",
                    "--runs-root",
                    str(self.runs),
                    "--run-id",
                    rejected_id,
                    "--config",
                    str(config),
                    "--rejected",
                ]
            ).stdout
        )
        stats = self.fixture_json(port, "/__stats")
        if stats != {"candidate": 1, "control": 0}:
            raise E2EFailure(f"unexpected rejected request counts: {stats}")
        return {
            "e2e_id": self.e2e_id,
            "rejected_run_id": rejected_id,
            "rejected_state": rejected_state["execution_state"],
            "rejected_stats": stats,
            "rejected_verification": rejected_verification,
            "artifact_root": str(self.root),
        }

    def cleanup(self) -> None:
        if self.lab_container:
            subprocess.run(
                ["docker", "rm", "--force", self.lab_container],
                capture_output=True,
                text=True,
                check=False,
            )
        remaining = subprocess.run(
            ["docker", "ps", "--quiet", "--filter", f"label=com.hermes.e2e_id={self.e2e_id}"],
            capture_output=True,
            text=True,
            check=False,
        )
        container_ids = remaining.stdout.split()
        if container_ids:
            subprocess.run(
                ["docker", "rm", "--force", *container_ids],
                capture_output=True,
                text=True,
                check=False,
            )
        for run_id in self.run_ids:
            roles = subprocess.run(
                ["docker", "ps", "--quiet", "--filter", f"label=com.hermes.run_id={run_id}"],
                capture_output=True,
                text=True,
                check=False,
            ).stdout.split()
            if roles:
                subprocess.run(
                    ["docker", "rm", "--force", *roles],
                    capture_output=True,
                    text=True,
                    check=False,
                )
        self.temp.cleanup()


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--hermes-cli", type=Path, required=True)
    result.add_argument("--hermes-python", type=Path, required=True)
    result.add_argument("--model", required=True)
    result.add_argument("--mode", choices=("both", "rejected"), default="both")
    result.add_argument("--base-image", default=DEFAULT_BASE)
    result.add_argument(
        "--artifact-root", type=Path, default=PROJECT_ROOT / "artifacts" / "phase2-e2e"
    )
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    driver = Driver(args)

    def interrupted(_signum: int, _frame: object) -> None:
        raise KeyboardInterrupt

    signal.signal(signal.SIGINT, interrupted)
    signal.signal(signal.SIGTERM, interrupted)
    try:
        summary = driver.execute_rejected_only() if args.mode == "rejected" else driver.execute()
        (driver.root / "summary.json").write_text(
            json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
        return 0
    except (E2EFailure, subprocess.TimeoutExpired, OSError, ValueError) as exc:
        print(f"phase2-e2e: {exc}", file=sys.stderr)
        return 1
    finally:
        driver.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Execute and preserve real ACP + Docker acceptance artifacts for V4.

The driver is intentionally localhost-only.  It creates temporary keys,
certificate authority and identity vault outside the repository/run roots,
builds a signed V4 role image, then preserves only non-secret acceptance
artifacts under ``artifacts/phase5-e2e``.  It exercises an accepted run, a
rejected run, an idempotent post-completion recovery and fail-closed tamper
copies of the accepted run.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import ssl
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
FINAL_REPORTS = (
    "report/report-v4.md",
    "report/findings-v4.json",
    "report/report-write-receipt-v4.json",
    "report/reporter-ack-v4.json",
    "report/reporter-launch-v4.json",
)


class E2EFailure(RuntimeError):
    """A persisted real-V4 acceptance invariant was not satisfied."""


def _json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise E2EFailure(f"missing or invalid JSON artifact: {path}") from exc
    if not isinstance(value, dict):
        raise E2EFailure(f"artifact is not a JSON object: {path}")
    return value


def _executable(path: Path) -> Path:
    return Path(os.path.abspath(os.path.expanduser(path)))


class Driver:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.e2e_id = f"phase5-{uuid.uuid4().hex[:12]}"
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        self.root = args.artifact_root.resolve() / f"{stamp}-{self.e2e_id}"
        self.root.mkdir(parents=True)
        self.logs = self.root / "logs"
        self.logs.mkdir()
        self.runs = self.root / "runs"
        self.runs.mkdir()
        self.tamper = self.root / "tamper"
        self.tamper.mkdir()
        self.sequence = 0
        self.lab_container: str | None = None
        self.run_ids: list[str] = []
        self.temp = tempfile.TemporaryDirectory(prefix="hermes-phase5-secrets-")
        self.private_root = Path(self.temp.name)
        self.env = dict(os.environ)
        source = str(PROJECT_ROOT / "src")
        current = self.env.get("PYTHONPATH")
        self.env["PYTHONPATH"] = source if not current else f"{source}{os.pathsep}{current}"

    def command(
        self, argv: list[str], *, expected: set[int] | None = None, timeout: int = 1800
    ) -> subprocess.CompletedProcess[str]:
        self.sequence += 1
        completed = subprocess.run(
            argv,
            cwd=PROJECT_ROOT,
            env=self.env,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
        (self.logs / f"{self.sequence:03d}.json").write_text(
            json.dumps(
                {
                    "argv": argv,
                    "returncode": completed.returncode,
                    "stdout": completed.stdout,
                    "stderr": completed.stderr,
                },
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        if expected is not None and completed.returncode not in expected:
            raise E2EFailure(
                f"command {argv[0]!r} returned {completed.returncode}; see log {self.sequence:03d}"
            )
        return completed

    def cli(
        self,
        args: list[str],
        *,
        expected: set[int],
        timeout: int = 1800,
    ) -> dict[str, Any]:
        completed = self.command(
            [sys.executable, "-m", "hermes", "--json", *args],
            expected=expected,
            timeout=timeout,
        )
        try:
            value = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise E2EFailure("V4 CLI did not emit machine-readable JSON") from exc
        if not isinstance(value, dict):
            raise E2EFailure("V4 CLI JSON is not an object")
        return value

    def key(self, usage: str, key_id: str) -> tuple[Path, dict[str, Any]]:
        from hermes.security import encode_base64, generate_ed25519_private_key, public_key_bytes

        value = generate_ed25519_private_key()
        path = self.private_root / f"{usage}.pem"
        path.write_bytes(
            value.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        path.chmod(0o600)
        now = datetime.now(UTC)
        return path, {
            "key_id": key_id,
            "public_key": encode_base64(public_key_bytes(value)),
            "usages": [usage],
            "status": "active",
            "valid_from": (now - timedelta(minutes=5)).isoformat(),
            "valid_until": (now + timedelta(days=1)).isoformat(),
            "revoked_at": None,
        }

    def prepare(self) -> tuple[Path, Path, str, Path, Path, str]:
        from hermes.passive_v4 import write_localhost_test_certificates

        role_tag = f"hermes-role-runtime:{self.e2e_id}"
        lab_tag = f"hermes-phase5-lab:{self.e2e_id}"
        self.command(
            [
                sys.executable,
                "scripts/build_role_image_v4.py",
                "build",
                "--base-image",
                self.args.base_image,
                "--tag",
                role_tag,
            ],
            expected={0},
        )
        role_image = self.command(
            ["docker", "image", "inspect", "--format", "{{.Id}}", role_tag], expected={0}
        ).stdout.strip()
        if not role_image.startswith("sha256:"):
            raise E2EFailure("built role image did not have an immutable content digest")
        self.command(
            ["docker", "build", "--tag", lab_tag, str(PROJECT_ROOT / "tests" / "e2e_lab_v4")],
            expected={0},
        )
        publisher_key, publisher = self.key("role_manifest", "publisher-v4-e2e")
        approver_key, approver = self.key("approval", "approver-v4-e2e")
        reviewer_key, reviewer = self.key("human_review", "reviewer-v4-e2e")
        for name, record in {
            "publisher-trust.json": publisher,
            "approval-trust.json": approver,
            "review-trust.json": reviewer,
        }.items():
            (self.root / name).write_text(
                json.dumps({"version": "2", "keys": [record]}, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
        manifests = self.root / "role-manifests-v4.json"
        self.command(
            [
                sys.executable,
                "scripts/build_role_image_v4.py",
                "manifest",
                "--image",
                role_image,
                "--key-id",
                "publisher-v4-e2e",
                "--private-key",
                str(publisher_key),
                "--output",
                str(manifests),
            ],
            expected={0},
        )
        vault = self.private_root / "identity-vault.json"
        vault.write_text(
            json.dumps(
                {
                    "version": "1",
                    "identities": {
                        "alice": "phase5-alice-token",
                        "bob": "phase5-bob-token",
                        "fixture-admin": "phase5-fixture-admin-token",
                    },
                }
            ),
            encoding="utf-8",
        )
        vault.chmod(0o600)
        cert_root = self.private_root / "certs"
        ca_file, _cert, _key = write_localhost_test_certificates(str(cert_root))
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
                "--mount",
                f"type=bind,src={cert_root},dst=/certs,readonly",
                "--env",
                "HERMES_V4_PORT=8080",
                "--env",
                "HERMES_V4_TLS_CERT=/certs/localhost.pem",
                "--env",
                "HERMES_V4_TLS_KEY=/certs/localhost-key.pem",
                lab_tag,
            ],
            expected={0},
        ).stdout.strip()
        binding = self.command(
            ["docker", "port", self.lab_container, "8080/tcp"], expected={0}
        ).stdout.strip()
        port = int(binding.rsplit(":", 1)[1])
        target = f"https://localhost:{port}/candidate"
        self.wait_fixture(target, Path(ca_file))
        initial_hash = str(self.fixture_json(target, "/fixture/stats", Path(ca_file))["state_hash"])
        scope = self.root / "scope.yaml"
        scope.write_text(
            "\n".join(
                (
                    "profile: local-lab",
                    "automation_allowed: true",
                    "dry_run: false",
                    "rate_limit_rps: 50",
                    "max_requests: 32",
                    "max_duration_seconds: 2700",
                    "max_concurrency: 4",
                    "allowed_commands: []",
                    "rules:",
                    "  - host: localhost",
                    "    schemes: [https]",
                    f"    ports: [{port}]",
                    "    allow_dns: true",
                    "    allow_private: true",
                    "    profile: local-lab",
                    "",
                )
            ),
            encoding="utf-8",
        )
        config = self.root / "config.json"
        config.write_text(
            json.dumps(
                {
                    "runs_root": str(self.runs),
                    "role_manifests_v4": str(manifests),
                    "role_trust_store": str(self.root / "publisher-trust.json"),
                    "approval_trust_store": str(self.root / "approval-trust.json"),
                    "review_trust_store": str(self.root / "review-trust.json"),
                    "identity_vault": str(vault),
                    "v4_fixture_ca_file": ca_file,
                    "v4_quality_dataset": str(
                        PROJECT_ROOT
                        / "tests"
                        / "fixtures"
                        / "quality"
                        / "v4"
                        / "ground-truth-v2.json"
                    ),
                    "prompt_root": str(PROJECT_ROOT),
                    "hermes_cli": str(_executable(self.args.hermes_cli)),
                    "hermes_python": str(_executable(self.args.hermes_python)),
                    "restricted_bridge": str(PROJECT_ROOT / "scripts" / "restricted_hermes_acp.py"),
                    "model": self.args.model,
                    "docker_binary": "docker",
                },
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        return config, scope, target, approver_key, reviewer_key, initial_hash

    def wait_fixture(self, target: str, ca_file: Path) -> None:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                self.fixture_json(target, "/fixture/stats", ca_file)
                return
            except OSError:
                time.sleep(0.25)
        raise E2EFailure("V4 HTTPS Docker fixture did not become healthy")

    @staticmethod
    def fixture_json(target: str, path: str, ca_file: Path) -> dict[str, Any]:
        context = ssl.create_default_context(cafile=str(ca_file))
        base = target.rsplit("/", 1)[0]
        with urllib.request.urlopen(f"{base}{path}", context=context, timeout=5) as response:
            value = json.loads(response.read())
        if not isinstance(value, dict):
            raise E2EFailure("fixture response is not a JSON object")
        return value

    def _start(self, config: Path, scope: Path, target: str) -> str:
        state = self.cli(
            [
                "run",
                "--schema-version",
                "4",
                "--workflow",
                "v4",
                "--config",
                str(config),
                "--scope",
                str(scope),
                "--target",
                target,
            ],
            expected={20},
        )
        if state.get("execution_state") != "awaiting_readonly_approval":
            raise E2EFailure("V4 run did not pause for read-only approval")
        run_id = str(state["run_id"])
        self.run_ids.append(run_id)
        return run_id

    def _decision(
        self, config: Path, run_id: str, group: str, decision: str, key: Path
    ) -> dict[str, Any]:
        challenge = _json(self.runs / run_id / "approvals_v4" / f"challenge-{group}.json")
        expected = {20} if decision == "approve" else {22}
        return self.cli(
            [
                decision,
                "--config",
                str(config),
                "--run-id",
                run_id,
                "--challenge-id",
                str(challenge["challenge_id"]),
                "--risk-group",
                group,
                "--key",
                str(key),
                "--reason",
                f"{decision} exact V4 {group} localhost teaching-fixture action graph",
            ],
            expected=expected,
        )

    def accepted(
        self,
        config: Path,
        scope: Path,
        target: str,
        approver: Path,
        reviewer: Path,
        initial_hash: str,
    ) -> dict[str, Any]:
        run_id = self._start(config, scope, target)
        self._decision(config, run_id, "readonly", "approve", approver)
        state = self.cli(["resume", "--config", str(config), "--run-id", run_id], expected={20})
        if state.get("execution_state") != "awaiting_mutation_approval":
            raise E2EFailure("read-only V4 approval did not stop for mutation approval")
        self._decision(config, run_id, "mutation", "approve", approver)
        state = self.cli(
            ["resume", "--config", str(config), "--run-id", run_id], expected={21}, timeout=2400
        )
        if state.get("execution_state") != "awaiting_review":
            raise E2EFailure("V4 verification did not stop for human review")
        self.cli(
            [
                "review",
                "sign",
                "--config",
                str(config),
                "--run-id",
                run_id,
                "--outcome-id",
                "phase5-findings",
                "--verdict",
                "accepted",
                "--key",
                str(reviewer),
                "--rationale",
                "Independent reviewer accepts the complete local V4 evidence and coverage.",
            ],
            expected={21},
        )
        state = self.cli(
            ["resume", "--config", str(config), "--run-id", run_id], expected={0}, timeout=1200
        )
        if state.get("execution_state") != "completed":
            raise E2EFailure("V4 Reporter did not complete the accepted run")
        verification = self.verify_accepted(run_id, target, config, initial_hash)
        return {"run_id": run_id, "verification": verification}

    def rejected(self, config: Path, scope: Path, target: str, approver: Path) -> dict[str, Any]:
        run_id = self._start(config, scope, target)
        state = self._decision(config, run_id, "readonly", "reject", approver)
        if state.get("execution_state") != "rejected":
            raise E2EFailure("V4 rejected read-only batch did not terminate the run")
        restarted = self.cli(["resume", "--config", str(config), "--run-id", run_id], expected={22})
        root = self.runs / run_id
        evidence = list((root / "evidence").glob("*/manifest.json"))
        reports = [root / item for item in FINAL_REPORTS]
        if len(evidence) != 2 or any(path.exists() for path in reports):
            raise E2EFailure("rejected V4 run created unauthorized evidence or report output")
        self.assert_no_role_containers(run_id)
        return {
            "run_id": run_id,
            "state": restarted["execution_state"],
            "evidence_artifacts": len(evidence),
            "formal_report": False,
        }

    def mutation_rejected(
        self, config: Path, scope: Path, target: str, approver: Path
    ) -> dict[str, Any]:
        """Reject the second approval batch after read-only evidence exists."""

        run_id = self._start(config, scope, target)
        self._decision(config, run_id, "readonly", "approve", approver)
        state = self.cli(["resume", "--config", str(config), "--run-id", run_id], expected={20})
        if state.get("execution_state") != "awaiting_mutation_approval":
            raise E2EFailure("mutation-reject scenario did not reach its second approval boundary")
        state = self._decision(config, run_id, "mutation", "reject", approver)
        if state.get("execution_state") != "rejected":
            raise E2EFailure("rejected V4 mutation batch did not terminate the run")
        restarted = self.cli(["resume", "--config", str(config), "--run-id", run_id], expected={22})
        root = self.runs / run_id
        evidence = list((root / "evidence").glob("*/manifest.json"))
        consumptions = list((root / "governance_v4" / "consumptions").glob("*.json"))
        reports = [root / item for item in FINAL_REPORTS]
        if len(evidence) != 13 or len(consumptions) != 11 or any(path.exists() for path in reports):
            raise E2EFailure("mutation rejection performed unauthorized mutation or wrote a report")
        self.assert_no_role_containers(run_id)
        return {
            "run_id": run_id,
            "state": restarted["execution_state"],
            "evidence_artifacts": len(evidence),
            "approval_consumptions": len(consumptions),
            "formal_report": False,
        }

    def verify_accepted(
        self, run_id: str, target: str, config: Path, initial_hash: str
    ) -> dict[str, Any]:
        root = self.runs / run_id
        state = _json(root / "state.json")
        if (
            state.get("version") != "4"
            or state.get("execution_state") != "completed"
            or state.get("requests_used") != 28
            or state.get("requests_planned") != 28
        ):
            raise E2EFailure("accepted V4 state does not bind the 28-request completion")
        handoffs = sorted((root / "handoffs_v4").glob("phase5-*.json"))
        providers = sorted((root / "provider").glob("phase5-*.json"))
        if len(handoffs) != 24 or len(providers) != 24:
            raise E2EFailure("accepted V4 run did not use exactly 24 role/ACP tasks")
        expected_prefixes = {
            "phase5-gatekeeper": 1,
            "phase5-recon": 1,
            "phase5-mapper": 1,
            "phase5-assessment-": 4,
            "phase5-cross-review-": 8,
            "phase5-verifier-": 8,
            "phase5-reporter": 1,
        }
        names = [path.stem for path in handoffs]
        for prefix, expected in expected_prefixes.items():
            observed = sum(name == prefix or name.startswith(prefix) for name in names)
            if observed != expected:
                raise E2EFailure(
                    f"expected {expected} real tasks with prefix {prefix!r}, got {observed}"
                )
        containers: set[str] = set()
        pids: set[int] = set()
        for path in handoffs:
            result = _json(path).get("result")
            handoff = result.get("handoff") if isinstance(result, dict) else None
            container = handoff.get("container_id") if isinstance(handoff, dict) else None
            pid = result.get("host_process_id") if isinstance(result, dict) else None
            if (
                not isinstance(container, str)
                or not container
                or not isinstance(pid, int)
                or pid < 1
            ):
                raise E2EFailure("a V4 role task was not a real Docker child process")
            containers.add(container)
            pids.add(pid)
        sessions = {_json(path).get("session_id") for path in providers}
        attempts = sum(int(_json(path).get("prompt_attempts", 0)) for path in providers)
        if len(containers) != 24 or len(pids) != 24 or None in sessions or len(sessions) != 24:
            raise E2EFailure(
                "V4 roles did not receive independent containers, PIDs and ACP sessions"
            )
        if not 24 <= attempts <= 64:
            raise E2EFailure("V4 ACP attempt budget was not enforced")
        for path in providers:
            task_id = path.stem
            if not (root / "provider" / "sessions" / task_id / "state.db").is_file():
                raise E2EFailure(f"V4 ACP task {task_id} has no isolated session DB")
        manifests = sorted((root / "evidence").glob("*/manifest.json"))
        analyses = sorted((root / "evidence").glob("*/analysis.json"))
        consumptions = sorted((root / "governance_v4" / "consumptions").glob("*.json"))
        outcomes = sorted((root / "verification_v4" / "outcomes").glob("*.json"))
        if (
            len(manifests) != 28
            or len(analyses) != 28
            or len(consumptions) != 26
            or len(outcomes) != 8
        ):
            raise E2EFailure("V4 evidence, consumption or verifier-outcome count is incorrect")
        cleanup = _json(root / "verification_v4" / "cleanup.json")
        if cleanup.get("state_restored") is not True or len(cleanup.get("results", [])) != 3:
            raise E2EFailure("V4 mutation cleanup was not fully attested")
        for relative in (
            "quality/dataset-v4.json",
            "quality/receipt-v4.json",
            "report/finding-set-v4.json",
            "report/coverage-v4.json",
            "reviews/signed-v4.json",
            "report/reporter-launch-v4.json",
            "report/reporter-ack-v4.json",
            "report/report-v4.md",
            "report/findings-v4.json",
            "report/report-write-receipt-v4.json",
        ):
            if not (root / relative).is_file():
                raise E2EFailure(f"accepted V4 report chain omits {relative}")
        dataset = _json(root / "quality" / "dataset-v4.json")
        cases = dataset.get("cases")
        if dataset.get("version") != "phase5-ground-truth-v2" or not isinstance(cases, list):
            raise E2EFailure("accepted V4 run did not freeze the explicit quality dataset")
        receipt = _json(root / "quality" / "receipt-v4.json")
        families = receipt.get("families")
        if receipt.get("overall_passed") is not True or not isinstance(families, list):
            raise E2EFailure("accepted V4 quality receipt did not pass")
        expected_quality = {"web", "api", "authz", "infra", "workflow"}
        observed_quality = {item.get("family") for item in families if isinstance(item, dict)}
        if observed_quality != expected_quality:
            raise E2EFailure("accepted V4 quality receipt omits a detector family")
        for family in families:
            if not isinstance(family, dict) or (
                family.get("positives", 0) < 20
                or family.get("negatives", 0) < 20
                or family.get("candidate_recall") != 1.0
                or family.get("verified_precision") != 1.0
                or family.get("passed") is not True
                or family.get("estimated_cost_microusd") is not None
            ):
                raise E2EFailure("accepted V4 quality metrics are not explicit and measured")
        if sum(int(item["requests_used"]) for item in families) != 26:
            raise E2EFailure("V4 quality receipt does not account for all governed requests")
        findings = _json(root / "report" / "finding-set-v4.json").get("findings")
        if not isinstance(findings, list) or len(findings) != 8:
            raise E2EFailure("accepted V4 run did not promote eight fixed findings")
        ca_file = Path(_json(config)["v4_fixture_ca_file"])
        stats = self.fixture_json(target, "/fixture/stats", ca_file)
        requests = stats.get("requests")
        if not isinstance(requests, dict):
            raise E2EFailure("fixture did not provide request statistics")
        observed = sum(value for path, value in requests.items() if path != "/fixture/stats")
        if observed != 28 or stats.get("state_hash") != initial_hash:
            raise E2EFailure("V4 fixture request count or restored state is incorrect")
        self.assert_no_role_containers(run_id)
        return {
            "agent_tasks": 24,
            "containers": 24,
            "host_processes": 24,
            "acp_sessions": 24,
            "prompt_attempts": attempts,
            "evidence_artifacts": 28,
            "approval_consumptions": 26,
            "verifier_outcomes": 8,
            "findings": 8,
            "network_requests": 28,
            "state_restored": True,
        }

    def recovery(self, config: Path, run_id: str) -> dict[str, Any]:
        before = _json(self.runs / run_id / "state.json")
        provider_before = len(list((self.runs / run_id / "provider").glob("phase5-*.json")))
        resumed = self.cli(["resume", "--config", str(config), "--run-id", run_id], expected={0})
        provider_after = len(list((self.runs / run_id / "provider").glob("phase5-*.json")))
        if resumed.get("execution_state") != "completed" or provider_before != provider_after:
            raise E2EFailure("completed V4 recovery was not idempotent")
        receipt = {
            "kind": "completed_run_idempotent_restart",
            "run_id": run_id,
            "state_digest_before": _sha256_json(before),
            "state_digest_after": _sha256_json(_json(self.runs / run_id / "state.json")),
            "provider_records_before": provider_before,
            "provider_records_after": provider_after,
            "result": "resumed_without_new_model_or_network_work",
        }
        (self.root / "recovery.json").write_text(
            json.dumps(receipt, indent=2) + "\n", encoding="utf-8"
        )
        return receipt

    def tamper_cases(self, config: Path, run_id: str) -> dict[str, str]:
        from hermes.campaign_v4 import VerificationCampaignPlanV4
        from hermes.cli_v4 import verify_review_v4
        from hermes.preflight_v4 import ReportPreflightV4Error, ReportPreflightVerifierV4
        from hermes.runtime import RunContext
        from hermes.security import TrustStoreV2
        from hermes.security_v4 import ApprovalBatchV4, verify_approval_batch_v4

        source = self.runs / run_id
        approval_store = TrustStoreV2.model_validate(_json(self.root / "approval-trust.json"))
        review_store = TrustStoreV2.model_validate(_json(self.root / "review-trust.json"))
        cases: dict[str, tuple[str, str]] = {
            "approval_signature": ("approvals_v4/readonly.json", "signature_b64"),
            "review_signature": ("reviews/signed-v4.json", "signature_b64"),
            "consumption_action": ("governance_v4/consumptions", "action_digest"),
            "coverage": ("report/coverage-v4.json", "requests_used"),
            "outcome": ("verification_v4/outcomes/web-xcto.json", "outcome_id"),
            "action_ledger": ("governance_v4/action_ledger/events.jsonl", "event_hash"),
            "budget_ledger": ("governance_v4/budget_ledger/events.jsonl", "event_hash"),
            "evidence_manifest": ("evidence", "response_hash"),
            "quality_dataset": ("quality/dataset-v4.json", "version"),
            "quality_receipt": ("quality/receipt-v4.json", "overall_passed"),
            "cleanup": ("verification_v4/cleanup.json", "final_state_sha256"),
            "branch_result": ("collaboration_v4/branch-results.json", "gaps"),
            "cross_review": ("collaboration_v4/review-plan.json", "reviewers"),
        }
        results: dict[str, str] = {}
        for name, (relative, field) in cases.items():
            root = self.tamper / name / "runs"
            copied = root / run_id
            shutil.copytree(source, copied)
            for final in FINAL_REPORTS:
                (copied / final).unlink(missing_ok=True)
            target = copied / relative
            if target.is_dir():
                candidates = sorted((*target.glob("*.json"), *target.rglob("manifest.json")))
                if not candidates:
                    raise E2EFailure(f"tamper target has no JSON artifact: {relative}")
                target = candidates[0]
            if target.suffix == ".jsonl":
                lines = target.read_text(encoding="utf-8").splitlines()
                record = json.loads(lines[-1])
                record[field] = "sha256:" + "0" * 64
                lines[-1] = json.dumps(record, sort_keys=True, separators=(",", ":"))
                target.write_text("\n".join(lines) + "\n", encoding="utf-8")
            else:
                value = _json(target)
                value[field] = "tampered-value" if field.endswith("b64") else "sha256:" + "0" * 64
                target.write_text(
                    json.dumps(value, sort_keys=True, separators=(",", ":")), encoding="utf-8"
                )
            scope = _json(copied / "scope.json")
            context = RunContext.open_existing(root, scope, run_id)
            campaign = VerificationCampaignPlanV4.model_validate_json(
                context.artifact_path("verification_v4/campaign.json").read_bytes()
            )
            verifier = ReportPreflightVerifierV4(
                context,
                approval_signature_verifier=lambda batch: verify_approval_batch_v4(
                    batch
                    if isinstance(batch, ApprovalBatchV4)
                    else ApprovalBatchV4.model_validate(batch),
                    campaign,
                    approval_store,
                ),
                review_signature_verifier=lambda review, _findings, _coverage: verify_review_v4(
                    review, review_store
                ),
            )
            try:
                verifier.authorize_reporter()
            except ReportPreflightV4Error:
                if any((copied / final).exists() for final in FINAL_REPORTS):
                    raise E2EFailure(f"tamper case {name} created a formal report")
                results[name] = "blocked_before_reporter"
            else:
                raise E2EFailure(f"tamper case {name} unexpectedly authorized Reporter")
        (self.root / "tamper-summary.json").write_text(
            json.dumps(results, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        return results

    def assert_no_role_containers(self, run_id: str) -> None:
        values = self.command(
            ["docker", "ps", "--quiet", "--filter", f"label=com.hermes.run_id={run_id}"],
            expected={0},
        ).stdout.split()
        if values:
            raise E2EFailure(f"V4 left role containers running: {values}")

    def execute(self) -> dict[str, Any]:
        config, scope, target, approver, reviewer, initial_hash = self.prepare()
        self.command(
            [
                sys.executable,
                "-m",
                "hermes",
                "validate-config",
                "--schema-version",
                "4",
                "--config",
                str(config),
                "--scope",
                str(scope),
            ],
            expected={0},
        )
        self.command(
            [
                sys.executable,
                "-m",
                "hermes",
                "doctor",
                "--schema-version",
                "4",
                "--config",
                str(config),
            ],
            expected={0},
        )
        accepted = self.accepted(config, scope, target, approver, reviewer, initial_hash)
        rejected = self.rejected(config, scope, target, approver)
        mutation_rejected = self.mutation_rejected(config, scope, target, approver)
        recovery = self.recovery(config, str(accepted["run_id"]))
        tamper = self.tamper_cases(config, str(accepted["run_id"]))
        return {
            "e2e_id": self.e2e_id,
            "artifact_root": str(self.root),
            "accepted": accepted,
            "rejected": rejected,
            "mutation_rejected": mutation_rejected,
            "recovery": recovery,
            "tamper": tamper,
        }

    def cleanup(self) -> None:
        if self.lab_container:
            subprocess.run(
                ["docker", "rm", "--force", self.lab_container], capture_output=True, text=True
            )
        remaining = subprocess.run(
            ["docker", "ps", "--quiet", "--filter", f"label=com.hermes.e2e_id={self.e2e_id}"],
            capture_output=True,
            text=True,
        ).stdout.split()
        if remaining:
            subprocess.run(["docker", "rm", "--force", *remaining], capture_output=True, text=True)
        self.temp.cleanup()


def _sha256_json(value: object) -> str:
    import hashlib

    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--hermes-cli", type=Path, required=True)
    result.add_argument("--hermes-python", type=Path, required=True)
    result.add_argument("--model", required=True)
    result.add_argument("--base-image", default=DEFAULT_BASE)
    result.add_argument(
        "--artifact-root", type=Path, default=PROJECT_ROOT / "artifacts" / "phase5-e2e"
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
        summary = driver.execute()
        (driver.root / "summary.json").write_text(
            json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
        return 0
    except (E2EFailure, OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print(f"phase5-e2e: {exc}", file=sys.stderr)
        return 1
    finally:
        driver.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())

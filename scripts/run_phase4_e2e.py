#!/usr/bin/env python3
"""Build and execute the real Phase 4 localhost collaboration gate."""

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
from typing import Any, Literal, cast

from cryptography.hazmat.primitives import serialization

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))
DEFAULT_BASE = (
    "python:3.11-slim@sha256:cdbd05fb6f457ca275ff51ce00d93d865ca0b6a25f5ffb08262d94f6835771e5"
)
EXPECTED_FIXTURE_REQUESTS = {
    "/candidate": 2,
    "/control": 1,
    "/debug": 1,
    "/debug-control": 1,
    "/graphql": 2,
    "/graphql/mutate": 1,
    "/graphql/control": 1,
    "/graphql/cleanup": 1,
    "/authz/status": 2,
    "/authz/elevate": 1,
    "/authz/admin": 1,
    "/authz/revoke": 1,
}

Scenario = Literal[
    "accepted-full",
    "web-infra",
    "mutation-rejected",
    "readonly-rejected",
    "all-rejected",
]

_SCENARIO_DECISIONS: dict[Scenario, tuple[tuple[str, str], ...]] = {
    "accepted-full": (("readonly", "approve"), ("mutation", "approve")),
    "web-infra": (("readonly", "approve"),),
    "mutation-rejected": (("readonly", "approve"), ("mutation", "reject")),
    "readonly-rejected": (("readonly", "reject"), ("mutation", "approve")),
    "all-rejected": (("readonly", "reject"), ("mutation", "reject")),
}

_SCENARIO_EXPECTATIONS: dict[Scenario, dict[str, int | str | bool]] = {
    "accepted-full": {
        "tasks": 16,
        "requests": 15,
        "evidence": 15,
        "consumptions": 14,
        "findings": 4,
        "state": "completed",
        "coverage": "completed",
        "report": True,
    },
    "web-infra": {
        "tasks": 10,
        "requests": 5,
        "evidence": 5,
        "consumptions": 4,
        "findings": 2,
        "state": "completed",
        "coverage": "completed",
        "report": True,
    },
    "mutation-rejected": {
        "tasks": 14,
        "requests": 5,
        "evidence": 5,
        "consumptions": 4,
        "findings": 2,
        "state": "completed_with_gaps",
        "coverage": "completed_with_gaps",
        "report": True,
    },
    "readonly-rejected": {
        "tasks": 14,
        "requests": 11,
        "evidence": 11,
        "consumptions": 10,
        "findings": 2,
        "state": "completed_with_gaps",
        "coverage": "completed_with_gaps",
        "report": True,
    },
    "all-rejected": {
        "tasks": 11,
        "requests": 1,
        "evidence": 1,
        "consumptions": 0,
        "findings": 0,
        "state": "rejected",
        "coverage": "not_created",
        "report": False,
    },
}


class E2EFailure(RuntimeError):
    """A real Phase 4 acceptance invariant was not satisfied."""


def executable_path(path: Path) -> Path:
    """Make a path absolute without resolving a virtualenv interpreter symlink."""

    return Path(os.path.abspath(os.path.expanduser(path)))


def _json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise E2EFailure(f"invalid or missing acceptance artifact: {path}") from exc
    if not isinstance(value, dict):
        raise E2EFailure(f"acceptance artifact is not an object: {path}")
    return value


def _interval(record: dict[str, Any]) -> tuple[datetime, datetime]:
    result = record.get("result")
    if not isinstance(result, dict):
        raise E2EFailure("handoff record has no result object")
    try:
        started = datetime.fromisoformat(str(result["started_at"]).replace("Z", "+00:00"))
        finished = datetime.fromisoformat(str(result["finished_at"]).replace("Z", "+00:00"))
    except (KeyError, ValueError) as exc:
        raise E2EFailure("handoff record has invalid execution timestamps") from exc
    return started, finished


def _assert_true_overlap(records: list[dict[str, Any]], label: str) -> None:
    if len(records) < 2:
        raise E2EFailure(f"{label} did not contain at least two independent tasks")
    intervals = [_interval(record) for record in records]
    if max(started for started, _ in intervals) >= min(finished for _, finished in intervals):
        raise E2EFailure(f"{label} tasks did not overlap in real execution time")


def verify_accepted_run(
    run_root: Path,
    *,
    fixture_stats: dict[str, Any],
    initial_state_hash: str,
) -> dict[str, Any]:
    """Verify the persisted accepted path without trusting CLI success alone."""

    state = _json(run_root / "state.json")
    if state.get("version") != "3" or state.get("execution_state") != "completed":
        raise E2EFailure(f"accepted V3 run did not complete: {state.get('execution_state')}")
    if state.get("requests_used") != 15 or state.get("requests_planned") != 15:
        raise E2EFailure("accepted V3 state does not bind the exact 15-request campaign")

    handoff_paths = sorted((run_root / "handoffs").glob("phase4-*.json"))
    provider_paths = sorted((run_root / "provider").glob("phase4-*.json"))
    if len(handoff_paths) != 16 or len(provider_paths) != 16:
        raise E2EFailure(
            f"expected 16 agent tasks, found {len(handoff_paths)} handoffs and "
            f"{len(provider_paths)} provider records"
        )
    handoffs = {path.stem: _json(path) for path in handoff_paths}
    providers = {path.stem: _json(path) for path in provider_paths}
    expected_prefix_counts = {
        "phase4-gatekeeper": 1,
        "phase4-recon": 1,
        "phase4-mapper": 1,
        "phase4-assessment-": 4,
        "phase4-review-": 4,
        "phase4-verifier-": 4,
        "phase4-reporter": 1,
    }
    for prefix, count in expected_prefix_counts.items():
        observed = sum(name == prefix or name.startswith(prefix) for name in handoffs)
        if observed != count:
            raise E2EFailure(f"expected {count} {prefix!r} tasks, found {observed}")

    containers: set[str] = set()
    host_pids: set[int] = set()
    for record in handoffs.values():
        result = record.get("result")
        handoff = result.get("handoff") if isinstance(result, dict) else None
        container_id = handoff.get("container_id") if isinstance(handoff, dict) else None
        process_id = result.get("host_process_id") if isinstance(result, dict) else None
        if not isinstance(container_id, str) or not container_id:
            raise E2EFailure("a Phase 4 task did not run in a real role container")
        if not isinstance(process_id, int) or process_id < 1:
            raise E2EFailure("a Phase 4 task did not record a real host process")
        containers.add(container_id)
        host_pids.add(process_id)
    if len(containers) != 16 or len(host_pids) != 16:
        raise E2EFailure("the 16 Phase 4 tasks did not use independent containers and PIDs")

    sessions = {record.get("session_id") for record in providers.values()}
    if None in sessions or len(sessions) != 16:
        raise E2EFailure("the 16 Phase 4 tasks did not use independent ACP sessions")
    attempts = sum(int(record.get("prompt_attempts", 0)) for record in providers.values())
    if not 16 <= attempts <= 32:
        raise E2EFailure(f"unexpected ACP prompt attempt count: {attempts}")
    for task_id in providers:
        if not (run_root / "provider" / "sessions" / task_id / "state.db").is_file():
            raise E2EFailure(f"task {task_id} has no isolated ACP session database")

    _assert_true_overlap(
        [record for name, record in handoffs.items() if name.startswith("phase4-assessment-")],
        "assessment fan-out",
    )
    _assert_true_overlap(
        [record for name, record in handoffs.items() if name.startswith("phase4-review-")],
        "cross-review fan-out",
    )
    verifier_by_risk: dict[str, list[dict[str, Any]]] = {"readonly": [], "mutation": []}
    for name, record in handoffs.items():
        if not name.startswith("phase4-verifier-"):
            continue
        task = record.get("task")
        payload = task.get("payload") if isinstance(task, dict) else None
        actions = payload.get("actions") if isinstance(payload, dict) else None
        if not isinstance(actions, list) or not actions:
            raise E2EFailure("verifier handoff does not bind campaign actions")
        risks = {action.get("risk_group") for action in actions if isinstance(action, dict)}
        if len(risks) != 1 or next(iter(risks)) not in verifier_by_risk:
            raise E2EFailure("verifier handoff mixes or omits a risk group")
        verifier_by_risk[str(next(iter(risks)))].append(record)
    _assert_true_overlap(verifier_by_risk["readonly"], "read-only verifier fan-out")
    _assert_true_overlap(verifier_by_risk["mutation"], "mutation verifier fan-out")

    evidence_manifests = sorted((run_root / "evidence").glob("*/manifest.json"))
    analyses = sorted((run_root / "evidence").glob("*/analysis.json"))
    if len(evidence_manifests) != 15 or len(analyses) != 15:
        raise E2EFailure("accepted V3 run must contain exactly 15 evidence manifests/analyses")
    approval_bound = recon_bound = 0
    for path in evidence_manifests:
        binding = _json(path).get("binding")
        if not isinstance(binding, dict):
            raise E2EFailure("evidence manifest has no complete binding")
        values = (
            binding.get("approval_bundle_id"),
            binding.get("approval_bundle_digest"),
            binding.get("approval_consumption_digest"),
        )
        if all(value is None for value in values):
            if binding.get("task_id") != "phase4-recon":
                raise E2EFailure("only Recon evidence may be unbound from approval")
            recon_bound += 1
        elif all(isinstance(value, str) and value for value in values):
            approval_bound += 1
        else:
            raise E2EFailure("evidence has a partial approval binding")
    if recon_bound != 1 or approval_bound != 14:
        raise E2EFailure("evidence bindings are not exactly one Recon plus 14 approved actions")

    consumptions = sorted((run_root / "approvals_v3" / "consumptions").glob("*.json"))
    if len(consumptions) != 14:
        raise E2EFailure(f"expected 14 approval consumptions, found {len(consumptions)}")
    for name in ("readonly.json", "mutation.json"):
        approval = _json(run_root / "approvals_v3" / name)
        if approval.get("verdict") != "approved" or not approval.get("signature_b64"):
            raise E2EFailure(f"{name} is not an immutable signed approval")

    finding_set = _json(run_root / "report" / "finding-set-v3.json")
    findings = finding_set.get("findings")
    if not isinstance(findings, list) or len(findings) != 4:
        raise E2EFailure("accepted full fixture must promote exactly four findings")
    coverage = _json(run_root / "report" / "coverage-v3.json")
    if coverage.get("completion") != "completed" or coverage.get("gaps"):
        raise E2EFailure("full fixture coverage is not gap-free and completed")
    cleanup = _json(run_root / "verification_v3" / "cleanup.json")
    if cleanup.get("state_restored") is not True:
        raise E2EFailure("mutation fixture state was not restored")
    for relative in (
        "reviews/signed-v3.json",
        "report/reporter-launch-v3.json",
        "report/reporter-ack-v3.json",
        "report/report-v3.md",
        "report/findings-v3.json",
        "report/report-write-receipt-v3.json",
    ):
        if not (run_root / relative).is_file():
            raise E2EFailure(f"formal report chain is missing {relative}")

    requests = fixture_stats.get("requests")
    if not isinstance(requests, dict):
        raise E2EFailure("fixture did not return request statistics")
    relevant = {key: value for key, value in requests.items() if key != "/fixture/stats"}
    if relevant != EXPECTED_FIXTURE_REQUESTS or sum(relevant.values()) != 15:
        raise E2EFailure(f"unexpected fixture request ledger: {relevant}")
    if fixture_stats.get("state_hash") != initial_state_hash:
        raise E2EFailure("fixture state hash changed after compensation")
    if not isinstance(fixture_stats.get("max_active"), int) or fixture_stats["max_active"] < 2:
        raise E2EFailure("fixture did not observe overlapping verifier requests")

    return {
        "agent_tasks": 16,
        "containers": len(containers),
        "host_processes": len(host_pids),
        "acp_sessions": len(sessions),
        "prompt_attempts": attempts,
        "evidence_artifacts": len(evidence_manifests),
        "approval_consumptions": len(consumptions),
        "findings": len(findings),
        "network_requests": sum(relevant.values()),
        "fixture_max_active": fixture_stats["max_active"],
        "fixture_state_restored": True,
    }


def verify_scenario_run(
    run_root: Path,
    *,
    scenario: Scenario,
    fixture_stats: dict[str, Any],
    initial_state_hash: str,
) -> dict[str, Any]:
    """Verify each approved/rejected real-ACP scenario from persisted artifacts."""

    if scenario == "accepted-full":
        return verify_accepted_run(
            run_root,
            fixture_stats=fixture_stats,
            initial_state_hash=initial_state_hash,
        )

    expected = _SCENARIO_EXPECTATIONS[scenario]
    state = _json(run_root / "state.json")
    if state.get("version") != "3" or state.get("execution_state") != expected["state"]:
        raise E2EFailure(f"{scenario} did not reach the expected terminal state")
    if state.get("requests_used") != expected["requests"]:
        raise E2EFailure(f"{scenario} did not bind the expected request count")

    handoff_paths = sorted((run_root / "handoffs").glob("phase4-*.json"))
    provider_paths = sorted((run_root / "provider").glob("phase4-*.json"))
    task_count = int(expected["tasks"])
    if len(handoff_paths) != task_count or len(provider_paths) != task_count:
        raise E2EFailure(f"{scenario} did not use the expected number of real role tasks")
    handoffs = [_json(path) for path in handoff_paths]
    containers: set[str] = set()
    host_pids: set[int] = set()
    for record in handoffs:
        result = record.get("result")
        handoff = result.get("handoff") if isinstance(result, dict) else None
        container_id = handoff.get("container_id") if isinstance(handoff, dict) else None
        process_id = result.get("host_process_id") if isinstance(result, dict) else None
        if not isinstance(container_id, str) or not container_id:
            raise E2EFailure(f"{scenario} used a non-container role task")
        if not isinstance(process_id, int) or process_id < 1:
            raise E2EFailure(f"{scenario} role task has no host process ID")
        containers.add(container_id)
        host_pids.add(process_id)
    if len(containers) != task_count or len(host_pids) != task_count:
        raise E2EFailure(f"{scenario} reused a role container or host process")

    providers = [_json(path) for path in provider_paths]
    sessions = {record.get("session_id") for record in providers}
    attempts = sum(int(record.get("prompt_attempts", 0)) for record in providers)
    if (
        None in sessions
        or len(sessions) != task_count
        or not task_count <= attempts <= task_count * 2
    ):
        raise E2EFailure(f"{scenario} does not have isolated bounded ACP execution")

    evidence_manifests = sorted((run_root / "evidence").glob("*/manifest.json"))
    analyses = sorted((run_root / "evidence").glob("*/analysis.json"))
    consumptions = sorted((run_root / "approvals_v3" / "consumptions").glob("*.json"))
    if (
        len(evidence_manifests) != int(expected["evidence"])
        or len(analyses) != int(expected["evidence"])
        or len(consumptions) != int(expected["consumptions"])
    ):
        raise E2EFailure(f"{scenario} evidence or approval-consumption count is incorrect")
    requests = fixture_stats.get("requests")
    if not isinstance(requests, dict):
        raise E2EFailure("fixture did not return request statistics")
    relevant = {key: value for key, value in requests.items() if key != "/fixture/stats"}
    if sum(relevant.values()) != int(expected["requests"]):
        raise E2EFailure(f"{scenario} executed an unexpected number of fixture requests")
    if fixture_stats.get("state_hash") != initial_state_hash:
        raise E2EFailure(f"{scenario} left the fixture in a mutated state")

    formal_paths = (
        "reviews/signed-v3.json",
        "report/reporter-launch-v3.json",
        "report/reporter-ack-v3.json",
        "report/report-v3.md",
        "report/findings-v3.json",
        "report/report-write-receipt-v3.json",
    )
    if expected["report"] is True:
        finding_set = _json(run_root / "report" / "finding-set-v3.json")
        findings = finding_set.get("findings")
        coverage = _json(run_root / "report" / "coverage-v3.json")
        if (
            not isinstance(findings, list)
            or len(findings) != int(expected["findings"])
            or coverage.get("completion") != expected["coverage"]
            or any(not (run_root / relative).is_file() for relative in formal_paths)
        ):
            raise E2EFailure(f"{scenario} formal report chain is incomplete")
    elif any((run_root / relative).exists() for relative in formal_paths):
        raise E2EFailure(f"{scenario} created a formal report after rejection")

    return {
        "agent_tasks": task_count,
        "containers": len(containers),
        "host_processes": len(host_pids),
        "acp_sessions": len(sessions),
        "prompt_attempts": attempts,
        "evidence_artifacts": len(evidence_manifests),
        "approval_consumptions": len(consumptions),
        "findings": int(expected["findings"]),
        "network_requests": sum(relevant.values()),
        "fixture_state_restored": True,
    }


class Driver:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.e2e_id = f"phase4-{uuid.uuid4().hex[:12]}"
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
        self.temp = tempfile.TemporaryDirectory(prefix="hermes-phase4-secrets-")
        self.private_root = Path(self.temp.name)
        self.env = dict(os.environ)
        source = str(PROJECT_ROOT / "src")
        current = self.env.get("PYTHONPATH")
        self.env["PYTHONPATH"] = source if not current else f"{source}{os.pathsep}{current}"

    def command(
        self,
        argv: list[str],
        *,
        expected: set[int] = {0},
        timeout: int = 1200,
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
        (self.logs / f"{self.sequence:03d}.json").write_text(
            json.dumps(
                {
                    "argv": argv,
                    "returncode": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                },
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        if result.returncode not in expected:
            raise E2EFailure(
                f"command {argv[0]!r} returned {result.returncode}; see log {self.sequence:03d}"
            )
        return result

    def cli(self, arguments: list[str], *, expected: set[int]) -> dict[str, Any]:
        result = self.command(
            [sys.executable, "-m", "hermes", "--json", *arguments],
            expected=expected,
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
        return path, {
            "key_id": key_id,
            "public_key": encode_base64(public_key_bytes(key)),
            "usages": [usage],
            "status": "active",
            "valid_from": (now - timedelta(minutes=5)).isoformat(),
            "valid_until": (now + timedelta(days=1)).isoformat(),
            "revoked_at": None,
        }

    def prepare(self) -> tuple[Path, int, Path, Path, Path, str]:
        role_tag = f"hermes-role-runtime:{self.e2e_id}"
        lab_tag = f"hermes-phase4-lab:{self.e2e_id}"
        self.command(
            [
                sys.executable,
                "scripts/build_role_image_v3.py",
                "build",
                "--base-image",
                self.args.base_image,
                "--tag",
                role_tag,
            ]
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
                str(PROJECT_ROOT / "tests" / "e2e_lab_v3"),
            ]
        )
        publisher_key, publisher = self.generate_key("role_manifest", "publisher-v3-e2e")
        approver_key, approver = self.generate_key("approval", "approver-v3-e2e")
        reviewer_key, reviewer = self.generate_key("human_review", "reviewer-v3-e2e")
        for name, record in {
            "publisher-trust.json": publisher,
            "approval-trust.json": approver,
            "review-trust.json": reviewer,
        }.items():
            (self.root / name).write_text(
                json.dumps({"version": "2", "keys": [record]}, indent=2) + "\n",
                encoding="utf-8",
            )

        v2_manifests = self.root / "role-manifests-v2.json"
        v3_manifests = self.root / "role-manifests-v3.json"
        for script, output in (
            ("scripts/build_role_image.py", v2_manifests),
            ("scripts/build_role_image_v3.py", v3_manifests),
        ):
            self.command(
                [
                    sys.executable,
                    script,
                    "manifest",
                    "--image",
                    role_image,
                    "--key-id",
                    "publisher-v3-e2e",
                    "--private-key",
                    str(publisher_key),
                    "--output",
                    str(output),
                ]
            )

        vault = self.private_root / "identity-vault.json"
        vault.write_text(
            json.dumps(
                {
                    "version": "1",
                    "identities": {
                        "member": "phase4-member-token",
                        "fixture-admin": "phase4-fixture-admin-token",
                    },
                }
            ),
            encoding="utf-8",
        )
        vault.chmod(0o600)
        scenario = cast(Scenario, self.args.scenario)
        enabled_features = "web,infra" if scenario == "web-infra" else "web,api,authz,infra"
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
                "--env",
                f"HERMES_PHASE4_FEATURES={enabled_features}",
                lab_tag,
            ]
        ).stdout.strip()
        binding = self.command(["docker", "port", self.lab_container, "8080/tcp"]).stdout.strip()
        port = int(binding.rsplit(":", 1)[1])
        self.wait_for_fixture(port)
        initial_state_hash = str(self.fixture_json(port, "/fixture/stats")["state_hash"])

        scope = self.root / "scope.yaml"
        scope.write_text(
            "\n".join(
                [
                    "profile: local-lab",
                    "automation_allowed: true",
                    "dry_run: false",
                    "rate_limit_rps: 50",
                    "max_requests: 15",
                    "max_duration_seconds: 1800",
                    "max_concurrency: 4",
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
                    "role_manifests": str(v2_manifests),
                    "role_manifests_v3": str(v3_manifests),
                    "role_trust_store": str(self.root / "publisher-trust.json"),
                    "approval_trust_store": str(self.root / "approval-trust.json"),
                    "review_trust_store": str(self.root / "review-trust.json"),
                    "identity_vault": str(vault),
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
        return config, port, scope, approver_key, reviewer_key, initial_state_hash

    def wait_for_fixture(self, port: int) -> None:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            try:
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/fixture/stats", timeout=1
                ) as response:
                    if response.status == 200:
                        return
            except OSError:
                time.sleep(0.2)
        raise E2EFailure("Phase 4 fixture did not become healthy within 20 seconds")

    def fixture_json(self, port: int, path: str) -> dict[str, Any]:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=3) as response:
            value = json.loads(response.read())
        if not isinstance(value, dict):
            raise E2EFailure("fixture response was not a JSON object")
        return value

    def execute(self) -> dict[str, Any]:
        scenario = cast(Scenario, self.args.scenario)
        expected = _SCENARIO_EXPECTATIONS[scenario]
        config, port, scope, approver_key, reviewer_key, initial_hash = self.prepare()
        target = f"http://localhost:{port}/candidate"
        self.command(
            [
                sys.executable,
                "-m",
                "hermes",
                "validate-config",
                "--schema-version",
                "3",
                "--config",
                str(config),
                "--scope",
                str(scope),
            ]
        )
        self.command(
            [
                sys.executable,
                "-m",
                "hermes",
                "doctor",
                "--schema-version",
                "3",
                "--config",
                str(config),
            ]
        )
        state = self.cli(
            [
                "run",
                "--schema-version",
                "3",
                "--config",
                str(config),
                "--scope",
                str(scope),
                "--target",
                target,
            ],
            expected={20},
        )
        run_id = str(state["run_id"])
        self.run_ids.append(run_id)

        decisions = _SCENARIO_DECISIONS[scenario]
        for index, (risk_group, decision) in enumerate(decisions):
            challenge = _json(self.runs / run_id / "approvals_v3" / f"challenge-{risk_group}.json")
            self.cli(
                [
                    decision,
                    "--config",
                    str(config),
                    "--run-id",
                    run_id,
                    "--challenge-id",
                    str(challenge["challenge_id"]),
                    "--risk-group",
                    risk_group,
                    "--key",
                    str(approver_key),
                    "--reason",
                    f"{decision.title()} exact Phase 4 {risk_group} local-lab action graph.",
                ],
                expected={20},
            )
            is_last = index == len(decisions) - 1
            resume_exit = 22 if is_last and scenario == "all-rejected" else 21 if is_last else 20
            state = self.cli(
                ["resume", "--config", str(config), "--run-id", run_id],
                expected={resume_exit},
            )

        if scenario == "all-rejected":
            if state.get("execution_state") != "rejected":
                raise E2EFailure("two rejected approval batches did not terminate the V3 run")
        else:
            if state.get("execution_state") != "awaiting_review":
                raise E2EFailure("V3 verification did not pause for signed review")
            review_verdict = (
                "accepted" if expected["coverage"] == "completed" else "accepted_with_gaps"
            )
            self.cli(
                [
                    "review",
                    "sign",
                    "--config",
                    str(config),
                    "--run-id",
                    run_id,
                    "--outcome-id",
                    "phase4-outcomes",
                    "--verdict",
                    review_verdict,
                    "--key",
                    str(reviewer_key),
                    "--rationale",
                    "Independent review accepts the exact local Phase 4 coverage boundary.",
                ],
                expected={21},
            )
            completed = self.cli(
                ["resume", "--config", str(config), "--run-id", run_id], expected={0}
            )
            if completed.get("execution_state") != expected["state"]:
                raise E2EFailure(
                    "final reporter resume did not reach the expected V3 terminal state"
                )
        stats = self.fixture_json(port, "/fixture/stats")
        verified = verify_scenario_run(
            self.runs / run_id,
            scenario=scenario,
            fixture_stats=stats,
            initial_state_hash=initial_hash,
        )
        self.assert_no_role_containers(run_id)
        summary = {
            "e2e_id": self.e2e_id,
            "scenario": scenario,
            "run_id": run_id,
            "verification": verified,
            "artifact_root": str(self.root),
        }
        if scenario == "accepted-full":
            summary["accepted_run_id"] = run_id
            summary["accepted_verification"] = verified
        return summary

    def assert_no_role_containers(self, run_id: str) -> None:
        remaining = self.command(
            ["docker", "ps", "--quiet", "--filter", f"label=com.hermes.run_id={run_id}"]
        ).stdout.split()
        if remaining:
            raise E2EFailure(f"Phase 4 left role containers running: {remaining}")

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
        ).stdout.split()
        if remaining:
            subprocess.run(
                ["docker", "rm", "--force", *remaining],
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
    result.add_argument(
        "--scenario",
        choices=tuple(_SCENARIO_DECISIONS),
        default="accepted-full",
        help="Execute one bounded real-ACP Phase 4 approval scenario.",
    )
    result.add_argument("--base-image", default=DEFAULT_BASE)
    result.add_argument(
        "--artifact-root", type=Path, default=PROJECT_ROOT / "artifacts" / "phase4-e2e"
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
    except (E2EFailure, subprocess.TimeoutExpired, OSError, ValueError) as exc:
        print(f"phase4-e2e: {exc}", file=sys.stderr)
        return 1
    finally:
        driver.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())

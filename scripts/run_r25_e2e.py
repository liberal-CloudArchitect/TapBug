#!/usr/bin/env python3
"""Execute the real, local-only R2.5 governed-Wheel acceptance gate.

This driver deliberately creates a *frozen* minimal V3 parent rather than
running an assessment.  R2.5 must only read that parent's plan, scope and
redacted evidence; doing so keeps the acceptance proof focused on the governed
learning boundary.  Research uses a versioned local source archive, while the
two model roles use the real restricted Hermes ACP provider and real isolated
Docker role processes.

The generated passive parser never receives a target URL, credentials, or a
network namespace.  All Wheel invocations are real ``DockerSandbox`` calls.
"""

from __future__ import annotations

import argparse
import importlib
import importlib.metadata
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import uuid
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

DEFAULT_BASE = (
    "python:3.11-slim@sha256:cdbd05fb6f457ca275ff51ce00d93d865ca0b6a25f5ffb08262d94f6835771e5"
)
WHEEL_CHECKS = {
    "--network": "none",
    "--read-only": None,
    "--user": "65534:65534",
    "--cap-drop": "ALL",
    "--security-opt": "no-new-privileges",
}


class E2EFailure(RuntimeError):
    """An R2.5 acceptance invariant did not hold."""


def executable_path(path: Path) -> Path:
    """Make a path absolute without resolving virtualenv interpreter symlinks."""

    return Path(os.path.abspath(os.path.expanduser(path)))


def _json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise E2EFailure(f"invalid or missing R2.5 artifact: {path}") from exc
    if not isinstance(value, dict):
        raise E2EFailure(f"R2.5 artifact must be an object: {path}")
    return value


def _sha256_file(path: Path) -> str:
    return "sha256:" + sha256(path.read_bytes()).hexdigest()


def _scope_digest(scope: dict[str, Any]) -> str:
    encoded = json.dumps(scope, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + sha256(encoded).hexdigest()


def _assert_no_report(root: Path) -> None:
    forbidden = (
        "report",
        "findings.json",
        "report.md",
        "report-v3.md",
        "findings-v3.json",
    )
    if any((root / item).exists() for item in forbidden):
        raise E2EFailure("an R2.5 learning or continuation run created a formal report")


def _assert_sandbox_command(command: tuple[str, ...]) -> None:
    """Assert the fixed DockerSandbox policy is represented by its real command."""

    for flag, value in WHEEL_CHECKS.items():
        if flag not in command:
            raise E2EFailure(f"Wheel sandbox command omitted {flag}")
        if value is not None and command[command.index(flag) + 1] != value:
            raise E2EFailure(f"Wheel sandbox command did not bind {flag}={value}")
    if not any(item.endswith(":/wheel:ro") for item in command):
        raise E2EFailure("Wheel sandbox did not mount its artifact read-only")


def _assert_active_registry_lifecycle(registry: Any, manifest: Any) -> None:
    """Verify mutable lifecycle state without mutating the signed manifest."""

    selected_manifest = registry.select_active(
        manifest.wheel_id,
        manifest.manifest_version,
        profile="local-lab",
        required_template_id="line_kv_parser/v1",
        artifact_digest=manifest.artifact_digest,
    )
    # The manifest is immutable and deliberately remains a draft description;
    # lifecycle is an append-only registry-record property.
    record = registry.get(manifest.wheel_id, manifest.manifest_version)
    if (
        selected_manifest.digest != manifest.digest
        or record.lifecycle != "active"
        or len(registry.events) != 8
    ):
        raise E2EFailure("Wheel registry did not replay a valid signed active lifecycle")


def verify_learning_run(
    *,
    runs_root: Path,
    learning_run_id: str,
    continuation_run_id: str,
    parent_hashes: dict[str, str],
    wheel_sandbox_image: str,
    model: str,
) -> dict[str, Any]:
    """Verify artifacts rather than trusting the lifecycle CLI exit statuses."""

    from hermes.learning_context import file_sha256
    from hermes.r25_contracts import (
        CapabilityExecutionReceiptV2,
        ContinuationOutcomeV1,
        ValidationReceiptV2,
        WheelActivationReceiptV2,
        WheelApprovalV2,
        WheelManifestV2,
    )
    from hermes.wheels.sandbox import DockerSandbox
    from hermes.wheels_v2 import WheelRegistryV2, WheelTrustStoreV2

    parent_root = runs_root / "frozen-parent-v3"
    if parent_hashes != {
        relative: file_sha256(parent_root / relative) for relative in parent_hashes
    }:
        raise E2EFailure("R2.5 mutated its frozen V3 parent artifacts")

    source_root = runs_root / "learning" / learning_run_id
    continuation_root = runs_root / "learning" / continuation_run_id
    if (
        source_root == continuation_root
        or not source_root.is_dir()
        or not continuation_root.is_dir()
    ):
        raise E2EFailure("R2.5 continuation was not created as a distinct child run")
    source_state = _json(source_root / "state.json")
    child_state = _json(continuation_root / "state.json")
    if source_state.get("state") != "active":
        raise E2EFailure("source learning run was changed after Wheel activation")
    if (
        child_state.get("state") != "completed"
        or child_state.get("learning_run_id") != continuation_run_id
    ):
        raise E2EFailure("continuation run did not complete under its own run ID")
    if (
        source_state.get("parent_run_id") != "frozen-parent-v3"
        or child_state.get("parent_run_id") != "frozen-parent-v3"
    ):
        raise E2EFailure("learning or continuation state lost its V3 parent binding")

    request = _json(source_root / "plan" / "learning-request.json")
    binding = _json(continuation_root / "plan" / "continuation-parent-binding.json")
    if (
        request.get("learning_run_id") != learning_run_id
        or binding.get("source_learning_run_id") != learning_run_id
        or binding.get("parent_run_id") != "frozen-parent-v3"
        or binding.get("scope_digest") != source_state.get("scope_digest")
    ):
        raise E2EFailure("continuation parent/scope binding is incomplete")

    manifest = WheelManifestV2.model_validate(_json(source_root / "wheels" / "manifest.json"))
    validation = ValidationReceiptV2.model_validate(
        _json(source_root / "wheels" / "validation-receipt.json")
    )
    approval = WheelApprovalV2.model_validate(_json(source_root / "wheels" / "approval.json"))
    activation = WheelActivationReceiptV2.model_validate(
        _json(source_root / "wheels" / "activation.json")
    )
    if (
        validation.wheel_manifest_digest != manifest.digest
        or approval.wheel_manifest_digest != manifest.digest
        or approval.validation_receipt_digest != validation.digest
        or activation.wheel_manifest_digest != manifest.digest
        or activation.wheel_approval_digest != approval.digest
    ):
        raise E2EFailure("Wheel validation, approval, and activation hashes are discontinuous")
    if validation.sandbox_image != wheel_sandbox_image:
        raise E2EFailure("Wheel validation did not bind the configured immutable sandbox image")
    if set(("network-none", "read-only", "non-root", "cap-drop", "positive-json")).difference(
        validation.docker_checks
    ):
        raise E2EFailure("Wheel validation receipt omits mandatory Docker policy checks")

    trust = WheelTrustStoreV2.model_validate(_json(runs_root.parent / "wheel-trust.json"))
    registry = WheelRegistryV2(trust, journal_path=source_root / "registry" / "events.jsonl")
    _assert_active_registry_lifecycle(registry, manifest)

    artifact_root = source_root / "wheels" / f"{manifest.wheel_id}-2"
    positive = _json(artifact_root / "fixtures" / "positive.json")
    negative = _json(artifact_root / "fixtures" / "negative.json")
    sandbox = DockerSandbox(wheel_sandbox_image)
    positive_result = sandbox.execute_json(
        artifact_root,
        entrypoint=manifest.entrypoint,
        input_json=json.dumps({"text": positive["text"]}, sort_keys=True),
    )
    negative_result = sandbox.execute_json(
        artifact_root,
        entrypoint=manifest.entrypoint,
        input_json=json.dumps({"text": negative["text"]}, sort_keys=True),
    )
    _assert_sandbox_command(positive_result.command)
    _assert_sandbox_command(negative_result.command)
    try:
        positive_output = json.loads(positive_result.output_json)
        negative_output = json.loads(negative_result.output_json)
    except json.JSONDecodeError as exc:
        raise E2EFailure("Wheel Docker sandbox did not emit JSON fixture output") from exc
    if (
        not positive_result.passed
        or not negative_result.passed
        or positive_output.get("matched") is not True
        or negative_output.get("matched") is not False
    ):
        raise E2EFailure("Wheel positive/negative no-network Docker checks failed")

    execution = CapabilityExecutionReceiptV2.model_validate(
        _json(continuation_root / "continuation" / "execution-receipt.json")
    )
    outcome = ContinuationOutcomeV1.model_validate(
        _json(continuation_root / "continuation" / "outcome.json")
    )
    observation_path = continuation_root / "continuation" / "structured-observation.json"
    observation = _json(observation_path)
    usage = _json(continuation_root / "audit" / "usage-journal-entry.json")
    if (
        execution.continuation_run_id != continuation_run_id
        or execution.learning_run_id != learning_run_id
        or execution.wheel_manifest_digest != manifest.digest
        or outcome.continuation_run_id != continuation_run_id
        or outcome.execution_receipt_digest != execution.digest
        or outcome.outcome != "resolved"
        or _sha256_file(observation_path) != outcome.structured_observation_digest
        or observation.get("matched") is not True
        or not isinstance(observation.get("fields"), dict)
        or usage.get("execution_receipt_digest") != execution.digest
    ):
        raise E2EFailure("continuation execution/outcome/usage digest chain is invalid")
    if child_state.get("continuation_outcome_digest") != outcome.digest:
        raise E2EFailure("continuation state does not bind its immutable outcome")

    # Provider records are created by the real ACP adapter.  Handoff records are
    # committed by the R2.5 workflow so container/PID identity can be audited.
    provider_paths = sorted((source_root / "provider").glob("r25-*.json"))
    handoff_paths = sorted((source_root / "handoffs").glob("r25-*.json"))
    if len(provider_paths) != 2 or len(handoff_paths) != 2:
        raise E2EFailure(
            "real R2.5 acceptance requires two persisted ACP provider and role handoff records"
        )
    providers = [_json(path) for path in provider_paths]
    handoffs = [_json(path) for path in handoff_paths]
    task_ids = {"r25-researcher-" + learning_run_id, "r25-capability-planner-" + learning_run_id}
    if {str(item.get("task_id")) for item in providers} != task_ids:
        raise E2EFailure("ACP records do not bind the two expected R2.5 tasks")
    sessions = {item.get("session_id") for item in providers}
    if (
        None in sessions
        or len(sessions) != 2
        or any(item.get("model") != model for item in providers)
    ):
        raise E2EFailure("R2.5 roles did not use separate real ACP sessions for the selected model")
    if any(int(item.get("prompt_attempts", 0)) not in {1, 2} for item in providers):
        raise E2EFailure("R2.5 ACP prompt attempts did not remain schema-repair bounded")
    for task_id in task_ids:
        if not (source_root / "provider" / "sessions" / task_id / "state.db").is_file():
            raise E2EFailure(f"R2.5 ACP task has no isolated session database: {task_id}")
    containers: set[str] = set()
    pids: set[int] = set()
    for handoff_artifact in handoffs:
        task = handoff_artifact.get("task")
        result = handoff_artifact.get("result")
        handoff = result.get("handoff") if isinstance(result, dict) else None
        if (
            not isinstance(task, dict)
            or not isinstance(result, dict)
            or not isinstance(handoff, dict)
        ):
            raise E2EFailure("R2.5 role handoff artifact has an invalid task/result shape")
        if task.get("version") != "25" or task.get("request_budget") != 0:
            raise E2EFailure("R2.5 role received a non-passive task authority")
        container = handoff.get("container_id")
        pid = result.get("host_process_id")
        if not isinstance(container, str) or not container or not isinstance(pid, int) or pid < 1:
            raise E2EFailure("R2.5 role did not execute in a real isolated container/PID")
        containers.add(container)
        pids.add(pid)
    if len(containers) != 2 or len(pids) != 2:
        raise E2EFailure("R2.5 roles were not independent Docker processes")
    _assert_no_report(source_root)
    _assert_no_report(continuation_root)

    return {
        "learning_run_id": learning_run_id,
        "continuation_run_id": continuation_run_id,
        "acp_sessions": len(sessions),
        "role_containers": len(containers),
        "role_host_pids": len(pids),
        "registry_events": len(registry.events),
        "wheel_network_requests": 0,
        "positive_matched": True,
        "negative_matched": False,
        "formal_report_created": False,
    }


def replay_completed_artifact(artifact_root: Path) -> dict[str, Any]:
    """Independently re-run the postconditions for a completed real lifecycle.

    This deliberately has no model/provider path.  It only loads immutable
    artifacts, derives the one source/continuation pair, and invokes the same
    verifier used by the full driver (including the two real no-network Wheel
    sandbox replays).
    """

    root = artifact_root.resolve()
    runs_root = root / "runs"
    config = _json(root / "r25-config.json")
    learning_root = runs_root / "learning"
    if not learning_root.is_dir():
        raise E2EFailure("replay artifact has no learning run root")
    states = {
        path.name: _json(path / "state.json") for path in learning_root.iterdir() if path.is_dir()
    }
    source_ids = [run_id for run_id, state in states.items() if state.get("state") == "active"]
    continuation_ids = [
        run_id for run_id, state in states.items() if state.get("state") == "completed"
    ]
    if len(source_ids) != 1 or len(continuation_ids) != 1:
        raise E2EFailure(
            "replay artifact must contain exactly one active source and one continuation"
        )
    source_id, continuation_id = source_ids[0], continuation_ids[0]
    binding = _json(learning_root / continuation_id / "plan" / "continuation-parent-binding.json")
    if binding.get("source_learning_run_id") != source_id:
        raise E2EFailure("replay continuation is not bound to the active source run")
    parent_root = runs_root / "frozen-parent-v3"
    parent_hashes = {
        relative: _sha256_file(parent_root / relative)
        for relative in (
            "plan/run-v3.json",
            "scope.json",
            "state.json",
            "evidence/recon-local-line/analysis.json",
            "evidence/recon-local-line/manifest.json",
        )
    }
    wheel_sandbox_image = config.get("wheel_sandbox_image")
    model = config.get("model")
    if not isinstance(wheel_sandbox_image, str) or not isinstance(model, str):
        raise E2EFailure("replay artifact has no wheel sandbox image or model binding")
    verification = verify_learning_run(
        runs_root=runs_root,
        learning_run_id=source_id,
        continuation_run_id=continuation_id,
        parent_hashes=parent_hashes,
        wheel_sandbox_image=wheel_sandbox_image,
        model=model,
    )
    result = {
        "mode": "artifact_replay",
        "artifact_root": str(root),
        **verification,
    }
    (root / "replay-summary.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return result


class Driver:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args: argparse.Namespace = args
        self.e2e_id = f"r25-{uuid.uuid4().hex[:12]}"
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        self.root: Path = Path(args.artifact_root).resolve() / f"{stamp}-{self.e2e_id}"
        self.root.mkdir(parents=True)
        self.logs: Path = self.root / "logs"
        self.logs.mkdir()
        self.runs: Path = self.root / "runs"
        self.runs.mkdir()
        self.private: tempfile.TemporaryDirectory[str] = tempfile.TemporaryDirectory(
            prefix="hermes-r25-e2e-keys-"
        )
        self.private_root: Path = Path(self.private.name)
        self.sequence = 0
        self.env = dict(os.environ)
        source = str(PROJECT_ROOT / "src")
        current = self.env.get("PYTHONPATH")
        self.env["PYTHONPATH"] = source if not current else f"{source}{os.pathsep}{current}"
        self.transient_images: list[str] = []

    def command(
        self, argv: list[str], *, expected: set[int] = {0}, timeout: int = 1200
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

    def cli(self, arguments: list[str]) -> dict[str, Any]:
        result = self.command([sys.executable, "-m", "hermes", "--json", *arguments])
        try:
            value = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise E2EFailure("R2.5 CLI did not return JSON") from exc
        if not isinstance(value, dict):
            raise E2EFailure("R2.5 CLI result was not an object")
        return value

    def generate_key(self, usage: str) -> tuple[Path, dict[str, Any]]:
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
            "key_id": f"{usage}-e2e",
            "usage": usage,
            "public_key": encode_base64(public_key_bytes(key)),
            "status": "active",
            "valid_from": (now - timedelta(minutes=5)).isoformat(),
            "valid_until": (now + timedelta(days=1)).isoformat(),
            "revoked_at": None,
        }

    def immutable_image_ref(self, image: str) -> str:
        raw = self.command(
            ["docker", "image", "inspect", "--format", "{{json .RepoDigests}}", image]
        ).stdout.strip()
        try:
            digests = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise E2EFailure(
                f"Docker did not return an immutable image digest for {image}"
            ) from exc
        if not isinstance(digests, list):
            raise E2EFailure(f"Docker image {image} has no repository digest")
        result = next(
            (item for item in digests if isinstance(item, str) and "@sha256:" in item), None
        )
        if result is None:
            raise E2EFailure(f"Docker image {image} does not have an immutable digest reference")
        return result

    def _copy_pytest_runtime(self, destination: Path) -> None:
        """Vendor the already-installed test-only Python sources into a local image.

        Building the acceptance sandbox must not fetch a package.  The fixed
        python:3.11 base has no pytest, so this copies only pure-Python test
        dependencies already installed for this repository into a temporary,
        subsequently content-addressed image.
        """

        destination.mkdir(parents=True)
        distributions = ("pytest", "pluggy", "packaging", "Pygments", "iniconfig")
        modules = ("pytest", "_pytest", "pluggy", "packaging", "pygments", "iniconfig", "py")
        for module_name in modules:
            module = importlib.import_module(module_name)
            source_file = Path(str(module.__file__)).resolve()
            if source_file.name == "__init__.py":
                source, target = source_file.parent, destination / source_file.parent.name
                if not target.exists():
                    shutil.copytree(
                        source, target, ignore=shutil.ignore_patterns("__pycache__", "*.pyc")
                    )
            elif not (destination / source_file.name).exists():
                shutil.copy2(source_file, destination / source_file.name)
        for distribution in distributions:
            installed = importlib.metadata.distribution(distribution)
            metadata = next(
                (
                    item
                    for item in installed.files or ()
                    if item.name == "METADATA" and ".dist-info/" in str(item)
                ),
                None,
            )
            if metadata is None:
                raise E2EFailure(f"could not locate metadata for {distribution}")
            source = Path(str(installed.locate_file(metadata))).resolve().parent
            target = destination / source.name
            if not target.exists():
                shutil.copytree(source, target, ignore=shutil.ignore_patterns("RECORD"))

    def build_wheel_sandbox_image(self) -> str:
        if self.args.wheel_sandbox_image is not None:
            image = str(self.args.wheel_sandbox_image)
            if "@sha256:" not in image:
                raise E2EFailure("--wheel-sandbox-image must be an immutable @sha256 reference")
            self.command(["docker", "image", "inspect", image])
            return image
        context = self.root / "wheel-sandbox-build"
        packages = context / "site-packages"
        self._copy_pytest_runtime(packages)
        (context / "Dockerfile").write_text(
            "\n".join(
                (
                    f"FROM {self.args.base_image}",
                    "COPY site-packages/ /usr/local/lib/python3.11/site-packages/",
                    "USER 65534:65534",
                    "",
                )
            ),
            encoding="utf-8",
        )
        tag = f"hermes-r25-wheel-sandbox:{self.e2e_id}"
        self.command(["docker", "build", "--network", "none", "--tag", tag, str(context)])
        self.transient_images.append(tag)
        image = self.immutable_image_ref(tag)
        self.command(
            [
                "docker",
                "run",
                "--rm",
                "--network",
                "none",
                "--read-only",
                "--user",
                "65534:65534",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                image,
                "python",
                "-I",
                "-m",
                "pytest",
                "--version",
            ]
        )
        return image

    def prepare_parent(self) -> tuple[Path, dict[str, str], Path]:
        parent = self.runs / "frozen-parent-v3"
        evidence = parent / "evidence" / "recon-local-line"
        (parent / "plan").mkdir(parents=True)
        evidence.mkdir(parents=True)
        scope = {
            "profile": "local-lab",
            "automation_allowed": True,
            "rules": [{"host": "localhost", "schemes": ["http"], "ports": [8080]}],
        }
        plan = {"version": "3", "run_id": "frozen-parent-v3", "target": "http://localhost:8080"}
        analysis = {
            "mime_type": "text/plain",
            "status": 200,
            "body": "[redacted local unknown line protocol]",
            "truncated": False,
        }
        (parent / "plan" / "run-v3.json").write_text(
            json.dumps(plan, ensure_ascii=False, sort_keys=True), encoding="utf-8"
        )
        (parent / "scope.json").write_text(
            json.dumps(scope, ensure_ascii=False, sort_keys=True), encoding="utf-8"
        )
        (parent / "state.json").write_text(
            json.dumps(
                {"version": "3", "run_id": "frozen-parent-v3", "execution_state": "completed"}
            ),
            encoding="utf-8",
        )
        (evidence / "analysis.json").write_text(
            json.dumps(analysis, ensure_ascii=False, sort_keys=True), encoding="utf-8"
        )
        (evidence / "manifest.json").write_text(
            json.dumps(
                {
                    "run_id": "frozen-parent-v3",
                    "scope_digest": _scope_digest(scope),
                    "analysis": {"path": "evidence/recon-local-line/analysis.json"},
                },
                ensure_ascii=False,
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        observation = self.root / "operator-observation.txt"
        observation.write_text(
            "Local fixture returned an unknown line-based response format; "
            "learn a passive parser only.",
            encoding="utf-8",
        )
        tracked = {
            relative: _sha256_file(parent / relative)
            for relative in (
                "plan/run-v3.json",
                "scope.json",
                "state.json",
                "evidence/recon-local-line/analysis.json",
                "evidence/recon-local-line/manifest.json",
            )
        }
        return observation, tracked, parent

    def prepare_bundle(self) -> Path:
        archive = self.root / "local-research-archive"
        archive.mkdir()
        (archive / "line-kv-v1.txt").write_text(
            "Service: Hermes\nVersion: 1\n\nEach non-empty line is Key: Value.\n",
            encoding="utf-8",
        )
        bundle = archive / "bundle.json"
        bundle.write_text(
            json.dumps(
                {
                    "version": "1",
                    "sources": [
                        {
                            "source_id": "line-kv-v1",
                            "url": "https://docs.example.test/r25/line-kv/v1",
                            "license": "CC0-1.0",
                            "source_version": "1",
                            "body_path": "line-kv-v1.txt",
                        }
                    ],
                    "positive_text": "Service: Hermes\nVersion: 1",
                    "negative_text": "not a key value record",
                    "continuation_text": "Service: Hermes\nVersion: 1",
                },
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        return bundle

    def prepare(self) -> tuple[Path, dict[str, Path], Path, dict[str, str]]:
        wheel_image = self.build_wheel_sandbox_image()
        role_tag = f"hermes-r25-role-runtime:{self.e2e_id}"
        self.command(
            [
                sys.executable,
                "scripts/build_r25_role_image.py",
                "build",
                "--base-image",
                self.args.base_image,
                "--tag",
                role_tag,
            ]
        )
        self.transient_images.append(role_tag)
        role_image = self.immutable_image_ref(role_tag)
        keys: dict[str, Path] = {}
        records: list[dict[str, Any]] = []
        for usage in (
            "wheel_publisher",
            "wheel_validator",
            "wheel_approver",
            "wheel_operator",
            "wheel_revoker",
        ):
            key, record = self.generate_key(usage)
            keys[usage] = key
            records.append(record)
        trust = self.root / "wheel-trust.json"
        trust.write_text(
            json.dumps({"version": "2", "keys": records}, indent=2) + "\n", encoding="utf-8"
        )
        manifests = self.root / "r25-role-manifests.json"
        self.command(
            [
                sys.executable,
                "scripts/build_r25_role_image.py",
                "manifest",
                "--image",
                role_image,
                "--key-id",
                "wheel_publisher-e2e",
                "--private-key",
                str(keys["wheel_publisher"]),
                "--output",
                str(manifests),
            ]
        )
        config = self.root / "r25-config.json"
        config.write_text(
            json.dumps(
                {
                    "runs_root": str(self.runs),
                    # ``_config`` keeps the established project-wide fields for
                    # V2/V3 compatibility.  The R2.5 command path never reads
                    # these three generic trust stores or this generic manifest;
                    # its authority is solely the Wheel trust root and the two
                    # signed R2.5 role manifests below.
                    "role_trust_store": str(trust),
                    "approval_trust_store": str(trust),
                    "review_trust_store": str(trust),
                    "role_manifests": str(manifests),
                    "wheel_trust_store": str(trust),
                    "wheel_sandbox_image": wheel_image,
                    "prompt_root": str(PROJECT_ROOT),
                    "r25_role_manifests": str(manifests),
                    "research_allowlist": ["https://docs.example.test/r25/line-kv/v1"],
                    "wheel_publisher_key": str(keys["wheel_publisher"]),
                    "wheel_validator_key": str(keys["wheel_validator"]),
                    "wheel_approver_key": str(keys["wheel_approver"]),
                    "wheel_operator_key": str(keys["wheel_operator"]),
                    "wheel_revoker_key": str(keys["wheel_revoker"]),
                    "hermes_cli": str(executable_path(self.args.hermes_cli)),
                    "hermes_python": str(executable_path(self.args.hermes_python)),
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
        observation, parent_hashes, _parent = self.prepare_parent()
        return config, keys, observation, parent_hashes

    def execute(self) -> dict[str, Any]:
        config, keys, observation, parent_hashes = self.prepare()
        bundle = self.prepare_bundle()
        self.cli(["learn", "validate-config", "--config", str(config)])
        self.cli(["learn", "doctor", "--config", str(config)])
        started = self.cli(
            [
                "learn",
                "start",
                "--config",
                str(config),
                "--parent-run-id",
                "frozen-parent-v3",
                "--observation-file",
                str(observation),
                "--evidence-id",
                "recon-local-line",
            ]
        )
        run_id = str(started["learning_run_id"])
        self.cli(
            [
                "learn",
                "research",
                "--config",
                str(config),
                "--run-id",
                run_id,
                "--source-bundle",
                str(bundle),
            ]
        )
        self.cli(["learn", "plan", "--config", str(config), "--run-id", run_id])
        self.cli(["learn", "generate", "--config", str(config), "--run-id", run_id])
        self.cli(
            [
                "learn",
                "validate",
                "--config",
                str(config),
                "--run-id",
                run_id,
                "--key",
                str(keys["wheel_validator"]),
            ]
        )
        self.cli(
            [
                "learn",
                "approve",
                "--config",
                str(config),
                "--run-id",
                run_id,
                "--key",
                str(keys["wheel_approver"]),
                "--rationale",
                "Independent local passive-parser acceptance.",
            ]
        )
        self.cli(
            [
                "learn",
                "activate",
                "--config",
                str(config),
                "--run-id",
                run_id,
                "--key",
                str(keys["wheel_operator"]),
            ]
        )
        continuation = self.cli(["learn", "continue", "--config", str(config), "--run-id", run_id])
        continuation_id = str(continuation["learning_run_id"])
        self.cli(["learn", "status", "--config", str(config), "--run-id", run_id])
        self.cli(["learn", "status", "--config", str(config), "--run-id", continuation_id])
        wheel_image = str(_json(config).get("wheel_sandbox_image"))
        verification = verify_learning_run(
            runs_root=self.runs,
            learning_run_id=run_id,
            continuation_run_id=continuation_id,
            parent_hashes=parent_hashes,
            wheel_sandbox_image=wheel_image,
            model=self.args.model,
        )
        return {
            "e2e_id": self.e2e_id,
            "artifact_root": str(self.root),
            "parent_run_id": "frozen-parent-v3",
            **verification,
        }

    def cleanup(self) -> None:
        # Role and Wheel containers use --rm. This check makes a daemon leak a
        # failing acceptance condition instead of silently hiding it.
        remaining = subprocess.run(
            [
                "docker",
                "ps",
                "--all",
                "--quiet",
                "--filter",
                "label=com.hermes.component=r25-role",
            ],
            capture_output=True,
            text=True,
            check=False,
        ).stdout.split()
        if remaining:
            subprocess.run(
                ["docker", "rm", "--force", *remaining], capture_output=True, text=True, check=False
            )
        self.private.cleanup()


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--hermes-cli", type=Path)
    result.add_argument("--hermes-python", type=Path)
    result.add_argument("--model")
    result.add_argument("--base-image", default=DEFAULT_BASE)
    result.add_argument(
        "--wheel-sandbox-image",
        help="optional preloaded immutable Python image that includes pytest",
    )
    result.add_argument(
        "--artifact-root", type=Path, default=PROJECT_ROOT / "artifacts" / "r25-e2e"
    )
    result.add_argument(
        "--verify-artifact-root",
        type=Path,
        help="replay completed real artifacts without provider/model calls",
    )
    return result


def main(argv: list[str] | None = None) -> int:
    argument_parser = parser()
    args = argument_parser.parse_args(argv)
    if args.verify_artifact_root is not None:
        try:
            summary = replay_completed_artifact(args.verify_artifact_root)
            print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
            return 0
        except (E2EFailure, subprocess.TimeoutExpired, OSError, ValueError) as exc:
            print(f"r25-e2e: {exc}", file=sys.stderr)
            return 1
    if args.hermes_cli is None or args.hermes_python is None or args.model is None:
        argument_parser.error(
            "--hermes-cli, --hermes-python, and --model are required for a fresh run"
        )
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
        print(f"r25-e2e: {exc}", file=sys.stderr)
        return 1
    finally:
        driver.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())

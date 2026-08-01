"""Independent-process and deterministic fixture implementations of AgentRunner."""

from __future__ import annotations

import json
import os
import selectors
import signal
import subprocess
import time
from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any, Protocol, TypedDict, cast

from pydantic import ValidationError

from ...evidence import EvidenceArtifactRef
from ..errors import ApprovalDenied, PolicyDenied
from .contracts import (
    IPC_MESSAGE_ADAPTER,
    ApprovalState,
    EvidenceRef,
    FailureLayer,
    FinalHandoffMessage,
    GatewayActionRequest,
    HandoffEnvelope,
    HostIpcResponse,
    ModelRequest,
    RoleManifest,
    RoleManifestError,
    RoleTrustStore,
    TaskEnvelope,
    TaskResult,
    TransportState,
    canonical_json_hash,
)


class _FailureFields(TypedDict, total=False):
    failure_layer: FailureLayer
    failure_code: str
    retryable: bool
    exit_code: int | None
    request_id: str
    transport_state: TransportState
    approval_state: ApprovalState


def _digest_text(value: str) -> str:
    return f"sha256:{sha256(value.encode('utf-8')).hexdigest()}"


class AgentContractError(RuntimeError):
    """Raised when a role response fails the versioned handoff contract."""


class AgentRunner(ABC):
    """Invokes one role from a minimal task envelope."""

    @abstractmethod
    def run(self, task: TaskEnvelope) -> TaskResult:
        raise NotImplementedError


class SubprocessAgentRunner(AgentRunner):
    """Run roles as separate processes speaking JSON over standard streams.

    ``command_for_role`` must return an argv sequence, never a shell string.  The
    runner does not pass the parent environment to children by default, preventing
    accidental leakage of credentials or opt-in environment switches.
    """

    def __init__(
        self,
        command_for_role: Callable[[str], Sequence[str]],
        *,
        cwd: Path | None = None,
        environment: Mapping[str, str] | None = None,
    ) -> None:
        self._command_for_role = command_for_role
        self._cwd = cwd
        self._environment = dict(environment) if environment is not None else {}

    def run(self, task: TaskEnvelope) -> TaskResult:
        started = datetime.now(UTC)
        input_hash = task.input_hash()
        try:
            command = tuple(self._command_for_role(task.role))
            if not command or any(not isinstance(item, str) or not item for item in command):
                raise AgentContractError("role command must be a non-empty argv sequence")
            completed = subprocess.run(
                command,
                input=task.model_dump_json(),
                capture_output=True,
                text=True,
                cwd=self._cwd,
                env=self._environment,
                timeout=task.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            finished = datetime.now(UTC)
            stdout = _coerce_stream(exc.stdout)
            stderr = _coerce_stream(exc.stderr)
            return TaskResult(
                task=task,
                lifecycle="timed_out",
                input_sha256=input_hash,
                started_at=started,
                finished_at=finished,
                stdout_sha256=_digest_text(stdout) if stdout else None,
                stderr_sha256=_digest_text(stderr) if stderr else None,
                error=f"role exceeded {task.timeout_seconds}s timeout",
            )
        except (OSError, AgentContractError) as exc:
            finished = datetime.now(UTC)
            return TaskResult(
                task=task,
                lifecycle="failed",
                input_sha256=input_hash,
                started_at=started,
                finished_at=finished,
                error=str(exc),
            )

        finished = datetime.now(UTC)
        stdout_hash = _digest_text(completed.stdout) if completed.stdout else None
        stderr_hash = _digest_text(completed.stderr) if completed.stderr else None
        if completed.returncode != 0:
            return TaskResult(
                task=task,
                lifecycle="failed",
                input_sha256=input_hash,
                started_at=started,
                finished_at=finished,
                stdout_sha256=stdout_hash,
                stderr_sha256=stderr_hash,
                error=f"role exited with status {completed.returncode}",
            )
        try:
            # One document prevents a child from smuggling unaccounted output.
            payload = json.loads(completed.stdout)
            handoff = HandoffEnvelope.model_validate(payload)
            self._assert_handoff_matches_task(task, handoff)
        except (json.JSONDecodeError, ValidationError, AgentContractError) as exc:
            return TaskResult(
                task=task,
                lifecycle="invalid_handoff",
                input_sha256=input_hash,
                started_at=started,
                finished_at=finished,
                stdout_sha256=stdout_hash,
                stderr_sha256=stderr_hash,
                error=str(exc),
            )
        return TaskResult(
            task=task,
            handoff=handoff,
            lifecycle="completed" if handoff.status == "completed" else "failed",
            input_sha256=input_hash,
            output_sha256=canonical_json_hash(handoff.model_dump(mode="json")),
            started_at=started,
            finished_at=finished,
            stdout_sha256=stdout_hash,
            stderr_sha256=stderr_hash,
            error=handoff.error,
        )

    @staticmethod
    def _assert_handoff_matches_task(task: TaskEnvelope, handoff: HandoffEnvelope) -> None:
        expected = (task.run_id, task.task_id, task.role, task.scope_digest, task.input_hash())
        actual = (
            handoff.run_id,
            handoff.task_id,
            handoff.role,
            handoff.scope_digest,
            handoff.input_sha256,
        )
        if actual != expected:
            raise AgentContractError("handoff identity or input hash does not match task")


def _coerce_stream(value: str | bytes | None) -> str:
    if value is None:
        return ""
    return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value


FixtureHandler = Callable[[TaskEnvelope], HandoffEnvelope] | HandoffEnvelope


class FixtureAgentRunner(AgentRunner):
    """A deterministic in-process runner strictly for contract/workflow tests."""

    def __init__(self, fixtures: Mapping[str, FixtureHandler]) -> None:
        self._fixtures = dict(fixtures)

    def run(self, task: TaskEnvelope) -> TaskResult:
        started = datetime.now(UTC)
        input_hash = task.input_hash()
        fixture = self._fixtures.get(task.role)
        if fixture is None:
            finished = datetime.now(UTC)
            return TaskResult(
                task=task,
                lifecycle="failed",
                input_sha256=input_hash,
                started_at=started,
                finished_at=finished,
                error=f"no fixture for role {task.role!r}",
            )
        try:
            handoff = fixture(task) if callable(fixture) else fixture
            SubprocessAgentRunner._assert_handoff_matches_task(task, handoff)
        except (AgentContractError, ValidationError, ValueError) as exc:
            finished = datetime.now(UTC)
            return TaskResult(
                task=task,
                lifecycle="invalid_handoff",
                input_sha256=input_hash,
                started_at=started,
                finished_at=finished,
                error=str(exc),
            )
        finished = datetime.now(UTC)
        return TaskResult(
            task=task,
            handoff=handoff,
            lifecycle="completed" if handoff.status == "completed" else "failed",
            input_sha256=input_hash,
            output_sha256=canonical_json_hash(handoff.model_dump(mode="json")),
            started_at=started,
            finished_at=finished,
            error=handoff.error,
        )


GatewayHandler = Callable[[GatewayActionRequest, TaskEnvelope], Mapping[str, Any]]
ModelHandler = Callable[[ModelRequest, TaskEnvelope], Mapping[str, Any]]
EvidenceValidator = Callable[[EvidenceRef, TaskEnvelope], bool]
EvidenceArtifactValidator = Callable[[EvidenceArtifactRef, TaskEnvelope], bool]
PopenFactory = Callable[..., subprocess.Popen[bytes]]


class ManifestPromptRegistry(Protocol):
    def verify_manifest(self, manifest: RoleManifest) -> None: ...


class DockerRoleSandbox:
    """Build the only production role command: a tightly restricted Docker container.

    The role image contains its executable. No host paths, environment variables,
    sockets, credentials, or network namespace are made available to it; it can
    only communicate through stdin/stdout JSON Lines with :class:`RunnerHost`.
    """

    def __init__(
        self, *, docker_binary: str = "docker", labels: Mapping[str, str] | None = None
    ) -> None:
        self._docker_binary = docker_binary
        self._labels = dict(labels or {})
        if any(
            not key.startswith("com.hermes.") or not value or "\x00" in value
            for key, value in self._labels.items()
        ):
            raise ValueError("Docker role labels must use non-empty com.hermes.* values")

    def build_command(self, manifest: RoleManifest) -> tuple[str, ...]:
        limits = manifest.limits
        labels = tuple(
            part
            for key, value in sorted(self._labels.items())
            for part in ("--label", f"{key}={value}")
        )
        return (
            self._docker_binary,
            "run",
            "--rm",
            "--pull",
            "never",
            "--interactive",
            "--network",
            "none",
            "--read-only",
            "--user",
            "65532:65532",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges=true",
            "--pids-limit",
            str(limits.pids_limit),
            "--cpus",
            str(limits.cpu_count),
            "--memory",
            f"{limits.memory_mib}m",
            "--ulimit",
            f"nofile={limits.nofile_limit}:{limits.nofile_limit}",
            "--tmpfs",
            f"/tmp:rw,noexec,nosuid,size={limits.tmpfs_mib}m",
            "--env",
            "PATH=/usr/local/bin:/usr/bin:/bin",
            *labels,
            manifest.image,
            *manifest.command,
        )


class RunnerHost(AgentRunner):
    """Parent-owned JSONL protocol host for signed, isolated role containers.

    The Host never grants a child ambient egress: every proposed action is checked
    against both the signed manifest and the task before a caller-supplied gateway
    adapter can see it. The production command always comes from
    :class:`DockerRoleSandbox`; ``popen_factory`` exists solely to unit-test the
    protocol without a Docker daemon.
    """

    def __init__(
        self,
        *,
        manifests: Mapping[str, RoleManifest],
        trust_store: RoleTrustStore,
        sandbox: DockerRoleSandbox | None = None,
        gateway_handler: GatewayHandler | None = None,
        model_handler: ModelHandler | None = None,
        evidence_validator: EvidenceValidator | None = None,
        evidence_artifact_validator: EvidenceArtifactValidator | None = None,
        prompt_registry: ManifestPromptRegistry | None = None,
        popen_factory: PopenFactory = subprocess.Popen,
    ) -> None:
        self._manifests = dict(manifests)
        self._trust_store = trust_store
        self._sandbox = sandbox or DockerRoleSandbox()
        self._gateway_handler = gateway_handler
        self._model_handler = model_handler
        # Evidence cannot be asserted by a role. Callers must bind each ref to a
        # current-run, gateway-written artifact before the Host will accept it.
        self._evidence_validator = evidence_validator or (lambda _ref, _task: False)
        self._evidence_artifact_validator = evidence_artifact_validator or (
            lambda _ref, _task: False
        )
        self._popen_factory = popen_factory
        self._prompt_registry = prompt_registry
        if not self._manifests:
            raise ValueError("RunnerHost requires at least one signed role manifest")
        for role, manifest in self._manifests.items():
            if role != manifest.role:
                raise RoleManifestError("role manifest mapping keys must match manifest.role")
            self._trust_store.verify(manifest)
            if self._prompt_registry is not None:
                self._prompt_registry.verify_manifest(manifest)

    def run(self, task: TaskEnvelope) -> TaskResult:
        started = datetime.now(UTC)
        input_hash = task.input_hash()
        manifest = self._manifests.get(task.role)
        if manifest is None:
            return self._failed(
                task, input_hash, started, f"no trusted manifest for role {task.role!r}"
            )
        try:
            self._trust_store.verify(manifest)
            if self._prompt_registry is not None:
                self._prompt_registry.verify_manifest(manifest)
        except RoleManifestError as exc:
            return self._failed(task, input_hash, started, str(exc))
        timeout = min(task.timeout_seconds, manifest.limits.timeout_seconds)
        encoded_task = (
            json.dumps(
                {
                    "type": "task",
                    "task": task.model_dump(mode="json"),
                    "input_sha256": input_hash,
                },
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )

        try:
            process = self._popen_factory(
                self._sandbox.build_command(manifest),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=None,
                env={},
                start_new_session=True,
            )
        except (OSError, ValueError) as exc:
            return self._failed(
                task,
                input_hash,
                started,
                f"could not start isolated role: {exc}",
                failure_layer="docker",
                failure_code="docker_start_failed",
                retryable=True,
            )
        if process.stdin is None or process.stdout is None or process.stderr is None:
            self._stop_process(process)
            return self._failed(
                task,
                input_hash,
                started,
                "isolated role has no JSONL stdio channels",
                failure_layer="runtime",
                failure_code="container_stdio_unavailable",
                retryable=True,
            )
        try:
            process.stdin.write(encoded_task)
            process.stdin.flush()
        except OSError as exc:
            self._stop_process(process)
            return self._failed(
                task,
                input_hash,
                started,
                f"could not deliver task to role: {exc}",
                failure_layer="ipc",
                failure_code="task_delivery_failed",
                retryable=True,
            )

        stdout, stderr, handoff, error, timed_out = self._collect_protocol(
            process, task, manifest, input_hash, timeout
        )
        finished = datetime.now(UTC)
        stdout_hash = _digest_bytes(stdout) if stdout else None
        stderr_hash = _digest_bytes(stderr) if stderr else None
        if timed_out:
            return TaskResult(
                task=task,
                lifecycle="timed_out",
                input_sha256=input_hash,
                started_at=started,
                finished_at=finished,
                stdout_sha256=stdout_hash,
                stderr_sha256=stderr_hash,
                error=f"role exceeded {timeout}s timeout",
                failure_layer="runtime",
                failure_code="container_timeout",
                retryable=True,
                host_process_id=process.pid,
            )
        if error is not None:
            failure = self._classify_protocol_error(error, process.returncode)
            return TaskResult(
                task=task,
                lifecycle="invalid_handoff" if error.startswith("protocol") else "failed",
                input_sha256=input_hash,
                started_at=started,
                finished_at=finished,
                stdout_sha256=stdout_hash,
                stderr_sha256=stderr_hash,
                # Pydantic keeps task errors bounded; protocol validation can
                # include a complete model-schema diff, so never let a remote
                # or malformed role response turn a controlled failure into a
                # host-side validation exception.
                error=error[:2000],
                host_process_id=process.pid,
                failure_layer=failure.get("failure_layer"),
                failure_code=failure.get("failure_code"),
                retryable=failure.get("retryable"),
                exit_code=failure.get("exit_code"),
                request_id=failure.get("request_id"),
                transport_state=failure.get("transport_state"),
                approval_state=failure.get("approval_state"),
            )
        if handoff is None:
            return TaskResult(
                task=task,
                lifecycle="invalid_handoff",
                input_sha256=input_hash,
                started_at=started,
                finished_at=finished,
                stdout_sha256=stdout_hash,
                stderr_sha256=stderr_hash,
                error="protocol did not produce a final handoff",
                failure_layer="ipc",
                failure_code="handoff_missing",
                retryable=True,
                host_process_id=process.pid,
            )
        return TaskResult(
            task=task,
            handoff=handoff,
            lifecycle="completed" if handoff.status == "completed" else "failed",
            input_sha256=input_hash,
            output_sha256=canonical_json_hash(handoff.model_dump(mode="json")),
            started_at=started,
            finished_at=finished,
            stdout_sha256=stdout_hash,
            stderr_sha256=stderr_hash,
            error=handoff.error,
            host_process_id=process.pid,
        )

    def _collect_protocol(
        self,
        process: subprocess.Popen[bytes],
        task: TaskEnvelope,
        manifest: RoleManifest,
        input_hash: str,
        timeout: int,
    ) -> tuple[bytes, bytes, HandoffEnvelope | None, str | None, bool]:
        selector = selectors.DefaultSelector()
        assert process.stdout is not None
        assert process.stderr is not None
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        stdout = bytearray()
        stderr = bytearray()
        pending = bytearray()
        handoff: HandoffEnvelope | None = None
        gateway_requests_used = 0
        deadline = time.monotonic() + timeout
        error: str | None = None
        try:
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self._stop_process(process)
                    return bytes(stdout), bytes(stderr), None, None, True
                events = selector.select(min(remaining, 0.1))
                # A process can exit between ``select`` and ``poll`` while its
                # final pipe buffer is still readable. Keep draining until EOF.
                if not events:
                    continue
                for key, _ in events:
                    chunk = os.read(key.fd, 4096)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    target = stdout if key.data == "stdout" else stderr
                    available = manifest.limits.max_output_bytes - len(stdout) - len(stderr)
                    if available <= 0 or len(chunk) > available:
                        target.extend(chunk[: max(available, 0)])
                        self._stop_process(process)
                        return (
                            bytes(stdout),
                            bytes(stderr),
                            None,
                            "role output limit exceeded",
                            False,
                        )
                    target.extend(chunk)
                    if key.data != "stdout":
                        continue
                    pending.extend(chunk)
                    while b"\n" in pending:
                        raw_line, _, remainder = pending.partition(b"\n")
                        pending = bytearray(remainder)
                        if not raw_line:
                            continue
                        if handoff is not None:
                            self._stop_process(process)
                            return (
                                bytes(stdout),
                                bytes(stderr),
                                None,
                                "protocol emitted data after final handoff",
                                False,
                            )
                        try:
                            message = IPC_MESSAGE_ADAPTER.validate_json(raw_line)
                        except ValidationError as exc:
                            self._stop_process(process)
                            return (
                                bytes(stdout),
                                bytes(stderr),
                                None,
                                f"protocol message rejected: {exc}",
                                False,
                            )
                        if isinstance(message, FinalHandoffMessage):
                            try:
                                SubprocessAgentRunner._assert_handoff_matches_task(
                                    task, message.handoff
                                )
                                self._assert_evidence(task, message.handoff)
                            except AgentContractError as exc:
                                self._stop_process(process)
                                return (
                                    bytes(stdout),
                                    bytes(stderr),
                                    None,
                                    f"protocol handoff rejected: {exc}",
                                    False,
                                )
                            handoff = message.handoff
                            # The role has no further authority once it submits its result.
                            if process.stdin is not None:
                                process.stdin.close()
                            try:
                                process.wait(timeout=2)
                            except subprocess.TimeoutExpired:
                                self._stop_process(process)
                            if error is not None and handoff.status != "completed":
                                return bytes(stdout), bytes(stderr), None, error, False
                            return bytes(stdout), bytes(stderr), handoff, None, False
                        response, gateway_requests_used, parent_failure = self._dispatch_request(
                            message,
                            task,
                            manifest,
                            gateway_requests_used,
                        )
                        if parent_failure is not None:
                            error = "parent request failed: " + json.dumps(
                                parent_failure, sort_keys=True, separators=(",", ":")
                            )
                        try:
                            self._write_response(process, response)
                        except OSError as exc:
                            self._stop_process(process)
                            return (
                                bytes(stdout),
                                bytes(stderr),
                                None,
                                f"protocol response failed: {exc}",
                                False,
                            )
            if pending:
                return (
                    bytes(stdout),
                    bytes(stderr),
                    None,
                    "protocol ended with a partial JSONL message",
                    False,
                )
            if process.poll() is None:
                try:
                    process.wait(timeout=0.2)
                except subprocess.TimeoutExpired:
                    self._stop_process(process)
            if process.returncode not in {0, None}:
                if error is not None:
                    return bytes(stdout), bytes(stderr), None, error, False
                return (
                    bytes(stdout),
                    bytes(stderr),
                    None,
                    f"role exited with status {process.returncode}",
                    False,
                )
            return bytes(stdout), bytes(stderr), handoff, error, False
        finally:
            selector.close()
            if process.poll() is None:
                self._stop_process(process)

    def _dispatch_request(
        self,
        message: GatewayActionRequest | ModelRequest,
        task: TaskEnvelope,
        manifest: RoleManifest,
        gateway_requests_used: int,
    ) -> tuple[HostIpcResponse, int, _FailureFields | None]:
        if message.type not in manifest.allowed_ipc:
            return (
                self._denied(message.request_id, "IPC capability is not granted by role manifest"),
                gateway_requests_used,
                self._parent_failure(
                    "ipc", "ipc_capability_denied", message.request_id, retryable=False
                ),
            )
        if isinstance(message, GatewayActionRequest):
            if message.action.kind.value not in task.allowed_actions:
                return (
                    self._denied(message.request_id, "gateway action is not granted by task"),
                    gateway_requests_used,
                    self._parent_failure(
                        "ipc", "ipc_task_action_denied", message.request_id, retryable=False
                    ),
                )
            requested = message.action.max_requests
            if gateway_requests_used + requested > task.request_budget:
                return (
                    self._denied(message.request_id, "task request budget would be exceeded"),
                    gateway_requests_used,
                    self._parent_failure(
                        "ipc", "ipc_budget_denied", message.request_id, retryable=False
                    ),
                )
            if self._gateway_handler is None:
                return (
                    self._denied(message.request_id, "no parent gateway handler is configured"),
                    gateway_requests_used,
                    self._parent_failure(
                        "gateway", "gateway_unavailable", message.request_id, retryable=False
                    ),
                )
            try:
                payload = dict(self._gateway_handler(message, task))
            except Exception as exc:  # The role receives no internal detail or stack trace.
                failure = self._classify_parent_exception(exc, message.request_id, "gateway")
                return (
                    self._denied(message.request_id, "gateway rejected the action"),
                    gateway_requests_used,
                    failure,
                )
            return (
                HostIpcResponse(
                    type="gateway_result", request_id=message.request_id, ok=True, payload=payload
                ),
                gateway_requests_used + requested,
                None,
            )
        if self._model_handler is None:
            return (
                self._denied(message.request_id, "no parent model proxy is configured"),
                gateway_requests_used,
                self._parent_failure(
                    "provider", "provider_unavailable", message.request_id, retryable=False
                ),
            )
        try:
            payload = dict(self._model_handler(message, task))
        except Exception as exc:
            failure = self._classify_parent_exception(exc, message.request_id, "provider")
            return (
                self._denied(message.request_id, "model proxy rejected the request"),
                gateway_requests_used,
                failure,
            )
        return (
            HostIpcResponse(
                type="model_result", request_id=message.request_id, ok=True, payload=payload
            ),
            gateway_requests_used,
            None,
        )

    @staticmethod
    def _parent_failure(
        layer: FailureLayer,
        code: str,
        request_id: str,
        *,
        retryable: bool,
        transport_state: TransportState = "not_attempted",
        approval_state: ApprovalState = "unknown",
    ) -> _FailureFields:
        return {
            "failure_layer": layer,
            "failure_code": code,
            "request_id": request_id,
            "retryable": retryable,
            "transport_state": transport_state,
            "approval_state": approval_state,
        }

    @classmethod
    def _classify_parent_exception(
        cls, exc: Exception, request_id: str, layer: FailureLayer
    ) -> _FailureFields:
        if layer == "gateway":
            if isinstance(exc, ApprovalDenied):
                return cls._parent_failure(
                    layer,
                    "gateway_approval_denied",
                    request_id,
                    retryable=False,
                    approval_state="not_consumed",
                )
            if isinstance(exc, PolicyDenied):
                return cls._parent_failure(
                    layer, "gateway_policy_denied", request_id, retryable=False
                )
            if isinstance(exc, (OSError, TimeoutError)):
                return cls._parent_failure(
                    layer,
                    "gateway_transport_failed",
                    request_id,
                    retryable=True,
                    transport_state="attempted",
                )
            return cls._parent_failure(layer, "gateway_internal_error", request_id, retryable=False)
        name = type(exc).__name__
        if name == "ProviderDenied":
            code, retryable = "provider_denied", False
        elif name == "ProviderBillingError":
            code, retryable = "provider_billing_unavailable", False
        elif name == "ProviderProtocolError":
            code, retryable = "provider_protocol_invalid", False
        elif name == "ProviderError":
            code, retryable = "provider_internal_error", True
        elif isinstance(exc, TimeoutError):
            code, retryable = "provider_timeout", True
        else:
            code, retryable = "provider_internal_error", False
        return cls._parent_failure(layer, code, request_id, retryable=retryable)

    @staticmethod
    def _denied(request_id: str, reason: str) -> HostIpcResponse:
        return HostIpcResponse(type="denied", request_id=request_id, ok=False, error=reason)

    @staticmethod
    def _write_response(process: subprocess.Popen[bytes], response: HostIpcResponse) -> None:
        if process.stdin is None:
            raise OSError("role stdin closed")
        process.stdin.write(response.model_dump_json().encode("utf-8") + b"\n")
        process.stdin.flush()

    def _assert_evidence(self, task: TaskEnvelope, handoff: HandoffEnvelope) -> None:
        if task.evidence_required and not (handoff.evidence_refs or handoff.evidence_artifact_refs):
            raise AgentContractError("task requires gateway evidence")
        if any(not self._evidence_validator(ref, task) for ref in handoff.evidence_refs):
            raise AgentContractError("handoff contains evidence not verified for this run")
        if any(
            not self._evidence_artifact_validator(ref, task)
            for ref in handoff.evidence_artifact_refs
        ):
            raise AgentContractError("handoff contains V2 evidence not verified for this run")

    @staticmethod
    def _stop_process(process: subprocess.Popen[bytes]) -> None:
        if process.poll() is not None:
            return
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:  # pragma: no cover - Windows process-group handling is exercised by CI there.
                process.kill()
            process.wait(timeout=1)
        except (OSError, subprocess.TimeoutExpired):
            process.kill()

    @staticmethod
    def _failed(
        task: TaskEnvelope,
        input_hash: str,
        started: datetime,
        error: str,
        *,
        failure_layer: FailureLayer = "runtime",
        failure_code: str = "runner_failed",
        retryable: bool = False,
    ) -> TaskResult:
        return TaskResult(
            task=task,
            lifecycle="failed",
            input_sha256=input_hash,
            started_at=started,
            finished_at=datetime.now(UTC),
            error=error[:2000],
            failure_layer=failure_layer,
            failure_code=failure_code,
            retryable=retryable,
        )

    @staticmethod
    def _classify_protocol_error(error: str, returncode: int | None) -> _FailureFields:
        if error.startswith("parent request failed: "):
            payload = cast(
                _FailureFields,
                json.loads(error.removeprefix("parent request failed: ")),
            )
            if returncode not in {0, None}:
                payload["exit_code"] = returncode
            return payload
        if error.startswith("role exited with status"):
            return {
                "failure_layer": "docker",
                "failure_code": "container_exit_nonzero",
                "retryable": True,
                "exit_code": returncode,
            }
        if error == "role output limit exceeded":
            return {
                "failure_layer": "runtime",
                "failure_code": "role_output_limit_exceeded",
                "retryable": False,
            }
        if error.startswith("protocol message rejected"):
            code = "protocol_message_invalid"
        elif error.startswith("protocol handoff rejected"):
            code = "handoff_invalid"
        elif error.startswith("protocol response failed"):
            code = "ipc_response_failed"
        elif error.startswith("protocol"):
            code = "protocol_invalid"
        else:
            code = "runtime_failed"
        return {
            "failure_layer": "ipc" if code != "runtime_failed" else "runtime",
            "failure_code": code,
            "retryable": code in {"ipc_response_failed"},
            "exit_code": returncode if returncode not in {0, None} else None,
        }


def _digest_bytes(value: bytes) -> str:
    return f"sha256:{sha256(value).hexdigest()}"

"""Safe Docker command construction for executing a candidate only after review."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from .models import SandboxExecutionResult, SandboxJsonExecutionResult

_DEFAULT_IMAGE = "python:3.12-slim@sha256:" + "0" * 64
_JSON_HOST = """import importlib,json,sys
sys.path.insert(0,'/wheel')
module,name=sys.argv[1].split(':',1)
value=json.dumps(json.load(sys.stdin),ensure_ascii=False,sort_keys=True,separators=(',',':'))
result=getattr(importlib.import_module(module),name)(value)
json.dump(result,sys.stdout,ensure_ascii=False,sort_keys=True,separators=(',',':'))
"""


class DockerSandbox:
    """Execute a candidate only inside a no-network, immutable Docker boundary.

    The default image is deliberately a digest-shaped placeholder. Deployments must
    supply their preloaded, reviewed image digest; a mutable tag is never accepted.
    """

    def __init__(self, image: str = _DEFAULT_IMAGE, *, timeout_seconds: int = 60) -> None:
        if "@sha256:" not in image or len(image.rsplit("@sha256:", 1)[1]) != 64:
            raise ValueError("Docker sandbox image must be pinned by an immutable sha256 digest")
        if timeout_seconds < 1 or timeout_seconds > 600:
            raise ValueError("sandbox timeout must be between 1 and 600 seconds")
        self.image = image
        self.timeout_seconds = timeout_seconds

    def build_command(self, artifact_root: Path, *, test_target: str = "/wheel/tests") -> list[str]:
        source = artifact_root.resolve()
        if not source.is_dir():
            raise ValueError("artifact_root must be an existing directory")
        if not test_target.startswith("/wheel/"):
            raise ValueError("sandbox test target must remain inside the read-only wheel mount")
        return [
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
            "--pids-limit",
            "64",
            "--memory",
            "256m",
            "--cpus",
            "0.5",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=16m",
            "--volume",
            f"{source}:/wheel:ro",
            "--workdir",
            "/wheel",
            self.image,
            "python",
            "-I",
            "-m",
            "pytest",
            test_target,
        ]

    def execute(
        self, artifact_root: Path, *, test_target: str = "/wheel/tests"
    ) -> SandboxExecutionResult:
        """Run a candidate and return complete bounded diagnostics without raising.

        Docker availability is a required production gate. A missing CLI, daemon, image,
        timeout, or non-zero test result is a failed validation outcome, never a fallback
        to host execution.
        """
        command = tuple(self.build_command(artifact_root, test_target=test_target))
        image_digest = self.image.rsplit("@", 1)[1]
        executed_at = datetime.now(UTC)
        if shutil.which("docker") is None:
            return self._result(
                command,
                image_digest,
                failure_reason="docker CLI is unavailable",
                executed_at=executed_at,
            )
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                timeout=self.timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            return self._result(
                command,
                image_digest,
                stdout=exc.stdout or b"",
                stderr=exc.stderr or b"",
                timed_out=True,
                failure_reason="sandbox execution timed out",
                executed_at=executed_at,
            )
        except OSError as exc:
            return self._result(
                command,
                image_digest,
                failure_reason=f"docker sandbox could not start: {exc}",
                executed_at=executed_at,
            )
        return self._result(
            command,
            image_digest,
            stdout=completed.stdout,
            stderr=completed.stderr,
            exit_code=completed.returncode,
            failure_reason=None if completed.returncode == 0 else "sandbox test command failed",
            executed_at=executed_at,
        )

    def execute_json(
        self, artifact_root: Path, *, entrypoint: str, input_json: str
    ) -> SandboxJsonExecutionResult:
        """Execute only a fixed JSON host inside the same isolated container.

        Generated code is never imported by Hermes. The host script is constant,
        accepts one JSON object from stdin, imports the manifest entrypoint only in
        the no-network container, and returns a bounded JSON document.
        """
        source = artifact_root.resolve()
        if not source.is_dir():
            raise ValueError("artifact_root must be an existing directory")
        module, separator, function = entrypoint.partition(":")
        if not separator or not module.isidentifier() or not function.isidentifier():
            raise ValueError("sandbox entrypoint must be a module:function identifier")
        try:
            parsed_input = json.loads(input_json)
        except json.JSONDecodeError as exc:
            raise ValueError("sandbox input must be JSON") from exc
        if not isinstance(parsed_input, dict):
            raise ValueError("sandbox input must be a JSON object")
        command = tuple(
            self._container_prefix(source)
            + [self.image, "python", "-I", "-c", _JSON_HOST, entrypoint]
        )
        image_digest = self.image.rsplit("@", 1)[1]
        executed_at = datetime.now(UTC)
        if shutil.which("docker") is None:
            return self._json_result(
                command,
                image_digest,
                failure_reason="docker CLI is unavailable",
                executed_at=executed_at,
            )
        try:
            completed = subprocess.run(
                command,
                input=input_json.encode("utf-8"),
                check=False,
                capture_output=True,
                timeout=self.timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            return self._json_result(
                command,
                image_digest,
                stdout=exc.stdout or b"",
                stderr=exc.stderr or b"",
                timed_out=True,
                failure_reason="sandbox execution timed out",
                executed_at=executed_at,
            )
        except OSError as exc:
            return self._json_result(
                command,
                image_digest,
                failure_reason=f"docker sandbox could not start: {exc}",
                executed_at=executed_at,
            )
        output = completed.stdout.decode("utf-8", errors="replace")
        failure = (
            None
            if completed.returncode == 0 and len(output) <= 65_536
            else "sandbox command failed"
        )
        if len(output) > 65_536:
            failure = "sandbox JSON output exceeded limit"
        return self._json_result(
            command,
            image_digest,
            stdout=completed.stdout,
            stderr=completed.stderr,
            exit_code=completed.returncode,
            failure_reason=failure,
            output_json=output if failure is None else "",
            executed_at=executed_at,
        )

    def _container_prefix(self, source: Path) -> list[str]:
        return [
            "docker",
            "run",
            "--rm",
            "--interactive",
            "--network",
            "none",
            "--read-only",
            "--user",
            "65534:65534",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            "64",
            "--memory",
            "256m",
            "--cpus",
            "0.5",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=16m",
            "--volume",
            f"{source}:/wheel:ro",
            "--workdir",
            "/wheel",
        ]

    def _result(
        self,
        command: tuple[str, ...],
        image_digest: str,
        *,
        stdout: bytes = b"",
        stderr: bytes = b"",
        exit_code: int | None = None,
        timed_out: bool = False,
        failure_reason: str | None = None,
        executed_at: datetime,
    ) -> SandboxExecutionResult:
        return SandboxExecutionResult(
            image=self.image,
            image_digest=image_digest,
            command=command,
            passed=exit_code == 0 and not timed_out and failure_reason is None,
            exit_code=exit_code,
            timed_out=timed_out,
            failure_reason=failure_reason,
            stdout_sha256=f"sha256:{hashlib.sha256(stdout).hexdigest()}",
            stderr_sha256=f"sha256:{hashlib.sha256(stderr).hexdigest()}",
            stdout_preview=stdout.decode("utf-8", errors="replace")[:4096],
            stderr_preview=stderr.decode("utf-8", errors="replace")[:4096],
            executed_at=executed_at,
        )

    def _json_result(
        self,
        command: tuple[str, ...],
        image_digest: str,
        *,
        stdout: bytes = b"",
        stderr: bytes = b"",
        exit_code: int | None = None,
        timed_out: bool = False,
        failure_reason: str | None = None,
        output_json: str = "",
        executed_at: datetime,
    ) -> SandboxJsonExecutionResult:
        base = self._result(
            command,
            image_digest,
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            timed_out=timed_out,
            failure_reason=failure_reason,
            executed_at=executed_at,
        )
        return SandboxJsonExecutionResult(**base.model_dump(), output_json=output_json)

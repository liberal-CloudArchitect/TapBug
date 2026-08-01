from __future__ import annotations

import fcntl
import hashlib
import json
import os
import tempfile
import threading
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


class RunContext:
    """Owns a single immutable run directory and its artifact layout."""

    ARTIFACTS = (
        "plan",
        "approvals",
        "evidence",
        "handoffs",
        "knowledge",
        "provider",
        "report",
        "reviews",
        "wheels",
    )

    def __init__(
        self, runs_root: Path | str, scope_snapshot: dict[str, Any], run_id: str | None = None
    ):
        self.runs_root = Path(runs_root)
        self.run_id = run_id or str(uuid.uuid4())
        if (
            not self.run_id
            or "/" in self.run_id
            or "\\" in self.run_id
            or self.run_id in {".", ".."}
        ):
            raise ValueError("run_id must be a single safe path segment")
        self.path = self.runs_root / self.run_id
        self.path.mkdir(parents=True, exist_ok=False)
        self._initialize_process_lock()
        for name in self.ARTIFACTS:
            (self.path / name).mkdir()
        self.scope_digest = "sha256:" + hashlib.sha256(_canonical(scope_snapshot)).hexdigest()
        self.write_json("scope.json", scope_snapshot, immutable=True)

    @classmethod
    def open_existing(
        cls, runs_root: Path | str, scope_snapshot: dict[str, Any], run_id: str
    ) -> RunContext:
        """Reopen an existing run only when its frozen scope is byte-for-byte equivalent.

        Resume is deliberately not a convenience constructor: a caller must provide the
        scope it believes it is resuming, and Hermes rejects any mismatch before reading
        handoffs, approvals, or workflow state.
        """
        root = Path(runs_root)
        if not run_id or "/" in run_id or "\\" in run_id or run_id in {".", ".."}:
            raise ValueError("run_id must be a single safe path segment")
        path = root / run_id
        if not path.is_dir():
            raise FileNotFoundError("run directory does not exist")
        scope_path = path / "scope.json"
        try:
            frozen = json.loads(scope_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError("existing run has no valid frozen scope snapshot") from exc
        if not isinstance(frozen, dict) or _canonical(frozen) != _canonical(scope_snapshot):
            raise ValueError("scope snapshot does not match the frozen run scope")
        if any(not (path / artifact).is_dir() for artifact in cls.ARTIFACTS):
            raise ValueError("existing run has an incomplete artifact layout")
        cls._verify_workflow_events(path)
        context = object.__new__(cls)
        context.runs_root = root
        context.run_id = run_id
        context.path = path
        context.scope_digest = "sha256:" + hashlib.sha256(_canonical(frozen)).hexdigest()
        context._initialize_process_lock()
        return context

    def _initialize_process_lock(self) -> None:
        """Install the in-process half of the run artifact lock.

        ``flock`` protects the run from other processes, but its interaction with
        multiple threads in one process is platform-dependent.  The V3 fan-out
        coordinator shares one RunContext across worker threads, so serialize
        those callers explicitly and retain re-entrant behavior for helpers that
        persist more than one artifact under a wider run lock.
        """

        self._thread_lock = threading.RLock()
        self._lock_state = threading.local()

    @staticmethod
    def _verify_workflow_events(path: Path) -> None:
        """Reject a resumed run with an edited workflow event chain."""
        journal = path / "workflow" / "events.jsonl"
        if not journal.exists():
            return
        previous_hash: str | None = None
        try:
            lines = journal.read_text(encoding="utf-8").splitlines()
            for line in lines:
                if not line:
                    continue
                event = json.loads(line)
                if not isinstance(event, dict):
                    raise ValueError("workflow event is not an object")
                event_hash = event.pop("event_hash")
                if event.get("previous_hash") != previous_hash:
                    raise ValueError("workflow event previous hash mismatch")
                calculated = "sha256:" + hashlib.sha256(_canonical(event)).hexdigest()
                if event_hash != calculated:
                    raise ValueError("workflow event hash mismatch")
                previous_hash = event_hash
        except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise ValueError("existing run has an invalid workflow event chain") from exc

    @property
    def audit_path(self) -> Path:
        return self.path / "audit.jsonl"

    def artifact_path(self, relative: str) -> Path:
        candidate = (self.path / relative).resolve()
        if self.path.resolve() not in candidate.parents and candidate != self.path.resolve():
            raise ValueError("artifact path escapes run directory")
        return candidate

    @contextmanager
    def lock(self) -> Iterator[None]:
        with self._thread_lock:
            depth = getattr(self._lock_state, "depth", 0)
            if depth:
                self._lock_state.depth = depth + 1
                try:
                    yield
                finally:
                    self._lock_state.depth -= 1
                return

            lock_path = self.path / ".lock"
            with lock_path.open("a+") as handle:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                self._lock_state.depth = 1
                try:
                    yield
                finally:
                    self._lock_state.depth = 0
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def write_json(self, relative: str, value: Any, *, immutable: bool = False) -> Path:
        return self._write_bytes(relative, _canonical(value), immutable=immutable)

    def write_text(self, relative: str, value: str, *, immutable: bool = False) -> Path:
        return self._write_bytes(relative, value.encode("utf-8"), immutable=immutable)

    def write_json_exclusive(self, relative: str, value: Any) -> Path:
        """Create one immutable claim without an exists-then-replace race."""
        path = self.artifact_path(relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        fd = os.open(path, flags, 0o600)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(_canonical(value))
                handle.flush()
                os.fsync(handle.fileno())
        except Exception:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            raise
        return path

    def _write_bytes(self, relative: str, value: bytes, *, immutable: bool) -> Path:
        path = self.artifact_path(relative)
        with self.lock():
            if immutable and path.exists():
                raise FileExistsError(f"immutable artifact already exists: {relative}")
            path.parent.mkdir(parents=True, exist_ok=True)
            fd, temp_name = tempfile.mkstemp(prefix=".tmp-", dir=path.parent)
            try:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(value)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temp_name, path)
            finally:
                if os.path.exists(temp_name):
                    os.unlink(temp_name)
        return path

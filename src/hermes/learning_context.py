"""Immutable, child-run storage for R2.5 learning work.

Learning runs deliberately live beside, never inside, assessment runs.  This
keeps the V3 artifact and report-preflight authority immutable while retaining
the same exclusive-write and path-containment properties for the Wheel
lifecycle.
"""

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


def canonical_json(value: Any) -> bytes:
    """Encode a JSON-compatible value with the project-wide canonical form."""

    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def file_sha256(path: Path) -> str:
    """Return a content hash for an artifact after its path was trusted."""

    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


class LearningContext:
    """Own one isolated R2.5 learning or continuation artifact directory.

    The context intentionally exposes no parent assessment write capability. A
    parent run is represented only through immutable digests in R2.5 contracts.
    """

    ARTIFACTS = (
        "plan",
        "research",
        "handoffs",
        "provider",
        "wheels",
        "registry",
        "continuation",
        "audit",
    )

    def __init__(self, runs_root: Path | str, *, run_id: str | None = None) -> None:
        self.runs_root = Path(runs_root).resolve()
        self.run_id = self._safe_id(run_id or str(uuid.uuid4()))
        self.path = self.runs_root / "learning" / self.run_id
        self.path.mkdir(parents=True, exist_ok=False)
        for name in self.ARTIFACTS:
            (self.path / name).mkdir()
        self._initialize_lock()

    @classmethod
    def open_existing(cls, runs_root: Path | str, run_id: str) -> LearningContext:
        root = Path(runs_root).resolve()
        safe_id = cls._safe_id(run_id)
        path = root / "learning" / safe_id
        if not path.is_dir():
            raise FileNotFoundError("learning run directory does not exist")
        if any(not (path / name).is_dir() for name in cls.ARTIFACTS):
            raise ValueError("learning run has an incomplete artifact layout")
        context = object.__new__(cls)
        context.runs_root = root
        context.run_id = safe_id
        context.path = path
        context._initialize_lock()
        return context

    @staticmethod
    def _safe_id(value: str) -> str:
        if not value or "/" in value or "\\" in value or value in {".", ".."}:
            raise ValueError("learning run_id must be a single safe path segment")
        return value

    def _initialize_lock(self) -> None:
        self._thread_lock = threading.RLock()
        self._lock_state = threading.local()

    def artifact_path(self, relative: str) -> Path:
        candidate = (self.path / relative).resolve()
        if self.path not in candidate.parents and candidate != self.path:
            raise ValueError("learning artifact path escapes its run directory")
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
            with (self.path / ".lock").open("a+") as handle:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                self._lock_state.depth = 1
                try:
                    yield
                finally:
                    self._lock_state.depth = 0
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def write_json(self, relative: str, value: Any, *, immutable: bool = False) -> Path:
        return self.write_bytes(relative, canonical_json(value), immutable=immutable)

    def write_text(self, relative: str, value: str, *, immutable: bool = False) -> Path:
        return self.write_bytes(relative, value.encode("utf-8"), immutable=immutable)

    def write_bytes(self, relative: str, value: bytes, *, immutable: bool = False) -> Path:
        path = self.artifact_path(relative)
        with self.lock():
            if immutable and path.exists():
                raise FileExistsError(f"immutable learning artifact already exists: {relative}")
            path.parent.mkdir(parents=True, exist_ok=True)
            fd, temporary = tempfile.mkstemp(prefix=".tmp-", dir=path.parent)
            try:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(value)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, path)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
        return path

    def write_json_exclusive(self, relative: str, value: Any) -> Path:
        path = self.artifact_path(relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        with self.lock():
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            try:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(canonical_json(value))
                    stream.flush()
                    os.fsync(stream.fileno())
            except Exception:
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass
                raise
        return path


__all__ = ["LearningContext", "canonical_json", "file_sha256"]

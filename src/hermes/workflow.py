"""Persistent, contract-enforced expert workflow for Hermes."""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from .legacy import LegacyRunReadOnlyError
from .runtime import AuditLogger, RunContext
from .runtime.agents import AgentRunner, EvidenceRef, TaskEnvelope, TaskResult


class WorkflowBlocked(RuntimeError):
    """A role cannot safely provide a completed handoff."""


@dataclass(frozen=True)
class RolePolicy:
    role: str
    allowed_actions: tuple[str, ...]
    requires_evidence: bool = False
    parents: tuple[str, ...] = ()


ROLE_POLICIES = {
    "gatekeeper": RolePolicy("gatekeeper", ()),
    "recon": RolePolicy("recon", ("http_get",), parents=("gatekeeper",)),
    "mapper": RolePolicy("mapper", ("http_get",), parents=("recon",)),
    "web-vuln": RolePolicy("web-vuln", (), parents=("mapper",)),
    "api": RolePolicy("api", (), parents=("mapper",)),
    "authz": RolePolicy("authz", (), parents=("mapper",)),
    "infra": RolePolicy("infra", (), parents=("mapper",)),
    "verifier": RolePolicy(
        "verifier", ("http_get", "http_post"), True, ("web-vuln", "api", "authz", "infra")
    ),
    "reporter": RolePolicy("reporter", (), True, ("verifier",)),
    # Knowledge capability work uses the same controlled runner and state model.
    "researcher": RolePolicy("researcher", ()),
    "capability-planner": RolePolicy("capability-planner", (), parents=("researcher",)),
    "wheel-generator": RolePolicy("wheel-generator", (), parents=("capability-planner",)),
    "wheel-validator": RolePolicy("wheel-validator", (), parents=("wheel-generator",)),
    "wheel-reviewer": RolePolicy("wheel-reviewer", (), parents=("wheel-validator",)),
    "capability-host": RolePolicy("capability-host", (), parents=("wheel-reviewer",)),
    "outcome-review": RolePolicy("outcome-review", (), parents=("capability-host",)),
}

DEFAULT_ROLE_ORDER = (
    "gatekeeper",
    "recon",
    "mapper",
    "web-vuln",
    "api",
    "authz",
    "infra",
    "verifier",
    "reporter",
)


def _event_hash(value: dict[str, Any]) -> str:
    return (
        "sha256:"
        + hashlib.sha256(
            json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
        ).hexdigest()
    )


class WorkflowEventLog:
    """Locked append-only event chain used for resume diagnostics."""

    def __init__(self, context: RunContext) -> None:
        self._context = context
        self._path = context.artifact_path("workflow/events.jsonl")

    def record(self, event: str, **fields: Any) -> None:
        with self._context.lock():
            previous_hash: str | None = None
            sequence = 1
            if self._path.exists():
                lines = [
                    line for line in self._path.read_text(encoding="utf-8").splitlines() if line
                ]
                if lines:
                    previous_hash = json.loads(lines[-1])["event_hash"]
                    sequence = len(lines) + 1
            payload: dict[str, Any] = {
                "sequence": sequence,
                "at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                "event": event,
                "previous_hash": previous_hash,
                **fields,
            }
            payload["event_hash"] = _event_hash(payload)
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("a", encoding="utf-8") as handle:
                handle.write(
                    json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                )
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())


class WorkflowEngine:
    """Execute a typed DAG, persist handoffs, and resume only hash-identical tasks."""

    def __init__(
        self, context: RunContext, runner: AgentRunner, audit: AuditLogger | None = None
    ) -> None:
        self.context = context
        self.runner = runner
        self.audit = audit or AuditLogger(context)
        self.events = WorkflowEventLog(context)
        self._cancelled = False

    def cancel(self, reason: str = "operator cancelled workflow") -> None:
        self._cancelled = True
        self.events.record("workflow_cancelled", reason=reason)
        self.audit.record("workflow", decision="cancelled", reason=reason)

    def run_roles(
        self,
        roles: Iterable[str] = DEFAULT_ROLE_ORDER,
        payload: dict[str, Any] | None = None,
        evidence_refs: tuple[EvidenceRef, ...] = (),
    ) -> list[TaskResult]:
        selected = tuple(roles)
        self._validate_order(selected)
        supplied_payload = payload or {}
        results: list[TaskResult] = []
        completed: dict[str, TaskResult] = {}
        for index, role in enumerate(selected):
            if self._cancelled:
                raise WorkflowBlocked("workflow was cancelled")
            policy = ROLE_POLICIES[role]
            parent_results = {name: completed[name] for name in policy.parents if name in completed}
            task_payload = self._project_payload(supplied_payload, parent_results)
            if role == "verifier" and not task_payload.get("approval_id"):
                self._block(role, "missing_approval")
                raise WorkflowBlocked("verifier requires an approval_id before validation")
            task = TaskEnvelope(
                run_id=self.context.run_id,
                task_id=f"{index:03d}-{role}",
                role=role,
                scope_digest=self.context.scope_digest,
                payload=task_payload,
                evidence_refs=evidence_refs,
                allowed_actions=policy.allowed_actions,
                request_budget=1 if policy.allowed_actions else 0,
                evidence_required=policy.requires_evidence,
            )
            result = self._load_completed(task)
            if result is None:
                result = self._run_with_retry(task)
                self.context.write_json(
                    f"handoffs/{task.task_id}.json",
                    {
                        "task": task.model_dump(mode="json"),
                        "result": result.model_dump(mode="json"),
                    },
                    immutable=True,
                )
            if result.lifecycle != "completed" or result.handoff is None:
                self._block(role, result.lifecycle, result.error)
                message = result.error or result.lifecycle
                raise WorkflowBlocked(f"role {role} blocked workflow: {message}")
            if policy.requires_evidence and not result.handoff.evidence_refs:
                self._block(role, "missing_evidence")
                raise WorkflowBlocked(f"role {role} completed without required evidence")
            self._assert_evidence_refs(result.handoff.evidence_refs)
            if role == "reporter":
                self._write_validated_report(result)
            self.events.record(
                "task_completed",
                task_id=task.task_id,
                role=role,
                input_sha256=result.input_sha256,
                output_sha256=result.output_sha256,
            )
            self.audit.record(
                "agent_handoff",
                decision="allowed",
                role=role,
                input_sha256=result.input_sha256,
                output_sha256=result.output_sha256,
            )
            results.append(result)
            completed[role] = result
        return results

    def _run_with_retry(self, task: TaskEnvelope) -> TaskResult:
        attempts = 3 if not task.allowed_actions else 1
        last: TaskResult | None = None
        for attempt in range(1, attempts + 1):
            self.events.record(
                "task_started", task_id=task.task_id, role=task.role, attempt=attempt
            )
            result = self.runner.run(task)
            if result.lifecycle == "completed":
                return result
            last = result
            self.events.record(
                "task_failed",
                task_id=task.task_id,
                role=task.role,
                attempt=attempt,
                lifecycle=result.lifecycle,
                error=result.error,
            )
            # Contract violations, timeouts, and an action-capable role are never
            # safe to retry automatically. Only an ordinary pre-action failure of
            # a pure analysis node receives the bounded retry budget.
            if result.lifecycle != "failed":
                break
        assert last is not None
        return last

    def _load_completed(self, task: TaskEnvelope) -> TaskResult | None:
        path = self.context.artifact_path(f"handoffs/{task.task_id}.json")
        if not path.exists():
            return None
        try:
            stored = json.loads(path.read_text(encoding="utf-8"))
            stored_task = TaskEnvelope.model_validate(stored["task"])
            result = TaskResult.model_validate(stored["result"])
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise WorkflowBlocked(f"invalid persisted handoff for {task.task_id}") from exc
        if stored_task.input_hash() != task.input_hash():
            raise WorkflowBlocked(f"persisted task input differs for {task.task_id}")
        if result.lifecycle == "completed" and result.handoff is not None:
            self.events.record("task_resumed", task_id=task.task_id, role=task.role)
            return result
        return None

    @staticmethod
    def _project_payload(payload: dict[str, Any], parents: dict[str, TaskResult]) -> dict[str, Any]:
        projected = dict(payload)
        if parents:
            projected["upstream"] = {
                role: result.handoff.result
                for role, result in parents.items()
                if result.handoff is not None
            }
        return projected

    def _assert_evidence_refs(self, refs: tuple[EvidenceRef, ...]) -> None:
        for ref in refs:
            if not ref.redacted or not ref.path.startswith("evidence/"):
                raise WorkflowBlocked("handoff evidence is not a redacted run-local reference")
            path = self.context.artifact_path(ref.path)
            if not path.is_file():
                raise WorkflowBlocked("handoff evidence does not exist in this run")

    def _write_validated_report(self, result: TaskResult) -> None:
        del result
        raise LegacyRunReadOnlyError

    def _block(self, role: str, lifecycle: str, error: str | None = None) -> None:
        self.events.record("task_blocked", role=role, lifecycle=lifecycle, error=error)
        self.audit.record(
            "agent_handoff", decision="blocked", role=role, lifecycle=lifecycle, error=error
        )

    @staticmethod
    def _validate_order(roles: tuple[str, ...]) -> None:
        unknown = set(roles).difference(ROLE_POLICIES)
        if unknown:
            raise ValueError(f"unknown workflow roles: {', '.join(sorted(unknown))}")
        positions = [DEFAULT_ROLE_ORDER.index(role) for role in roles if role in DEFAULT_ROLE_ORDER]
        if positions != sorted(positions) or len(roles) != len(set(roles)):
            raise ValueError("roles must be unique and follow the Hermes workflow order")
        # Partial workflows are intentionally allowed for fixture and role contract tests.

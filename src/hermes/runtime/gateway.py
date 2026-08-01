from __future__ import annotations

import hashlib
import json
import os
import threading
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..evidence import EvidenceArtifactRef, EvidenceBinding, EvidenceStore, HeaderField
from .actions import (
    ActionKind,
    ApprovalAuthority,
    ApprovalChallenge,
    ApprovalToken,
    ProposedAction,
)
from .audit import AuditLogger
from .context import RunContext
from .errors import ApprovalDenied, PolicyDenied
from .policy import PolicyEngine

if TYPE_CHECKING:
    from ..vertical_contracts import ApprovalConsumptionV2


def _hash(value: Any) -> str:
    return (
        "sha256:"
        + hashlib.sha256(
            json.dumps(value, sort_keys=True, default=str, separators=(",", ":")).encode()
        ).hexdigest()
    )


@dataclass(frozen=True)
class HttpRequest:
    method: str
    url: str
    connect_ip: str
    host_header: str
    tls_server_name: str | None
    headers: Mapping[str, str]
    body: bytes | None = None
    response_body_limit: int = 1_048_576


@dataclass(frozen=True)
class HttpResponse:
    status_code: int
    headers: Mapping[str, str]
    body: bytes = b""
    header_fields: tuple[tuple[str, str], ...] = ()
    original_body_bytes: int | None = None
    truncated: bool = False


@dataclass(frozen=True)
class EvidenceRef:
    evidence_id: str
    request_hash: str
    response_hash: str
    target: str
    status_code: int


Transport = Callable[[HttpRequest], HttpResponse]
CommandExecutor = Callable[[Sequence[str]], tuple[int, str, str]]
ExternalApprovalValidator = Callable[[ProposedAction, ApprovalToken | str | None], None]
ExternalApprovalValidatorV2 = Callable[
    [ProposedAction, ApprovalToken | str | None, "GatewayExecutionContext", str],
    "ApprovalConsumptionV2",
]


class GatewayExecutionContext(BaseModel):
    """Task and signed-plan identity for one V2 Gateway exchange."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    task_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$")
    task_input_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    role: str = Field(pattern=r"^[a-z][a-z0-9-]{0,63}$")
    request_id: str = Field(pattern=r"^[A-Za-z0-9._:-]{1,128}$")
    action_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$")
    plan_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    approval_bundle_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9._-]{1,128}$")
    approval_bundle_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")

    @model_validator(mode="after")
    def complete_approval_context(self) -> GatewayExecutionContext:
        values = (
            self.plan_digest,
            self.approval_bundle_id,
            self.approval_bundle_digest,
        )
        if any(value is not None for value in values) and any(value is None for value in values):
            raise ValueError("approval execution context must be complete or entirely absent")
        return self

    @property
    def has_approval_context(self) -> bool:
        return self.plan_digest is not None


class ToolGateway:
    """The only HTTP egress boundary; it validates and pins every connection."""

    def __init__(
        self,
        *,
        engine: PolicyEngine,
        context: RunContext,
        audit: AuditLogger | None = None,
        approval_authority: ApprovalAuthority | None = None,
        external_approval_validator: ExternalApprovalValidator | None = None,
        external_approval_validator_v2: ExternalApprovalValidatorV2 | None = None,
        evidence_store: EvidenceStore | None = None,
        transport: Transport | None = None,
    ):
        self.engine, self.context = engine, context
        self.audit = audit or AuditLogger(context)
        self.approvals = approval_authority or ApprovalAuthority()
        self.external_approval_validator = external_approval_validator
        self.external_approval_validator_v2 = external_approval_validator_v2
        self.evidence_store = evidence_store
        self.transport = transport
        self._count = 0
        self._started = time.monotonic()
        self._last_request = 0.0
        self._lock = threading.Lock()
        self._concurrency = threading.BoundedSemaphore(engine.policy.max_concurrency)

    def _reserve(self, action: ProposedAction, token: ApprovalToken | str | None) -> None:
        try:
            self.engine.assert_automation()
            if action.requires_approval:
                if self.external_approval_validator is not None:
                    self.external_approval_validator(action, token)
                else:
                    self._consume_approval(action, token)
            self._reserve_budget(action)
        except (PolicyDenied, ApprovalDenied) as exc:
            self.audit.record(
                "action",
                decision="denied",
                target=action.target,
                action=action.kind.value,
                reason=str(exc),
            )
            raise

    def _reserve_budget(self, action: ProposedAction) -> None:
        with self._lock:
            now = time.monotonic()
            if now - self._started > self.engine.policy.max_duration_seconds:
                raise PolicyDenied("run duration budget exhausted")
            reservation_id = str(uuid.uuid4())
            reserved = self._reserve_run_slots(action, reservation_id)
            if self._count:
                wait_seconds = 1 / self.engine.policy.rate_limit_rps - (now - self._last_request)
                if wait_seconds > 0:
                    if now - self._started + wait_seconds > (
                        self.engine.policy.max_duration_seconds
                    ):
                        raise PolicyDenied("rate-limit wait would exceed run duration")
                    time.sleep(wait_seconds)
                    now = time.monotonic()
            self._count += action.max_requests
            self._last_request = now
            if len(reserved) != action.max_requests:  # pragma: no cover - defensive
                raise PolicyDenied("persistent request reservation was incomplete")

    def _reserve_v2(
        self,
        action: ProposedAction,
        token: ApprovalToken | str | None,
        execution: GatewayExecutionContext,
        evidence_id: str,
    ) -> ApprovalConsumptionV2 | None:
        from ..vertical_contracts import ApprovalConsumptionV2

        try:
            self.engine.assert_automation()
            consumption: ApprovalConsumptionV2 | None = None
            if action.requires_approval:
                if not execution.has_approval_context:
                    raise ApprovalDenied("validation request omitted its approval context")
                if self.external_approval_validator_v2 is None:
                    raise ApprovalDenied("validation request has no V2 approval validator")
                result = self.external_approval_validator_v2(action, token, execution, evidence_id)
                if not isinstance(result, ApprovalConsumptionV2):
                    raise ApprovalDenied("V2 approval validator returned no typed consumption")
                expected = (
                    execution.approval_bundle_id,
                    execution.approval_bundle_digest,
                    execution.plan_digest,
                    self.context.run_id,
                    self.context.scope_digest,
                    execution.task_id,
                    execution.request_id,
                    evidence_id,
                    execution.action_id,
                    action.digest,
                )
                actual = (
                    result.bundle_id,
                    result.bundle_digest,
                    result.plan_digest,
                    result.run_id,
                    result.scope_digest,
                    result.task_id,
                    result.request_id,
                    result.evidence_id,
                    result.action_id,
                    result.action_digest,
                )
                if actual != expected:
                    raise ApprovalDenied(
                        "approval consumption is not bound to the exact Gateway execution"
                    )
                consumption = result
            elif execution.has_approval_context or token is not None:
                raise ApprovalDenied("read-only evidence must not carry approval context")
            self._reserve_budget(action)
            return consumption
        except (PolicyDenied, ApprovalDenied) as exc:
            self.audit.record(
                "action",
                decision="denied",
                target=action.target,
                action=action.kind.value,
                reason=str(exc),
            )
            raise

    def _reserve_run_slots(self, action: ProposedAction, reservation_id: str) -> list[str]:
        reserved: list[str] = []
        limit = self.engine.policy.max_requests
        payload = {
            "reservation_id": reservation_id,
            "action_digest": action.digest,
            "target": action.target,
            "kind": action.kind.value,
            "reserved_at": int(time.time()),
        }
        for slot in range(1, limit + 1):
            relative = f"network/reservations/{slot:06d}.json"
            try:
                self.context.write_json_exclusive(relative, payload)
            except FileExistsError:
                continue
            reserved.append(relative)
            if len(reserved) == action.max_requests:
                return reserved
        for relative in reserved:
            self.context.artifact_path(relative).unlink(missing_ok=True)
        raise PolicyDenied("request budget exhausted")

    def request_approval(
        self, action: ProposedAction, *, ttl_seconds: int = 300
    ) -> ApprovalChallenge:
        """Create an auditable, run-bound approval challenge without executing it."""
        challenge = self.approvals.challenge(
            run_id=self.context.run_id,
            scope_digest=self.context.scope_digest,
            action=action,
            ttl_seconds=ttl_seconds,
        )
        self.context.write_json(
            f"approvals/challenges/{challenge.challenge_id}.json",
            challenge.model_dump(mode="json"),
            immutable=True,
        )
        self.audit.record(
            "approval_challenge",
            decision="asked",
            target=action.target,
            action=action.kind.value,
            challenge_id=challenge.challenge_id,
        )
        return challenge

    def grant_approval(
        self,
        challenge: ApprovalChallenge,
        action: ProposedAction,
        *,
        max_requests: int | None = None,
    ) -> ApprovalToken:
        """Record a signed approval's metadata; raw bearer token stays with the operator."""
        token = self.approvals.approve(challenge, action, max_requests=max_requests)
        token_id_hash = hashlib.sha256(token.token_id.encode("utf-8")).hexdigest()
        self.context.write_json(
            f"approvals/granted/{token_id_hash}.json",
            {
                "token_id_sha256": token_id_hash,
                "challenge_id": token.challenge_id,
                "action_digest": token.action_digest,
                "target": token.target,
                "expires_at": token.expires_at,
                "max_requests": token.max_requests,
            },
            immutable=True,
        )
        self.audit.record(
            "approval_grant",
            decision="approved",
            target=action.target,
            action=action.kind.value,
            token_id_sha256=token_id_hash,
        )
        return token

    def _consume_approval(
        self, action: ProposedAction, token: ApprovalToken | str | None
    ) -> ApprovalToken:
        """Consume an approval once for the whole run, including after a restart.

        ``ApprovalAuthority`` protects a single in-memory verifier.  The run-local
        marker closes the replay gap between independently constructed gateways
        that share a run directory and verification key.
        """
        if token is None:
            raise ApprovalDenied("this action requires an approval token")
        decoded = self.approvals.decode(token) if isinstance(token, str) else token
        token_id_hash = hashlib.sha256(decoded.token_id.encode("utf-8")).hexdigest()
        marker = self.context.artifact_path(f"approvals/consumed/{token_id_hash}.json")
        with self.context.lock():
            if marker.exists():
                raise ApprovalDenied("approval token was already consumed for this run")
            consumed = self.approvals.consume(
                decoded,
                run_id=self.context.run_id,
                scope_digest=self.context.scope_digest,
                action=action,
            )
            marker.parent.mkdir(parents=True, exist_ok=True)
            try:
                with marker.open("x", encoding="utf-8") as handle:
                    json.dump(
                        {
                            "token_id_sha256": token_id_hash,
                            "action_digest": action.digest,
                            "target": action.target,
                            "consumed_at": int(time.time()),
                        },
                        handle,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    handle.flush()
                    os.fsync(handle.fileno())
            except FileExistsError as exc:  # Defensive if a non-cooperating writer races us.
                raise ApprovalDenied("approval token was already consumed for this run") from exc
        return consumed

    def _acquire_external_slot(self, action: ProposedAction) -> None:
        if not self._concurrency.acquire(blocking=False):
            reason = "concurrency budget exhausted"
            self.audit.record(
                "action",
                decision="denied",
                target=action.target,
                action=action.kind.value,
                reason=reason,
            )
            raise PolicyDenied(reason)

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        body: bytes | None = None,
        action_kind: ActionKind | None = None,
        approval: ApprovalToken | str | None = None,
        follow_redirects: bool = False,
        max_redirects: int = 0,
    ) -> tuple[HttpResponse, EvidenceRef]:
        method = method.upper()
        if action_kind is ActionKind.HTTP_GET and method not in {"GET", "HEAD"}:
            reason = "a non-read HTTP method cannot be classified as a safe read action"
            self.audit.record("http", decision="denied", target=url, reason=reason)
            raise PolicyDenied(reason)
        kind = action_kind or (
            ActionKind.HTTP_GET if method in {"GET", "HEAD"} else ActionKind.HTTP_POST
        )
        action = ProposedAction(kind=kind, target=url, method=method)
        # URL and resolved address are validated before reserve/transport.
        # Denied requests have zero egress.
        try:
            target = self.engine.resolve_url(url)
        except PolicyDenied as exc:
            self.audit.record("dns", decision="denied", target=url, reason=str(exc))
            raise
        self.audit.record(
            "dns",
            decision="allowed",
            target=target.host,
            connect_ip=target.connect_ip,
            scheme=target.scheme,
            port=target.port,
        )
        if self.transport is None:
            self.audit.record(
                "http", decision="denied", target=url, reason="no transport configured"
            )
            raise PolicyDenied("no HTTP transport configured")
        self._reserve(action, approval)
        safe_headers = dict(headers or {})
        safe_headers["Host"] = (
            target.host if target.port in {80, 443} else f"{target.host}:{target.port}"
        )
        request = HttpRequest(
            method=method,
            url=url,
            connect_ip=target.connect_ip,
            host_header=safe_headers["Host"],
            tls_server_name=target.host if target.scheme == "https" else None,
            headers=safe_headers,
            body=body,
            response_body_limit=self.engine.policy.evidence_capture_max_bytes,
        )
        self._acquire_external_slot(action)
        try:
            response = self.transport(request)
            while (
                follow_redirects
                and response.status_code in {301, 302, 303, 307, 308}
                and response.headers.get("Location")
            ):
                if max_redirects <= 0:
                    raise PolicyDenied("redirect limit reached")
                redirect_url = urljoin(url, response.headers["Location"])
                # The gateway performs scope/DNS validation before it can ever
                # connect to a redirect destination. A new action/token is still
                # required because redirect targets are action-bound.
                self.engine.resolve_url(redirect_url)
                # A redirect is a distinct target/action and must be authorised in a new call/token.
                raise PolicyDenied("redirects require a separately approved action")
        finally:
            self._concurrency.release()
        evidence = EvidenceRef(
            evidence_id=str(uuid.uuid4()),
            request_hash=_hash(
                {
                    "method": method,
                    "url": url,
                    "headers": safe_headers,
                    "body": body.hex() if body else "",
                }
            ),
            response_hash=_hash(
                {
                    "status": response.status_code,
                    "headers": dict(response.headers),
                    "body": response.body.hex(),
                }
            ),
            target=url,
            status_code=response.status_code,
        )
        # Persist only hashes and metadata.  Raw traffic remains outside the run
        # artifact contract so a report cannot accidentally disclose secrets.
        self.context.write_json(
            f"evidence/{evidence.evidence_id}.json",
            {
                "request_hash": evidence.request_hash,
                "response_hash": evidence.response_hash,
                "target": evidence.target,
                "status_code": evidence.status_code,
            },
            immutable=True,
        )
        self.audit.record(
            "http",
            decision="allowed",
            target=url,
            action=kind.value,
            evidence=evidence.request_hash,
        )
        return response, evidence

    def request_v2(
        self,
        method: str,
        url: str,
        *,
        execution: GatewayExecutionContext,
        headers: Mapping[str, str] | None = None,
        body: bytes | None = None,
        action_kind: ActionKind | None = None,
        approval: ApprovalToken | str | None = None,
    ) -> tuple[HttpResponse, EvidenceArtifactRef]:
        """Execute one task-bound request and commit an EvidenceArtifact V2.

        The evidence ID is allocated before approval consumption.  A V2 approval
        validator therefore persists a one-shot consumption already bound to the
        exact artifact that the subsequent network exchange must produce.
        """
        if self.evidence_store is None:
            raise ValueError("request_v2 requires an EvidenceStore")
        method = method.upper()
        if action_kind is ActionKind.HTTP_GET and method not in {"GET", "HEAD"}:
            reason = "a non-read HTTP method cannot be classified as a safe read action"
            self.audit.record("http", decision="denied", target=url, reason=reason)
            raise PolicyDenied(reason)
        kind = action_kind or (
            ActionKind.HTTP_GET if method in {"GET", "HEAD"} else ActionKind.HTTP_POST
        )
        action = ProposedAction(kind=kind, target=url, method=method)
        try:
            target = self.engine.resolve_url(url)
        except PolicyDenied as exc:
            self.audit.record("dns", decision="denied", target=url, reason=str(exc))
            raise
        self.audit.record(
            "dns",
            decision="allowed",
            target=target.host,
            connect_ip=target.connect_ip,
            scheme=target.scheme,
            port=target.port,
        )
        if self.transport is None:
            self.audit.record(
                "http", decision="denied", target=url, reason="no transport configured"
            )
            raise PolicyDenied("no HTTP transport configured")

        evidence_id = str(uuid.uuid4())
        consumption = self._reserve_v2(action, approval, execution, evidence_id)
        safe_headers = dict(headers or {})
        safe_headers["Host"] = (
            target.host if target.port in {80, 443} else f"{target.host}:{target.port}"
        )
        request = HttpRequest(
            method=method,
            url=url,
            connect_ip=target.connect_ip,
            host_header=safe_headers["Host"],
            tls_server_name=target.host if target.scheme == "https" else None,
            headers=safe_headers,
            body=body,
            response_body_limit=self.engine.policy.evidence_capture_max_bytes,
        )
        self._acquire_external_slot(action)
        try:
            response = self.transport(request)
        finally:
            self._concurrency.release()

        captured_at = datetime.now(UTC)
        binding = EvidenceBinding(
            evidence_id=evidence_id,
            run_id=self.context.run_id,
            scope_digest=self.context.scope_digest,
            task_id=execution.task_id,
            task_input_sha256=execution.task_input_sha256,
            role=execution.role,
            request_id=execution.request_id,
            action_id=execution.action_id,
            action_digest=action.digest,
            plan_digest=execution.plan_digest,
            approval_bundle_id=execution.approval_bundle_id,
            approval_bundle_digest=execution.approval_bundle_digest,
            approval_consumption_digest=(consumption.digest if consumption else None),
            captured_at=captured_at,
        )
        response_fields = response.header_fields or tuple(response.headers.items())
        artifact_ref = self.evidence_store.capture(
            binding=binding,
            request_method=method,
            request_url=url,
            request_headers=tuple(
                HeaderField(name=name, value=value) for name, value in safe_headers.items()
            ),
            request_body=body or b"",
            response_status=response.status_code,
            response_headers=tuple(
                HeaderField(name=name, value=value) for name, value in response_fields
            ),
            response_body=response.body,
            response_original_bytes=response.original_body_bytes,
            response_was_truncated=response.truncated,
        )
        manifest = self.evidence_store.verify(artifact_ref)
        self.audit.record(
            "http",
            decision="allowed",
            target=url,
            action=kind.value,
            evidence=artifact_ref.manifest_sha256,
            response_hash=manifest.response_hash,
        )
        return response, artifact_ref


class CommandGateway:
    """External command boundary. It is inert unless an executor is injected."""

    def __init__(self, *, gateway: ToolGateway, executor: CommandExecutor | None = None):
        self.gateway = gateway
        self.executor = executor

    def run(
        self, argv: Sequence[str], *, approval: ApprovalToken | str | None = None
    ) -> tuple[int, str, str]:
        if not argv or not argv[0]:
            raise PolicyDenied("command argv must be non-empty")
        executable = argv[0]
        action = ProposedAction(
            kind=ActionKind.COMMAND, target=f"command:{executable}", detail=" ".join(argv)
        )
        if executable not in self.gateway.engine.policy.allowed_commands:
            self.gateway.audit.record(
                "command",
                decision="denied",
                target=action.target,
                reason="command not in allowlist",
            )
            raise PolicyDenied("command is not explicitly allowed by scope")
        if self.executor is None:
            self.gateway.audit.record(
                "command", decision="denied", target=action.target, reason="no executor configured"
            )
            raise PolicyDenied("no command executor configured")
        self.gateway._reserve(action, approval)
        self.gateway._acquire_external_slot(action)
        try:
            result = self.executor(tuple(argv))
        finally:
            self.gateway._concurrency.release()
        self.gateway.audit.record(
            "command", decision="allowed", target=action.target, exit_code=result[0]
        )
        return result

"""Fail-closed ACP model provider over newline-delimited JSON-RPC stdio."""

from __future__ import annotations

import json
import os
import re
import selectors
import subprocess
import time
from collections.abc import Mapping, Sequence
from hashlib import sha256
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, Protocol

from pydantic import BaseModel, ValidationError

from hermes.domain_contracts import (
    AssetInventory,
    CandidateSet,
    EndpointInventory,
    GateDecisionV2,
    ReporterAcknowledgement,
    VerificationOutcome,
)
from hermes.domain_contracts_v3 import (
    AssetInventoryV3,
    BranchAssessment,
    CrossReviewSet,
    EndpointInventoryV3,
    GateDecisionV3,
    ReporterAckV3,
    VerificationOutcomeSet,
)
from hermes.domain_contracts_v4 import (
    AssetInventoryV4,
    BranchAssessmentV4,
    CrossReviewSetV4,
    GateDecisionV4,
    ReporterAckV4,
    SurfaceMapV4,
    VerificationOutcomeSetV4,
)
from hermes.r25_contracts import CapabilitySpecV2 as R25CapabilitySpecV2
from hermes.r25_contracts import ResearchFactsOutputV1
from hermes.runtime.agents import ModelRequest, TaskEnvelope
from hermes.runtime.agents.contracts import (
    ROLE_OUTPUT_CONTRACT_IDS,
    ROLE_OUTPUT_CONTRACT_IDS_R25,
    ROLE_OUTPUT_CONTRACT_IDS_V3,
    ROLE_OUTPUT_CONTRACT_IDS_V4,
)

if TYPE_CHECKING:
    from hermes.ledgers_v3 import BudgetLedger, BudgetReservation
    from hermes.ledgers_v4 import BudgetLedgerV4, BudgetReservationV4

    _BudgetLedger = BudgetLedger | BudgetLedgerV4
    _BudgetReservation = BudgetReservation | BudgetReservationV4

ROLE_PAYLOAD_MODELS: dict[str, type[BaseModel]] = {
    "gatekeeper": GateDecisionV2,
    "recon": AssetInventory,
    "mapper": EndpointInventory,
    "web-vuln": CandidateSet,
    "verifier": VerificationOutcome,
    "reporter": ReporterAcknowledgement,
}
ROLE_PAYLOAD_MODELS_V3: dict[str, type[BaseModel]] = {
    "gatekeeper": GateDecisionV3,
    "recon": AssetInventoryV3,
    "mapper": EndpointInventoryV3,
    "verifier": VerificationOutcomeSet,
    "reporter": ReporterAckV3,
}
ROLE_PAYLOAD_MODELS_V4: dict[str, type[BaseModel]] = {
    "gatekeeper": GateDecisionV4,
    "recon": AssetInventoryV4,
    "mapper": SurfaceMapV4,
    "verifier": VerificationOutcomeSetV4,
    "reporter": ReporterAckV4,
}
ROLE_PAYLOAD_MODELS_R25: dict[str, type[BaseModel]] = {
    "researcher": ResearchFactsOutputV1,
    "capability-planner": R25CapabilitySpecV2,
}
_V3_BRANCH_ROLES = {"web-vuln", "api", "authz", "infra"}
_V4_BRANCH_ROLES = {"web-vuln", "api", "authz", "infra"}
_R25_ROLES = {"researcher", "capability-planner"}
_DEFAULT_PROTOCOL_OUTPUT_BYTES = 8 * 1024 * 1024
_DEFAULT_STRUCTURED_OUTPUT_BYTES = 65_536
_STDERR_TAIL_BYTES = 65_536


def provider_metadata_authority_digest(value: Mapping[str, Any]) -> str:
    """Digest the non-circular provider identity echoed by Reporter.

    The complete metadata file contains the model output hash, so embedding its
    file hash in that same output is impossible.  This projection deliberately
    excludes output- and repair-dependent fields while binding the provider,
    versions, model, ACP session, run, task, prompt, and input.
    """

    fields = (
        "provider",
        "hermes_agent_version",
        "hermes_upstream",
        "acp_protocol",
        "agent_client_protocol",
        "model",
        "session_id",
        "run_id",
        "task_id",
        "prompt_sha256",
        "input_sha256",
    )
    projection = {field: value.get(field) for field in fields}
    if any(item is None for item in projection.values()):
        raise ProviderProtocolError("provider metadata authority projection is incomplete")
    return (
        "sha256:"
        + sha256(json.dumps(projection, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    )


class ProviderError(RuntimeError):
    """An isolated model provider could not complete a request."""


class ProviderProtocolError(ProviderError):
    """The ACP peer emitted malformed or unexpected protocol data."""


class ProviderDenied(ProviderError):
    """The ACP peer requested a capability that Hermes never grants."""


class ProviderBillingError(ProviderError):
    """The configured provider rejected the request for billing or entitlement."""


class ProviderBudgetError(ProviderError):
    """A V3 prompt was denied by the parent-owned conservative budget ledger."""


class ModelProvider(Protocol):
    """RunnerHost-compatible structured model-provider contract."""

    def __call__(self, request: ModelRequest, task: TaskEnvelope) -> Mapping[str, Any]: ...


class _AcpProcess:
    def __init__(
        self,
        command: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str],
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> None:
        self.deadline = time.monotonic() + timeout_seconds
        self.max_output_bytes = max_output_bytes
        self.stdout_bytes = 0
        self.pending = bytearray()
        self.stderr = bytearray()
        try:
            self.process = subprocess.Popen(
                tuple(command),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=cwd,
                env=dict(env),
                start_new_session=True,
            )
        except (OSError, ValueError) as exc:
            raise ProviderError(f"could not start ACP provider: {exc}") from exc
        if self.process.stdin is None or self.process.stdout is None or self.process.stderr is None:
            self.close()
            raise ProviderError("ACP provider has no stdio channels")
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.process.stdout, selectors.EVENT_READ, "stdout")
        self.selector.register(self.process.stderr, selectors.EVENT_READ, "stderr")

    def send(self, message: Mapping[str, Any]) -> None:
        assert self.process.stdin is not None
        encoded = json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode() + b"\n"
        try:
            self.process.stdin.write(encoded)
            self.process.stdin.flush()
        except OSError as exc:
            raise ProviderProtocolError("ACP provider closed stdin") from exc

    def receive(self) -> dict[str, Any]:
        while True:
            if b"\n" in self.pending:
                raw, _, remainder = self.pending.partition(b"\n")
                self.pending = bytearray(remainder)
                if not raw:
                    continue
                try:
                    value = json.loads(raw)
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise ProviderProtocolError("ACP provider emitted invalid JSON") from exc
                if not isinstance(value, dict) or value.get("jsonrpc") != "2.0":
                    raise ProviderProtocolError("ACP provider emitted a non-JSON-RPC message")
                return value
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise ProviderError("ACP provider timed out")
            events = self.selector.select(min(remaining, 0.1))
            if not events:
                if self.process.poll() is not None:
                    raise ProviderProtocolError("ACP provider exited before completing the request")
                continue
            for key, _ in events:
                chunk = os.read(key.fd, 4096)
                if not chunk:
                    self.selector.unregister(key.fileobj)
                    if key.data == "stdout" and not self.pending:
                        raise ProviderProtocolError("ACP provider closed stdout")
                    continue
                if key.data == "stdout":
                    self.stdout_bytes += len(chunk)
                    if self.stdout_bytes > self.max_output_bytes:
                        raise ProviderProtocolError("ACP stdout protocol limit exceeded")
                    self.pending.extend(chunk)
                else:
                    self._append_stderr(chunk)

    def drain_stderr(self) -> None:
        """Collect diagnostics already emitted when stdout completed first."""

        for key, _ in self.selector.select(0.05):
            if key.data != "stderr":
                continue
            chunk = os.read(key.fd, 4096)
            if not chunk:
                self.selector.unregister(key.fileobj)
                continue
            self._append_stderr(chunk)

    def _append_stderr(self, chunk: bytes) -> None:
        """Retain bounded diagnostics without charging them to the ACP protocol."""

        self.stderr.extend(chunk)
        if len(self.stderr) > _STDERR_TAIL_BYTES:
            del self.stderr[:-_STDERR_TAIL_BYTES]

    def close(self) -> None:
        selector = getattr(self, "selector", None)
        if selector is not None:
            selector.close()
        process = getattr(self, "process", None)
        if process is None or process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=1)


class HermesAcpProvider:
    """One-request-per-process ACP client for the restricted Hermes bridge."""

    def __init__(
        self,
        command: Sequence[str],
        *,
        run_dir: Path,
        env: Mapping[str, str] | None = None,
        timeout_seconds: float = 60,
        max_output_bytes: int = _DEFAULT_PROTOCOL_OUTPUT_BYTES,
        max_structured_output_bytes: int = _DEFAULT_STRUCTURED_OUTPUT_BYTES,
        model_name: str = "deepseek-v4-flash",
        budget_ledger: _BudgetLedger | None = None,
    ) -> None:
        if not command or any(not isinstance(part, str) or not part for part in command):
            raise ValueError("ACP provider command must be a non-empty argv sequence")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if max_output_bytes < 1024:
            raise ValueError("max_output_bytes must be at least 1024")
        if max_structured_output_bytes < 1024:
            raise ValueError("max_structured_output_bytes must be at least 1024")
        if max_structured_output_bytes > max_output_bytes:
            raise ValueError("max_structured_output_bytes cannot exceed max_output_bytes")
        if not model_name or len(model_name) > 256:
            raise ValueError("model_name must be a non-empty bounded identifier")
        root = run_dir.resolve()
        if not root.is_dir():
            raise ValueError("run_dir must already exist")
        self.command = tuple(command)
        self.run_dir = root
        self.timeout_seconds = timeout_seconds
        self.max_output_bytes = max_output_bytes
        self.max_structured_output_bytes = max_structured_output_bytes
        self.model_name = model_name
        self.budget_ledger = budget_ledger
        self.env = {"PATH": os.defpath, "PYTHONUNBUFFERED": "1", **dict(env or {})}

    def handle(self, request: ModelRequest, task: TaskEnvelope) -> Mapping[str, Any]:
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", task.task_id) is None:
            raise ProviderProtocolError("task_id is not safe for ACP session isolation")
        budget_reservations: list[_BudgetReservation] = []
        if task.version in {"3", "4"}:
            budget_reservations.append(
                self._reserve_budget(
                    task,
                    "reporter" if task.role == "reporter" else "initial",
                )
            )
        task_env = {**self.env, "HERMES_ACP_TASK_ID": task.task_id}
        try:
            process = _AcpProcess(
                self.command,
                cwd=self.run_dir,
                env=task_env,
                timeout_seconds=min(self.timeout_seconds, task.timeout_seconds),
                max_output_bytes=self.max_output_bytes,
            )
        except Exception:
            self._settle_budget_reservations(budget_reservations)
            raise
        chunks: list[str] = []
        prompt_attempts = 1
        try:
            self._request(
                process,
                1,
                "initialize",
                {
                    "protocolVersion": 1,
                    "clientInfo": {"name": "hermes-security-team", "version": "0.1.0"},
                    "clientCapabilities": {},
                },
                chunks,
            )
            session = self._request(
                process, 2, "session/new", {"cwd": str(self.run_dir), "mcpServers": []}, chunks
            )
            session_id = session.get("sessionId")
            if not isinstance(session_id, str) or not session_id:
                raise ProviderProtocolError("ACP session/new omitted sessionId")
            prompt_input = dict(request.input)
            # Reporter acknowledgements bind the fresh ACP session.  The
            # provider derives that authority after session/new, so schema
            # validation must use the same parent-authored input that is sent
            # to the model rather than the immutable pre-session request.
            validation_request = request
            if task.version in {"3", "4"} and task.role == "reporter":
                authority = {
                    "provider": "hermes-acp-restricted",
                    "hermes_agent_version": "0.16.0",
                    "hermes_upstream": "dcc32169",
                    "acp_protocol": 1,
                    "agent_client_protocol": "0.9.0",
                    "model": self.model_name,
                    "session_id": session_id,
                    "run_id": task.run_id,
                    "task_id": task.task_id,
                    "prompt_sha256": request.input.get("prompt_sha256"),
                    "input_sha256": "sha256:"
                    + sha256(request.model_dump_json().encode()).hexdigest(),
                }
                prompt_input["provider_metadata_authority_digest"] = (
                    provider_metadata_authority_digest(authority)
                )
                validation_request = request.model_copy(update={"input": prompt_input})
            prompt = json.dumps(
                {
                    "contract": {
                        "instruction": (
                            "Return only one JSON payload matching this exact schema. "
                            "Do not add a function, payload, result, or envelope wrapper. "
                            "Do not call tools."
                        ),
                        "contract_id": self._contract_id(request, task),
                        "json_schema": self._payload_schema(task),
                    },
                    "operation": request.operation,
                    "input": prompt_input,
                    "run_id": task.run_id,
                    "task_id": task.task_id,
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            prompt_result = self._request(
                process,
                3,
                "session/prompt",
                {"sessionId": session_id, "prompt": [{"type": "text", "text": prompt}]},
                chunks,
            )
            first_text = self._structured_text(chunks)
            self._raise_known_provider_failure(process, first_text)
            try:
                result = self._parse_structured_json(first_text)
            except json.JSONDecodeError:
                result = None
            schema_error = self._schema_error(result, validation_request, task)
            if schema_error is not None:
                prompt_attempts = 2
                if task.version in {"3", "4"}:
                    budget_reservations.append(self._reserve_budget(task, "schema_repair"))
                chunks.clear()
                try:
                    repair_result = self._request(
                        process,
                        4,
                        "session/prompt",
                        {
                            "sessionId": session_id,
                            "prompt": [
                                {
                                    "type": "text",
                                    "text": (
                                        "Schema repair only. Return only the corrected "
                                        "payload JSON. Do not add function, payload, result, "
                                        "or envelope wrappers. Do not call tools. All string "
                                        "enums and the version string must "
                                        "match exactly. Validation error: "
                                        f"{schema_error[:2000]}. Exact JSON schema: "
                                        f"{json.dumps(self._payload_schema(task), sort_keys=True)}"
                                    ),
                                }
                            ],
                        },
                        chunks,
                    )
                except ProviderError as exc:
                    raise ProviderProtocolError("ACP structured JSON schema repair failed") from exc
                repair_text = self._structured_text(chunks)
                try:
                    result = self._parse_structured_json(repair_text)
                except json.JSONDecodeError as exc:
                    raise ProviderProtocolError(
                        "ACP response failed its single schema-repair attempt; "
                        f"first={first_text[:300]!r}; repair={repair_text[:300]!r}; "
                        f"first_stop={prompt_result!r}; repair_stop={repair_result!r}; "
                        "bridge_stderr="
                        f"{process.stderr.decode('utf-8', errors='replace')[-1000:]!r}"
                    ) from exc
            schema_error = self._schema_error(result, validation_request, task)
            if schema_error is not None:
                raise ProviderProtocolError(
                    f"ACP response failed its structured output contract: {schema_error[:1000]}"
                )
            result = self._normalize_result(result, validation_request, task)
            self._record_metadata(
                task,
                request,
                session_id,
                result,
                prompt_attempts=prompt_attempts,
                budget_reservations=budget_reservations,
            )
            return result
        except ProviderError as exc:
            self._record_failure(task, request, exc)
            raise
        finally:
            process.close()
            self._settle_budget_reservations(budget_reservations)

    def __call__(self, request: ModelRequest, task: TaskEnvelope) -> Mapping[str, Any]:
        result = dict(self.handle(request, task))
        if (
            isinstance(result.get("result"), dict)
            and result.get("status") in {"completed", "blocked", "failed"}
            and isinstance(result.get("evidence_ref_ids"), list)
        ):
            return result
        evidence = request.input.get("evidence_refs", [])
        artifact_evidence = request.input.get("evidence_artifact_refs", [])
        evidence_ids = [
            item["id"]
            for item in evidence
            if isinstance(item, dict) and isinstance(item.get("id"), str)
        ]
        evidence_ids.extend(
            item["evidence_id"]
            for item in artifact_evidence
            if isinstance(item, dict) and isinstance(item.get("evidence_id"), str)
        )
        domain_result = (
            result["result"]
            if set(result) == {"result"} and isinstance(result["result"], dict)
            else result
        )
        return {
            "status": "completed",
            "result": domain_result,
            "evidence_ref_ids": evidence_ids,
        }

    def _structured_text(self, chunks: Sequence[str]) -> str:
        text = "".join(chunks).strip()
        if len(text.encode("utf-8")) > self.max_structured_output_bytes:
            raise ProviderProtocolError("ACP structured response limit exceeded")
        return text

    @staticmethod
    def _parse_structured_json(text: str) -> object:
        """Parse one bounded JSON document, accepting only a JSON code fence.

        Some compliant ACP providers wrap an otherwise valid structured payload
        in `````json`` despite the output instruction.  Accepting that single
        presentation form avoids wasting the one permitted schema repair, while
        still rejecting prose, multiple documents, and every non-JSON wrapper.
        """

        candidate = text.strip()
        if candidate.startswith("```json\n") and candidate.endswith("\n```"):
            candidate = candidate[len("```json\n") : -len("\n```")]
        return json.loads(candidate)

    @staticmethod
    def _valid_result(value: object) -> bool:
        return isinstance(value, dict)

    @classmethod
    def _schema_error(cls, value: object, request: ModelRequest, task: TaskEnvelope) -> str | None:
        if not cls._valid_result(value):
            return "response is not a JSON object"
        prompt_version = request.input.get("prompt_version")
        if not cls._supported_prompt_version(prompt_version):
            return None
        assert isinstance(value, dict)
        value = cls._bind_non_authoritative_fields(value, request, task)
        model = cls._payload_model(request, task)
        if model is None:
            return f"role {task.role!r} has no registered structured output contract"
        try:
            model.model_validate(value)
        except ValidationError as exc:
            return str(exc)
        return None

    @classmethod
    def _payload_schema(cls, task: TaskEnvelope) -> dict[str, Any]:
        prompt_version = task.payload.get("prompt_version")
        request_like = {"prompt_version": prompt_version}
        model = cls._payload_model_from_values(request_like, task)
        if model is None:
            # The role runtime supplies prompt identity in ModelRequest, while older
            # callers keep it only in the request. Fall back to operation-aware V3
            # task metadata before rejecting the task.
            model = (
                cls._v3_payload_model(task)
                if task.version == "3"
                else cls._v4_payload_model(task)
                if task.version == "4"
                else ROLE_PAYLOAD_MODELS_R25.get(task.role)
                if task.version == "25"
                else ROLE_PAYLOAD_MODELS.get(task.role)
            )
        if model is None:
            raise ProviderProtocolError(
                f"role {task.role!r} has no registered structured output contract"
            )
        return model.model_json_schema()

    @staticmethod
    def _normalize_result(
        value: object, request: ModelRequest, task: TaskEnvelope
    ) -> dict[str, Any]:
        if not isinstance(value, dict):  # pragma: no cover - checked by _schema_error
            raise ProviderProtocolError("ACP response is not a JSON object")
        if not HermesAcpProvider._supported_prompt_version(request.input.get("prompt_version")):
            return value
        value = HermesAcpProvider._bind_non_authoritative_fields(value, request, task)
        model = HermesAcpProvider._payload_model(request, task)
        if model is None:  # pragma: no cover - checked by _schema_error
            raise ProviderProtocolError(
                f"role {task.role!r} has no registered structured output contract"
            )
        return model.model_validate(value).model_dump(mode="json")

    @staticmethod
    def _bind_non_authoritative_fields(
        value: Mapping[str, Any], request: ModelRequest, task: TaskEnvelope
    ) -> dict[str, Any]:
        """Bind parent-owned V3/V4 authority before schema validation.

        The model has no authority over the run, scope, approved campaign or
        approval batch.  Verifier responses are nevertheless typed as a full
        contract, so normalise exactly those outer claims from the immutable
        TaskEnvelope before validating.  Candidate/action/evidence fields stay
        model-provided and are checked later against the governed gateway.
        """

        normalized = dict(value)
        if task.version == "4":
            # Roles may reason over the supplied facts, but they never own the
            # identity of the governed run, scope, or task that produced a
            # handoff.  Normalising those fields prevents a plausible-looking
            # model response from crossing a run boundary.
            normalized.update(
                {
                    "run_id": task.run_id,
                    "scope_digest": task.scope_digest,
                    "generated_by_task_id": task.task_id,
                }
            )
            payload = task.payload
            target = payload.get("target")
            if task.role in {"gatekeeper", "recon"} and isinstance(target, str):
                normalized["target"] = target
            if task.role in _V4_BRANCH_ROLES:
                branch = payload.get("branch")
                if isinstance(branch, str):
                    normalized["branch"] = branch
            if task.role == "verifier":
                campaign_digest = payload.get("campaign_digest")
                approval_batch_digests = payload.get("approval_batch_digests")
                candidate_id = payload.get("candidate_id")
                if (
                    not isinstance(campaign_digest, str)
                    or not isinstance(approval_batch_digests, list)
                    or not isinstance(candidate_id, str)
                ):
                    raise ProviderProtocolError("V4 verifier task omitted parent-owned authority")
                normalized.update(
                    {
                        "outcome_set_id": f"phase5-outcomes-{candidate_id}",
                        "campaign_digest": campaign_digest,
                        "approval_batch_digests": approval_batch_digests,
                    }
                )
            if task.role == "reporter":
                for key in (
                    "reporter_launch_receipt_digest",
                    "quality_gate_digest",
                    "finding_set_digest",
                    "coverage_appendix_digest",
                ):
                    if not isinstance(payload.get(key), str):
                        raise ProviderProtocolError("V4 reporter task omitted preflight authority")
                provider_digest = request.input.get("provider_metadata_authority_digest")
                if not isinstance(provider_digest, str):
                    raise ProviderProtocolError("V4 reporter metadata authority is missing")
                normalized.update(
                    {
                        "launch_receipt_digest": payload["reporter_launch_receipt_digest"],
                        "quality_gate_digest": payload["quality_gate_digest"],
                        "finding_set_digest": payload["finding_set_digest"],
                        "coverage_appendix_digest": payload["coverage_appendix_digest"],
                        "provider_metadata_digest": provider_digest,
                        "accepted": True,
                    }
                )
            return normalized
        if task.version != "3" or task.role != "verifier":
            return normalized
        campaign_digest = task.payload.get("campaign_digest")
        approval_batch_digest = task.payload.get("approval_batch_digest")
        if not isinstance(campaign_digest, str) or not isinstance(approval_batch_digest, str):
            raise ProviderProtocolError("V3 verifier task omitted parent-owned authority")
        normalized.update(
            {
                "run_id": task.run_id,
                "scope_digest": task.scope_digest,
                "generated_by_task_id": task.task_id,
                "campaign_digest": campaign_digest,
                "approval_batch_digests": [approval_batch_digest],
            }
        )
        return normalized

    @classmethod
    def _payload_model(cls, request: ModelRequest, task: TaskEnvelope) -> type[BaseModel] | None:
        return cls._payload_model_from_values(request.input, task)

    @staticmethod
    def _supported_prompt_version(value: object) -> bool:
        return value == "2.0" or (
            isinstance(value, str)
            and (
                re.fullmatch(r"3\.[0-9]+", value) is not None
                or re.fullmatch(r"4\.[0-9]+", value) is not None
                or re.fullmatch(r"25\.[0-9]+", value) is not None
            )
        )

    @classmethod
    def _payload_model_from_values(
        cls, values: Mapping[str, Any], task: TaskEnvelope
    ) -> type[BaseModel] | None:
        if task.version == "25" or values.get("prompt_version") == "25.0":
            return ROLE_PAYLOAD_MODELS_R25.get(task.role)
        if values.get("prompt_version") == "4.0" or task.version == "4":
            return cls._v4_payload_model(task)
        if values.get("prompt_version") == "3.0" or task.version == "3":
            return cls._v3_payload_model(task)
        return ROLE_PAYLOAD_MODELS.get(task.role)

    @staticmethod
    def _v3_payload_model(task: TaskEnvelope) -> type[BaseModel] | None:
        if task.role in _V3_BRANCH_ROLES:
            operation = task.payload.get("operation")
            if operation == "assessment":
                return BranchAssessment
            if operation == "cross_review":
                return CrossReviewSet
            return None
        return ROLE_PAYLOAD_MODELS_V3.get(task.role)

    @staticmethod
    def _v4_payload_model(task: TaskEnvelope) -> type[BaseModel] | None:
        if task.role in _V4_BRANCH_ROLES:
            operation = task.payload.get("operation")
            if operation == "assessment":
                return BranchAssessmentV4
            if operation == "cross_review":
                return CrossReviewSetV4
            return None
        return ROLE_PAYLOAD_MODELS_V4.get(task.role)

    @classmethod
    def _contract_id(cls, request: ModelRequest, task: TaskEnvelope) -> str | None:
        if task.version == "25" or request.input.get("prompt_version") == "25.0":
            return ROLE_OUTPUT_CONTRACT_IDS_R25.get(task.role)
        if request.input.get("prompt_version") == "4.0" or task.version == "4":
            if task.role in _V4_BRANCH_ROLES:
                return {
                    "assessment": "hermes.branch_operation/v4",
                    "cross_review": "hermes.cross_review_set/v4",
                }.get(str(task.payload.get("operation")))
            return ROLE_OUTPUT_CONTRACT_IDS_V4.get(task.role)
        if request.input.get("prompt_version") != "3.0" and task.version != "3":
            return ROLE_OUTPUT_CONTRACT_IDS.get(task.role)
        if task.role in _V3_BRANCH_ROLES:
            return {
                "assessment": "hermes.branch_assessment/v3",
                "cross_review": "hermes.cross_review_set/v3",
            }.get(str(task.payload.get("operation")))
        return ROLE_OUTPUT_CONTRACT_IDS_V3.get(task.role)

    @staticmethod
    def _raise_known_provider_failure(process: _AcpProcess, response_text: str) -> None:
        process.drain_stderr()
        diagnostic = process.stderr.decode("utf-8", errors="replace")
        if not response_text and (
            "Insufficient Balance" in diagnostic
            or "HTTP 402" in diagnostic
            or "billing, credits, or account entitlement is exhausted" in diagnostic
        ):
            raise ProviderBillingError(
                "configured Hermes provider has insufficient balance or entitlement"
            )

    def _record_metadata(
        self,
        task: TaskEnvelope,
        request: ModelRequest,
        session_id: str,
        result: Mapping[str, Any],
        *,
        prompt_attempts: int,
        budget_reservations: Sequence[_BudgetReservation] = (),
    ) -> None:
        provider_dir = self.run_dir / "provider"
        provider_dir.mkdir(exist_ok=True)
        prompt_hash = request.input.get("prompt_sha256")
        value = {
            "provider": "hermes-acp-restricted",
            "hermes_agent_version": "0.16.0",
            "hermes_upstream": "dcc32169",
            "acp_protocol": 1,
            "agent_client_protocol": "0.9.0",
            "model": self.model_name,
            "session_id": session_id,
            "run_id": task.run_id,
            "task_id": task.task_id,
            "prompt_attempts": prompt_attempts,
            "prompt_sha256": prompt_hash,
            "input_sha256": "sha256:" + sha256(request.model_dump_json().encode()).hexdigest(),
            "output_sha256": (
                "sha256:"
                + sha256(
                    json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
                ).hexdigest()
            ),
            "token_usage": None,
            "budget_reservations": [
                {
                    "reservation_id": item.reservation_id,
                    "attempt_kind": item.attempt_kind,
                    "attempt_number": item.attempt_number,
                    "reserved_microusd": item.reserved_microusd,
                }
                for item in budget_reservations
            ],
        }
        if task.version in {"3", "4"}:
            value["authority_digest"] = provider_metadata_authority_digest(value)
        path = provider_dir / f"{task.task_id}.json"
        try:
            with path.open("x", encoding="utf-8") as handle:
                json.dump(value, handle, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        except FileExistsError as exc:
            raise ProviderProtocolError("provider metadata already exists for this task") from exc

    def _record_failure(
        self, task: TaskEnvelope, request: ModelRequest, error: ProviderError
    ) -> None:
        failure_dir = self.run_dir / "provider" / "failures"
        failure_dir.mkdir(parents=True, exist_ok=True)
        value = {
            "provider": "hermes-acp-restricted",
            "run_id": task.run_id,
            "task_id": task.task_id,
            "prompt_sha256": request.input.get("prompt_sha256"),
            "error_type": type(error).__name__,
            "error": str(error)[:1000],
        }
        path = failure_dir / f"{task.task_id}.json"
        try:
            with path.open("x", encoding="utf-8") as handle:
                json.dump(value, handle, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        except FileExistsError:
            return

    def _reserve_budget(
        self,
        task: TaskEnvelope,
        attempt_kind: Literal["initial", "schema_repair", "reporter"],
    ) -> _BudgetReservation:
        if self.budget_ledger is None:
            raise ProviderBudgetError("governed ACP task has no parent BudgetLedger")
        try:
            return self.budget_ledger.reserve_prompt(
                task_id=task.task_id,
                role=task.role,
                attempt_kind=attempt_kind,
                reservation_id=f"{task.task_id}:{attempt_kind}",
            )
        except Exception as exc:
            raise ProviderBudgetError("governed model budget reservation was denied") from exc

    def _settle_budget_reservations(self, reservations: Sequence[_BudgetReservation]) -> None:
        if self.budget_ledger is None:
            return
        for reservation in reservations:
            self.budget_ledger.settle(
                reservation.reservation_id,
                token_usage=None,
                actual_cost_microusd=None,
            )

    def _request(
        self,
        process: _AcpProcess,
        request_id: int,
        method: str,
        params: Mapping[str, Any],
        chunks: list[str],
    ) -> dict[str, Any]:
        process.send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
        while True:
            message = process.receive()
            if "method" in message:
                self._handle_peer_message(process, message, chunks)
                continue
            if message.get("id") != request_id:
                raise ProviderProtocolError("ACP response id did not match the request")
            if "error" in message:
                raise ProviderError(f"ACP {method} request failed")
            result = message.get("result")
            if not isinstance(result, dict):
                raise ProviderProtocolError(f"ACP {method} returned a non-object result")
            return result

    @staticmethod
    def _handle_peer_message(
        process: _AcpProcess, message: dict[str, Any], chunks: list[str]
    ) -> None:
        method = message.get("method")
        if not isinstance(method, str):
            raise ProviderProtocolError("ACP peer message omitted method")
        if "id" in message:
            if method == "session/request_permission":
                process.send(
                    {
                        "jsonrpc": "2.0",
                        "id": message["id"],
                        "result": {"outcome": {"outcome": "cancelled"}},
                    }
                )
            else:
                process.send(
                    {
                        "jsonrpc": "2.0",
                        "id": message["id"],
                        "error": {"code": -32601, "message": "capability not available"},
                    }
                )
            raise ProviderDenied(f"ACP peer requested forbidden capability {method!r}")
        if method != "session/update":
            raise ProviderProtocolError(f"unexpected ACP notification {method!r}")
        params = message.get("params")
        update = params.get("update") if isinstance(params, dict) else None
        if not isinstance(update, dict):
            raise ProviderProtocolError("ACP session/update omitted a structured update")
        kind = update.get("sessionUpdate")
        if isinstance(kind, str) and kind.startswith("tool_call"):
            raise ProviderDenied("ACP peer attempted a forbidden tool call")
        if kind == "agent_message_chunk":
            content = update.get("content")
            text = content.get("text") if isinstance(content, dict) else None
            if not isinstance(text, str):
                raise ProviderProtocolError("ACP agent message chunk omitted text")
            chunks.append(text)

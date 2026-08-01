"""Versioned, minimal contracts for independently executed Hermes roles.

These envelopes deliberately contain no policy controls or credentials.  A role may
describe an action, but executing it remains the responsibility of the gateway.
"""

from __future__ import annotations

import json
from base64 import urlsafe_b64decode
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    TypeAdapter,
    ValidationError,
    field_validator,
    model_validator,
)

from ...domain_contracts import ContractEnvelope
from ...domain_contracts_v3 import ContractEnvelopeV3
from ...domain_contracts_v4 import ContractEnvelopeV4
from ...evidence import EvidenceArtifactRef
from ...r25_contracts import ContractEnvelopeR25
from ...security import KeyUsage, TrustStoreV2
from ..actions import ProposedAction

PROTOCOL_VERSION = "1"
HandoffStatus = Literal["completed", "failed", "blocked"]
IpcKind = Literal["gateway_action", "model_request"]
FailureLayer = Literal["docker", "runtime", "ipc", "gateway", "provider", "schema", "workflow"]
TransportState = Literal["not_attempted", "attempted", "unknown"]
ApprovalState = Literal["not_required", "not_consumed", "consumed", "unknown"]
ROLE_OUTPUT_CONTRACT_IDS: dict[str, str] = {
    "gatekeeper": "hermes.gate_decision/v2",
    "recon": "hermes.asset_inventory/v2",
    "mapper": "hermes.endpoint_inventory/v2",
    "web-vuln": "hermes.candidate_set/v2",
    "verifier": "hermes.verification_outcome/v2",
    "reporter": "hermes.reporter_acknowledgement/v2",
}
ROLE_OUTPUT_CONTRACT_IDS_V3: dict[str, str] = {
    "gatekeeper": "hermes.gate_decision/v3",
    "recon": "hermes.asset_inventory/v3",
    "mapper": "hermes.endpoint_inventory/v3",
    "web-vuln": "hermes.branch_operation/v3",
    "api": "hermes.branch_operation/v3",
    "authz": "hermes.branch_operation/v3",
    "infra": "hermes.branch_operation/v3",
    "verifier": "hermes.verification_outcome_set/v3",
    "reporter": "hermes.reporter_acknowledgement/v3",
}
ROLE_OUTPUT_CONTRACT_IDS_V4: dict[str, str] = {
    "gatekeeper": "hermes.gate_decision/v4",
    "recon": "hermes.asset_inventory/v4",
    "mapper": "hermes.surface_map/v4",
    "web-vuln": "hermes.branch_operation/v4",
    "api": "hermes.branch_operation/v4",
    "authz": "hermes.branch_operation/v4",
    "infra": "hermes.branch_operation/v4",
    "verifier": "hermes.verification_outcome_set/v4",
    "reporter": "hermes.reporter_acknowledgement/v4",
}
ROLE_OUTPUT_CONTRACT_IDS_R25: dict[str, str] = {
    "researcher": "hermes.r25.research_facts/v1",
    "capability-planner": "hermes.r25.capability_spec/v2",
}
_V3_BRANCH_ROLES = {"web-vuln", "api", "authz", "infra"}
_V4_BRANCH_ROLES = {"web-vuln", "api", "authz", "infra"}
_R25_ROLES = {"researcher", "capability-planner"}


def canonical_json_hash(value: Any) -> str:
    """Return the stable SHA-256 used to link task input and returned handoffs."""
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return f"sha256:{sha256(encoded.encode('utf-8')).hexdigest()}"


class EvidenceRef(BaseModel):
    """A redacted evidence pointer; raw HTTP material never belongs in a handoff."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(min_length=1, max_length=160)
    kind: Literal["request", "response", "log", "fixture", "artifact", "other"]
    sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    path: str = Field(min_length=1, max_length=512)
    redacted: bool = True


class TaskEnvelope(BaseModel):
    """The complete input handed to one role invocation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1", "3", "4", "25"] = "1"
    run_id: str = Field(min_length=1, max_length=128)
    task_id: str = Field(min_length=1, max_length=128)
    role: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    scope_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    payload: dict[str, Any] = Field(default_factory=dict)
    evidence_refs: tuple[EvidenceRef, ...] = ()
    evidence_artifact_refs: tuple[EvidenceArtifactRef, ...] = ()
    allowed_actions: tuple[str, ...] = ()
    request_budget: int = Field(default=0, ge=0, le=1_000)
    evidence_required: bool = False
    timeout_seconds: int = Field(default=60, ge=1, le=3600)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def input_hash(self) -> str:
        """Hash only the replay-relevant task contract, never its creation timestamp."""
        return canonical_json_hash(self.model_dump(mode="json", exclude={"created_at"}))


class HandoffEnvelope(BaseModel):
    """A role's externally produced, validated response."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1", "2", "3", "4", "25"] = "1"
    run_id: str = Field(min_length=1, max_length=128)
    task_id: str = Field(min_length=1, max_length=128)
    role: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    scope_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    input_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    status: HandoffStatus
    result: (
        ContractEnvelope
        | ContractEnvelopeV3
        | ContractEnvelopeV4
        | ContractEnvelopeR25
        | dict[str, Any]
    ) = Field(default_factory=dict)
    evidence_refs: tuple[EvidenceRef, ...] = ()
    evidence_artifact_refs: tuple[EvidenceArtifactRef, ...] = ()
    error: str | None = Field(default=None, max_length=2000)
    process_id: int | None = Field(default=None, ge=1)
    container_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9._-]{1,128}$")
    completed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @model_validator(mode="before")
    @classmethod
    def _restore_typed_contract_from_python_dict(cls, value: Any) -> Any:
        """Make JSON and decoded artifact replay choose the same typed union branch."""

        if not isinstance(value, dict) or value.get("version") not in {"2", "3", "4", "25"}:
            return value
        result = value.get("result")
        if not isinstance(result, dict):
            return value
        try:
            contract = (
                ContractEnvelope.model_validate(result)
                if value.get("version") == "2"
                else ContractEnvelopeR25.model_validate(result)
                if value.get("version") == "25"
                else ContractEnvelopeV4.model_validate(result)
                if value.get("version") == "4"
                else ContractEnvelopeV3.model_validate(result)
            )
        except ValidationError:
            return value
        restored = dict(value)
        restored["result"] = contract
        return restored

    @model_validator(mode="after")
    def _status_has_consistent_payload(self) -> HandoffEnvelope:
        if self.status == "completed" and self.error is not None:
            raise ValueError("completed handoffs cannot include an error")
        if self.status != "completed" and not self.error:
            raise ValueError("failed or blocked handoffs must explain the failure")
        if self.version == "2" and self.status == "completed":
            if not isinstance(self.result, ContractEnvelope):
                raise ValueError("completed V2 handoffs require a typed ContractEnvelope")
            expected = ROLE_OUTPUT_CONTRACT_IDS.get(self.role)
            if expected is None or self.result.contract_id != expected:
                raise ValueError("V2 handoff result contract does not match its role")
        if self.version == "3" and self.status == "completed":
            if not isinstance(self.result, ContractEnvelopeV3):
                raise ValueError("completed V3 handoffs require a typed ContractEnvelopeV3")
            expected = ROLE_OUTPUT_CONTRACT_IDS_V3.get(self.role)
            if expected is None:
                raise ValueError("V3 handoff role is not registered")
            if self.role in _V3_BRANCH_ROLES:
                if self.result.contract_id not in {
                    "hermes.branch_assessment/v3",
                    "hermes.cross_review_set/v3",
                }:
                    raise ValueError("V3 branch handoff returned an invalid operation contract")
            elif self.result.contract_id != expected:
                raise ValueError("V3 handoff result contract does not match its role")
        if self.version == "4" and self.status == "completed":
            if not isinstance(self.result, ContractEnvelopeV4):
                raise ValueError("completed V4 handoffs require a typed ContractEnvelopeV4")
            expected = ROLE_OUTPUT_CONTRACT_IDS_V4.get(self.role)
            if expected is None:
                raise ValueError("V4 handoff role is not registered")
            if self.role in _V4_BRANCH_ROLES:
                if self.result.contract_id not in {
                    "hermes.branch_operation/v4",
                    "hermes.cross_review_set/v4",
                }:
                    raise ValueError("V4 branch handoff returned an invalid operation contract")
            elif self.result.contract_id != expected:
                raise ValueError("V4 handoff result contract does not match its role")
        if self.version == "25" and self.status == "completed":
            if not isinstance(self.result, ContractEnvelopeR25):
                raise ValueError("completed R2.5 handoffs require a typed ContractEnvelopeR25")
            expected = ROLE_OUTPUT_CONTRACT_IDS_R25.get(self.role)
            if expected is None or self.result.contract_id != expected:
                raise ValueError("R2.5 handoff result contract does not match its role")
        return self


class TaskResult(BaseModel):
    """Lifecycle record owned by the runner, rather than supplied by an agent."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    task: TaskEnvelope
    handoff: HandoffEnvelope | None = None
    lifecycle: Literal["completed", "failed", "timed_out", "invalid_handoff"]
    input_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    output_sha256: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    started_at: datetime
    finished_at: datetime
    stdout_sha256: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    stderr_sha256: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    error: str | None = Field(default=None, max_length=2000)
    host_process_id: int | None = Field(default=None, ge=1)
    failure_layer: FailureLayer | None = None
    failure_code: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_]{0,127}$")
    retryable: bool | None = None
    exit_code: int | None = None
    request_id: str | None = Field(default=None, max_length=128)
    transport_state: TransportState | None = None
    approval_state: ApprovalState | None = None

    @field_validator("finished_at")
    @classmethod
    def _finish_after_start(cls, value: datetime, info: Any) -> datetime:
        start = info.data.get("started_at")
        if start is not None and value < start:
            raise ValueError("finished_at must not precede started_at")
        return value


class RoleManifestError(RuntimeError):
    """Raised when a role manifest is malformed, unknown, or not trusted."""


class SandboxLimits(BaseModel):
    """Upper bounds applied by the isolated role container."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    timeout_seconds: int = Field(default=60, ge=1, le=3600)
    cpu_count: float = Field(default=1.0, gt=0, le=8)
    memory_mib: int = Field(default=256, ge=64, le=4096)
    pids_limit: int = Field(default=64, ge=8, le=512)
    nofile_limit: int = Field(default=128, ge=32, le=4096)
    max_output_bytes: int = Field(default=65_536, ge=256, le=1_048_576)
    tmpfs_mib: int = Field(default=16, ge=1, le=256)


class RoleManifest(BaseModel):
    """A signed declaration of exactly one role's executable authority."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"] = "1"
    protocol_version: Literal["1"] = "1"
    role: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    prompt_id: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9._/-]{0,127}$")
    prompt_version: str | None = Field(default=None, pattern=r"^[0-9]+(?:\.[0-9]+){0,2}$")
    prompt_sha256: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    output_contract_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9._/-]{1,160}$")
    signed_at: datetime | None = None
    image: str = Field(min_length=1, max_length=512)
    command: tuple[str, ...] = Field(min_length=1, max_length=32)
    allowed_ipc: tuple[IpcKind, ...] = ()
    input_schema: str = Field(default="task-envelope/v1", min_length=1, max_length=160)
    output_schema: str = Field(default="handoff-envelope/v1", min_length=1, max_length=160)
    limits: SandboxLimits = Field(default_factory=SandboxLimits)
    key_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$")
    signature: str = Field(min_length=1, max_length=512)

    @field_validator("image")
    @classmethod
    def _requires_digest_pinned_image(cls, value: str) -> str:
        if value.startswith("sha256:"):
            digest = value.removeprefix("sha256:")
            if len(digest) == 64 and all(char in "0123456789abcdef" for char in digest):
                return value
        prefix, marker, digest = value.rpartition("@sha256:")
        valid_digest = len(digest) == 64 and all(char in "0123456789abcdef" for char in digest)
        if not prefix or not marker or not valid_digest:
            raise ValueError("role manifests require an immutable image sha256 ID or repo digest")
        return value

    @field_validator("command")
    @classmethod
    def _requires_clean_argv(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not part or "\x00" in part for part in value):
            raise ValueError("role command must be a non-empty argv without NUL bytes")
        return value

    @field_validator("signed_at")
    @classmethod
    def _signed_at_is_aware(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError("manifest signed_at must be timezone-aware")
        return value

    @model_validator(mode="after")
    def _v2_prompt_binds_output_contract(self) -> RoleManifest:
        if self.prompt_version is not None and self.prompt_version.split(".", 1)[0] == "2":
            expected = ROLE_OUTPUT_CONTRACT_IDS.get(self.role)
            if expected is None or self.output_contract_id != expected:
                raise ValueError("V2 role manifest must bind its registered output contract")
        if self.prompt_version is not None and self.prompt_version.split(".", 1)[0] == "3":
            expected_v3 = ROLE_OUTPUT_CONTRACT_IDS_V3.get(self.role)
            if expected_v3 is None or self.output_contract_id != expected_v3:
                raise ValueError("V3 role manifest must bind its registered output contract")
        if self.prompt_version is not None and self.prompt_version.split(".", 1)[0] == "4":
            expected_v4 = ROLE_OUTPUT_CONTRACT_IDS_V4.get(self.role)
            if expected_v4 is None or self.output_contract_id != expected_v4:
                raise ValueError("V4 role manifest must bind its registered output contract")
        if self.prompt_version is not None and self.prompt_version.split(".", 1)[0] == "25":
            expected_r25 = ROLE_OUTPUT_CONTRACT_IDS_R25.get(self.role)
            if (
                expected_r25 is None
                or self.output_contract_id != expected_r25
                or self.input_schema != "task-envelope/v25"
                or self.output_schema != "handoff-envelope/v25"
            ):
                raise ValueError("R2.5 role manifest must bind its isolated output contract")
        return self


def role_manifest_signing_payload(manifest: RoleManifest) -> bytes:
    """Return the canonical, signature-free payload for a role manifest."""
    return json.dumps(
        manifest.model_dump(mode="json", exclude={"signature"}),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def load_role_manifest(path: Path) -> RoleManifest:
    """Load, but do not trust, one JSON role manifest from an operator path."""
    try:
        return RoleManifest.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValidationError) as exc:
        raise RoleManifestError(f"could not load role manifest: {exc}") from exc


def _decode_signature(value: str) -> bytes:
    """Accept URL-safe base64 (production) and hex (operator-friendly tests)."""
    try:
        if len(value) == 128 and all(char in "0123456789abcdef" for char in value):
            return bytes.fromhex(value)
        return urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as exc:
        raise RoleManifestError("role manifest signature is malformed") from exc


class RoleTrustStore:
    """Public-key-only publisher trust store for signed role manifests."""

    def __init__(
        self, keys: dict[str, bytes], *, trust_store_v2: TrustStoreV2 | None = None
    ) -> None:
        if not keys:
            raise ValueError("role trust store must contain at least one public key")
        self._keys: dict[str, Ed25519PublicKey] = {}
        self._trust_store_v2 = trust_store_v2
        for key_id, raw_key in keys.items():
            if not key_id or len(raw_key) != 32:
                raise ValueError("role trust store keys must be 32-byte Ed25519 public keys")
            self._keys[key_id] = Ed25519PublicKey.from_public_bytes(raw_key)

    @classmethod
    def from_file(cls, path: Path) -> RoleTrustStore:
        """Load a JSON trust store of ``{\"keys\": {key_id: base64_raw_key}}``."""
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(document, dict) and document.get("version") == "2":
                store = TrustStoreV2.model_validate(document)
                decoded_v2 = {
                    item.key_id: urlsafe_b64decode(
                        item.public_key + "=" * (-len(item.public_key) % 4)
                    )
                    for item in store.keys
                    if KeyUsage.ROLE_MANIFEST in item.usages
                }
                return cls(decoded_v2, trust_store_v2=store)
            entries = document.get("keys", document)
            if not isinstance(entries, dict):
                raise ValueError("keys must be an object")
            decoded = {
                str(key_id): urlsafe_b64decode(str(encoded) + "=" * (-len(str(encoded)) % 4))
                for key_id, encoded in entries.items()
            }
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            raise RoleManifestError(f"could not load role trust store: {exc}") from exc
        try:
            return cls(decoded)
        except ValueError as exc:
            raise RoleManifestError(str(exc)) from exc

    def verify(self, manifest: RoleManifest) -> None:
        payload = role_manifest_signing_payload(manifest)
        if self._trust_store_v2 is not None:
            try:
                self._trust_store_v2.verify(
                    key_id=manifest.key_id,
                    usage=KeyUsage.ROLE_MANIFEST,
                    payload=payload,
                    signature=manifest.signature,
                )
            except ValueError as exc:
                raise RoleManifestError("role manifest signature was rejected") from exc
            return
        key = self._keys.get(manifest.key_id)
        if key is None:
            raise RoleManifestError(f"role manifest key_id {manifest.key_id!r} is not trusted")
        try:
            key.verify(
                _decode_signature(manifest.signature),
                payload,
            )
        except (InvalidSignature, ValueError, RoleManifestError) as exc:
            raise RoleManifestError("role manifest signature was rejected") from exc

    def verify_historical(self, manifest: RoleManifest) -> None:
        """Verify a retained manifest at signing time; never use this to launch a role."""
        if self._trust_store_v2 is None or manifest.signed_at is None:
            self.verify(manifest)
            return
        try:
            self._trust_store_v2.verify(
                key_id=manifest.key_id,
                usage=KeyUsage.ROLE_MANIFEST,
                payload=role_manifest_signing_payload(manifest),
                signature=manifest.signature,
                at=manifest.signed_at,
            )
        except ValueError as exc:
            raise RoleManifestError("historical role manifest signature was rejected") from exc


class GatewayActionRequest(BaseModel):
    """A role's typed request for the Host to invoke the only egress gateway."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    type: Literal["gateway_action"] = "gateway_action"
    request_id: str = Field(pattern=r"^[A-Za-z0-9._:-]{1,128}$")
    action: ProposedAction
    url: str = Field(min_length=1, max_length=2048)
    headers: dict[str, str] = Field(default_factory=dict)
    body_base64: str | None = Field(default=None, max_length=1_048_576)
    approval_token: str | None = Field(default=None, max_length=4096)

    @model_validator(mode="after")
    def _action_binds_url(self) -> GatewayActionRequest:
        if self.action.target != self.url:
            raise ValueError("gateway request URL must match its proposed action target")
        return self


class ModelRequest(BaseModel):
    """A role's typed request to the parent-owned model proxy."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    type: Literal["model_request"] = "model_request"
    request_id: str = Field(pattern=r"^[A-Za-z0-9._:-]{1,128}$")
    operation: Literal["classify", "summarize", "extract"]
    input: dict[str, Any] = Field(default_factory=dict)


class FinalHandoffMessage(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    type: Literal["handoff"] = "handoff"
    handoff: HandoffEnvelope


AgentIpcMessage = GatewayActionRequest | ModelRequest | FinalHandoffMessage
IPC_MESSAGE_ADAPTER: TypeAdapter[AgentIpcMessage] = TypeAdapter(AgentIpcMessage)


class HostIpcResponse(BaseModel):
    """The only response shape delivered from the Host to an isolated role."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    type: Literal["gateway_result", "model_result", "denied"]
    request_id: str = Field(pattern=r"^[A-Za-z0-9._:-]{1,128}$")
    ok: bool
    payload: dict[str, Any] = Field(default_factory=dict)
    error: str | None = Field(default=None, max_length=512)

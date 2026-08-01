"""Contract-checked role runners and the isolated R2 Runner Host."""

from .contracts import (
    EvidenceRef,
    GatewayActionRequest,
    HandoffEnvelope,
    HostIpcResponse,
    ModelRequest,
    RoleManifest,
    RoleManifestError,
    RoleTrustStore,
    SandboxLimits,
    TaskEnvelope,
    TaskResult,
    canonical_json_hash,
    load_role_manifest,
    role_manifest_signing_payload,
)
from .runner import (
    AgentContractError,
    AgentRunner,
    DockerRoleSandbox,
    FixtureAgentRunner,
    RunnerHost,
    SubprocessAgentRunner,
)

__all__ = [
    "AgentContractError",
    "AgentRunner",
    "DockerRoleSandbox",
    "EvidenceRef",
    "FixtureAgentRunner",
    "GatewayActionRequest",
    "HandoffEnvelope",
    "HostIpcResponse",
    "ModelRequest",
    "RoleManifest",
    "RoleManifestError",
    "RoleTrustStore",
    "RunnerHost",
    "SandboxLimits",
    "SubprocessAgentRunner",
    "TaskEnvelope",
    "TaskResult",
    "canonical_json_hash",
    "load_role_manifest",
    "role_manifest_signing_payload",
]

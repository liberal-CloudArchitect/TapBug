"""Operator CLI for the real, pause-and-resume Phase 2 vertical run."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import runpy
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import uuid
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, TypeVar, cast

if TYPE_CHECKING:
    from .capability_verifier import CapabilityGapResolver

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import BaseModel

from .campaign_v4 import RiskGroupV4, VerificationCampaignPlanV4
from .cli_status_v3 import status_payload_v3
from .cli_status_v4 import status_payload_v4
from .cli_v3 import V3ManagementError, sign_decision_v3, sign_review_v3
from .cli_v4 import V4ManagementError, sign_decision_v4
from .domain_contracts import CandidateSet, VerificationOutcome, VerificationPlan
from .domain_contracts_v3 import ExecutionBudgetV3
from .domain_contracts_v4 import ExecutionBudgetV4, RunPlanV4
from .evidence import EvidencePolicy, EvidenceStore, FileEvidenceKeyProvider
from .ledgers_v3 import ActiveTimeLedger, BudgetLedger, BudgetLimitsV3
from .ledgers_v4 import BudgetLedgerV4
from .legacy import LegacyRunReadOnlyError, require_v2_run
from .orchestrator import (
    _evidence_artifact_validator,
    _evidence_validator,
    _gateway_handler_v2,
    load_scope_policy,
)
from .promotion import file_sha256
from .prompts import PromptRegistry
from .prompts_v3 import V3_ROLES, PromptRegistryV3
from .prompts_v4 import V4_ROLES, PromptRegistryV4
from .providers import HermesAcpProvider
from .r25_workflow import (
    activate_learning_capability,
    approve_learning_capability,
    continue_learning_run,
    generate_learning_capability,
    learning_status_payload,
    plan_learning_run,
    quarantine_or_revoke_learning_capability,
    research_learning_run,
    start_learning_run,
    validate_learning_capability,
    validate_learning_config,
)
from .runtime import (
    HttpRequest,
    PinnedHttpTransport,
    PolicyEngine,
    RunContext,
    ToolGateway,
    system_resolver,
)
from .runtime.agents import (
    AgentRunner,
    DockerRoleSandbox,
    RoleManifest,
    RoleTrustStore,
    RunnerHost,
)
from .runtime.errors import PolicyDenied
from .security import (
    KeyUsage,
    TrustStoreV2,
    decode_base64,
    encode_base64,
    generate_ed25519_private_key,
    load_ed25519_private_key,
    public_key_bytes,
)
from .security_v3 import approval_actions_v3, load_identity_vault_v3
from .vertical_contracts import (
    ActionDecision,
    ApprovalBundle,
    RunPlan,
    SignedHumanReview,
    sign_approval_bundle,
    sign_human_review,
)
from .vertical_v2 import (
    ApprovalBundleValidatorV2,
    ExecutionState,
    VerticalState,
    VerticalWorkflowV2,
)
from .vertical_v3 import ExecutionStateV3, VerticalStateV3, VerticalWorkflowV3
from .vertical_v4 import ExecutionStateV4, NetworkStateV4, VerticalStateV4, VerticalWorkflowV4
from .wheels_v2 import WheelTrustStoreV2

_ReturnT = TypeVar("_ReturnT")

EXIT_APPROVAL = 20
EXIT_REVIEW = 21
EXIT_REJECTED = 22
EXIT_CLEANUP = 23
EXPECTED_ROLES = {"gatekeeper", "recon", "mapper", "web-vuln", "verifier", "reporter"}
EXPECTED_ROLES_V3 = set(V3_ROLES)
EXPECTED_ROLES_V4 = set(V4_ROLES)


class CliError(ValueError):
    pass


class CliRunFailure(RuntimeError):
    """A run failed after a canonical failed state was persisted."""

    def __init__(
        self, state: VerticalState | VerticalStateV3 | VerticalStateV4, cause: Exception
    ) -> None:
        super().__init__(str(cause))
        self.state = state


def _json_file(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CliError(f"could not load {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise CliError(f"{path} must contain a JSON object")
    return value


def _config(path: Path) -> dict[str, Any]:
    value = _json_file(path)
    required = {
        "runs_root",
        "role_trust_store",
        "approval_trust_store",
        "review_trust_store",
        "prompt_root",
        "hermes_cli",
        "hermes_python",
        "restricted_bridge",
        "model",
    }
    missing = required.difference(value)
    if missing:
        raise CliError(f"config is missing: {', '.join(sorted(missing))}")
    if not {"role_manifests", "role_manifests_v3", "role_manifests_v4"}.intersection(value):
        raise CliError("config requires role_manifests, role_manifests_v3, or role_manifests_v4")
    base = path.resolve().parent
    for name in required.difference({"model"}):
        raw = Path(str(value[name])).expanduser()
        value[name] = raw if raw.is_absolute() else (base / raw).resolve()
    value.setdefault("docker_binary", "docker")
    for name in (
        "raw_key_file",
        "role_manifests",
        "role_manifests_v3",
        "role_manifests_v4",
        "identity_vault",
        "v4_fixture_ca_file",
        "v4_quality_dataset",
        "learn_role_manifests",
        "wheel_trust_store",
        "wheel_publisher_key_file",
        "wheel_validator_key_file",
    ):
        if name in value and value[name] is not None:
            raw = Path(str(value[name])).expanduser()
            value[name] = raw if raw.is_absolute() else (base / raw).resolve()
    if (value.get("raw_key_file") is None) != (value.get("raw_key_id") is None):
        raise CliError("raw_key_file and raw_key_id must be configured together")
    return value


def _manifests(path: Path) -> dict[str, RoleManifest]:
    document = _json_file(path)
    entries = document.get("roles")
    if not isinstance(entries, list):
        raise CliError("role manifest bundle must contain a roles list")
    manifests = [RoleManifest.model_validate(entry) for entry in entries]
    mapped = {item.role: item for item in manifests}
    if set(mapped) != EXPECTED_ROLES or len(mapped) != len(manifests):
        raise CliError("role manifest bundle must contain exactly six unique baseline roles")
    return mapped


def _manifests_v3(path: Path) -> dict[str, RoleManifest]:
    document = _json_file(path)
    if document.get("version") != "3":
        raise CliError("V3 role manifest bundle must declare version 3")
    entries = document.get("roles")
    if not isinstance(entries, list):
        raise CliError("V3 role manifest bundle must contain a roles list")
    manifests = [RoleManifest.model_validate(entry) for entry in entries]
    mapped = {item.role: item for item in manifests}
    if set(mapped) != EXPECTED_ROLES_V3 or len(mapped) != len(manifests):
        raise CliError("V3 role manifest bundle must contain exactly nine unique roles")
    return mapped


def _manifests_v4(path: Path) -> dict[str, RoleManifest]:
    document = _json_file(path)
    if document.get("version") != "4":
        raise CliError("V4 role manifest bundle must declare version 4")
    entries = document.get("roles")
    if not isinstance(entries, list):
        raise CliError("V4 role manifest bundle must contain a roles list")
    manifests = [RoleManifest.model_validate(entry) for entry in entries]
    mapped = {item.role: item for item in manifests}
    if set(mapped) != EXPECTED_ROLES_V4 or len(mapped) != len(manifests):
        raise CliError("V4 role manifest bundle must contain exactly nine unique roles")
    return mapped


def _open_context(config: dict[str, Any], run_id: str) -> RunContext:
    root = Path(config["runs_root"])
    scope = _json_file(root / run_id / "scope.json")
    return RunContext.open_existing(root, scope, run_id)


def _stores(config: dict[str, Any]) -> tuple[TrustStoreV2, TrustStoreV2]:
    return (
        TrustStoreV2.from_file(Path(config["approval_trust_store"])),
        TrustStoreV2.from_file(Path(config["review_trust_store"])),
    )


def _evidence_store(config: dict[str, Any], context: RunContext, policy: Any) -> EvidenceStore:
    evidence_policy = EvidencePolicy(
        capture_limit_bytes=policy.evidence_capture_max_bytes,
        analysis_limit_bytes=policy.evidence_analysis_max_bytes,
        raw_retention=policy.retain_encrypted_raw_evidence,
    )
    provider = None
    if evidence_policy.raw_retention:
        if config.get("raw_key_file") is None or config.get("raw_key_id") is None:
            raise CliError("raw evidence retention requires raw_key_file and raw_key_id")
        provider = FileEvidenceKeyProvider(
            key_path=Path(config["raw_key_file"]),
            key_id=str(config["raw_key_id"]),
            forbidden_roots=(Path(__file__).resolve().parents[2], context.runs_root),
        )
    return EvidenceStore(context.path, policy=evidence_policy, key_provider=provider)


def _build_runner(config: dict[str, Any], context: RunContext, policy: Any) -> RunnerHost:
    approval_store, _ = _stores(config)
    prompt_registry = PromptRegistry(Path(config["prompt_root"]))
    provider = HermesAcpProvider(
        (
            str(config["hermes_python"]),
            str(config["restricted_bridge"]),
            "--run-dir",
            str(context.path),
            "--model",
            str(config["model"]),
        ),
        run_dir=context.path,
        timeout_seconds=180,
        model_name=str(config["model"]),
    )
    evidence_store = _evidence_store(config, context, policy)
    gateway = ToolGateway(
        engine=PolicyEngine(policy, resolver=system_resolver),
        context=context,
        transport=PinnedHttpTransport(),
        evidence_store=evidence_store,
        external_approval_validator_v2=ApprovalBundleValidatorV2(context, approval_store),
    )
    docker_binary = shutil.which(str(config["docker_binary"]))
    if docker_binary is None:
        raise CliError("configured Docker binary is not available")
    return RunnerHost(
        manifests=_manifests(Path(config["role_manifests"])),
        trust_store=RoleTrustStore.from_file(Path(config["role_trust_store"])),
        gateway_handler=_gateway_handler_v2(gateway),
        model_handler=provider,
        evidence_validator=_evidence_validator(context),
        evidence_artifact_validator=_evidence_artifact_validator(context, evidence_store),
        prompt_registry=prompt_registry,
        sandbox=DockerRoleSandbox(
            docker_binary=docker_binary,
            labels={"com.hermes.run_id": context.run_id, "com.hermes.component": "role"},
        ),
    )


def _build_runner_v3(
    config: dict[str, Any],
    context: RunContext,
    policy: Any,
    *,
    gateway_handler: Any | None = None,
) -> RunnerHost:
    manifest_path = config.get("role_manifests_v3")
    if not isinstance(manifest_path, Path):
        raise CliError("V3 execution requires role_manifests_v3")
    registry = PromptRegistryV3(Path(config["prompt_root"]))
    budget = ExecutionBudgetV3()
    budget_ledger = BudgetLedger(
        context,
        limits=BudgetLimitsV3(
            max_prompt_attempts=budget.max_model_attempts,
            reservation_microusd=budget.reservation_per_attempt_microusd,
            max_estimated_cost_microusd=budget.max_estimated_cost_microusd,
        ),
    )
    provider = HermesAcpProvider(
        (
            str(config["hermes_python"]),
            str(config["restricted_bridge"]),
            "--run-dir",
            str(context.path),
            "--model",
            str(config["model"]),
        ),
        run_dir=context.path,
        timeout_seconds=budget.max_role_seconds,
        max_output_bytes=8 * 1024 * 1024,
        max_structured_output_bytes=65_536,
        model_name=str(config["model"]),
        budget_ledger=budget_ledger,
    )
    evidence_store = _evidence_store(config, context, policy)
    gateway = ToolGateway(
        engine=PolicyEngine(policy, resolver=system_resolver),
        context=context,
        transport=PinnedHttpTransport(),
        evidence_store=evidence_store,
    )
    docker_binary = shutil.which(str(config["docker_binary"]))
    if docker_binary is None:
        raise CliError("configured Docker binary is not available")
    return RunnerHost(
        manifests=_manifests_v3(manifest_path),
        trust_store=RoleTrustStore.from_file(Path(config["role_trust_store"])),
        gateway_handler=gateway_handler or _gateway_handler_v2(gateway),
        model_handler=provider,
        evidence_validator=_evidence_validator(context),
        evidence_artifact_validator=_evidence_artifact_validator(context, evidence_store),
        prompt_registry=registry,
        sandbox=DockerRoleSandbox(
            docker_binary=docker_binary,
            labels={"com.hermes.run_id": context.run_id, "com.hermes.component": "role-v3"},
        ),
    )


def _build_runner_v4(
    config: dict[str, Any],
    context: RunContext,
    policy: Any,
) -> RunnerHost:
    """Construct the V4-only role host without widening V3 configuration."""

    manifest_path = config.get("role_manifests_v4")
    if not isinstance(manifest_path, Path):
        raise CliError("V4 execution requires role_manifests_v4")
    registry = PromptRegistryV4(Path(config["prompt_root"]))
    budget = ExecutionBudgetV4()
    provider = HermesAcpProvider(
        (
            str(config["hermes_python"]),
            str(config["restricted_bridge"]),
            "--run-dir",
            str(context.path),
            "--model",
            str(config["model"]),
        ),
        run_dir=context.path,
        timeout_seconds=budget.max_role_seconds,
        max_output_bytes=8 * 1024 * 1024,
        max_structured_output_bytes=65_536,
        model_name=str(config["model"]),
        budget_ledger=BudgetLedgerV4(context),
    )
    evidence_store = _evidence_store(config, context, policy)
    gateway = ToolGateway(
        engine=PolicyEngine(policy, resolver=system_resolver),
        context=context,
        transport=PinnedHttpTransport(),
        evidence_store=evidence_store,
    )
    docker_binary = shutil.which(str(config["docker_binary"]))
    if docker_binary is None:
        raise CliError("configured Docker binary is not available")
    return RunnerHost(
        manifests=_manifests_v4(manifest_path),
        trust_store=RoleTrustStore.from_file(Path(config["role_trust_store"])),
        gateway_handler=_gateway_handler_v2(gateway),
        model_handler=provider,
        evidence_validator=_evidence_validator(context),
        evidence_artifact_validator=_evidence_artifact_validator(context, evidence_store),
        prompt_registry=registry,
        sandbox=DockerRoleSandbox(
            docker_binary=docker_binary,
            labels={"com.hermes.run_id": context.run_id, "com.hermes.component": "role-v4"},
        ),
    )


def _learning_model_handler(config: dict[str, Any], run_dir: Path) -> HermesAcpProvider:
    return HermesAcpProvider(
        (
            str(config["hermes_python"]),
            str(config["restricted_bridge"]),
            "--run-dir",
            str(run_dir),
            "--model",
            str(config["model"]),
        ),
        run_dir=run_dir,
        timeout_seconds=180,
        max_output_bytes=8 * 1024 * 1024,
        max_structured_output_bytes=65_536,
        model_name=str(config["model"]),
    )


def _r25_runner_factory(config: dict[str, Any]) -> Callable[[Any], RunnerHost]:
    """Build R2.5's two-role ACP host from the independent Wheel trust root."""
    from .learning_context import LearningContext
    from .prompts_r25 import PromptRegistryR25

    bundle = _json_file(Path(str(config["r25_role_manifests"])))
    raw_roles = bundle.get("roles")
    if not isinstance(raw_roles, list):
        raise CliError("R2.5 manifest bundle must contain a roles list")
    manifests = {
        item.role: item for item in (RoleManifest.model_validate(value) for value in raw_roles)
    }
    if set(manifests) != {"researcher", "capability-planner"}:
        raise CliError(
            "R2.5 manifest bundle must contain exactly Researcher and Capability Planner"
        )
    store = WheelTrustStoreV2.model_validate(_json_file(Path(str(config["wheel_trust_store"]))))
    publisher = next(item for item in store.keys if item.usage.value == "wheel_publisher")
    trust = RoleTrustStore({publisher.key_id: decode_base64(publisher.public_key)})
    registry = PromptRegistryR25(Path(str(config["prompt_root"])))
    docker = shutil.which(str(config["docker_binary"]))
    if docker is None:
        raise CliError("configured Docker binary is not available")

    def build(context: LearningContext) -> RunnerHost:
        return RunnerHost(
            manifests=manifests,
            trust_store=trust,
            gateway_handler=lambda _request, _task: (_ for _ in ()).throw(
                CliError("R2.5 roles cannot request Gateway actions")
            ),
            model_handler=_learning_model_handler(config, context.path),
            prompt_registry=registry,
            sandbox=DockerRoleSandbox(
                docker_binary=docker,
                labels={
                    "com.hermes.learning_run_id": context.run_id,
                    "com.hermes.component": "r25-role",
                },
            ),
        )

    return build


def _state_exit(state: VerticalState | VerticalStateV3 | VerticalStateV4) -> int:
    value = state.execution_state.value
    if value in {
        ExecutionState.AWAITING_APPROVAL.value,
        ExecutionStateV3.AWAITING_READONLY_APPROVAL.value,
        ExecutionStateV3.AWAITING_MUTATION_APPROVAL.value,
        ExecutionStateV3.AWAITING_CLEANUP_APPROVAL.value,
        ExecutionStateV4.AWAITING_READONLY_APPROVAL.value,
        ExecutionStateV4.AWAITING_MUTATION_APPROVAL.value,
        ExecutionStateV4.AWAITING_CLEANUP_APPROVAL.value,
    }:
        return EXIT_APPROVAL
    if value == ExecutionState.AWAITING_REVIEW.value:
        return EXIT_REVIEW
    if value in {ExecutionStateV3.CLEANUP_REQUIRED.value, ExecutionStateV4.CLEANUP_REQUIRED.value}:
        return EXIT_CLEANUP
    if value == ExecutionState.REJECTED.value:
        return EXIT_REJECTED
    if value in {
        ExecutionState.FAILED.value,
        ExecutionStateV3.FAILED.value,
        ExecutionStateV4.FAILED.value,
    }:
        return 1
    return 0


def _emit(state: VerticalState | VerticalStateV3 | VerticalStateV4, *, as_json: bool) -> int:
    payload = state.model_dump(mode="json")
    if as_json:
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    else:
        for key, value in payload.items():
            print(f"{key}: {value}")
    return _state_exit(state)


def _emit_model(value: BaseModel, *, as_json: bool) -> int:
    payload = value.model_dump(mode="json")
    if as_json:
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    else:
        for key, item in payload.items():
            print(f"{key}: {item}")
    return 0


def _start_vertical_run(
    config: dict[str, Any],
    *,
    policy: Any,
    scope_snapshot: dict[str, Any],
    target: str,
    retry_of: RunContext | None = None,
) -> VerticalState:
    context = RunContext(Path(config["runs_root"]), scope_snapshot)
    context.write_json(
        "plan/role-manifests.json",
        _json_file(Path(config["role_manifests"])),
        immutable=True,
    )
    context.write_json(
        "plan/prompt-registry.json",
        _json_file(Path(config["prompt_root"]) / "prompts" / "registry.json"),
        immutable=True,
    )
    if retry_of is not None:
        failure_path = retry_of.artifact_path("failure.json")
        failure_bytes = failure_path.read_bytes()
        context.write_json(
            "plan/retry-lineage.json",
            {
                "parent_run_id": retry_of.run_id,
                "parent_failure_sha256": "sha256:" + hashlib.sha256(failure_bytes).hexdigest(),
                "policy": "fresh_run_requires_fresh_candidate_and_approval",
            },
            immutable=True,
        )
    registry = PromptRegistry(Path(config["prompt_root"]))
    web_prompt = registry.roles["web-vuln"]
    workflow = VerticalWorkflowV2(
        context,
        _build_runner(config, context, policy),
        evidence_store=_evidence_store(config, context, policy),
        publisher_store=RoleTrustStore.from_file(Path(config["role_trust_store"])),
        prompt_registry=registry,
    )
    try:
        return workflow.start(
            target=target,
            engine=PolicyEngine(policy, resolver=system_resolver),
            provider="hermes-acp-restricted",
            model=str(config["model"]),
            prompt_registry_digest=registry.digest,
            web_prompt_id="hermes.web-vuln",
            web_prompt_version=str(web_prompt["prompt_version"]),
            web_prompt_sha256=str(web_prompt["prompt_sha256"]),
        )
    except Exception as exc:
        if workflow.state_path.exists():
            raise CliRunFailure(workflow.mark_failed(exc), exc) from exc
        raise


def _capability_resolver_from_config(
    config: dict[str, Any], context: RunContext
) -> CapabilityGapResolver | None:
    """Build the CAP-07 Verifier capability from an optional config section.

    Absent for every ordinary run (including the fixed Phase 4 acceptance), so the
    Verifier leaves a line_kv_capability_gap candidate a coverage gap. When a run
    has learned an active approved Wheel, the driver supplies the Wheel artifact
    root, digests, sandbox image, entrypoint, problem card, and the exact gap text.
    """
    raw = config.get("capability_resolver")
    if raw is None:
        return None
    from .capability_verifier import CapabilityGapResolver
    from .learning_recovery import ActiveWheelView
    from .wheels.sandbox import DockerSandbox

    active = ActiveWheelView(
        wheel_id=str(raw["wheel_id"]),
        wheel_manifest_digest=str(raw["wheel_manifest_digest"]),
        activation_digest=str(raw["wheel_activation_digest"]),
        status="active",
        problem_card_ids=(str(raw["problem_card_id"]),),
    )
    return CapabilityGapResolver(
        active_wheel=active,
        sandbox=DockerSandbox(str(raw["sandbox_image"])),
        wheel_artifact_root=Path(str(raw["wheel_artifact_root"])),
        entrypoint=str(raw["entrypoint"]),
        problem_card_id=str(raw["problem_card_id"]),
        resume_run_id=context.run_id,
        paused_run_id=str(raw.get("paused_run_id", context.run_id)),
        scope_digest=context.scope_digest,
        wheel_activation_digest=str(raw["wheel_activation_digest"]),
        gap_text=str(raw["gap_text"]),
    )


def _start_vertical_run_v3(
    config: dict[str, Any],
    *,
    policy: Any,
    scope_snapshot: dict[str, Any],
    target: str,
) -> VerticalStateV3:
    manifest_path = config.get("role_manifests_v3")
    vault_path = config.get("identity_vault")
    if not isinstance(manifest_path, Path) or not isinstance(vault_path, Path):
        raise CliError("V3 execution requires role_manifests_v3 and identity_vault")
    context = RunContext(Path(config["runs_root"]), scope_snapshot)
    manifest_document = _json_file(manifest_path)
    registry_document = _json_file(Path(config["prompt_root"]) / "prompts" / "v3" / "registry.json")
    context.write_json("plan/role-manifests-v3.json", manifest_document, immutable=True)
    context.write_json("plan/prompt-registry-v3.json", registry_document, immutable=True)
    vault = load_identity_vault_v3(
        vault_path,
        repo_root=Path(__file__).resolve().parents[2],
        runs_root=Path(config["runs_root"]),
    )
    registry = PromptRegistryV3(Path(config["prompt_root"]))
    workflow = VerticalWorkflowV3(
        context,
        _build_runner_v3(config, context, policy),
        capability_resolver=_capability_resolver_from_config(config, context),
    )
    try:
        return _run_active_v3(
            context,
            owner="cli-start",
            operation=lambda: workflow.start(
                target=target,
                engine=PolicyEngine(policy, resolver=system_resolver),
                provider_id="hermes-acp-restricted",
                model_id=str(config["model"]),
                prompt_registry_digest=registry.digest,
                role_manifest_set_digest=file_sha256(manifest_path),
                identity_binding_digests=dict(vault.binding_digests),
            ),
        )
    except Exception:
        if workflow.state_path.exists():
            failed = workflow.state().model_copy(
                update={
                    "execution_state": ExecutionStateV3.FAILED,
                    "next_required_action": "retry_as_new_run",
                    "failure_code": "workflow_execution_failed",
                }
            )
            workflow._save_state(failed)  # noqa: SLF001 - canonical failure transition
        raise


def _start_vertical_run_v4(
    config: dict[str, Any],
    *,
    policy: Any,
    scope_snapshot: dict[str, Any],
    target: str,
) -> VerticalStateV4:
    manifest_path = config.get("role_manifests_v4")
    vault_path = config.get("identity_vault")
    if not isinstance(manifest_path, Path) or not isinstance(vault_path, Path):
        raise CliError("V4 execution requires role_manifests_v4 and identity_vault")
    context = RunContext(Path(config["runs_root"]), scope_snapshot)
    manifest_document = _json_file(manifest_path)
    registry_document = _json_file(Path(config["prompt_root"]) / "prompts" / "v4" / "registry.json")
    context.write_json("plan/role-manifests-v4.json", manifest_document, immutable=True)
    context.write_json("plan/prompt-registry-v4.json", registry_document, immutable=True)
    vault = load_identity_vault_v3(
        vault_path,
        repo_root=Path(__file__).resolve().parents[2],
        runs_root=Path(config["runs_root"]),
    )
    registry = PromptRegistryV4(Path(config["prompt_root"]))
    plan = RunPlanV4(
        run_id=context.run_id,
        target=target,
        scope_digest=context.scope_digest,
        provider_id="hermes-acp-restricted",
        model_id=str(config["model"]),
        prompt_registry_digest=registry.digest,
        role_manifest_set_digest=file_sha256(manifest_path),
        roles=tuple(sorted(EXPECTED_ROLES_V4)),
        identity_binding_digests=dict(vault.binding_digests),
        created_at=datetime.now(UTC),
    )
    workflow = VerticalWorkflowV4(context, _build_runner_v4(config, context, policy))
    try:
        def start() -> VerticalStateV4:
            state = workflow.start(plan)
            if state.execution_state in {
                ExecutionStateV4.AWAITING_READONLY_APPROVAL,
                ExecutionStateV4.AWAITING_MUTATION_APPROVAL,
            }:
                from .discovery_v4 import capture_discovery_v4

                ca_file = config.get("v4_fixture_ca_file")
                if not isinstance(ca_file, Path):
                    raise CliError("V4 discovery requires an explicit fixture CA")
                capture_discovery_v4(
                    context,
                    plan,
                    policy_engine=PolicyEngine(policy, resolver=system_resolver),
                    evidence_store=_evidence_store(config, context, policy),
                    ca_file=ca_file,
                )
                state = state.model_copy(
                    update={"network_state": NetworkStateV4.USED, "requests_used": 2}
                )
                context.write_json("state.json", state.model_dump(mode="json"))
            return state

        return _run_active_v4(context, owner="cli-start", operation=start)
    except Exception as exc:
        if workflow.state_path.exists():
            raise CliRunFailure(workflow.mark_failed(exc), exc) from exc
        raise


def _run_active_v3(
    context: RunContext,
    *,
    owner: str,
    operation: Callable[[], _ReturnT],
) -> _ReturnT:
    """Charge one non-human CLI execution interval to the persistent deadline."""

    budget = ExecutionBudgetV3()
    ledger = ActiveTimeLedger(context, max_active_seconds=budget.max_active_seconds)
    ledger.reconcile_open_spans()
    ledger.assert_within_budget()
    span = ledger.start_span(span_id=f"{owner}-{uuid.uuid4()}", owner=owner)
    try:
        return operation()
    finally:
        ledger.stop_span(span)


def _run_active_v4(
    context: RunContext,
    *,
    owner: str,
    operation: Callable[[], _ReturnT],
) -> _ReturnT:
    """Account V4 active time with its own, versioned stability envelope."""

    budget = ExecutionBudgetV4()
    ledger = ActiveTimeLedger(context, max_active_seconds=budget.max_active_seconds)
    ledger.reconcile_open_spans()
    ledger.assert_within_budget()
    span = ledger.start_span(span_id=f"{owner}-{uuid.uuid4()}", owner=owner)
    try:
        return operation()
    finally:
        ledger.stop_span(span)


def _key_id(store: TrustStoreV2, usage: KeyUsage, private_path: Path) -> str:
    if stat.S_IMODE(private_path.stat().st_mode) != 0o600:
        raise CliError("private key permissions must be 0600")
    raw = public_key_bytes(load_ed25519_private_key(private_path))
    matches = [
        item.key_id
        for item in store.keys
        if usage in item.usages and item.public_key == encode_base64(raw)
    ]
    if len(matches) != 1:
        raise CliError("private key does not uniquely match an authorized trust-store key")
    store.trusted_public_key(matches[0], usage)
    return matches[0]


def _key_outside_project_state(config: dict[str, Any], key: Path) -> None:
    resolved = key.resolve()
    for root_name in ("runs_root", "prompt_root"):
        root = Path(config[root_name]).resolve()
        if resolved == root or root in resolved.parents:
            raise CliError("private keys must remain outside the project and run directories")


def _decision(args: argparse.Namespace, decision: Literal["approved", "rejected"]) -> VerticalState:
    config = _config(args.config)
    _validate(config)
    context = _open_context(config, args.run_id)
    require_v2_run(context)
    state = VerticalState.model_validate_json(context.artifact_path("state.json").read_bytes())
    if state.execution_state is not ExecutionState.AWAITING_APPROVAL:
        raise CliError("run is not awaiting approval")
    candidates = CandidateSet.model_validate_json(
        context.artifact_path("candidates/set.json").read_bytes()
    )
    plan = VerificationPlan.model_validate_json(
        context.artifact_path("plan/verification.json").read_bytes()
    )
    if args.challenge_id != plan.plan_id:
        raise CliError("challenge ID does not match this run")
    _key_outside_project_state(config, args.key)
    approval_store, _ = _stores(config)
    key_id = _key_id(approval_store, KeyUsage.APPROVAL, args.key)
    now = datetime.now(UTC)
    rationale = args.reason or ("operator approved the exact two-action plan")
    unsigned = ApprovalBundle(
        version="2",
        bundle_id=f"approval-{uuid.uuid4().hex}",
        plan_digest=plan.digest,
        run_id=context.run_id,
        scope_digest=context.scope_digest,
        candidate_id=candidates.candidates[0].candidate_id,
        total_requests=plan.request_budget,
        approver=args.operator,
        reviewer=args.operator,
        decisions=tuple(
            ActionDecision(action_id=item.action_id, decision=decision, rationale=rationale)
            for item in plan.steps
        ),
        issued_at=now,
        expires_at=plan.expires_at,
        key_id=key_id,
        signature="unsigned",
    )
    signed = sign_approval_bundle(unsigned, load_ed25519_private_key(args.key))
    context.write_json("approvals/decision.json", signed.model_dump(mode="json"), immutable=True)
    if decision == "rejected":
        state = state.model_copy(
            update={"execution_state": ExecutionState.REJECTED, "next_required_action": None}
        )
        context.write_json("state.json", state.model_dump(mode="json"))
    else:
        state = state.model_copy(update={"next_required_action": "resume"})
        context.write_json("state.json", state.model_dump(mode="json"))
    return state


def _decision_v3(
    args: argparse.Namespace, decision: Literal["approved", "rejected"]
) -> VerticalStateV3:
    config = _config(args.config)
    _validate_v3(config)
    context = _open_context(config, args.run_id)
    state = VerticalStateV3.model_validate_json(context.artifact_path("state.json").read_bytes())
    if args.risk_group is None:
        risk_group = {
            ExecutionStateV3.AWAITING_READONLY_APPROVAL: "readonly",
            ExecutionStateV3.AWAITING_MUTATION_APPROVAL: "mutation",
            ExecutionStateV3.AWAITING_CLEANUP_APPROVAL: "cleanup",
        }.get(state.execution_state)
        if risk_group is None:
            raise CliError("V3 run is not awaiting a risk-group decision")
    else:
        risk_group = args.risk_group
    if args.challenge_id != f"phase4-{risk_group}":
        raise CliError("challenge ID does not match the V3 risk group")
    from .domain_contracts_v3 import RiskGroup, VerificationCampaignPlan

    campaign = VerificationCampaignPlan.model_validate_json(
        context.artifact_path("verification_v3/campaign.json").read_bytes()
    )
    available = tuple(
        dict.fromkeys(
            item.candidate_id for item in approval_actions_v3(campaign, cast(RiskGroup, risk_group))
        )
    )
    selected = tuple(args.candidate_id) or available
    _key_outside_project_state(config, args.key)
    approval_store, _ = _stores(config)
    sign_decision_v3(
        context,
        campaign,
        cast(RiskGroup, risk_group),
        selected,
        decision,
        args.key.resolve(),
        approval_store,
        args.operator,
        args.reason or f"operator {decision} the exact {risk_group} candidate action graph",
    )
    state = state.model_copy(update={"next_required_action": "resume"})
    context.write_json("state.json", state.model_dump(mode="json"))
    return state


def _decision_v4(
    args: argparse.Namespace, decision: Literal["approved", "rejected"]
) -> VerticalStateV4:
    config = _config(args.config)
    _validate_v4(config)
    context = _open_context(config, args.run_id)
    state = VerticalStateV4.model_validate_json(context.artifact_path("state.json").read_bytes())
    raw_risk_group = args.risk_group or {
        ExecutionStateV4.AWAITING_READONLY_APPROVAL: "readonly",
        ExecutionStateV4.AWAITING_MUTATION_APPROVAL: "mutation",
        ExecutionStateV4.AWAITING_CLEANUP_APPROVAL: "cleanup",
        ExecutionStateV4.CLEANUP_REQUIRED: "cleanup",
    }.get(state.execution_state)
    if raw_risk_group is None:
        raise CliError("V4 run is not awaiting a risk-group decision")
    if raw_risk_group not in {"readonly", "mutation", "cleanup"}:
        raise CliError("V4 risk group is invalid")
    risk_group = cast(RiskGroupV4, raw_risk_group)
    if args.challenge_id != f"phase5-{risk_group}":
        raise CliError("challenge ID does not match the V4 risk group")
    campaign = VerificationCampaignPlanV4.model_validate_json(
        context.artifact_path("verification_v4/campaign.json").read_bytes()
    )
    from .campaign_v4 import approval_actions_v4

    selected = tuple(args.candidate_id) or tuple(
        dict.fromkeys(item.candidate_id for item in approval_actions_v4(campaign, risk_group))
    )
    _key_outside_project_state(config, args.key)
    approval_store, _ = _stores(config)
    try:
        _ = sign_decision_v4(
            context,
            risk_group=risk_group,
            decision=decision,
            selected_candidate_ids=selected,
            key=args.key.resolve(),
            trust_store=approval_store,
            operator=args.operator,
            rationale=args.reason or f"operator {decision} the exact V4 {risk_group} graph",
        )
    except V4ManagementError as exc:
        raise CliError(str(exc)) from exc
    if decision == "rejected" and risk_group == "mutation":
        next_state = ExecutionStateV4.REJECTED
        next_required = None
    elif risk_group == "readonly" and decision == "rejected":
        # A rejected first batch cannot safely promote a partial campaign until
        # the explicit gaps path is implemented.  Terminate fail-closed rather
        # than allowing mutation verification to reach an incomplete promotion.
        next_state = ExecutionStateV4.REJECTED
        next_required = None
    else:
        next_state = state.execution_state
        next_required = "resume"
    state = state.model_copy(
        update={"execution_state": next_state, "next_required_action": next_required}
    )
    context.write_json("state.json", state.model_dump(mode="json"))
    return state


class _NoRunner(AgentRunner):
    def run(self, task: Any) -> Any:
        raise RuntimeError("management command cannot run an agent")


def _build_runner_stub() -> _NoRunner:
    return _NoRunner()


def _review(args: argparse.Namespace) -> VerticalState:
    config = _config(args.config)
    _validate(config)
    context = _open_context(config, args.run_id)
    require_v2_run(context)
    state = VerticalState.model_validate_json(context.artifact_path("state.json").read_bytes())
    if state.execution_state is not ExecutionState.AWAITING_REVIEW:
        raise CliError("run is not awaiting human review")
    outcome = VerificationOutcome.model_validate_json(
        context.artifact_path("report/outcome.json").read_text(encoding="utf-8")
    )
    if outcome.outcome_id != args.outcome_id:
        raise CliError("outcome ID does not match this run")
    _, review_store = _stores(config)
    _key_outside_project_state(config, args.key)
    key_id = _key_id(review_store, KeyUsage.HUMAN_REVIEW, args.key)
    draft_digest = file_sha256(context.artifact_path("report/draft.md"))
    unsigned = SignedHumanReview(
        version="2",
        review_id=f"review-{uuid.uuid4().hex}",
        finding_id=outcome.candidate_id,
        run_id=context.run_id,
        scope_digest=context.scope_digest,
        evidence_digest=outcome.digest,
        outcome_digest=outcome.digest,
        report_draft_digest=draft_digest,
        reviewer=args.operator,
        verdict=args.verdict,
        rationale=args.rationale,
        reviewed_at=datetime.now(UTC),
        key_id=key_id,
        signature="unsigned",
    )
    signed = sign_human_review(unsigned, load_ed25519_private_key(args.key))
    context.write_json("reviews/signed.json", signed.model_dump(mode="json"), immutable=True)
    if args.verdict == "rejected":
        state = state.model_copy(
            update={"execution_state": ExecutionState.REJECTED, "next_required_action": None}
        )
        context.write_json("state.json", state.model_dump(mode="json"))
    else:
        state = state.model_copy(update={"next_required_action": "resume"})
        context.write_json("state.json", state.model_dump(mode="json"))
    return state


def _review_v3(args: argparse.Namespace) -> VerticalStateV3:
    config = _config(args.config)
    _validate_v3(config)
    context = _open_context(config, args.run_id)
    state = VerticalStateV3.model_validate_json(context.artifact_path("state.json").read_bytes())
    from .domain_contracts_v3 import VerificationOutcomeSet

    outcomes = VerificationOutcomeSet.model_validate_json(
        context.artifact_path("verification_v3/outcomes.json").read_bytes()
    )
    if args.outcome_id != outcomes.outcome_set_id:
        raise CliError("outcome ID does not match this V3 run")
    _key_outside_project_state(config, args.key)
    approval_store, review_store = _stores(config)
    sign_review_v3(
        context,
        args.verdict,
        args.key.resolve(),
        review_store,
        args.rationale,
        operator=args.operator,
        approval_store=approval_store,
    )
    if args.verdict == "rejected":
        state = state.model_copy(
            update={"execution_state": ExecutionStateV3.REJECTED, "next_required_action": None}
        )
    else:
        state = state.model_copy(update={"next_required_action": "resume"})
    context.write_json("state.json", state.model_dump(mode="json"))
    return state


def _review_v4(args: argparse.Namespace) -> VerticalStateV4:
    """Sign the already-frozen V4 finding/coverage pair; never regenerate it."""

    from .cli_v4 import sign_review_v4
    from .domain_contracts_v4 import CoverageAppendixV4, FindingSetV4, SignedReviewBatchV4

    config = _config(args.config)
    _validate_v4(config)
    context = _open_context(config, args.run_id)
    state = VerticalStateV4.model_validate_json(context.artifact_path("state.json").read_bytes())
    if state.execution_state is not ExecutionStateV4.AWAITING_REVIEW:
        raise CliError("V4 run is not awaiting human review")
    findings = FindingSetV4.model_validate_json(
        context.artifact_path("report/finding-set-v4.json").read_bytes()
    )
    coverage = CoverageAppendixV4.model_validate_json(
        context.artifact_path("report/coverage-v4.json").read_bytes()
    )
    if args.outcome_id != findings.finding_set_id:
        raise CliError("outcome ID does not match this V4 finding set")
    _key_outside_project_state(config, args.key)
    _, review_store = _stores(config)
    key_id = _key_id(review_store, KeyUsage.HUMAN_REVIEW, args.key)
    draft_digest = file_sha256(context.artifact_path("report/draft-v4.md"))
    gaps = tuple(
        "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()
        for value in sorted(coverage.gaps)
    )
    if args.verdict == "accepted" and gaps:
        raise CliError("V4 coverage gaps require accepted_with_gaps")
    if args.verdict == "accepted_with_gaps" and not gaps:
        raise CliError("accepted_with_gaps requires explicit V4 coverage gaps")
    unsigned = SignedReviewBatchV4(
        run_id=context.run_id,
        scope_digest=context.scope_digest,
        generated_by_task_id="phase5-human-review",
        review_id=f"review-v4-{uuid.uuid4().hex}",
        finding_set_digest=findings.digest,
        coverage_appendix_digest=coverage.digest,
        report_draft_digest=draft_digest,
        gap_digests=gaps,
        verdict=args.verdict,
        reviewer_key_id=key_id,
        reviewed_at=datetime.now(UTC),
        rationale=args.rationale,
        signature_b64="unsigned-signature",
    )
    signed = sign_review_v4(unsigned, args.key.resolve())
    context.write_json("reviews/signed-v4.json", signed.model_dump(mode="json"), immutable=True)
    state = state.model_copy(
        update={
            "execution_state": (
                ExecutionStateV4.REJECTED if args.verdict == "rejected" else state.execution_state
            ),
            "next_required_action": None if args.verdict == "rejected" else "resume",
        }
    )
    context.write_json("state.json", state.model_dump(mode="json"))
    return state


def _fixture_observed_state_hash(
    context: RunContext,
    campaign: Any,
    candidate_types: Mapping[str, str],
    purpose: Literal["baseline", "cleanup_check"],
) -> str:
    from .execution_v3 import ExecutionResultV3

    values: dict[str, Any] = {}
    evidence_store = EvidenceStore(context.path)
    for action in campaign.actions:
        if action.purpose != purpose:
            continue
        execution_path = context.artifact_path(
            f"governance_v3/executions/{action.action_digest[7:]}.json"
        )
        if not execution_path.is_file():
            continue
        result = ExecutionResultV3.model_validate_json(execution_path.read_bytes())
        manifest = evidence_store.verify(result.evidence_artifact_ref)
        analysis = _json_file(context.artifact_path(manifest.analysis.path))
        response = analysis.get("response")
        body = response.get("body") if isinstance(response, dict) else None
        candidate_type = candidate_types.get(action.candidate_id)
        if candidate_type == "unauthorized_graphql_mutation":
            if not isinstance(body, dict) or not isinstance(body.get("data"), dict):
                raise CliError("GraphQL state evidence lacks its structured fixture value")
            values["graphql_value"] = body["data"].get("fixtureValue")
        elif candidate_type == "privilege_escalation":
            if not isinstance(body, dict) or not isinstance(body.get("privileged"), bool):
                raise CliError("Authz state evidence lacks its privilege boolean")
            values["member_privileged"] = body["privileged"]
    if not values:
        raise CliError(f"no {purpose} fixture state evidence is available")
    encoded = json.dumps(values, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _resume_v3(config: dict[str, Any], context: RunContext, policy: Any) -> VerticalStateV3:
    state = VerticalStateV3.model_validate_json(context.artifact_path("state.json").read_bytes())
    if state.execution_state in {
        ExecutionStateV3.COMPLETED,
        ExecutionStateV3.COMPLETED_WITH_GAPS,
        ExecutionStateV3.REJECTED,
    }:
        return state
    return _run_active_v3(
        context,
        owner=f"cli-resume-{state.execution_state.value}",
        operation=lambda: _resume_v3_active(config, context, policy, state),
    )


def _resume_v4(config: dict[str, Any], context: RunContext, policy: Any) -> VerticalStateV4:
    state = VerticalStateV4.model_validate_json(context.artifact_path("state.json").read_bytes())
    if state.execution_state in {
        ExecutionStateV4.COMPLETED,
        ExecutionStateV4.COMPLETED_WITH_GAPS,
        ExecutionStateV4.REJECTED,
    }:
        return state
    return _run_active_v4(
        context,
        owner=f"cli-resume-{state.execution_state.value}",
        operation=lambda: _resume_v4_active(config, context, policy),
    )


def _resume_v4_active(
    config: dict[str, Any], context: RunContext, policy: Any
) -> VerticalStateV4:
    """Execute exactly one V4 approval batch or publish after a signed review.

    V4 execution is intentionally staged.  A readonly decision cannot unlock a
    mutation request, and an incomplete/missing decision never starts a
    transport.  The executor receives only parent-held identities and a pinned
    localhost transport; role containers never receive these credentials.
    """

    from .campaign_v4 import approval_actions_v4
    from .execution_v4 import GovernedExecutorV4
    from .promotion_v4 import build_quality_receipt_v4, promote_v4
    from .security_v4 import ApprovalBatchV4, verify_approval_batch_v4

    _validate_v4(config)
    state = VerticalStateV4.model_validate_json(context.artifact_path("state.json").read_bytes())
    if state.execution_state in {
        ExecutionStateV4.COMPLETED,
        ExecutionStateV4.COMPLETED_WITH_GAPS,
        ExecutionStateV4.REJECTED,
    }:
        return state
    if state.execution_state is ExecutionStateV4.VERIFYING_MUTATION:
        # A process can die after the first mutation transport boundary and
        # before it records the batch outcome.  Never replay that graph: the
        # predeclared cleanup-only challenge is the only safe continuation.
        challenge = context.artifact_path("approvals_v4/challenge-cleanup.json")
        if not challenge.is_file():
            raise CliError("interrupted V4 mutation has no cleanup-only challenge")
        recovered = state.model_copy(
            update={
                "execution_state": ExecutionStateV4.CLEANUP_REQUIRED,
                "current_role": None,
                "next_required_action": "approve_or_reject:cleanup",
                "cleanup_state": "required",
                "failure_code": "interrupted_mutation",
            }
        )
        context.write_json("state.json", recovered.model_dump(mode="json"))
        return recovered
    if state.execution_state is ExecutionStateV4.AWAITING_REVIEW:
        if not context.artifact_path("reviews/signed-v4.json").is_file():
            raise CliError("V4 run still requires a signed human review")
        from .cli_v4 import verify_review_v4
        from .domain_contracts_v4 import ContractEnvelopeV4, CoverageAppendixV4, ReporterAckV4
        from .preflight_v4 import ReportPreflightVerifierV4
        from .runtime.agents import TaskEnvelope
        from .security_v4 import verify_approval_batch_v4

        campaign = VerificationCampaignPlanV4.model_validate_json(
            context.artifact_path("verification_v4/campaign.json").read_bytes()
        )
        approval_store, review_store = _stores(config)

        def verify_approval(batch: Any) -> None:
            if not isinstance(batch, ApprovalBatchV4):
                raise CliError("V4 report preflight encountered a legacy approval record")
            verify_approval_batch_v4(batch, campaign, approval_store)

        def verify_review(review: Any, findings: Any, coverage: Any) -> None:
            verify_review_v4(review, review_store)

        preflight = ReportPreflightVerifierV4(
            context,
            approval_signature_verifier=verify_approval,
            review_signature_verifier=verify_review,
            evidence_store=_evidence_store(config, context, policy),
        )
        launch = preflight.authorize_reporter()
        finding_document = _json_file(context.artifact_path("report/finding-set-v4.json"))
        coverage_document = _json_file(context.artifact_path("report/coverage-v4.json"))
        reporter_task = TaskEnvelope(
            version="4",
            run_id=context.run_id,
            task_id="phase5-reporter",
            role="reporter",
            scope_digest=context.scope_digest,
            payload={
                "operation": "reporting",
                "reporter_launch_receipt_digest": launch.digest,
                "quality_gate_digest": launch.quality_gate_digest,
                "finding_set_digest": launch.finding_set_digest,
                "coverage_appendix_digest": launch.coverage_appendix_digest,
                "finding_set": finding_document,
                "coverage_appendix": coverage_document,
            },
            request_budget=0,
            allowed_actions=(),
            evidence_required=False,
            timeout_seconds=ExecutionBudgetV4().max_role_seconds,
        )
        handoff_path = context.artifact_path("handoffs_v4/phase5-reporter.json")
        provider_path = context.artifact_path("provider/phase5-reporter.json")
        if handoff_path.exists() or provider_path.exists():
            raise CliError("V4 Reporter task is indeterminate; create a new run")
        result = _build_runner_v4(config, context, policy).run(reporter_task)
        context.write_json(
            "handoffs_v4/phase5-reporter.json",
            {
                "task": reporter_task.model_dump(mode="json"),
                "result": result.model_dump(mode="json"),
            },
            immutable=True,
        )
        envelope = result.handoff.result if result.handoff is not None else None
        payload = envelope.payload if isinstance(envelope, ContractEnvelopeV4) else None
        if not isinstance(payload, ReporterAckV4):
            raise CliError("V4 Reporter did not return a valid acknowledgement")
        context.write_json(
            "report/reporter-ack-v4.json", payload.model_dump(mode="json"), immutable=True
        )
        preflight.write_report(payload)
        coverage = CoverageAppendixV4.model_validate_json(
            context.artifact_path("report/coverage-v4.json").read_bytes()
        )
        completed = state.model_copy(
            update={
                "execution_state": (
                    ExecutionStateV4.COMPLETED_WITH_GAPS
                    if coverage.completion == "completed_with_gaps"
                    else ExecutionStateV4.COMPLETED
                ),
                "current_role": None,
                "next_required_action": None,
                "last_successful_checkpoint": "report_written_v4",
            }
        )
        context.write_json("state.json", completed.model_dump(mode="json"))
        return completed
    expected_raw = {
        ExecutionStateV4.AWAITING_READONLY_APPROVAL: "readonly",
        ExecutionStateV4.AWAITING_MUTATION_APPROVAL: "mutation",
        ExecutionStateV4.AWAITING_CLEANUP_APPROVAL: "cleanup",
        ExecutionStateV4.CLEANUP_REQUIRED: "cleanup",
    }.get(state.execution_state)
    if expected_raw is None:
        raise CliError(f"cannot resume V4 state {state.execution_state.value}")
    expected = cast(RiskGroupV4, expected_raw)
    decision_path = context.artifact_path(f"approvals_v4/{expected}.json")
    if not decision_path.is_file():
        raise CliError(f"run still requires a signed {expected} decision")
    campaign = VerificationCampaignPlanV4.model_validate_json(
        context.artifact_path("verification_v4/campaign.json").read_bytes()
    )
    batch = ApprovalBatchV4.model_validate_json(decision_path.read_bytes())
    approval_store, _ = _stores(config)
    try:
        verify_approval_batch_v4(batch, campaign, approval_store)
    except Exception as exc:
        raise CliError("V4 signed approval did not verify") from exc
    if batch.verdict == "rejected":
        next_state = state.model_copy(
            update={"execution_state": ExecutionStateV4.REJECTED, "next_required_action": None}
        )
        context.write_json("state.json", next_state.model_dump(mode="json"))
        return next_state
    vault_path = config.get("identity_vault")
    ca_file = config.get("v4_fixture_ca_file")
    if not isinstance(vault_path, Path) or not isinstance(ca_file, Path):
        raise CliError("V4 governed execution requires the identity vault and fixture CA")
    vault = load_identity_vault_v3(
        vault_path,
        repo_root=Path(__file__).resolve().parents[2],
        runs_root=Path(config["runs_root"]),
    )
    evidence_store = _evidence_store(config, context, policy)
    executor = GovernedExecutorV4(
        context,
        campaign,
        approval_batch=batch,
        approval_trust_store=approval_store,
        policy_engine=PolicyEngine(policy, resolver=system_resolver),
        evidence_store=evidence_store,
        transport=PinnedHttpTransport(ssl_context=ssl.create_default_context(cafile=str(ca_file))),
        identity_vault=vault,
    )
    actions = tuple(
        item
        for item in approval_actions_v4(campaign, expected)
        if item.candidate_id in batch.candidate_ids
    )
    verifying_state = {
        "readonly": ExecutionStateV4.VERIFYING_READONLY,
        "mutation": ExecutionStateV4.VERIFYING_MUTATION,
        "cleanup": ExecutionStateV4.CLEANUP_REQUIRED,
    }[expected]
    if expected != "cleanup":
        state = state.model_copy(
            update={
                "execution_state": verifying_state,
                "current_role": "verifier",
                "network_state": "requested",
                "next_required_action": None,
            }
        )
        context.write_json("state.json", state.model_dump(mode="json"))
    try:
        results = tuple(
            executor.execute(item, task_id=f"phase5-gateway-{item.candidate_id}")
            for item in actions
        )
    except Exception as exc:
        failed = state.model_copy(
            update={
                "execution_state": (
                    ExecutionStateV4.CLEANUP_REQUIRED
                    if expected in {"mutation", "cleanup"}
                    else ExecutionStateV4.FAILED
                ),
                "next_required_action": (
                    "approve_or_reject:cleanup"
                    if expected in {"mutation", "cleanup"}
                    else "retry_as_new_run"
                ),
                "cleanup_state": "required"
                if expected in {"mutation", "cleanup"}
                else state.cleanup_state,
                "failure_code": type(exc).__name__.lower(),
            }
        )
        context.write_json("state.json", failed.model_dump(mode="json"))
        raise CliRunFailure(failed, exc) from exc
    context.write_json(
        f"verification_v4/results-{expected}.json",
        {
            "batch_digest": batch.digest,
            "results": [item.model_dump(mode="json") for item in results],
        },
        immutable=True,
    )
    has_mutation = bool(approval_actions_v4(campaign, "mutation"))
    if expected == "cleanup":
        # Cleanup-only recovery proves that the local fixture is safe again,
        # but cannot recreate a trustworthy interrupted verification campaign.
        # It therefore terminates recovery without promotion or Reporter.
        cleaned = state.model_copy(
            update={
                "execution_state": ExecutionStateV4.FAILED,
                "current_role": None,
                "network_state": "used",
                "requests_used": state.requests_used + len(results),
                "next_required_action": "retry_as_new_run",
                "cleanup_state": "restored",
                "failure_code": "interrupted_mutation_recovered",
            }
        )
        context.write_json("state.json", cleaned.model_dump(mode="json"))
        return cleaned
    if expected == "readonly" and has_mutation:
        next_state = state.model_copy(
            update={
                "execution_state": ExecutionStateV4.AWAITING_MUTATION_APPROVAL,
                "next_required_action": "approve_or_reject:mutation",
                "network_state": "used",
                "requests_used": state.requests_used + len(results),
            }
        )
        context.write_json("state.json", next_state.model_dump(mode="json"))
        return next_state
    readonly_path = context.artifact_path("verification_v4/results-readonly.json")
    from .cleanup_v4 import build_cleanup_receipt_v4
    from .execution_v4 import ExecutionResultV4
    from .verification_v4 import run_verifier_tasks_v4

    if expected == "mutation":
        if not readonly_path.is_file():
            raise CliError("V4 mutation promotion requires completed readonly evidence")
        readonly_raw = _json_file(readonly_path)
        readonly_results = tuple(
            ExecutionResultV4.model_validate(item) for item in readonly_raw["results"]
        )
        all_results = readonly_results + results
    else:
        all_results = results
    batches = tuple(
        ApprovalBatchV4.model_validate_json(path.read_bytes())
        for path in sorted(context.artifact_path("approvals_v4").glob("*.json"))
        if not path.name.startswith("challenge-")
    )
    discovery = _json_file(context.artifact_path("discovery_v4/refs.json"))
    try:
        from .evidence import EvidenceArtifactRef

        discovery_evidence = tuple(
            EvidenceArtifactRef.model_validate(item) for item in discovery["evidence"]
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise CliError(
            "V4 promotion requires the two committed discovery evidence artifacts"
        ) from exc
    if len(discovery_evidence) != 2:
        raise CliError("V4 promotion requires exactly two discovery evidence artifacts")
    cleanup = None
    if has_mutation:
        cleanup = build_cleanup_receipt_v4(
            context,
            campaign,
            results,
            evidence_store=evidence_store,
        )
        if not cleanup.state_restored:
            failed = state.model_copy(
                update={
                    "execution_state": ExecutionStateV4.CLEANUP_REQUIRED,
                    "next_required_action": "approve_or_reject:cleanup",
                    "cleanup_state": "required",
                    "failure_code": "cleanup_state_not_restored",
                }
            )
            context.write_json(
                "verification_v4/cleanup.json", cleanup.model_dump(mode="json"), immutable=True
            )
            context.write_json("state.json", failed.model_dump(mode="json"))
            return failed
        context.write_json(
            "verification_v4/cleanup.json", cleanup.model_dump(mode="json"), immutable=True
        )
    outcomes = run_verifier_tasks_v4(
        context,
        _build_runner_v4(config, context, policy),
        campaign,
        all_results,
        batches,
        # Every verifier still has an isolated container and ACP session.  We
        # serialize these evidence-heavy attestations because the configured
        # managed ACP provider can queue concurrent long structured requests
        # beyond V4's non-negotiable 180-second per-task deadline.  This is
        # scheduling only: it neither retries nor re-executes a governed HTTP
        # action, and assessment/cross-review remain four-way fan-out.
        max_workers=1,
    )
    dataset_path = config.get("v4_quality_dataset")
    if not isinstance(dataset_path, Path):
        raise CliError("V4 promotion requires a validated frozen quality dataset")
    quality = build_quality_receipt_v4(
        context=context,
        dataset_path=dataset_path,
        campaign=campaign,
        results=all_results,
    )
    findings, coverage = promote_v4(
        campaign,
        all_results,
        batches,
        quality,
        discovery_evidence=discovery_evidence,
        outcomes=outcomes,
        cleanup=cleanup,
        gaps=_v4_collaboration_gaps(context),
    )
    context.write_json("quality/receipt-v4.json", quality.model_dump(mode="json"), immutable=True)
    context.write_json(
        "report/finding-set-v4.json", findings.model_dump(mode="json"), immutable=True
    )
    context.write_json("report/coverage-v4.json", coverage.model_dump(mode="json"), immutable=True)
    context.write_text(
        "report/draft-v4.md",
        "# Phase 5 local teaching fixture review draft\n\n"
        "This is a localhost teaching fixture, not a Bugcrowd submission.\n",
        immutable=True,
    )
    next_state = state.model_copy(
        update={
            "execution_state": ExecutionStateV4.AWAITING_REVIEW,
            "network_state": "used",
            "requests_used": state.requests_used + len(results),
            "next_required_action": "review_sign",
            "cleanup_state": "restored" if cleanup is not None else "not_required",
        }
    )
    context.write_json("state.json", next_state.model_dump(mode="json"))
    return next_state


def _v4_collaboration_gaps(context: RunContext) -> tuple[str, ...]:
    """Load the parent-owned isolated-branch gaps for CoverageAppendixV4.

    The artifacts are deliberately small JSON projections: role handoffs remain
    immutable elsewhere, while this is the exact, deterministic declaration
    consumed by promotion and rechecked by V4 preflight.
    """

    values: list[str] = []
    for relative, field in (
        ("collaboration_v4/branch-results.json", "gaps"),
        ("collaboration_v4/review-plan.json", "gaps"),
    ):
        raw = _json_file(context.artifact_path(relative))
        items = raw.get(field)
        if not isinstance(items, list) or not all(
            isinstance(item, str) and item for item in items
        ):
            raise CliError(f"V4 collaboration artifact {relative} has invalid gaps")
        values.extend(items)
    return tuple(sorted(set(values)))


def _resume_v3_active(
    config: dict[str, Any],
    context: RunContext,
    policy: Any,
    state: VerticalStateV3,
) -> VerticalStateV3:
    from .domain_contracts_v3 import (
        ApprovalBatchV3,
        CandidateCollection,
        CoverageReportV3,
        FindingSet,
        VerificationCampaignPlan,
    )
    from .execution_v3 import (
        ApprovalConsumptionStoreV3,
        CompensationManagerV3,
        GovernedGatewayV3,
    )
    from .ledgers_v3 import ActionLedger
    from .preflight_v3 import ReportPreflightVerifierV3
    from .security_v3 import verify_approval_batch_v3, verify_review_batch_v3

    _validate_v3(config)
    approval_store, review_store = _stores(config)
    if state.execution_state is ExecutionStateV3.VERIFYING_MUTATION:
        # A process may have crossed the mutation transport boundary before it
        # could persist the compensation result.  Recovery never re-enters the
        # verifier; it first requires a new cleanup-only human decision.
        return VerticalWorkflowV3(context, _build_runner_stub()).begin_cleanup_recovery()
    if state.execution_state in {
        ExecutionStateV3.AWAITING_READONLY_APPROVAL,
        ExecutionStateV3.AWAITING_MUTATION_APPROVAL,
        ExecutionStateV3.AWAITING_CLEANUP_APPROVAL,
        ExecutionStateV3.CLEANUP_REQUIRED,
    }:
        campaign = VerificationCampaignPlan.model_validate_json(
            context.artifact_path("verification_v3/campaign.json").read_bytes()
        )
        batches = tuple(
            ApprovalBatchV3.model_validate_json(path.read_bytes())
            for path in sorted(context.artifact_path("approvals_v3").glob("*.json"))
            if not path.name.startswith("challenge-")
        )
        current_group = {
            ExecutionStateV3.AWAITING_READONLY_APPROVAL: "readonly",
            ExecutionStateV3.AWAITING_MUTATION_APPROVAL: "mutation",
            ExecutionStateV3.AWAITING_CLEANUP_APPROVAL: "cleanup",
            ExecutionStateV3.CLEANUP_REQUIRED: "cleanup",
        }[state.execution_state]
        current = next((item for item in batches if item.risk_group == current_group), None)
        if current is None:
            raise CliError(f"run still requires a signed {current_group} decision")
        candidates = CandidateCollection.model_validate_json(
            context.artifact_path("collaboration_v3/candidates.json").read_bytes()
        )
        candidate_types = {
            item.candidate_id: item.candidate_type for item in candidates.canonical_candidates
        }
        vault_path = config.get("identity_vault")
        if not isinstance(vault_path, Path):
            raise CliError("V3 resume requires identity_vault")
        vault = load_identity_vault_v3(
            vault_path,
            repo_root=Path(__file__).resolve().parents[2],
            runs_root=Path(config["runs_root"]),
        )
        action_ledger = ActionLedger(context)
        evidence_store = _evidence_store(config, context, policy)
        gateway = GovernedGatewayV3(
            context=context,
            campaign=campaign,
            approval_batches=batches,
            consumption_store=ApprovalConsumptionStoreV3(context, campaign, approval_store),
            action_ledger=action_ledger,
            policy_engine=PolicyEngine(policy, resolver=system_resolver),
            evidence_store=evidence_store,
            transport=PinnedHttpTransport(),
            candidate_types=candidate_types,
            identity_vault=vault,
        )
        workflow = VerticalWorkflowV3(
            context,
            _build_runner_v3(config, context, policy, gateway_handler=gateway),
            # The Verifier runs here on resume (readonly verification follows the
            # signed readonly approval), so the CAP-07 Wheel resolver must be rebuilt
            # on this path too — otherwise a line_kv_capability_gap candidate is left
            # inconclusive instead of resolved by its active approved Wheel.
            capability_resolver=_capability_resolver_from_config(config, context),
        )

        def compensation_factory() -> CompensationManagerV3:
            initial = _fixture_observed_state_hash(context, campaign, candidate_types, "baseline")
            return CompensationManagerV3(
                context=context,
                campaign=campaign,
                gateway=gateway,
                action_ledger=action_ledger,
                mutation_approval=current,
                initial_state_sha256=initial,
                state_hash_reader=lambda: _fixture_observed_state_hash(
                    context, campaign, candidate_types, "cleanup_check"
                ),
            )

        if current_group == "cleanup":
            return workflow.recover_cleanup(
                approval_store=approval_store,
                compensation_manager=compensation_factory(),
            )
        return workflow.advance_verification(
            approval_store=approval_store,
            compensation_manager_factory=(
                compensation_factory if current_group == "mutation" else None
            ),
        )
    if state.execution_state is ExecutionStateV3.AWAITING_REVIEW:
        findings = FindingSet.model_validate_json(
            context.artifact_path("report/finding-set-v3.json").read_bytes()
        )
        coverage = CoverageReportV3.model_validate_json(
            context.artifact_path("report/coverage-v3.json").read_bytes()
        )
        approvals = tuple(
            ApprovalBatchV3.model_validate_json(path.read_bytes())
            for path in sorted(context.artifact_path("approvals_v3").glob("*.json"))
            if not path.name.startswith("challenge-")
        )

        def approval_verifier(batch: Any, campaign: Any) -> None:
            verify_approval_batch_v3(batch, campaign, approval_store)

        def review_verifier(review: Any, found: Any, covered: Any) -> None:
            verify_review_batch_v3(
                review,
                found,
                covered,
                review_store,
                report_draft_digest=file_sha256(context.artifact_path("report/draft-v3.md")),
                approval_batches=approvals,
                approval_trust_store=approval_store,
            )

        verifier = ReportPreflightVerifierV3(
            context,
            approval_signature_verifier=approval_verifier,
            review_signature_verifier=review_verifier,
            evidence_store=_evidence_store(config, context, policy),
        )
        if not context.artifact_path("reviews/signed-v3.json").is_file():
            raise CliError("run still requires a signed human review")
        workflow = VerticalWorkflowV3(context, _build_runner_v3(config, context, policy))
        _ = findings, coverage
        return workflow.complete_report(verifier)
    raise CliError(f"cannot resume V3 state {state.execution_state.value}")


def _validate(config: dict[str, Any], scope_path: Path | None = None) -> dict[str, Any]:
    if not isinstance(config.get("role_manifests"), Path):
        raise CliError("V2 config is missing role_manifests")
    manifest_document = _json_file(Path(config["role_manifests"]))
    manifests = _manifests(Path(config["role_manifests"]))
    trust = RoleTrustStore.from_file(Path(config["role_trust_store"]))
    registry = PromptRegistry(Path(config["prompt_root"]))
    if manifest_document.get("prompt_registry_sha256") != registry.digest:
        raise CliError("role manifest bundle is bound to another prompt registry")
    for manifest in manifests.values():
        trust.verify(manifest)
        registry.verify_manifest(manifest)
    approval, review = _stores(config)
    publisher_store = TrustStoreV2.from_file(Path(config["role_trust_store"]))
    publisher_ids = {item.key_id for item in manifests.values()}
    if any(
        not _currently_trusted(publisher_store, key_id, KeyUsage.ROLE_MANIFEST)
        for key_id in publisher_ids
    ):
        raise CliError("all active role manifests must use a currently active Publisher key")
    approval_ids = {
        item.key_id
        for item in approval.keys
        if KeyUsage.APPROVAL in item.usages
        and _currently_trusted(approval, item.key_id, KeyUsage.APPROVAL)
    }
    review_ids = {
        item.key_id
        for item in review.keys
        if KeyUsage.HUMAN_REVIEW in item.usages
        and _currently_trusted(review, item.key_id, KeyUsage.HUMAN_REVIEW)
    }
    if publisher_ids & approval_ids or publisher_ids & review_ids or approval_ids & review_ids:
        raise CliError("Publisher, Approver, and Reviewer key IDs must be disjoint")
    publisher_public = {
        item.public_key
        for item in publisher_store.keys
        if KeyUsage.ROLE_MANIFEST in item.usages
        and item.key_id in publisher_ids
        and _currently_trusted(publisher_store, item.key_id, KeyUsage.ROLE_MANIFEST)
    }
    approval_public = {
        item.public_key for item in approval.keys if KeyUsage.APPROVAL in item.usages
    }
    review_public = {
        item.public_key for item in review.keys if KeyUsage.HUMAN_REVIEW in item.usages
    }
    if (
        publisher_public & approval_public
        or publisher_public & review_public
        or approval_public & review_public
    ):
        raise CliError("Publisher, Approver, and Reviewer must use different key material")
    if not publisher_public:
        raise CliError("publisher trust store has no active manifest key used by the bundle")
    if not approval_ids or not review_ids:
        raise CliError("approval and review trust stores must each contain their required usage")
    if scope_path is not None:
        policy, _ = load_scope_policy(scope_path)
        _validate_local_lab_scope(policy)
        if policy.retain_encrypted_raw_evidence:
            if config.get("raw_key_file") is None or config.get("raw_key_id") is None:
                raise CliError("raw evidence retention requires raw_key_file and raw_key_id")
            FileEvidenceKeyProvider(
                key_path=Path(config["raw_key_file"]),
                key_id=str(config["raw_key_id"]),
                forbidden_roots=(
                    Path(__file__).resolve().parents[2],
                    Path(config["runs_root"]),
                ),
            )
    return {"valid": True, "roles": sorted(manifests), "prompt_registry_digest": registry.digest}


def _validate_v3(config: dict[str, Any], scope_path: Path | None = None) -> dict[str, Any]:
    manifest_path = config.get("role_manifests_v3")
    if not isinstance(manifest_path, Path):
        raise CliError("V3 config is missing role_manifests_v3")
    document = _json_file(manifest_path)
    manifests = _manifests_v3(manifest_path)
    trust = RoleTrustStore.from_file(Path(config["role_trust_store"]))
    registry = PromptRegistryV3(Path(config["prompt_root"]))
    if document.get("prompt_registry_sha256") != registry.digest:
        raise CliError("V3 manifest bundle is bound to another prompt registry")
    for manifest in manifests.values():
        trust.verify(manifest)
        registry.verify_manifest(manifest)
    _validate_v3_key_separation(config, manifests)
    budget = ExecutionBudgetV3()
    if (
        budget.max_concurrency != 4
        or budget.max_model_attempts != 40
        or budget.reservation_per_attempt_microusd * budget.max_model_attempts
        != budget.max_estimated_cost_microusd
    ):
        raise CliError("V3 conservative budget contract is inconsistent")
    if scope_path is not None:
        policy, _ = load_scope_policy(scope_path)
        _validate_local_lab_scope_v3(policy)
    vault_path = config.get("identity_vault")
    aliases: list[str] = []
    if isinstance(vault_path, Path):
        vault = load_identity_vault_v3(
            vault_path,
            repo_root=Path(__file__).resolve().parents[2],
            runs_root=Path(config["runs_root"]),
        )
        aliases = list(vault.aliases)
        if not {"member", "fixture-admin"} <= set(aliases):
            raise CliError("full Phase 4 fixture requires member and fixture-admin identities")
        if len(set(vault.binding_digests.values())) != len(vault.binding_digests):
            raise CliError("V3 identity aliases must have distinct credential bindings")
    elif scope_path is not None:
        raise CliError("V3 run config is missing identity_vault")
    return {
        "valid": True,
        "version": "3",
        "roles": sorted(manifests),
        "prompt_registry_digest": registry.digest,
        "identity_aliases": aliases,
        "identity_bindings": len(aliases),
        "max_requests": 15,
        "max_concurrency": 4,
        "max_model_attempts": 40,
        "max_estimated_cost_microusd": 10_000_000,
    }


def _validate_v4(config: dict[str, Any], scope_path: Path | None = None) -> dict[str, Any]:
    manifest_path = config.get("role_manifests_v4")
    if not isinstance(manifest_path, Path):
        raise CliError("V4 config is missing role_manifests_v4")
    document = _json_file(manifest_path)
    manifests = _manifests_v4(manifest_path)
    trust = RoleTrustStore.from_file(Path(config["role_trust_store"]))
    registry = PromptRegistryV4(Path(config["prompt_root"]))
    if document.get("prompt_registry_sha256") != registry.digest:
        raise CliError("V4 manifest bundle is bound to another prompt registry")
    for manifest in manifests.values():
        trust.verify(manifest)
        registry.verify_manifest(manifest)
    _validate_v3_key_separation(config, manifests)
    budget = ExecutionBudgetV4()
    if (
        budget.max_concurrency != 4
        or budget.max_requests != 32
        or budget.max_model_attempts != 64
        or budget.max_active_seconds != 2_700
        or budget.max_role_seconds != 300
        or budget.reservation_per_attempt_microusd * budget.max_model_attempts
        != budget.max_estimated_cost_microusd
    ):
        raise CliError("V4 conservative budget contract is inconsistent")
    vault_path = config.get("identity_vault")
    aliases: list[str] = []
    if isinstance(vault_path, Path):
        vault = load_identity_vault_v3(
            vault_path,
            repo_root=Path(__file__).resolve().parents[2],
            runs_root=Path(config["runs_root"]),
        )
        aliases = list(vault.aliases)
        if not {"alice", "bob", "fixture-admin"} <= set(aliases):
            raise CliError("V4 requires alice, bob, and fixture-admin identities")
        if len(set(vault.binding_digests.values())) != len(vault.binding_digests):
            raise CliError("V4 identity aliases must have distinct credential bindings")
    elif scope_path is not None:
        raise CliError("V4 run config is missing identity_vault")
    if scope_path is not None:
        policy, _ = load_scope_policy(scope_path)
        _validate_local_lab_scope_v4(policy)
        ca_file = config.get("v4_fixture_ca_file")
        dataset = config.get("v4_quality_dataset")
        if not isinstance(ca_file, Path) or not ca_file.is_file():
            raise CliError("V4 requires an explicit trusted localhost fixture CA file")
        if not isinstance(dataset, Path) or not dataset.is_file():
            raise CliError("V4 requires a frozen quality dataset")
        try:
            from .quality_v4 import load_quality_dataset_v4, validate_quality_dataset_v4

            validate_quality_dataset_v4(load_quality_dataset_v4(dataset))
        except ValueError as exc:
            raise CliError("V4 quality dataset does not meet the frozen quality floor") from exc
    return {
        "valid": True,
        "version": "4",
        "roles": sorted(manifests),
        "prompt_registry_digest": registry.digest,
        "identity_aliases": aliases,
        "max_requests": 32,
        "max_concurrency": 4,
        "max_model_attempts": 64,
        "max_estimated_cost_microusd": 16_000_000,
        "max_active_seconds": 2_700,
        "max_role_seconds": 300,
    }


def _validate_v3_key_separation(
    config: dict[str, Any], manifests: Mapping[str, RoleManifest]
) -> None:
    publisher = TrustStoreV2.from_file(Path(config["role_trust_store"]))
    approval, review = _stores(config)
    publisher_ids = {item.key_id for item in manifests.values()}
    approval_ids = {
        item.key_id
        for item in approval.keys
        if KeyUsage.APPROVAL in item.usages
        and _currently_trusted(approval, item.key_id, KeyUsage.APPROVAL)
    }
    review_ids = {
        item.key_id
        for item in review.keys
        if KeyUsage.HUMAN_REVIEW in item.usages
        and _currently_trusted(review, item.key_id, KeyUsage.HUMAN_REVIEW)
    }
    if not publisher_ids or not approval_ids or not review_ids:
        raise CliError("V3 requires active Publisher, Approver, and Reviewer keys")
    if publisher_ids & approval_ids or publisher_ids & review_ids or approval_ids & review_ids:
        raise CliError("Publisher, Approver, and Reviewer key IDs must be disjoint")
    publisher_public = {
        item.public_key
        for item in publisher.keys
        if item.key_id in publisher_ids
        and KeyUsage.ROLE_MANIFEST in item.usages
        and _currently_trusted(publisher, item.key_id, KeyUsage.ROLE_MANIFEST)
    }
    approval_public = {
        item.public_key
        for item in approval.keys
        if item.key_id in approval_ids and KeyUsage.APPROVAL in item.usages
    }
    review_public = {
        item.public_key
        for item in review.keys
        if item.key_id in review_ids and KeyUsage.HUMAN_REVIEW in item.usages
    }
    if (
        len(publisher_public) != len(publisher_ids)
        or publisher_public & approval_public
        or publisher_public & review_public
        or approval_public & review_public
    ):
        raise CliError("Publisher, Approver, and Reviewer must use active, distinct key material")


def _currently_trusted(store: TrustStoreV2, key_id: str, usage: KeyUsage) -> bool:
    try:
        store.trusted_public_key(key_id, usage)
    except ValueError:
        return False
    return True


def _validate_local_lab_scope(policy: Any) -> None:
    if (
        policy.profile != "local-lab"
        or not policy.automation_allowed
        or policy.dry_run
        or policy.max_requests != 3
        or policy.max_concurrency != 1
        or policy.allowed_commands
        or len(policy.rules) != 1
    ):
        raise CliError("Phase 2 requires the strict three-request local-lab profile")
    rule = policy.rules[0]
    if (
        rule.profile != "local-lab"
        or rule.host != "localhost"
        or rule.schemes != frozenset({"http"})
        or len(rule.ports) != 1
        or not rule.allow_dns
        or not rule.allow_private
    ):
        raise CliError("Phase 2 local-lab scope must contain one exact localhost HTTP port")


def _validate_local_lab_scope_v3(policy: Any) -> None:
    if (
        policy.profile != "local-lab"
        or not policy.automation_allowed
        or policy.dry_run
        or policy.max_requests != 15
        or policy.max_concurrency != 4
        or policy.allowed_commands
        or len(policy.rules) != 1
    ):
        raise CliError("Phase 4 requires the strict 15-request, concurrency-4 local-lab profile")
    rule = policy.rules[0]
    if (
        rule.profile != "local-lab"
        or rule.host != "localhost"
        or rule.schemes != frozenset({"http"})
        or len(rule.ports) != 1
        or not rule.allow_dns
        or not rule.allow_private
    ):
        raise CliError("Phase 4 scope must contain one exact localhost HTTP port")


def _validate_local_lab_scope_v4(policy: Any) -> None:
    if (
        policy.profile != "local-lab"
        or not policy.automation_allowed
        or policy.dry_run
        or policy.max_requests != 32
        or policy.max_concurrency != 4
        or policy.allowed_commands
        or len(policy.rules) != 1
    ):
        raise CliError("Phase 5 requires the strict 32-request, concurrency-4 local-lab profile")
    rule = policy.rules[0]
    if (
        rule.profile != "local-lab"
        or rule.host != "localhost"
        or rule.schemes != frozenset({"https"})
        or len(rule.ports) != 1
        or not rule.allow_dns
        or not rule.allow_private
    ):
        raise CliError("Phase 5 scope must contain one exact localhost HTTPS port")


def _loopback_transport_smoke() -> bool:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(2)
    port = int(listener.getsockname()[1])

    def serve() -> None:
        connection, _ = listener.accept()
        with connection:
            connection.recv(4096)
            connection.sendall(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")

    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    try:
        response = PinnedHttpTransport(timeout_seconds=2)(
            HttpRequest(
                method="GET",
                url=f"http://localhost:{port}/doctor",
                connect_ip="127.0.0.1",
                host_header=f"localhost:{port}",
                tls_server_name=None,
                headers={"Host": f"localhost:{port}"},
            )
        )
        worker.join(timeout=2)
        return response.status_code == 204 and not worker.is_alive()
    except OSError:
        return False
    finally:
        listener.close()


def _task_acp_db_smoke(bridge_path: Path) -> bool:
    """Exercise the bridge's real path policy in an isolated temporary run."""

    try:
        namespace = runpy.run_path(str(bridge_path))
        prepare = namespace.get("_prepare_home")
        if not callable(prepare):
            return False
        with tempfile.TemporaryDirectory(prefix="hermes-acp-doctor-") as raw_root:
            root = Path(raw_root)
            resolved_root = root.resolve()
            first = Path(prepare(root, "doctor-task-a"))
            second = Path(prepare(root, "doctor-task-b"))
            first_db = first / "state.db"
            second_db = second / "state.db"
            return (
                first != second
                and first_db != second_db
                and resolved_root in first.resolve().parents
                and resolved_root in second.resolve().parents
                and stat.S_IMODE(first.stat().st_mode) == 0o700
                and stat.S_IMODE(second.stat().st_mode) == 0o700
            )
    except (OSError, ValueError, TypeError, RuntimeError):
        return False


def _concurrency_smoke() -> bool:
    barrier = threading.Barrier(4)
    guard = threading.Lock()
    active = 0
    maximum = 0

    def participant() -> None:
        nonlocal active, maximum
        with guard:
            active += 1
            maximum = max(maximum, active)
        try:
            barrier.wait(timeout=2)
        finally:
            with guard:
                active -= 1

    try:
        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = [pool.submit(participant) for _ in range(4)]
            for future in futures:
                future.result(timeout=3)
    except (OSError, RuntimeError, threading.BrokenBarrierError):
        return False
    return maximum == 4 and active == 0


def _identity_injection_smoke(
    config: Mapping[str, Any],
    *,
    required_aliases: frozenset[str] = frozenset({"member", "fixture-admin"}),
) -> bool:
    vault_path = config.get("identity_vault")
    if not isinstance(vault_path, Path):
        return False
    try:
        vault = load_identity_vault_v3(
            vault_path,
            repo_root=Path(__file__).resolve().parents[2],
            runs_root=Path(config["runs_root"]),
        )
        bindings = dict(vault.binding_digests)
        return (
            required_aliases <= set(vault.aliases)
            and len(set(bindings.values())) == len(bindings)
            and all(
                vault.credential(alias).binding_digest == bindings[alias]
                and bool(vault.credential(alias).secret)
                and vault.credential(alias).secret not in repr(vault)
                for alias in vault.aliases
            )
        )
    except (OSError, ValueError):
        return False


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hermes-security")
    parser.add_argument("--json", action="store_true")
    commands = parser.add_subparsers(dest="command", required=True)
    doctor = commands.add_parser("doctor")
    doctor.add_argument("--config", type=Path, required=True)
    doctor.add_argument("--schema-version", choices=("2", "3", "4"), default="3")
    validate = commands.add_parser("validate-config")
    validate.add_argument("--config", type=Path, required=True)
    validate.add_argument("--scope", type=Path)
    validate.add_argument("--schema-version", choices=("2", "3", "4"), default="3")
    run = commands.add_parser("run")
    run.add_argument("--config", type=Path, required=True)
    run.add_argument("--scope", type=Path, required=True)
    run.add_argument("--target", required=True)
    run.add_argument("--schema-version", choices=("2", "3", "4"), default="3")
    run.add_argument("--workflow", choices=("v2", "v3", "v4"))
    for name in ("approve", "reject"):
        item = commands.add_parser(name)
        item.add_argument("--config", type=Path, required=True)
        item.add_argument("--run-id", required=True)
        item.add_argument("--challenge-id", required=True)
        item.add_argument("--key", type=Path, required=True)
        item.add_argument("--operator", default="operator")
        item.add_argument("--reason")
        item.add_argument("--risk-group", choices=("readonly", "mutation", "cleanup"))
        item.add_argument("--candidate-id", action="append", default=[])
    resume = commands.add_parser("resume")
    resume.add_argument("--config", type=Path, required=True)
    resume.add_argument("--run-id", required=True)
    retry = commands.add_parser("retry")
    retry.add_argument("--config", type=Path, required=True)
    retry.add_argument("--run-id", required=True)
    review = commands.add_parser("review")
    review_sub = review.add_subparsers(dest="review_command", required=True)
    sign = review_sub.add_parser("sign")
    sign.add_argument("--config", type=Path, required=True)
    sign.add_argument("--run-id", required=True)
    sign.add_argument("--outcome-id", required=True)
    sign.add_argument(
        "--verdict", choices=("accepted", "accepted_with_gaps", "rejected"), required=True
    )
    sign.add_argument("--key", type=Path, required=True)
    sign.add_argument("--rationale", required=True)
    sign.add_argument("--operator", default="reviewer")
    keys = commands.add_parser("keys")
    keys_sub = keys.add_subparsers(dest="keys_command", required=True)
    generate = keys_sub.add_parser("generate")
    generate.add_argument("--usage", choices=("publisher", "approver", "reviewer"), required=True)
    generate.add_argument("--out", type=Path, required=True)
    status = commands.add_parser("status")
    status.add_argument("--config", type=Path, required=True)
    status.add_argument("--run-id", required=True)
    learn = commands.add_parser("learn")
    learn_sub = learn.add_subparsers(dest="learn_command", required=True)
    learn_doctor = learn_sub.add_parser("doctor")
    learn_doctor.add_argument("--config", type=Path, required=True)
    learn_validate = learn_sub.add_parser("validate-config")
    learn_validate.add_argument("--config", type=Path, required=True)
    learn_start = learn_sub.add_parser("start")
    learn_start.add_argument("--config", type=Path, required=True)
    learn_start.add_argument("--parent-run-id", required=True)
    learn_start.add_argument("--observation-file", type=Path, required=True)
    learn_start.add_argument("--evidence-id", required=True)
    learn_start.add_argument("--risk-level", choices=("low", "medium", "high"), default="low")
    learn_research = learn_sub.add_parser("research")
    learn_research.add_argument("--config", type=Path, required=True)
    learn_research.add_argument("--run-id", required=True)
    learn_research.add_argument("--source-bundle", type=Path, required=True)
    learn_plan = learn_sub.add_parser("plan")
    learn_plan.add_argument("--config", type=Path, required=True)
    learn_plan.add_argument("--run-id", required=True)
    learn_generate = learn_sub.add_parser("generate")
    learn_generate.add_argument("--config", type=Path, required=True)
    learn_generate.add_argument("--run-id", required=True)
    learn_validate_run = learn_sub.add_parser("validate")
    learn_validate_run.add_argument("--config", type=Path, required=True)
    learn_validate_run.add_argument("--run-id", required=True)
    learn_validate_run.add_argument("--key", type=Path, required=True)
    learn_approve = learn_sub.add_parser("approve")
    learn_approve.add_argument("--config", type=Path, required=True)
    learn_approve.add_argument("--run-id", required=True)
    learn_approve.add_argument("--key", type=Path, required=True)
    learn_approve.add_argument("--rationale", required=True)
    learn_activate = learn_sub.add_parser("activate")
    learn_activate.add_argument("--config", type=Path, required=True)
    learn_activate.add_argument("--run-id", required=True)
    learn_activate.add_argument("--key", type=Path, required=True)
    learn_continue = learn_sub.add_parser("continue")
    learn_continue.add_argument("--config", type=Path, required=True)
    learn_continue.add_argument("--run-id", required=True)
    learn_status = learn_sub.add_parser("status")
    learn_status.add_argument("--config", type=Path, required=True)
    learn_status.add_argument("--run-id", required=True)
    for name in ("quarantine", "revoke"):
        item = learn_sub.add_parser(name)
        item.add_argument("--config", type=Path, required=True)
        item.add_argument("--run-id", required=True)
        item.add_argument("--key", type=Path, required=True)
        item.add_argument("--reason", required=True)
    # CAP-07 (docs/08 §6.3): compose a governed assessment recovery from a paused
    # assessment record + an R2.5 continuation outcome + the active Wheels. This is
    # a cross-artifact composition, so it takes standalone JSON files rather than a
    # run context. Fail-closed via hermes.cap07.verify_recovery_bundle.
    learn_recover = learn_sub.add_parser("recover")
    learn_recover.add_argument("--pause", type=Path, required=True)
    learn_recover.add_argument("--continuation", type=Path, required=True)
    learn_recover.add_argument("--wheels", type=Path, required=True)
    learn_recover.add_argument("--resume-run-id", required=True)
    learn_recover.add_argument("--summary", required=True)
    learn_recover.add_argument("--out", type=Path, default=None)
    return parser


def _learn_recover(args: argparse.Namespace) -> int:
    """CAP-07: compose + verify a governed recovery from standalone artifact files."""

    from .cap07 import Cap07Error, orchestrate_recovery
    from .learning_recovery import ActiveWheelView, AssessmentPauseRecordV1, RecoveryBlocked
    from .r25_contracts import ContinuationOutcomeV1

    pause = AssessmentPauseRecordV1.model_validate_json(args.pause.read_text(encoding="utf-8"))
    continuation = ContinuationOutcomeV1.model_validate_json(
        args.continuation.read_text(encoding="utf-8")
    )
    wheels_raw = json.loads(args.wheels.read_text(encoding="utf-8"))
    if not isinstance(wheels_raw, list):
        raise CliError("--wheels must be a JSON array of ActiveWheelView objects")
    wheels = tuple(ActiveWheelView.model_validate(item) for item in wheels_raw)
    try:
        bundle = orchestrate_recovery(
            pause,
            continuation,
            wheels,
            resume_run_id=args.resume_run_id,
            summary=args.summary,
            now=datetime.now(UTC),
        )
    except (Cap07Error, RecoveryBlocked) as exc:
        raise CliError(f"CAP-07 recovery refused: {exc}") from exc
    if args.out is not None:
        args.out.write_text(bundle.model_dump_json(indent=2) + "\n", encoding="utf-8")
    return _emit_model(bundle, as_json=args.json)


def _execute(args: argparse.Namespace) -> int:
    if args.command == "validate-config":
        config = _config(args.config)
        result = (
            _validate_v3(config, args.scope)
            if args.schema_version == "3"
            else _validate_v4(config, args.scope)
            if args.schema_version == "4"
            else _validate(config, args.scope)
        )
        print(json.dumps(result, ensure_ascii=False) if args.json else "configuration valid")
        return 0
    if args.command == "doctor":
        config = _config(args.config)
        result = (
            _validate_v3(config)
            if args.schema_version == "3"
            else _validate_v4(config)
            if args.schema_version == "4"
            else _validate(config)
        )
        checks = {
            **result,
            "python": sys.version.split()[0],
            "restricted_bridge": Path(config["restricted_bridge"]).is_file(),
            "hermes_python": Path(config["hermes_python"]).is_file(),
        }
        version = subprocess.run(
            [str(config["hermes_cli"]), "--version"],
            capture_output=True,
            text=True,
            check=False,
        )
        acp_check = subprocess.run(
            [str(config["hermes_cli"]), "acp", "--check"],
            capture_output=True,
            text=True,
            check=False,
        )
        acp_sdk = subprocess.run(
            [
                str(config["hermes_python"]),
                "-c",
                ("import importlib.metadata as m;print(m.version('agent-client-protocol'))"),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        checks["hermes_agent_0_16"] = version.returncode == 0 and "0.16.0" in (
            version.stdout + version.stderr
        )
        checks["hermes_acp_ready"] = acp_check.returncode == 0
        checks["agent_client_protocol_0_9"] = (
            acp_sdk.returncode == 0 and acp_sdk.stdout.strip() == "0.9.0"
        )
        checks["loopback_transport"] = _loopback_transport_smoke()
        if args.schema_version in {"3", "4"}:
            checks["task_acp_db_isolation"] = _task_acp_db_smoke(Path(config["restricted_bridge"]))
            checks["parallel_concurrency_4"] = _concurrency_smoke()
            checks["identity_injection"] = _identity_injection_smoke(
                config,
                required_aliases=(
                    frozenset({"alice", "bob", "fixture-admin"})
                    if args.schema_version == "4"
                    else frozenset({"member", "fixture-admin"})
                ),
            )
        aes_key = os.urandom(32)
        nonce = os.urandom(12)
        aad = b"hermes-evidence-v2-doctor"
        ciphertext = AESGCM(aes_key).encrypt(nonce, b"smoke", aad)
        checks["aes_256_gcm"] = AESGCM(aes_key).decrypt(nonce, ciphertext, aad) == b"smoke"
        docker = subprocess.run(
            [str(config["docker_binary"]), "info"], capture_output=True, text=True, check=False
        )
        checks["docker_daemon"] = docker.returncode == 0
        image_checks: dict[str, bool] = {}
        manifests = (
            _manifests_v3(Path(config["role_manifests_v3"]))
            if args.schema_version == "3"
            else _manifests_v4(Path(config["role_manifests_v4"]))
            if args.schema_version == "4"
            else _manifests(Path(config["role_manifests"]))
        )
        images = {item.image for item in manifests.values()}
        for image in sorted(images):
            inspected = subprocess.run(
                [str(config["docker_binary"]), "image", "inspect", image],
                capture_output=True,
                text=True,
                check=False,
            )
            image_checks[image] = inspected.returncode == 0
        checks["role_images"] = image_checks
        checks["role_images_available"] = bool(image_checks) and all(image_checks.values())
        required_checks: tuple[str, ...] = (
            "restricted_bridge",
            "hermes_python",
            "docker_daemon",
            "role_images_available",
            "hermes_agent_0_16",
            "hermes_acp_ready",
            "agent_client_protocol_0_9",
            "loopback_transport",
            "aes_256_gcm",
        )
        if args.schema_version in {"3", "4"}:
            required_checks += (
                "task_acp_db_isolation",
                "parallel_concurrency_4",
                "identity_injection",
            )
        if not all(checks[key] for key in required_checks):
            raise CliError(f"doctor checks failed: {checks}")
        print(json.dumps(checks, ensure_ascii=False) if args.json else "doctor checks passed")
        return 0
    if args.command == "run":
        config = _config(args.config)
        policy, snapshot = load_scope_policy(args.scope)
        selected_workflow = args.workflow or f"v{args.schema_version}"
        if selected_workflow == "v4":
            _validate_v4(config, args.scope)
            state: VerticalState | VerticalStateV3 | VerticalStateV4 = _start_vertical_run_v4(
                config, policy=policy, scope_snapshot=snapshot, target=args.target
            )
        elif selected_workflow == "v3":
            _validate_v3(config, args.scope)
            state = _start_vertical_run_v3(
                config, policy=policy, scope_snapshot=snapshot, target=args.target
            )
        else:
            _validate(config, args.scope)
            state = _start_vertical_run(
                config, policy=policy, scope_snapshot=snapshot, target=args.target
            )
        return _emit(state, as_json=args.json)
    if args.command == "status":
        config = _config(args.config)
        context = _open_context(config, args.run_id)
        raw = _json_file(context.artifact_path("state.json"))
        if raw.get("version") == "3":
            v3_state = VerticalStateV3.model_validate(raw)
            payload = status_payload_v3(context, v3_state)
            if args.json:
                print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
            else:
                for field_name, value in payload.items():
                    print(f"{field_name}: {value}")
            return _state_exit(v3_state)
        if raw.get("version") == "4":
            v4_state = VerticalStateV4.model_validate(raw)
            payload = status_payload_v4(context, v4_state)
            if args.json:
                print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
            else:
                for field_name, value in payload.items():
                    print(f"{field_name}: {value}")
            return _state_exit(v4_state)
        v2_state = VerticalState.model_validate(raw)
        return _emit(v2_state, as_json=args.json)
    if args.command == "retry":
        config = _config(args.config)
        _validate(config)
        parent = _open_context(config, args.run_id)
        require_v2_run(parent)
        parent_state = VerticalState.model_validate_json(
            parent.artifact_path("state.json").read_bytes()
        )
        if parent_state.execution_state is not ExecutionState.FAILED:
            raise CliError("only a failed run can be retried as a fresh run")
        if not parent.artifact_path("failure.json").is_file():
            raise CliError("failed run has no structured failure artifact")
        plan = RunPlan.model_validate_json(
            parent.artifact_path("plan/run-plan.json").read_text(encoding="utf-8")
        )
        scope_snapshot = _json_file(parent.artifact_path("scope.json"))
        from .runtime import ScopePolicy

        policy = ScopePolicy.model_validate(scope_snapshot)
        _validate_local_lab_scope(policy)
        state = _start_vertical_run(
            config,
            policy=policy,
            scope_snapshot=scope_snapshot,
            target=plan.target,
            retry_of=parent,
        )
        return _emit(state, as_json=args.json)
    if args.command in {"approve", "reject"}:
        config = _config(args.config)
        context = _open_context(config, args.run_id)
        if context.artifact_path("plan/run-v4.json").is_file():
            state = _decision_v4(args, "approved" if args.command == "approve" else "rejected")
        elif context.artifact_path("plan/run-v3.json").is_file():
            state = _decision_v3(args, "approved" if args.command == "approve" else "rejected")
        else:
            state = _decision(args, "approved" if args.command == "approve" else "rejected")
        return _emit(state, as_json=args.json)
    if args.command == "review":
        config = _config(args.config)
        context = _open_context(config, args.run_id)
        state = (
            _review_v4(args)
            if context.artifact_path("plan/run-v4.json").is_file()
            else _review_v3(args)
            if context.artifact_path("plan/run-v3.json").is_file()
            else _review(args)
        )
        return _emit(state, as_json=args.json)
    if args.command == "resume":
        config = _config(args.config)
        context = _open_context(config, args.run_id)
        if context.artifact_path("plan/run-v4.json").is_file():
            from .runtime import ScopePolicy

            policy = ScopePolicy.model_validate(_json_file(context.artifact_path("scope.json")))
            return _emit(_resume_v4(config, context, policy), as_json=args.json)
        if context.artifact_path("plan/run-v3.json").is_file():
            from .runtime import ScopePolicy

            policy = ScopePolicy.model_validate(_json_file(context.artifact_path("scope.json")))
            return _emit(_resume_v3(config, context, policy), as_json=args.json)
        _validate(config)
        require_v2_run(context)
        scope = _json_file(context.artifact_path("scope.json"))
        from .runtime import ScopePolicy

        policy = ScopePolicy.model_validate(scope)
        workflow = VerticalWorkflowV2(
            context,
            _build_runner(config, context, policy),
            evidence_store=_evidence_store(config, context, policy),
            publisher_store=RoleTrustStore.from_file(Path(config["role_trust_store"])),
            prompt_registry=PromptRegistry(Path(config["prompt_root"])),
        )
        try:
            state = workflow.resume(
                approval_store=_stores(config)[0], review_store=_stores(config)[1]
            )
        except Exception as exc:
            raise CliRunFailure(workflow.mark_failed(exc), exc) from exc
        return _emit(state, as_json=args.json)
    if args.command == "keys":
        if args.out.exists():
            raise CliError("refusing to overwrite an existing private key")
        source_root = Path(__file__).resolve().parents[2]
        output = args.out.resolve()
        if (source_root / "pyproject.toml").is_file() and (
            output == source_root or source_root in output.parents
        ):
            raise CliError("private keys must be generated outside the repository")
        args.out.parent.mkdir(parents=True, exist_ok=True)
        key = generate_ed25519_private_key()
        args.out.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        os.chmod(args.out, 0o600)
        print(json.dumps({"usage": args.usage, "public_key": encode_base64(public_key_bytes(key))}))
        return 0
    if args.command == "learn":
        # 'recover' composes standalone artifact files and needs no config context.
        if args.learn_command == "recover":
            return _learn_recover(args)
        config = _config(args.config)
        if args.learn_command == "doctor":
            result = validate_learning_config(config)
            docker = subprocess.run(
                [str(config["docker_binary"]), "info"], capture_output=True, text=True, check=False
            )
            image_inspect = subprocess.run(
                [
                    str(config["docker_binary"]),
                    "image",
                    "inspect",
                    str(config["wheel_sandbox_image"]),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            hermes_version_process = subprocess.run(
                [str(config["hermes_cli"]), "--version"],
                capture_output=True,
                text=True,
                check=False,
            )
            acp_sdk = subprocess.run(
                [
                    str(config["hermes_python"]),
                    "-c",
                    ("import importlib.metadata as m;print(m.version('agent-client-protocol'))"),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            checks = {
                **result,
                "docker_daemon": docker.returncode == 0,
                "wheel_sandbox_image_present": image_inspect.returncode == 0,
                "hermes_agent_0_16": hermes_version_process.returncode == 0
                and "0.16.0" in (hermes_version_process.stdout + hermes_version_process.stderr),
                "agent_client_protocol_0_9": acp_sdk.returncode == 0
                and acp_sdk.stdout.strip() == "0.9.0",
            }
            if not all(checks.values()):
                raise CliError(f"R2.5 doctor checks failed: {checks}")
            print(
                json.dumps(checks, ensure_ascii=False) if args.json else "R2.5 doctor checks passed"
            )
            return 0
        if args.learn_command == "validate-config":
            result = validate_learning_config(config)
            print(
                json.dumps(result, ensure_ascii=False) if args.json else "R2.5 configuration valid"
            )
            return 0
        if args.learn_command == "start":
            return _emit_model(
                start_learning_run(
                    config,
                    parent_run_id=args.parent_run_id,
                    evidence_id=args.evidence_id,
                    observation_file=args.observation_file,
                    risk_level=args.risk_level,
                ),
                as_json=args.json,
            )
        if args.learn_command == "research":
            return _emit_model(
                research_learning_run(
                    config,
                    run_id=args.run_id,
                    source_bundle=args.source_bundle,
                    runner_factory=_r25_runner_factory(config),
                ),
                as_json=args.json,
            )
        if args.learn_command == "plan":
            return _emit_model(
                plan_learning_run(
                    config,
                    run_id=args.run_id,
                    runner_factory=_r25_runner_factory(config),
                ),
                as_json=args.json,
            )
        if args.learn_command == "generate":
            return _emit_model(
                generate_learning_capability(config, run_id=args.run_id),
                as_json=args.json,
            )
        if args.learn_command == "validate":
            return _emit_model(
                validate_learning_capability(config, run_id=args.run_id, key_path=args.key),
                as_json=args.json,
            )
        if args.learn_command == "approve":
            return _emit_model(
                approve_learning_capability(
                    config,
                    run_id=args.run_id,
                    key_path=args.key,
                    rationale=args.rationale,
                ),
                as_json=args.json,
            )
        if args.learn_command == "activate":
            return _emit_model(
                activate_learning_capability(config, run_id=args.run_id, key_path=args.key),
                as_json=args.json,
            )
        if args.learn_command == "continue":
            return _emit_model(
                continue_learning_run(config, run_id=args.run_id),
                as_json=args.json,
            )
        if args.learn_command == "status":
            payload = learning_status_payload(config, run_id=args.run_id)
            if args.json:
                print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
            else:
                for field_name, value in payload.items():
                    print(f"{field_name}: {value}")
            return 0
        if args.learn_command in {"quarantine", "revoke"}:
            return _emit_model(
                quarantine_or_revoke_learning_capability(
                    config,
                    run_id=args.run_id,
                    key_path=args.key,
                    reason=args.reason,
                    revoke=args.learn_command == "revoke",
                ),
                as_json=args.json,
            )
        raise CliError("unknown R2.5 command")
    raise CliError("unknown command")


def main(argv: list[str] | None = None) -> int:
    actual = list(sys.argv[1:] if argv is None else argv)
    commands = {
        "doctor",
        "validate-config",
        "run",
        "approve",
        "reject",
        "resume",
        "retry",
        "review",
        "keys",
        "status",
        "learn",
    }
    if (
        actual
        and actual[0].startswith("-")
        and "--target" in actual
        and not commands.intersection(actual)
    ):
        print(
            "warning: legacy flat CLI is deprecated; use hermes-security run",
            file=sys.stderr,
        )
        from .orchestrator import main as legacy_main

        return legacy_main(actual)
    args = _parser().parse_args(actual)
    try:
        return _execute(args)
    except CliRunFailure as exc:
        exit_code = _emit(exc.state, as_json=args.json)
        if not args.json:
            print(f"hermes-security: run failed: {exc}", file=sys.stderr)
        # A persisted state is the source of truth even when the operation
        # raises after committing it.  In particular, cleanup_required must
        # remain distinguishable from an ordinary runtime failure so callers
        # can present the cleanup-only approval workflow.
        return exit_code
    except (
        CliError,
        LegacyRunReadOnlyError,
        PolicyDenied,
        V3ManagementError,
        ValueError,
        OSError,
    ) as exc:
        print(f"hermes-security: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"hermes-security: unexpected failure: {exc}", file=sys.stderr)
        return 1

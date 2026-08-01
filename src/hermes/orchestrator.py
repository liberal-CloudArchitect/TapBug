"""Safe default Hermes entry point.

The core creates reviewable plans and isolated artifacts.  It does not contain a
scanner, exploit engine, credential workflow, or implicit HTTP transport.
Configured adapters may execute only through ``ToolGateway`` after policy and
approval checks have succeeded.
"""

from __future__ import annotations

import argparse
import base64
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .domain_contracts import VerificationPlan
from .evidence import EvidenceArtifactRef, EvidenceStore
from .runtime import (
    ActionKind,
    GatewayExecutionContext,
    PinnedHttpTransport,
    PolicyEngine,
    ProposedAction,
    RunContext,
    ScopePolicy,
    ToolGateway,
)
from .runtime.agents import (
    AgentRunner,
    EvidenceRef,
    GatewayActionRequest,
    RoleManifest,
    RoleTrustStore,
    RunnerHost,
    TaskEnvelope,
    TaskResult,
)
from .workflow import DEFAULT_ROLE_ORDER, WorkflowEngine


def load_scope_policy(path: Path) -> tuple[ScopePolicy, dict[str, Any]]:
    try:
        import yaml  # type: ignore[import-untyped]
    except ModuleNotFoundError as exc:  # pragma: no cover - exercised in installed environments
        raise RuntimeError(
            "PyYAML is required to load a YAML scope file; install Hermes dependencies"
        ) from exc
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("scope file must contain a mapping")
    return ScopePolicy.model_validate(raw), raw


class Orchestrator:
    """Creates run plans and records the chosen execution mode honestly."""

    def __init__(
        self,
        policy: ScopePolicy,
        snapshot: dict[str, Any],
        *,
        runs_root: Path,
        resume_run: str | None = None,
    ) -> None:
        self.policy = policy
        self.snapshot = snapshot
        self.context = (
            RunContext.open_existing(runs_root, snapshot, resume_run)
            if resume_run
            else RunContext(runs_root, snapshot)
        )
        self.engine = PolicyEngine(policy)

    def plan(self, targets: list[str], *, agent_mode: str = "single-process-rules") -> Path:
        if not targets:
            raise ValueError("at least one target is required")
        actions = []
        for target in targets:
            # Validate URL/scope while still performing zero network I/O.
            resolved = self.engine.resolve_url(target)
            actions.append(
                {
                    "action": ProposedAction(kind=ActionKind.HTTP_GET, target=target).model_dump(
                        mode="json"
                    ),
                    "resolved_target": {
                        "host": resolved.host,
                        "port": resolved.port,
                        "scheme": resolved.scheme,
                        "connect_ip": resolved.connect_ip,
                    },
                }
            )
        plan = {
            "run_id": self.context.run_id,
            "scope_digest": self.context.scope_digest,
            "execution_mode": agent_mode,
            "network_execution": "disabled-until-a-gateway-transport-is-configured",
            "actions": actions,
        }
        path = self.context.artifact_path("plan/run-plan.json")
        if path.exists():
            try:
                existing = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise ValueError("resumed run contains an invalid plan") from exc
            if existing != plan:
                raise ValueError("resumed run plan does not match requested targets or mode")
            return path
        return self.context.write_json("plan/run-plan.json", plan, immutable=True)

    def run_expert_workflow(
        self,
        runner: AgentRunner,
        *,
        roles: tuple[str, ...] = DEFAULT_ROLE_ORDER,
        payload: dict[str, Any] | None = None,
    ) -> list[TaskResult]:
        """Run a configured independent-agent workflow after creating the run context.

        CLI planning deliberately does not fabricate a runner. Integrators must
        supply a concrete runner (for example ``SubprocessAgentRunner``) so the
        system never labels same-process scanner calls as expert collaboration.
        """
        return WorkflowEngine(self.context, runner).run_roles(roles, payload)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Hermes policy-governed assessment core")
    parser.add_argument(
        "--scope", type=Path, default=Path("scope.yaml"), help="strict scope/RoE YAML"
    )
    parser.add_argument(
        "--runs-root", type=Path, default=Path("runs"), help="isolated run artifact directory"
    )
    parser.add_argument(
        "--target", action="append", required=True, help="target URL; repeat for multiple targets"
    )
    parser.add_argument(
        "--agent-mode",
        choices=("single-process-rules", "subprocess"),
        default="single-process-rules",
        help="subprocess mode needs a separately configured AgentRunner adapter",
    )
    parser.add_argument(
        "--role-manifest",
        type=Path,
        help="signed JSON role manifest document; required in subprocess mode",
    )
    parser.add_argument(
        "--role-trust-store",
        type=Path,
        help="Ed25519 public-key trust-store JSON; required in subprocess mode",
    )
    parser.add_argument(
        "--runner-host-config",
        type=Path,
        help="explicit JSON host configuration; required in subprocess mode",
    )
    parser.add_argument(
        "--resume-run",
        help="resume this run ID only after frozen scope and workflow chain verification",
    )
    return parser


def _load_role_manifests(path: Path) -> dict[str, RoleManifest]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        entries = raw.get("roles", raw) if isinstance(raw, dict) else raw
        if isinstance(entries, dict):
            entries = list(entries.values())
        if not isinstance(entries, list):
            raise ValueError("role manifest must contain a roles list")
        manifests = [RoleManifest.model_validate(value) for value in entries]
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError(f"could not load signed role manifest: {exc}") from exc
    mapped = {manifest.role: manifest for manifest in manifests}
    if not mapped or len(mapped) != len(manifests):
        raise ValueError("role manifest roles must be non-empty and unique")
    return mapped


def _load_host_config(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"could not load runner host config: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError("runner host config must be a JSON object")
    # Provider credentials and arbitrary network settings are deliberately absent:
    # a deployment-specific parent model proxy can be introduced behind this schema.
    unknown = set(value).difference({"model_proxy"})
    if unknown or value.get("model_proxy", "disabled") != "disabled":
        raise ValueError("only the explicit disabled model_proxy is currently supported")
    return value


def _gateway_handler(
    gateway: ToolGateway,
) -> Callable[[GatewayActionRequest, TaskEnvelope], dict[str, Any]]:
    def handle(request: GatewayActionRequest, task: TaskEnvelope) -> dict[str, Any]:
        body = (
            base64.b64decode(request.body_base64, validate=True)
            if request.body_base64 is not None
            else None
        )
        response, evidence = gateway.request(
            request.action.method or "GET",
            request.url,
            headers=request.headers,
            body=body,
            action_kind=request.action.kind,
            approval=request.approval_token,
        )
        evidence_path = f"evidence/{evidence.evidence_id}.json"
        return {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body_sha256": evidence.response_hash,
            "evidence_ref": {
                "id": evidence.evidence_id,
                "kind": "response",
                "sha256": evidence.response_hash,
                "path": evidence_path,
                "redacted": True,
            },
        }

    return handle


def _gateway_handler_v2(
    gateway: ToolGateway,
) -> Callable[[GatewayActionRequest, TaskEnvelope], dict[str, Any]]:
    """Bind role IPC to a typed task/action context and EvidenceArtifact V2."""

    def handle(request: GatewayActionRequest, task: TaskEnvelope) -> dict[str, Any]:
        body = (
            base64.b64decode(request.body_base64, validate=True)
            if request.body_base64 is not None
            else None
        )
        plan_digest: str | None = None
        bundle_id: str | None = None
        bundle_digest: str | None = None
        if task.role == "recon":
            action_id = "recon-get"
            if request.action.kind is not ActionKind.HTTP_GET:
                raise ValueError("Recon may request only its single bounded read")
        elif task.role == "verifier":
            plan = VerificationPlan.model_validate(task.payload.get("verification_plan"))
            step = next(
                (item for item in plan.steps if item.action_digest == request.action.digest),
                None,
            )
            if step is None:
                raise ValueError("Verifier IPC action is absent from the signed plan")
            action_id = step.action_id
            plan_digest = plan.digest
            bundle_id = task.payload.get("approval_bundle_id")
            bundle_digest = task.payload.get("approval_bundle_digest")
            if not isinstance(bundle_id, str) or not isinstance(bundle_digest, str):
                raise ValueError("Verifier task omitted its approval bundle binding")
        else:
            raise ValueError("this V2 role has no Gateway capability")
        execution = GatewayExecutionContext(
            task_id=task.task_id,
            task_input_sha256=task.input_hash(),
            role=task.role,
            request_id=request.request_id,
            action_id=action_id,
            plan_digest=plan_digest,
            approval_bundle_id=bundle_id,
            approval_bundle_digest=bundle_digest,
        )
        response, evidence = gateway.request_v2(
            request.action.method or "GET",
            request.url,
            execution=execution,
            headers=request.headers,
            body=body,
            action_kind=request.action.kind,
            approval=request.approval_token,
        )
        if gateway.evidence_store is None:  # pragma: no cover - request_v2 checks first
            raise ValueError("V2 evidence store is unavailable")
        manifest = gateway.evidence_store.verify(evidence)
        allowed = {"content-type", "link", "x-content-type-options"}
        projected = {
            name.lower(): value
            for name, value in (response.header_fields or tuple(response.headers.items()))
            if name.lower() in allowed
        }
        return {
            "status_code": response.status_code,
            "headers": projected,
            "response_hash": manifest.response_hash,
            "response_body_sha256": manifest.response_body_sha256,
            "analysis_ref": {
                "path": manifest.analysis.path,
                "sha256": manifest.analysis.sha256,
            },
            "action_id": manifest.binding.action_id,
            "action_digest": manifest.binding.action_digest,
            "approval_consumption_digest": (manifest.binding.approval_consumption_digest),
            "evidence_artifact_ref": evidence.model_dump(mode="json"),
        }

    return handle


def _evidence_validator(context: RunContext) -> Callable[[EvidenceRef, TaskEnvelope], bool]:
    def validate(ref: EvidenceRef, task: TaskEnvelope) -> bool:
        if (
            task.run_id != context.run_id
            or not ref.redacted
            or not ref.path.startswith("evidence/")
        ):
            return False
        try:
            payload = json.loads(context.artifact_path(ref.path).read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError):
            return False
        if ref.kind == "request":
            request_hash = payload.get("request_hash")
            return isinstance(request_hash, str) and ref.sha256 == request_hash
        if ref.kind == "response":
            response_hash = payload.get("response_hash")
            return isinstance(response_hash, str) and ref.sha256 == response_hash
        return False

    return validate


def _evidence_artifact_validator(
    context: RunContext, store: EvidenceStore
) -> Callable[[EvidenceArtifactRef, TaskEnvelope], bool]:
    def validate(ref: EvidenceArtifactRef, task: TaskEnvelope) -> bool:
        try:
            manifest = store.verify(ref)
        except ValueError:
            return False
        binding = manifest.binding
        if binding.run_id != context.run_id or binding.scope_digest != context.scope_digest:
            return False
        if ref in task.evidence_artifact_refs:
            return True
        return binding.task_id == task.task_id and binding.role == task.role

    return validate


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.agent_mode == "subprocess" and not (
        args.role_manifest and args.role_trust_store and args.runner_host_config
    ):
        parser.error(
            "subprocess mode requires --role-manifest, --role-trust-store, and --runner-host-config"
        )
    policy, snapshot = load_scope_policy(args.scope)
    orchestrator = Orchestrator(
        policy, snapshot, runs_root=args.runs_root, resume_run=args.resume_run
    )
    plan_path = orchestrator.plan(args.target, agent_mode=args.agent_mode)
    if args.agent_mode == "subprocess":
        assert args.role_manifest and args.role_trust_store and args.runner_host_config
        _load_host_config(args.runner_host_config)
        manifests = _load_role_manifests(args.role_manifest)
        gateway = ToolGateway(
            engine=orchestrator.engine,
            context=orchestrator.context,
            transport=PinnedHttpTransport(),
        )
        runner = RunnerHost(
            manifests=manifests,
            trust_store=RoleTrustStore.from_file(args.role_trust_store),
            gateway_handler=_gateway_handler(gateway),
            evidence_validator=_evidence_validator(orchestrator.context),
        )
        orchestrator.run_expert_workflow(runner)
    print(
        json.dumps(
            {
                "run_id": orchestrator.context.run_id,
                "plan": str(plan_path),
                "mode": args.agent_mode,
                "network": "disabled",
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

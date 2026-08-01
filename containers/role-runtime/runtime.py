#!/usr/bin/env python3
"""Minimal JSONL role process used behind the parent-owned RunnerHost.

The process has no target or model credentials. It verifies its versioned prompt,
asks the Host model proxy for one structured result, and emits one final handoff.
Network isolation is enforced by the Host's Docker command, not by this module.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROLE_PATTERN = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
VERSION_PATTERN = re.compile(r"^[0-9]+(?:\.[0-9]+){0,2}$")
OUTPUT_CONTRACT_IDS = {
    "gatekeeper": "hermes.gate_decision/v2",
    "recon": "hermes.asset_inventory/v2",
    "mapper": "hermes.endpoint_inventory/v2",
    "web-vuln": "hermes.candidate_set/v2",
    "verifier": "hermes.verification_outcome/v2",
    "reporter": "hermes.reporter_acknowledgement/v2",
}
OUTPUT_CONTRACT_IDS_V3 = {
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
OUTPUT_CONTRACT_IDS_V4 = {
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
OUTPUT_CONTRACT_IDS_R25 = {
    "researcher": "hermes.r25.research_facts/v1",
    "capability-planner": "hermes.r25.capability_spec/v2",
}
V3_BRANCH_ROLES = {"web-vuln", "api", "authz", "infra"}
V4_BRANCH_ROLES = {"web-vuln", "api", "authz", "infra"}
R25_OPERATIONS = {
    "researcher": "research",
    "capability-planner": "plan",
}


class RegistryError(RuntimeError):
    """The prompt registry or a bound prompt asset is invalid."""


def file_digest(path: Path) -> str:
    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


def canonical_digest(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _contained_path(root: Path, relative: str) -> Path:
    path = (root / relative).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError as exc:
        raise RegistryError(f"registry path escapes asset root: {relative!r}") from exc
    return path


def load_prompt_registry(
    root: Path, registry_path: str = "prompts/registry.json"
) -> dict[str, dict[str, Any]]:
    """Load and verify the explicitly selected V2 or V3 prompt registry."""
    path = _contained_path(root, registry_path)
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RegistryError(f"could not load prompt registry: {exc}") from exc
    if not isinstance(document, dict) or document.get("version") not in {"1", "3", "4", "25"}:
        raise RegistryError("prompt registry must use supported version 1, 3, 4 or 25")
    registry_version = document["version"]
    roles = document.get("roles")
    if not isinstance(roles, dict) or not roles:
        raise RegistryError("prompt registry roles must be a non-empty object")
    if registry_version in {"3", "4", "25"}:
        if set(document) != {"version", "collection_sha256", "roles"} or document.get(
            "collection_sha256"
        ) != canonical_digest(roles):
            raise RegistryError(f"V{registry_version} prompt collection binding is invalid")
        if registry_version == "3" and set(roles) != set(OUTPUT_CONTRACT_IDS_V3):
            raise RegistryError("V3 prompt collection binding is invalid")
        if registry_version == "4" and set(roles) != set(OUTPUT_CONTRACT_IDS_V4):
            raise RegistryError("V4 prompt collection binding is invalid")
        if registry_version == "25" and set(roles) != set(OUTPUT_CONTRACT_IDS_R25):
            raise RegistryError("V25 prompt collection binding is invalid")
    verified: dict[str, dict[str, Any]] = {}
    for role, raw in roles.items():
        if not isinstance(role, str) or ROLE_PATTERN.fullmatch(role) is None:
            raise RegistryError(f"invalid registry role: {role!r}")
        if not isinstance(raw, dict):
            raise RegistryError(f"registry entry for {role!r} must be an object")
        required = {
            "agent_path",
            "prompt_path",
            "prompt_version",
            "prompt_sha256",
            "output_contract_id",
            "allowed_ipc",
        }
        if registry_version in {"3", "4"}:
            required |= {"prompt_id", "operations"}
        if registry_version == "25":
            required |= {"prompt_id", "operations"}
        if set(raw) != required:
            raise RegistryError(f"registry entry for {role!r} has unexpected fields")
        version = raw["prompt_version"]
        digest = raw["prompt_sha256"]
        ipc = raw["allowed_ipc"]
        output_contract_id = raw["output_contract_id"]
        if (
            not isinstance(version, str)
            or VERSION_PATTERN.fullmatch(version) is None
            or int(version.split(".", 1)[0]) < 1
        ):
            raise RegistryError(f"invalid prompt version for {role!r}")
        if not isinstance(digest, str) or DIGEST_PATTERN.fullmatch(digest) is None:
            raise RegistryError(f"invalid prompt digest for {role!r}")
        expected_contracts = {
            "1": OUTPUT_CONTRACT_IDS,
            "3": OUTPUT_CONTRACT_IDS_V3,
            "4": OUTPUT_CONTRACT_IDS_V4,
            "25": OUTPUT_CONTRACT_IDS_R25,
        }[registry_version]
        if output_contract_id != expected_contracts.get(role):
            raise RegistryError(f"invalid output contract for {role!r}")
        if registry_version in {"3", "4"}:
            operations = raw["operations"]
            if (
                raw["prompt_id"] != f"hermes.{role}"
                or not isinstance(operations, list)
                or not operations
                or len(operations) != len(set(operations))
            ):
                raise RegistryError(f"invalid V{registry_version} prompt identity for {role!r}")
        if registry_version == "25":
            operations = raw["operations"]
            if (
                raw["prompt_id"] != f"hermes.{role}"
                or not isinstance(operations, list)
                or operations != [R25_OPERATIONS[role]]
            ):
                raise RegistryError(f"invalid V25 prompt identity for {role!r}")
        if (
            not isinstance(ipc, list)
            or not ipc
            or len(ipc) != len(set(ipc))
            or any(item not in {"model_request", "gateway_action"} for item in ipc)
        ):
            raise RegistryError(f"invalid IPC declaration for {role!r}")
        prompt_path = _contained_path(root, str(raw["prompt_path"]))
        if not prompt_path.is_file() or file_digest(prompt_path) != digest:
            raise RegistryError(f"prompt digest mismatch for {role!r}")
        verified[role] = dict(raw)
    return verified


def canonical_task_hash(task: dict[str, Any]) -> str:
    replay_value = dict(task)
    replay_value.pop("created_at", None)
    encoded = json.dumps(
        replay_value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _canonical_payload_hash(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _read_message() -> dict[str, Any]:
    line = sys.stdin.buffer.readline()
    if not line:
        raise ValueError("JSONL input ended before a message was received")
    value = json.loads(line)
    if not isinstance(value, dict):
        raise ValueError("JSONL message must be an object")
    return value


def _write_message(value: dict[str, Any]) -> None:
    encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    sys.stdout.write(encoded + "\n")
    sys.stdout.flush()


def _validate_task_message(message: dict[str, Any], role: str) -> tuple[dict[str, Any], str]:
    task = message.get("task")
    input_hash = message.get("input_sha256")
    if message.get("type") != "task" or not isinstance(task, dict):
        raise ValueError("first JSONL message must contain a task")
    if task.get("role") != role:
        raise ValueError("task role does not match the bound runtime role")
    if not isinstance(input_hash, str) or DIGEST_PATTERN.fullmatch(input_hash) is None:
        raise ValueError("task input hash is malformed")
    if canonical_task_hash(task) != input_hash:
        raise ValueError("task input hash does not match its canonical payload")
    for field in ("run_id", "task_id"):
        if not isinstance(task.get(field), str) or not task[field]:
            raise ValueError(f"task {field} is required")
    scope_digest = task.get("scope_digest")
    if not isinstance(scope_digest, str) or DIGEST_PATTERN.fullmatch(scope_digest) is None:
        raise ValueError("task scope digest is malformed")
    return task, input_hash


def _final_handoff(
    task: dict[str, Any],
    input_hash: str,
    *,
    status: str,
    result: dict[str, Any] | None = None,
    evidence_refs: list[dict[str, Any]] | None = None,
    evidence_artifact_refs: list[dict[str, Any]] | None = None,
    error: str | None = None,
) -> dict[str, Any]:
    try:
        container_id = Path("/etc/hostname").read_text(encoding="utf-8").strip()
    except OSError:
        container_id = "unknown-process"
    handoff_version = (
        "25"
        if task.get("version") == "25"
        else "4"
        if task.get("version") == "4"
        else "3"
        if task.get("version") == "3"
        else "2"
    )
    return {
        "type": "handoff",
        "handoff": {
            "version": handoff_version,
            "run_id": task["run_id"],
            "task_id": task["task_id"],
            "role": task["role"],
            "scope_digest": task["scope_digest"],
            "input_sha256": input_hash,
            "status": status,
            "result": result or {},
            "evidence_refs": evidence_refs or [],
            "evidence_artifact_refs": evidence_artifact_refs or [],
            "error": error,
            "process_id": os.getpid(),
            "container_id": container_id,
            "completed_at": datetime.now(UTC).isoformat(),
        },
    }


def _model_result(
    task: dict[str, Any], input_hash: str, response: dict[str, Any]
) -> dict[str, Any]:
    if response.get("type") != "model_result" or response.get("ok") is not True:
        reason = response.get("error")
        if not isinstance(reason, str) or not reason:
            reason = "Host model proxy denied the role request"
        return _final_handoff(task, input_hash, status="blocked", error=reason[:2000])
    payload = response.get("payload")
    if not isinstance(payload, dict):
        return _final_handoff(
            task, input_hash, status="failed", error="model result payload is not an object"
        )
    status = payload.get("status", "completed")
    if status not in {"completed", "blocked", "failed"}:
        return _final_handoff(
            task, input_hash, status="failed", error="model result status is invalid"
        )
    model_result = payload.get("result", {})
    if not isinstance(model_result, dict):
        return _final_handoff(
            task, input_hash, status="failed", error="model structured result is not an object"
        )
    role = task["role"]
    if role in R25_OPERATIONS:
        contract_id = OUTPUT_CONTRACT_IDS_R25.get(role)
        expected_operations = R25_OPERATIONS.get(role)
        contract_version = {
            "researcher": "1",
            "capability-planner": "2",
        }.get(role)
        if (
            contract_id is None
            or expected_operations is None
            or contract_version is None
            or task.get("payload", {}).get("operation") not in expected_operations
        ):
            return _final_handoff(
                task,
                input_hash,
                status="failed",
                error="V25 task operation is not registered for this role",
            )
        result = {
            "contract_version": contract_version,
            "contract_id": contract_id,
            "payload": model_result,
            "payload_sha256": _canonical_payload_hash(model_result),
        }
    elif task.get("version") in {"3", "4"}:
        operation = task.get("payload", {}).get("operation")
        branch_roles = V4_BRANCH_ROLES if task.get("version") == "4" else V3_BRANCH_ROLES
        if role in branch_roles:
            contract_id = {
                "assessment": "hermes.branch_assessment/v3",
                "cross_review": "hermes.cross_review_set/v3",
            }.get(operation)
            if task.get("version") == "4":
                contract_id = {
                    "assessment": "hermes.branch_operation/v4",
                    "cross_review": "hermes.cross_review_set/v4",
                }.get(operation)
        else:
            contract_id = (
                OUTPUT_CONTRACT_IDS_V4.get(role)
                if task.get("version") == "4"
                else OUTPUT_CONTRACT_IDS_V3.get(role)
            )
        operation_names = {
            "gatekeeper": "gate",
            "recon": "recon",
            "mapper": "map",
            "verifier": "verification",
            "reporter": "reporting",
        }
        contract_operation = operation if role in branch_roles else operation_names.get(role)
        if contract_id is None or contract_operation is None:
            return _final_handoff(
                task,
                input_hash,
                status="failed",
                error=f"V{task.get('version')} task operation is not registered for this role",
            )
        result = {
            "version": task.get("version"),
            "contract_version": task.get("version"),
            "contract_id": contract_id,
            "operation": contract_operation,
            "payload": model_result,
            "payload_sha256": _canonical_payload_hash(model_result),
        }
    else:
        contract_id = OUTPUT_CONTRACT_IDS[role]
        result = {
            "version": "2",
            "contract_version": "2",
            "contract_id": contract_id,
            "payload": model_result,
            "payload_sha256": _canonical_payload_hash(model_result),
        }
    error = payload.get("error")
    if status == "completed":
        error = None
    elif not isinstance(error, str) or not error:
        error = f"role returned {status} without an explanation"

    supplied = task.get("evidence_refs", [])
    artifact_supplied = task.get("evidence_artifact_refs", [])
    if not isinstance(supplied, list) or not isinstance(artifact_supplied, list):
        return _final_handoff(
            task, input_hash, status="failed", error="task evidence collections are malformed"
        )
    all_supplied = [*supplied, *artifact_supplied]
    supplied_by_id = {
        ref.get("id", ref.get("evidence_id")): ref
        for ref in all_supplied
        if isinstance(ref, dict) and isinstance(ref.get("id", ref.get("evidence_id")), str)
    }
    requested_ids = payload.get("evidence_ref_ids")
    if requested_ids is None:
        requested_ids = list(supplied_by_id)
    if not isinstance(requested_ids, list) or any(
        not isinstance(item, str) or item not in supplied_by_id for item in requested_ids
    ):
        return _final_handoff(
            task,
            input_hash,
            status="failed",
            error="model referenced evidence not supplied by the Host",
        )
    selected = [supplied_by_id[item] for item in dict.fromkeys(requested_ids)]
    evidence = [item for item in selected if "id" in item]
    artifact_evidence = [item for item in selected if "evidence_id" in item]
    return _final_handoff(
        task,
        input_hash,
        status=status,
        result=result,
        evidence_refs=evidence,
        evidence_artifact_refs=artifact_evidence,
        error=error[:2000] if isinstance(error, str) else None,
    )


def _gateway_call(
    task: dict[str, Any], *, request_id: str, action: dict[str, Any], approval: str | None = None
) -> tuple[dict[str, Any], dict[str, Any]]:
    _write_message(
        {
            "type": "gateway_action",
            "request_id": request_id,
            "action": action,
            "url": action["target"],
            "headers": {},
            "approval_token": approval,
        }
    )
    response = _read_message()
    if response.get("request_id") != request_id or response.get("ok") is not True:
        raise ValueError("Host denied the exact gateway action")
    payload = response.get("payload")
    if not isinstance(payload, dict):
        raise ValueError("Host gateway result omitted its evidence reference")
    ref = payload.get("evidence_artifact_ref", payload.get("evidence_ref"))
    if not isinstance(ref, dict):
        raise ValueError("Host gateway result omitted its evidence reference")
    return payload, ref


def run(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    registry = load_prompt_registry(root, args.registry_path)
    entry = registry.get(args.role)
    if entry is None:
        raise RegistryError(f"role {args.role!r} is not registered")
    if entry["prompt_version"] != args.prompt_version:
        raise RegistryError("manifest-bound prompt version does not match registry")
    if entry["prompt_sha256"] != args.prompt_sha256:
        raise RegistryError("manifest-bound prompt digest does not match registry")
    prompt_path = _contained_path(root, entry["prompt_path"])
    prompt = prompt_path.read_text(encoding="utf-8")

    task, input_hash = _validate_task_message(_read_message(), args.role)
    expected_task_version = (
        "25"
        if args.prompt_version.startswith("25.")
        else "4"
        if args.prompt_version.startswith("4.")
        else "3"
        if args.prompt_version.startswith("3.")
        else "1"
    )
    actual_task_version = str(task.get("version", "1"))
    if actual_task_version != expected_task_version:
        raise RegistryError("task and prompt major versions do not match")
    observations: list[dict[str, Any]] = []
    evidence = list(task.get("evidence_refs", []))
    artifact_evidence = list(task.get("evidence_artifact_refs", []))
    if args.role == "recon" and task.get("version") != "4":
        target = task.get("payload", {}).get("target")
        if not isinstance(target, str):
            raise ValueError("Recon task omitted its target")
        payload, ref = _gateway_call(
            task,
            request_id=f"{task['task_id']}:gateway:0",
            action={
                "kind": "http_get",
                "target": target,
                "method": "GET",
                "max_requests": 1,
                "detail": "single bounded recon observation",
            },
        )
        observations.append(payload)
        if "evidence_id" in ref:
            artifact_evidence.append(ref)
        else:
            evidence.append(ref)
    elif args.role == "verifier":
        payload = task.get("payload", {})
        if task.get("version") == "3":
            steps = payload.get("actions") if isinstance(payload, dict) else None
            bundle_id = payload.get("approval_id") if isinstance(payload, dict) else None
            if (
                not isinstance(steps, list)
                or not 1 <= len(steps) <= 5
                or not isinstance(bundle_id, str)
            ):
                raise ValueError("V3 Verifier requires one exact approved candidate action graph")
        elif task.get("version") == "4":
            # V4 evidence is captured only by the parent-owned discovery and
            # governed executor. The role receives a projection in its task
            # and can request only the model proxy; it has no network budget.
            steps = []
        else:
            plan = payload.get("verification_plan") if isinstance(payload, dict) else None
            steps = plan.get("steps") if isinstance(plan, dict) else None
            bundle_id = payload.get("approval_bundle_id") if isinstance(payload, dict) else None
            if not isinstance(steps, list) or len(steps) != 2 or not isinstance(bundle_id, str):
                raise ValueError("Verifier requires the exact V2 two-step approved plan")
        for index, step in enumerate(steps):
            if not isinstance(step, dict) or not isinstance(step.get("target_url"), str):
                raise ValueError("Verifier plan step is malformed")
            method = str(step.get("method", "GET")).upper()
            action = {
                "kind": "validation_http_get" if method == "GET" else "http_post",
                "target": step["target_url"],
                "method": method,
                "max_requests": 1,
                "detail": str(step.get("action_digest", "")),
            }
            gateway_result, ref = _gateway_call(
                task,
                request_id=f"{task['task_id']}:gateway:{index}",
                action=action,
                approval=bundle_id,
            )
            observations.append(gateway_result)
            if "evidence_id" in ref:
                artifact_evidence.append(ref)
            else:
                evidence.append(ref)
    augmented_task = dict(task)
    augmented_task["evidence_refs"] = evidence
    augmented_task["evidence_artifact_refs"] = artifact_evidence
    request_id = f"{task['task_id']}:model"
    _write_message(
        {
            "type": "model_request",
            "request_id": request_id,
            "operation": "extract",
            "input": {
                "role": args.role,
                "prompt_version": args.prompt_version,
                "prompt_sha256": args.prompt_sha256,
                "system_prompt": prompt,
                "task_payload": task.get("payload", {}),
                "gateway_observations": observations,
                "evidence_refs": evidence,
                "evidence_artifact_refs": artifact_evidence,
            },
        }
    )
    response = _read_message()
    if response.get("request_id") != request_id:
        raise ValueError("Host response request_id does not match the model request")
    _write_message(_model_result(augmented_task, input_hash, response))
    return 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Hermes digest-bound JSONL role runtime")
    result.add_argument("--role", required=True)
    result.add_argument("--prompt-version", required=True)
    result.add_argument("--prompt-sha256", required=True)
    result.add_argument("--registry-path", default="prompts/registry.json")
    result.add_argument("--root", default="/opt/hermes")
    return result


def main(argv: list[str] | None = None) -> int:
    try:
        return run(parser().parse_args(argv))
    except (OSError, ValueError, RegistryError, json.JSONDecodeError) as exc:
        print(f"role runtime failed closed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

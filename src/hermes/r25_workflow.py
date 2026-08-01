"""Isolated R2.5 governed-learning workflow.

This module deliberately does not import the legacy ``learning``/``wheels``
promotion path.  A learning run is a sibling of its immutable V3 parent and
can only yield a passive observation from a separately activated Wheel V2.
"""

from __future__ import annotations

import json
import stat
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import BaseModel, ConfigDict, Field

from .learning_context import LearningContext, canonical_json, file_sha256
from .r25_contracts import (
    CapabilityExecutionReceiptV2,
    CapabilitySpecV2,
    ContinuationOutcomeV1,
    ContractEnvelopeR25,
    LearningOutcome,
    LearningRequestV1,
    ResearchFactsOutputV1,
    ResearchSourceArtifactV1,
    ValidationReceiptV2,
    WheelActivationReceiptV2,
    WheelApprovalV2,
    WheelLifecycleV2,
    WheelManifestV2,
)
from .r25_parser import generate_line_kv_parser, static_validate_line_kv_parser
from .security import decode_base64, load_ed25519_private_key, public_key_bytes
from .wheels.sandbox import DockerSandbox
from .wheels_v2 import (
    RegistryEventV2,
    WheelKeyUsageV2,
    WheelRegistryV2,
    WheelTrustStoreV2,
    WheelUsageEventV2,
    WheelUsageV2,
    sign_learning_contract,
    sign_registry_event_payload,
)


class R25WorkflowError(RuntimeError):
    """The isolated learning authority rejected an operation."""


class LearningStateV2(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: str = "2"
    learning_run_id: str = Field(min_length=1, max_length=128)
    parent_run_id: str = Field(min_length=1, max_length=128)
    scope_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    state: Literal[
        "started",
        "researched",
        "planned",
        "generated",
        "candidate",
        "approved",
        "active",
        "completed",
        "quarantined",
        "revoked",
    ]
    wheel_manifest_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    continuation_outcome_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    updated_at: datetime


def _now() -> datetime:
    return datetime.now(UTC)


def _json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise R25WorkflowError(f"invalid required artifact: {path}") from exc
    if not isinstance(value, dict):
        raise R25WorkflowError(f"artifact must be a JSON object: {path}")
    return value


def _learning_context(config: Mapping[str, Any], run_id: str) -> LearningContext:
    return LearningContext.open_existing(Path(str(config["runs_root"])), run_id)


def _state(context: LearningContext) -> LearningStateV2:
    return LearningStateV2.model_validate(_json(context.artifact_path("state.json")))


def _write_state(
    context: LearningContext, current: LearningStateV2, **changes: Any
) -> LearningStateV2:
    updated = current.model_copy(update={**changes, "updated_at": _now()})
    context.write_json("state.json", updated.model_dump(mode="json"))
    return updated


def _require(state: LearningStateV2, expected: str) -> None:
    if state.state != expected:
        raise R25WorkflowError(f"learning run is {state.state}, not ready for this operation")


def _scope_digest(scope: dict[str, Any]) -> str:
    encoded = json.dumps(scope, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + sha256(encoded).hexdigest()


def _parent_artifacts(
    config: Mapping[str, Any], parent_run_id: str, evidence_id: str
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], Path, Path]:
    root = Path(str(config["runs_root"])).resolve() / parent_run_id
    plan_path = root / "plan" / "run-v3.json"
    scope_path = root / "scope.json"
    manifest_path = root / "evidence" / evidence_id / "manifest.json"
    plan, scope, manifest = _json(plan_path), _json(scope_path), _json(manifest_path)
    if plan.get("version") != "3" or manifest.get("run_id") != parent_run_id:
        raise R25WorkflowError("parent must be an immutable V3 run with matching evidence")
    scope_digest = _scope_digest(scope)
    if manifest.get("scope_digest") != scope_digest:
        raise R25WorkflowError("parent evidence scope binding is invalid")
    analysis = manifest.get("analysis")
    analysis_rel = analysis.get("path") if isinstance(analysis, dict) else None
    if not isinstance(analysis_rel, str):
        raise R25WorkflowError("parent evidence has no analysis artifact")
    analysis_path = (root / analysis_rel).resolve()
    if root not in analysis_path.parents or not analysis_path.is_file():
        raise R25WorkflowError("parent evidence analysis path escaped the parent run")
    return plan, scope, manifest, manifest_path, analysis_path


def start_learning_run(
    config: Mapping[str, Any],
    *,
    parent_run_id: str,
    evidence_id: str,
    observation_file: Path,
    risk_level: str = "low",
) -> LearningStateV2:
    if risk_level != "low":
        raise R25WorkflowError("the initial governed Wheel supports low-risk local learning only")
    plan, scope, _manifest, manifest_path, analysis_path = _parent_artifacts(
        config, parent_run_id, evidence_id
    )
    observation = observation_file.read_text(encoding="utf-8").strip()
    if not observation:
        raise R25WorkflowError("operator observation must not be empty")
    context = LearningContext(Path(str(config["runs_root"])))
    request = LearningRequestV1(
        learning_run_id=context.run_id,
        parent_run_id=parent_run_id,
        scope_digest=_scope_digest(scope),
        parent_run_plan_digest=file_sha256(
            Path(str(config["runs_root"])) / parent_run_id / "plan" / "run-v3.json"
        ),
        evidence_manifest_digest=file_sha256(manifest_path),
        analysis_digest=file_sha256(analysis_path),
        generated_by_task_id="learning-start",
        operator_observation=observation,
        risk_level="low",
        profile="local-lab",
        created_at=_now(),
    )
    context.write_json(
        "plan/learning-request.json", request.model_dump(mode="json"), immutable=True
    )
    context.write_json(
        "plan/parent-binding.json", {"parent_run_id": parent_run_id, "plan": plan}, immutable=True
    )
    context.write_bytes("research/frozen-analysis.json", analysis_path.read_bytes(), immutable=True)
    state = LearningStateV2(
        learning_run_id=context.run_id,
        parent_run_id=parent_run_id,
        scope_digest=request.scope_digest,
        state="started",
        updated_at=_now(),
    )
    context.write_json("state.json", state.model_dump(mode="json"), immutable=True)
    return state


def _allow_source(config: Mapping[str, Any], url: str) -> None:
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise R25WorkflowError("research sources must use absolute HTTPS URLs")
    allowed = config.get("research_allowlist", [])
    if allowed:
        exact = {str(item) for item in allowed if isinstance(item, str)}
        origin_path = f"https://{parsed.netloc}{parsed.path}"
        if origin_path not in exact:
            raise R25WorkflowError("research source is outside the exact allowlist")


def _load_bundle(
    context: LearningContext, config: Mapping[str, Any], bundle_path: Path
) -> tuple[tuple[ResearchSourceArtifactV1, ...], dict[str, str]]:
    raw = _json(bundle_path)
    entries = raw.get("sources")
    if raw.get("version") != "1" or not isinstance(entries, list) or not entries:
        raise R25WorkflowError("research bundle must be a non-empty v1 local archive")
    artifacts: list[ResearchSourceArtifactV1] = []
    sample: dict[str, str] = {}
    for number, entry in enumerate(entries, 1):
        if not isinstance(entry, dict):
            raise R25WorkflowError("research source entry must be an object")
        source_id = str(entry.get("source_id", f"source-{number}"))
        url = entry.get("url")
        license_name = entry.get("license")
        relative = entry.get("body_path")
        if not (
            isinstance(url, str)
            and url
            and isinstance(license_name, str)
            and license_name
            and isinstance(relative, str)
            and relative
        ):
            raise R25WorkflowError("research source omitted url, license, or body_path")
        _allow_source(config, url)
        source_path = (bundle_path.parent / relative).resolve()
        if bundle_path.parent.resolve() not in source_path.parents or not source_path.is_file():
            raise R25WorkflowError("research source body escaped its bundle")
        body = source_path.read_bytes()
        projection = body.decode("utf-8", errors="replace")[:65_536]
        directory = context.artifact_path(f"research/sources/{source_id}")
        directory.mkdir(parents=True, exist_ok=False)
        archive = directory / "source.txt"
        projection_path = directory / "analysis.txt"
        archive.write_bytes(body)
        projection_path.write_text(projection, encoding="utf-8")
        artifact = ResearchSourceArtifactV1(
            source_id=source_id,
            learning_run_id=context.run_id,
            source_url=url,
            license=license_name,
            source_version=str(entry.get("source_version"))
            if entry.get("source_version")
            else None,
            content_digest="sha256:" + sha256(body).hexdigest(),
            projection_digest=file_sha256(projection_path),
            source_bundle_digest=file_sha256(bundle_path),
            retrieved_at=_now(),
            risk_flags=tuple(str(x) for x in entry.get("risk_flags", []) if isinstance(x, str)),
        )
        context.write_json(
            f"research/source-{source_id}.json", artifact.model_dump(mode="json"), immutable=True
        )
        artifacts.append(artifact)
    for name in ("positive_text", "negative_text", "continuation_text"):
        value = raw.get(name)
        if not isinstance(value, str) or not value:
            raise R25WorkflowError(f"research bundle omitted {name}")
        sample[name] = value
    context.write_json("research/frozen-samples.json", sample, immutable=True)
    return tuple(artifacts), sample


def _research_source_payload(
    context: LearningContext, artifacts: tuple[ResearchSourceArtifactV1, ...]
) -> list[dict[str, Any]]:
    """Expose only the bounded archived projection to the Researcher.

    The original archive remains a parent-runtime artifact.  This input is
    deliberately data-only: the role gets neither a host path nor a capability
    to retrieve or execute the source.
    """

    sources: list[dict[str, Any]] = []
    for artifact in artifacts:
        projection_path = context.artifact_path(
            f"research/sources/{artifact.source_id}/analysis.txt"
        )
        if (
            not projection_path.is_file()
            or file_sha256(projection_path) != artifact.projection_digest
        ):
            raise R25WorkflowError("archived research projection is missing or was modified")
        sources.append(
            {
                **artifact.model_dump(mode="json"),
                "analysis_projection": projection_path.read_text(encoding="utf-8"),
            }
        )
    return sources


def _frozen_line_kv_schema(samples: Mapping[str, str]) -> dict[str, Any]:
    """Derive the only planner input authority from the frozen positive sample."""

    positive = samples.get("positive_text")
    if not isinstance(positive, str):
        raise R25WorkflowError("frozen positive parser sample is unavailable")
    observed: set[str] = set()
    for line in positive.splitlines():
        key, separator, _value = line.partition(":")
        key = key.strip()
        if not separator or not key:
            raise R25WorkflowError("frozen positive sample is not a strict line_kv example")
        observed.add(key)
    if not observed:
        raise R25WorkflowError("frozen positive sample did not expose parser fields")
    return {
        "version": "1",
        "delimiter": ":",
        "observed_source_keys": sorted(observed),
    }


def _sample_source_keys(text: str, delimiter: str) -> set[str]:
    keys: set[str] = set()
    for line in text.splitlines():
        key, separator, _value = line.partition(delimiter)
        if separator and key.strip():
            keys.add(key.strip())
    return keys


def _validate_spec_against_frozen_samples(
    spec: CapabilitySpecV2, samples: Mapping[str, str]
) -> None:
    """Refuse planner output that cannot parse exactly the frozen local format."""

    schema = _frozen_line_kv_schema(samples)
    expected_keys = tuple(schema["observed_source_keys"])
    actual_keys = tuple(rule.source_key for rule in spec.field_rules)
    if spec.delimiter != schema["delimiter"]:
        raise R25WorkflowError("capability spec delimiter differs from the frozen sample schema")
    if len(actual_keys) != len(set(actual_keys)) or tuple(sorted(actual_keys)) != expected_keys:
        raise R25WorkflowError("capability spec source keys differ from the frozen sample schema")
    positive = samples.get("positive_text")
    negative = samples.get("negative_text")
    if not isinstance(positive, str) or not isinstance(negative, str):
        raise R25WorkflowError("frozen parser samples are unavailable")
    expected = set(expected_keys)
    if not expected.issubset(_sample_source_keys(positive, spec.delimiter)):
        raise R25WorkflowError("frozen positive sample cannot satisfy the capability spec")
    if expected.issubset(_sample_source_keys(negative, spec.delimiter)):
        raise R25WorkflowError("frozen negative sample would satisfy the capability spec")


def _runner_result(
    context: LearningContext,
    *,
    role: str,
    operation: str,
    prompt_version: str,
    payload: dict[str, Any],
    runner_factory: Callable[[LearningContext], Any],
) -> Any:
    from .runtime.agents import TaskEnvelope, TaskResult

    runner = runner_factory(context)
    task = TaskEnvelope(
        version="25",
        run_id=context.run_id,
        task_id=f"r25-{role}-{context.run_id}",
        role=role,
        scope_digest=_state(context).scope_digest,
        payload={"operation": operation, "prompt_version": prompt_version, **payload},
        timeout_seconds=180,
    )
    relative = f"handoffs/{task.task_id}.json"
    handoff_path = context.artifact_path(relative)
    if handoff_path.exists():
        stored = _json(handoff_path)
        persisted_task = TaskEnvelope.model_validate(stored.get("task"))
        result = TaskResult.model_validate(stored.get("result"))
        if persisted_task.input_hash() != task.input_hash():
            raise R25WorkflowError(
                f"persisted {role} task input differs from current learning state"
            )
    else:
        result = runner.run(task)
        context.write_json(
            relative,
            {"task": task.model_dump(mode="json"), "result": result.model_dump(mode="json")},
            immutable=True,
        )
    if result.lifecycle != "completed" or result.handoff is None:
        raise R25WorkflowError(f"{role} did not produce a valid R2.5 handoff")
    if not isinstance(result.handoff.result, ContractEnvelopeR25):
        raise R25WorkflowError(f"{role} did not produce a typed R2.5 handoff envelope")
    return result.handoff.result.payload


def research_learning_run(
    config: Mapping[str, Any],
    *,
    run_id: str,
    source_bundle: Path,
    runner_factory: Callable[[LearningContext], Any],
) -> LearningStateV2:
    context, state = _learning_context(config, run_id), None
    state = _state(context)
    _require(state, "started")
    request = LearningRequestV1.model_validate(
        _json(context.artifact_path("plan/learning-request.json"))
    )
    artifacts, _samples = _load_bundle(context, config, source_bundle)
    from .prompts_r25 import PromptRegistryR25

    prompt_version = str(
        PromptRegistryR25(Path(str(config["prompt_root"]))).roles["researcher"]["prompt_version"]
    )
    result = _runner_result(
        context,
        role="researcher",
        operation="research",
        prompt_version=prompt_version,
        runner_factory=runner_factory,
        payload={
            "learning_request": request.model_dump(mode="json"),
            "sources": _research_source_payload(context, artifacts),
        },
    )
    facts = ResearchFactsOutputV1.model_validate(result)
    if facts.learning_run_id != context.run_id or set(facts.source_digests) != {
        item.content_digest for item in artifacts
    }:
        raise R25WorkflowError("research handoff did not bind exactly the archived sources")
    if any(fact.source_id not in {item.source_id for item in artifacts} for fact in facts.facts):
        raise R25WorkflowError("research fact cites an unknown archived source")
    context.write_json("research/facts.json", facts.model_dump(mode="json"), immutable=True)
    return _write_state(context, state, state="researched")


def plan_learning_run(
    config: Mapping[str, Any], *, run_id: str, runner_factory: Callable[[LearningContext], Any]
) -> LearningStateV2:
    context, state = _learning_context(config, run_id), None
    state = _state(context)
    _require(state, "researched")
    facts = ResearchFactsOutputV1.model_validate(
        _json(context.artifact_path("research/facts.json"))
    )
    samples = _json(context.artifact_path("research/frozen-samples.json"))
    frozen_sample_schema = _frozen_line_kv_schema(samples)
    from .prompts_r25 import PromptRegistryR25

    prompt_version = str(
        PromptRegistryR25(Path(str(config["prompt_root"]))).roles["capability-planner"][
            "prompt_version"
        ]
    )
    result = _runner_result(
        context,
        role="capability-planner",
        operation="plan",
        prompt_version=prompt_version,
        runner_factory=runner_factory,
        payload={
            "research_facts": facts.model_dump(mode="json"),
            "frozen_sample_schema": frozen_sample_schema,
        },
    )
    spec = CapabilitySpecV2.model_validate(result)
    if set(spec.source_digests) != set(facts.source_digests):
        raise R25WorkflowError("capability spec did not bind exactly the research source set")
    _validate_spec_against_frozen_samples(spec, samples)
    context.write_json("wheels/capability-spec.json", spec.model_dump(mode="json"), immutable=True)
    return _write_state(context, state, state="planned")


def _trust(config: Mapping[str, Any]) -> WheelTrustStoreV2:
    return WheelTrustStoreV2.model_validate(_json(Path(str(config["wheel_trust_store"]))))


def _private(
    config: Mapping[str, Any], usage: WheelKeyUsageV2, key_path: Path | None = None
) -> tuple[str, Ed25519PrivateKey]:
    path = key_path or Path(str(config.get(f"{usage.value}_key", "")))
    if (
        not path.is_absolute()
        or path.is_symlink()
        or not path.is_file()
        or stat.S_IMODE(path.stat().st_mode) != 0o600
    ):
        raise R25WorkflowError("Wheel private key must be an absolute regular 0600 file")
    key = load_ed25519_private_key(path)
    store = _trust(config)
    record = next(item for item in store.keys if item.usage is usage)
    if decode_base64(record.public_key) != public_key_bytes(key):
        raise R25WorkflowError("private key does not match its Wheel trust-store duty")
    return record.key_id, key


def _registry(context: LearningContext, config: Mapping[str, Any]) -> WheelRegistryV2:
    return WheelRegistryV2(
        _trust(config), journal_path=context.artifact_path("registry/events.jsonl")
    )


def _event_signature(
    registry: WheelRegistryV2,
    manifest: WheelManifestV2,
    *,
    event_type: str,
    key_id: str,
    usage: WheelKeyUsageV2,
    target: WheelLifecycleV2,
    key: Ed25519PrivateKey,
    occurred_at: datetime,
    payload: Any | None = None,
    approved_until: datetime | None = None,
    activation_digest: str | None = None,
) -> str:
    body = registry.event_signing_payload(
        manifest,
        event_type=event_type,
        actor_key_id=key_id,
        actor_usage=usage,
        target_lifecycle=target,
        occurred_at=occurred_at,
        payload=payload,
        approved_until=approved_until,
        activation_digest=activation_digest,
    )
    return sign_registry_event_payload(body, key)


def generate_learning_capability(config: Mapping[str, Any], *, run_id: str) -> LearningStateV2:
    context, state = _learning_context(config, run_id), None
    state = _state(context)
    _require(state, "planned")
    spec = CapabilitySpecV2.model_validate(
        _json(context.artifact_path("wheels/capability-spec.json"))
    )
    samples = _json(context.artifact_path("research/frozen-samples.json"))
    root, manifest = generate_line_kv_parser(
        spec,
        context.artifact_path("wheels"),
        positive_text=str(samples["positive_text"]),
        negative_text=str(samples["negative_text"]),
    )
    key_id, key = _private(config, WheelKeyUsageV2.PUBLISHER)
    registry = _registry(context, config)
    instant = _now()
    registry.add_draft(
        manifest,
        publisher_key_id=key_id,
        signature_b64=sign_learning_contract(manifest, key),
        registry_signature_b64=_event_signature(
            registry,
            manifest,
            event_type=RegistryEventV2.REGISTERED,
            key_id=key_id,
            usage=WheelKeyUsageV2.PUBLISHER,
            target="draft",
            key=key,
            occurred_at=instant,
        ),
        occurred_at=instant,
    )
    for target in ("researched", "specified", "generated"):
        instant = _now()
        registry.transition(
            manifest.wheel_id,
            manifest.manifest_version,
            target,
            actor_key_id=key_id,
            actor_usage=WheelKeyUsageV2.PUBLISHER,
            signature_b64=_event_signature(
                registry,
                manifest,
                event_type=target,
                key_id=key_id,
                usage=WheelKeyUsageV2.PUBLISHER,
                target=target,
                key=key,
                occurred_at=instant,
            ),
            occurred_at=instant,
        )
    context.write_json("wheels/manifest.json", manifest.model_dump(mode="json"), immutable=True)
    context.write_json(
        "wheels/publisher-signature.json",
        {
            "key_id": key_id,
            "signature_b64": sign_learning_contract(manifest, key),
            "artifact_root": root.name,
        },
        immutable=True,
    )
    return _write_state(context, state, state="generated", wheel_manifest_digest=manifest.digest)


def validate_learning_capability(
    config: Mapping[str, Any], *, run_id: str, key_path: Path
) -> LearningStateV2:
    context, state = _learning_context(config, run_id), None
    state = _state(context)
    _require(state, "generated")
    manifest = WheelManifestV2.model_validate(_json(context.artifact_path("wheels/manifest.json")))
    root = context.artifact_path(f"wheels/{manifest.wheel_id}-2")
    checks = static_validate_line_kv_parser(manifest, root)
    sandbox = DockerSandbox(str(config["wheel_sandbox_image"]))
    tests = sandbox.execute(root)
    samples = _json(context.artifact_path("research/frozen-samples.json"))
    positive = sandbox.execute_json(
        root,
        entrypoint=manifest.entrypoint,
        input_json=json.dumps({"text": samples["positive_text"]}, sort_keys=True),
    )
    negative = sandbox.execute_json(
        root,
        entrypoint=manifest.entrypoint,
        input_json=json.dumps({"text": samples["negative_text"]}, sort_keys=True),
    )
    if not tests.passed or not positive.passed or not negative.passed:
        raise R25WorkflowError("immutable no-network Wheel Docker validation failed")
    try:
        positive_output = json.loads(positive.output_json)
        negative_output = json.loads(negative.output_json)
    except json.JSONDecodeError as exc:
        raise R25WorkflowError("Wheel sandbox validation emitted invalid JSON") from exc
    if (
        not isinstance(positive_output, dict)
        or positive_output.get("matched") is not True
        or not isinstance(negative_output, dict)
        or negative_output.get("matched") is not False
    ):
        raise R25WorkflowError("Wheel positive/negative fixture assertions did not hold")
    key_id, key = _private(config, WheelKeyUsageV2.VALIDATOR, key_path)
    unsigned = ValidationReceiptV2(
        receipt_id=f"validation-{context.run_id}",
        learning_run_id=context.run_id,
        wheel_manifest_digest=manifest.digest,
        validator_key_id=key_id,
        static_checks=checks,
        docker_checks=("network-none", "read-only", "non-root", "cap-drop", "positive-json"),
        sandbox_image=sandbox.image,
        sandbox_image_digest=sandbox.image.rsplit("@", 1)[1],
        fixture_positive_digest=file_sha256(root / "fixtures/positive.json"),
        fixture_negative_digest=file_sha256(root / "fixtures/negative.json"),
        validated_at=_now(),
        signature_b64="x" * 16,
    )
    receipt = unsigned.model_copy(update={"signature_b64": sign_learning_contract(unsigned, key)})
    registry = _registry(context, config)
    instant = receipt.validated_at
    registry.record_validation(
        manifest,
        receipt,
        event_signature_b64=_event_signature(
            registry,
            manifest,
            event_type=RegistryEventV2.VALIDATED,
            key_id=key_id,
            usage=WheelKeyUsageV2.VALIDATOR,
            target="validated",
            key=key,
            occurred_at=instant,
            payload=receipt,
        ),
    )
    instant = _now()
    registry.transition(
        manifest.wheel_id,
        manifest.manifest_version,
        "candidate",
        actor_key_id=key_id,
        actor_usage=WheelKeyUsageV2.VALIDATOR,
        signature_b64=_event_signature(
            registry,
            manifest,
            event_type=RegistryEventV2.CANDIDATE,
            key_id=key_id,
            usage=WheelKeyUsageV2.VALIDATOR,
            target="candidate",
            key=key,
            occurred_at=instant,
        ),
        occurred_at=instant,
    )
    context.write_json(
        "wheels/validation-receipt.json", receipt.model_dump(mode="json"), immutable=True
    )
    return _write_state(context, state, state="candidate")


def approve_learning_capability(
    config: Mapping[str, Any],
    *,
    run_id: str,
    key_path: Path,
    rationale: str = "approved passive local parser",
) -> LearningStateV2:
    context, state = _learning_context(config, run_id), None
    state = _state(context)
    _require(state, "candidate")
    manifest = WheelManifestV2.model_validate(_json(context.artifact_path("wheels/manifest.json")))
    validation = ValidationReceiptV2.model_validate(
        _json(context.artifact_path("wheels/validation-receipt.json"))
    )
    key_id, key = _private(config, WheelKeyUsageV2.APPROVER, key_path)
    instant = _now()
    unsigned = WheelApprovalV2(
        approval_id=f"approval-{context.run_id}",
        learning_run_id=context.run_id,
        wheel_manifest_digest=manifest.digest,
        validation_receipt_digest=validation.digest,
        approver_key_id=key_id,
        approved_at=instant,
        expires_at=instant + timedelta(days=7),
        signature_b64="x" * 16,
    )
    approval = unsigned.model_copy(update={"signature_b64": sign_learning_contract(unsigned, key)})
    registry = _registry(context, config)
    registry.approve(
        manifest,
        approval,
        event_signature_b64=_event_signature(
            registry,
            manifest,
            event_type=RegistryEventV2.APPROVED,
            key_id=key_id,
            usage=WheelKeyUsageV2.APPROVER,
            target="approved",
            key=key,
            occurred_at=instant,
            payload=approval,
            approved_until=approval.expires_at,
        ),
    )
    context.write_json("wheels/approval.json", approval.model_dump(mode="json"), immutable=True)
    context.write_json_exclusive(
        "audit/approval-rationale.json",
        {"approval_digest": approval.digest, "rationale": rationale},
    )
    return _write_state(context, state, state="approved")


def activate_learning_capability(
    config: Mapping[str, Any], *, run_id: str, key_path: Path
) -> LearningStateV2:
    context, state = _learning_context(config, run_id), None
    state = _state(context)
    _require(state, "approved")
    manifest = WheelManifestV2.model_validate(_json(context.artifact_path("wheels/manifest.json")))
    approval = WheelApprovalV2.model_validate(_json(context.artifact_path("wheels/approval.json")))
    key_id, key = _private(config, WheelKeyUsageV2.OPERATOR, key_path)
    instant = _now()
    unsigned = WheelActivationReceiptV2(
        activation_id=f"activation-{context.run_id}",
        learning_run_id=context.run_id,
        wheel_manifest_digest=manifest.digest,
        wheel_approval_digest=approval.digest,
        operator_key_id=key_id,
        activated_at=instant,
        signature_b64="x" * 16,
    )
    activation = unsigned.model_copy(
        update={"signature_b64": sign_learning_contract(unsigned, key)}
    )
    registry = _registry(context, config)
    registry.activate(
        manifest,
        activation,
        event_signature_b64=_event_signature(
            registry,
            manifest,
            event_type=RegistryEventV2.ACTIVE,
            key_id=key_id,
            usage=WheelKeyUsageV2.OPERATOR,
            target="active",
            key=key,
            occurred_at=instant,
            payload=activation,
            approved_until=approval.expires_at,
            activation_digest=activation.digest,
        ),
    )
    context.write_json("wheels/activation.json", activation.model_dump(mode="json"), immutable=True)
    return _write_state(context, state, state="active")


def _quarantine_after_capability_failure(
    config: Mapping[str, Any],
    *,
    source_context: LearningContext,
    source_state: LearningStateV2,
    continuation_context: LearningContext,
    manifest: WheelManifestV2,
    activation: WheelActivationReceiptV2,
    input_value: dict[str, str],
    usage: WheelUsageV2,
    failure_reason: str,
) -> LearningStateV2:
    """Fail closed, preserving an independently signed quarantine trail.

    An execution integrity failure is not merely a failed continuation.  It is
    evidence that the active artifact must no longer be selected.  The source
    learning run is therefore governed to ``quarantined`` by the dedicated
    Revoker key, while the child continuation stores the bounded failure
    observation and never creates a finding or report.
    """

    if usage not in {
        WheelUsageV2.INVALID_OUTPUT,
        WheelUsageV2.SANDBOX_VIOLATION,
        WheelUsageV2.INTEGRITY_FAILURE,
    }:
        raise R25WorkflowError("only integrity failures can automatically quarantine a Wheel")
    reason = failure_reason[:2_000]
    input_digest = "sha256:" + sha256(canonical_json(input_value)).hexdigest()
    observation = {
        "matched": False,
        "fields": {},
        "failure_reason": reason,
    }
    observation_path = continuation_context.write_json(
        "continuation/structured-observation.json", observation, immutable=True
    )
    observation_digest = file_sha256(observation_path)
    execution = CapabilityExecutionReceiptV2(
        execution_id=f"execution-{continuation_context.run_id}",
        continuation_run_id=continuation_context.run_id,
        learning_run_id=source_context.run_id,
        wheel_manifest_digest=manifest.digest,
        wheel_activation_digest=activation.digest,
        input_digest=input_digest,
        output_digest=observation_digest,
        outcome="quarantined",
        executed_at=_now(),
    )
    outcome = ContinuationOutcomeV1(
        continuation_run_id=continuation_context.run_id,
        learning_run_id=source_context.run_id,
        parent_run_id=source_state.parent_run_id,
        scope_digest=source_state.scope_digest,
        wheel_manifest_digest=manifest.digest,
        wheel_activation_digest=activation.digest,
        execution_receipt_digest=execution.digest,
        structured_observation_digest=observation_digest,
        outcome="quarantined",
        generated_at=_now(),
    )
    key_id, key = _private(config, WheelKeyUsageV2.REVOKER)
    usage_event = WheelUsageEventV2(
        usage_id=f"usage-{continuation_context.run_id}",
        wheel_id=manifest.wheel_id,
        wheel_version=manifest.manifest_version,
        usage=usage,
        execution_receipt_digest=execution.digest,
        recorded_at=_now(),
        operator_key_id=key_id,
    )
    registry = _registry(source_context, config)
    registry_record = registry.get(manifest.wheel_id, manifest.manifest_version)
    registry.record_usage(
        usage_event,
        event_signature_b64=_event_signature(
            registry,
            manifest,
            event_type=RegistryEventV2.QUARANTINED,
            key_id=key_id,
            usage=WheelKeyUsageV2.REVOKER,
            target="quarantined",
            key=key,
            occurred_at=usage_event.recorded_at,
            payload=usage_event,
            approved_until=registry_record.approved_until,
            activation_digest=registry_record.activation_digest,
        ),
    )
    source_context.write_json_exclusive(
        "audit/automatic-quarantine.json",
        {
            "usage_event_digest": "sha256:"
            + sha256(usage_event.model_dump_json().encode()).hexdigest(),
            "reason": reason,
            "continuation_run_id": continuation_context.run_id,
        },
    )
    _write_state(source_context, source_state, state="quarantined")
    continuation_context.write_json(
        "continuation/execution-receipt.json", execution.model_dump(mode="json"), immutable=True
    )
    continuation_context.write_json(
        "continuation/outcome.json", outcome.model_dump(mode="json"), immutable=True
    )
    continuation_context.write_json(
        "audit/usage-journal-entry.json", usage_event.model_dump(mode="json"), immutable=True
    )
    quarantined_state = LearningStateV2(
        learning_run_id=continuation_context.run_id,
        parent_run_id=source_state.parent_run_id,
        scope_digest=source_state.scope_digest,
        state="quarantined",
        wheel_manifest_digest=manifest.digest,
        continuation_outcome_digest=outcome.digest,
        updated_at=_now(),
    )
    continuation_context.write_json(
        "state.json", quarantined_state.model_dump(mode="json"), immutable=True
    )
    return quarantined_state


def continue_learning_run(config: Mapping[str, Any], *, run_id: str) -> LearningStateV2:
    """Run one active Wheel in a new, immutable continuation run.

    The activated learning run is an input authority only.  Its registry and
    artifacts are read but never mutated here; the resulting observation lives
    under a fresh ``runs_root/learning/<continuation_id>`` directory.  This
    prevents a successful parser execution from being confused with a V3
    resume, promotion, or report authorization.
    """

    source_context = _learning_context(config, run_id)
    source_state = _state(source_context)
    _require(source_state, "active")
    manifest = WheelManifestV2.model_validate(
        _json(source_context.artifact_path("wheels/manifest.json"))
    )
    activation = WheelActivationReceiptV2.model_validate(
        _json(source_context.artifact_path("wheels/activation.json"))
    )
    registry = _registry(source_context, config)
    registry.select_active(
        manifest.wheel_id,
        manifest.manifest_version,
        profile="local-lab",
        required_template_id="line_kv_parser/v1",
        artifact_digest=manifest.artifact_digest,
    )
    samples_path = source_context.artifact_path("research/frozen-samples.json")
    samples = _json(samples_path)
    input_value = {"text": str(samples["continuation_text"])}
    continuation_context = LearningContext(Path(str(config["runs_root"])))
    source_binding = {
        "source_learning_run_id": source_context.run_id,
        "parent_run_id": source_state.parent_run_id,
        "scope_digest": source_state.scope_digest,
        "wheel_manifest_digest": manifest.digest,
        "wheel_activation_digest": activation.digest,
        "frozen_samples_digest": file_sha256(samples_path),
        "continuation_input_digest": "sha256:" + sha256(canonical_json(input_value)).hexdigest(),
    }
    continuation_context.write_json(
        "plan/continuation-parent-binding.json", source_binding, immutable=True
    )
    input_path = continuation_context.write_json(
        "continuation/frozen-input.json", input_value, immutable=True
    )
    input_digest = file_sha256(input_path)
    root = source_context.artifact_path(f"wheels/{manifest.wheel_id}-2")
    try:
        result = DockerSandbox(str(config["wheel_sandbox_image"])).execute_json(
            root, entrypoint=manifest.entrypoint, input_json=json.dumps(input_value, sort_keys=True)
        )
    except (OSError, ValueError, RuntimeError) as exc:
        return _quarantine_after_capability_failure(
            config,
            source_context=source_context,
            source_state=source_state,
            continuation_context=continuation_context,
            manifest=manifest,
            activation=activation,
            input_value=input_value,
            usage=WheelUsageV2.SANDBOX_VIOLATION,
            failure_reason=f"CapabilityHostV2 sandbox exception: {exc}",
        )
    if not result.passed:
        return _quarantine_after_capability_failure(
            config,
            source_context=source_context,
            source_state=source_state,
            continuation_context=continuation_context,
            manifest=manifest,
            activation=activation,
            input_value=input_value,
            usage=WheelUsageV2.SANDBOX_VIOLATION,
            failure_reason="CapabilityHostV2 sandbox execution failed: "
            + str(result.failure_reason or "unknown failure"),
        )
    try:
        output = json.loads(result.output_json)
    except json.JSONDecodeError as exc:
        return _quarantine_after_capability_failure(
            config,
            source_context=source_context,
            source_state=source_state,
            continuation_context=continuation_context,
            manifest=manifest,
            activation=activation,
            input_value=input_value,
            usage=WheelUsageV2.INVALID_OUTPUT,
            failure_reason=f"CapabilityHostV2 emitted invalid JSON: {exc}",
        )
    if (
        not isinstance(output, dict)
        or not isinstance(output.get("matched"), bool)
        or not isinstance(output.get("fields"), dict)
    ):
        return _quarantine_after_capability_failure(
            config,
            source_context=source_context,
            source_state=source_state,
            continuation_context=continuation_context,
            manifest=manifest,
            activation=activation,
            input_value=input_value,
            usage=WheelUsageV2.INVALID_OUTPUT,
            failure_reason="CapabilityHostV2 emitted an invalid parser observation",
        )
    outcome_name: LearningOutcome = "resolved" if output["matched"] else "inconclusive"
    execution = CapabilityExecutionReceiptV2(
        execution_id=f"execution-{continuation_context.run_id}",
        continuation_run_id=continuation_context.run_id,
        learning_run_id=source_context.run_id,
        wheel_manifest_digest=manifest.digest,
        wheel_activation_digest=activation.digest,
        input_digest=input_digest,
        output_digest="sha256:" + sha256(result.output_json.encode()).hexdigest(),
        outcome=outcome_name,
        executed_at=_now(),
    )
    observation_path = continuation_context.write_json(
        "continuation/structured-observation.json", output, immutable=True
    )
    observation_digest = file_sha256(observation_path)
    outcome = ContinuationOutcomeV1(
        continuation_run_id=continuation_context.run_id,
        learning_run_id=source_context.run_id,
        parent_run_id=source_state.parent_run_id,
        scope_digest=source_state.scope_digest,
        wheel_manifest_digest=manifest.digest,
        wheel_activation_digest=activation.digest,
        execution_receipt_digest=execution.digest,
        structured_observation_digest=observation_digest,
        outcome=outcome_name,
        generated_at=_now(),
    )
    continuation_context.write_json(
        "continuation/execution-receipt.json", execution.model_dump(mode="json"), immutable=True
    )
    continuation_context.write_json(
        "continuation/outcome.json", outcome.model_dump(mode="json"), immutable=True
    )
    usage = WheelUsageEventV2(
        usage_id=f"usage-{continuation_context.run_id}",
        wheel_id=manifest.wheel_id,
        wheel_version=manifest.manifest_version,
        usage=WheelUsageV2.RESOLVED if outcome_name == "resolved" else WheelUsageV2.INCONCLUSIVE,
        execution_receipt_digest=execution.digest,
        recorded_at=_now(),
    )
    continuation_context.write_json(
        "audit/usage-journal-entry.json", usage.model_dump(mode="json"), immutable=True
    )
    continuation_state = LearningStateV2(
        learning_run_id=continuation_context.run_id,
        parent_run_id=source_state.parent_run_id,
        scope_digest=source_state.scope_digest,
        state="completed",
        wheel_manifest_digest=manifest.digest,
        continuation_outcome_digest=outcome.digest,
        updated_at=_now(),
    )
    continuation_context.write_json(
        "state.json", continuation_state.model_dump(mode="json"), immutable=True
    )
    return continuation_state


def quarantine_or_revoke_learning_capability(
    config: Mapping[str, Any], *, run_id: str, key_path: Path, reason: str, revoke: bool = False
) -> LearningStateV2:
    """Let only the independent revoker terminate an active governance chain."""
    if not reason.strip():
        raise R25WorkflowError("Wheel quarantine/revocation requires a reason")
    context = _learning_context(config, run_id)
    state = _state(context)
    if state.state not in {"candidate", "approved", "active", "quarantined"}:
        raise R25WorkflowError("Wheel is not in a revocable lifecycle state")
    manifest = WheelManifestV2.model_validate(_json(context.artifact_path("wheels/manifest.json")))
    registry = _registry(context, config)
    key_id, key = _private(config, WheelKeyUsageV2.REVOKER, key_path)
    target: WheelLifecycleV2 = "revoked" if revoke else "quarantined"
    record = registry.get(manifest.wheel_id, manifest.manifest_version)
    if record.lifecycle == "quarantined" and not revoke:
        return state
    instant = _now()
    registry.transition(
        manifest.wheel_id,
        manifest.manifest_version,
        target,
        actor_key_id=key_id,
        actor_usage=WheelKeyUsageV2.REVOKER,
        signature_b64=_event_signature(
            registry,
            manifest,
            event_type=target,
            key_id=key_id,
            usage=WheelKeyUsageV2.REVOKER,
            target=target,
            key=key,
            occurred_at=instant,
            payload={"reason": reason},
        ),
        occurred_at=instant,
    )
    context.write_json_exclusive(
        "audit/quarantine-or-revoke.json",
        {"reason": reason, "target": target, "key_id": key_id, "at": instant.isoformat()},
    )
    return _write_state(context, state, state=target)


def learning_status_payload(config: Mapping[str, Any], *, run_id: str) -> dict[str, Any]:
    context = _learning_context(config, run_id)
    state = _state(context)
    return {
        "learning_run_id": state.learning_run_id,
        "parent_run_id": state.parent_run_id,
        "scope_digest": state.scope_digest,
        "learning_state": state.state,
        "wheel_manifest_digest": state.wheel_manifest_digest,
        "continuation_outcome_digest": state.continuation_outcome_digest,
        "artifact_path": str(context.path),
        "network_requests": 0,
    }


def validate_learning_config(config: Mapping[str, Any]) -> dict[str, bool]:
    required = (
        "runs_root",
        "wheel_trust_store",
        "wheel_sandbox_image",
        "prompt_root",
        "r25_role_manifests",
    )
    if any(not config.get(name) for name in required):
        raise R25WorkflowError("R2.5 configuration omits a required isolated setting")
    store = _trust(config)
    image = str(config["wheel_sandbox_image"])
    if "@sha256:" not in image or len(image.rsplit("@sha256:", 1)[1]) != 64:
        raise R25WorkflowError("Wheel sandbox image must be an immutable digest")
    runs_root = Path(str(config["runs_root"])).resolve()
    repository_root = Path(__file__).resolve().parents[2]
    for usage in WheelKeyUsageV2:
        key_path = config.get(f"{usage.value}_key")
        if not isinstance(key_path, (str, Path)):
            raise R25WorkflowError(f"R2.5 configuration omits {usage.value}_key")
        original_path = Path(key_path)
        resolved_path = original_path.resolve()
        if (
            repository_root in resolved_path.parents
            or resolved_path == repository_root
            or runs_root in resolved_path.parents
        ):
            raise R25WorkflowError("Wheel private keys must be outside repository and runs_root")
        _private(config, usage, original_path)

    from .prompts_r25 import PromptRegistryR25
    from .runtime.agents import RoleManifest, RoleTrustStore

    registry = PromptRegistryR25(Path(str(config["prompt_root"])))
    bundle = _json(Path(str(config["r25_role_manifests"])))
    raw_roles = bundle.get("roles")
    if not isinstance(raw_roles, list):
        raise R25WorkflowError("R2.5 manifest bundle must contain a roles list")
    publisher = next(item for item in store.keys if item.usage is WheelKeyUsageV2.PUBLISHER)
    manifest_trust = RoleTrustStore({publisher.key_id: decode_base64(publisher.public_key)})
    manifests = [RoleManifest.model_validate(item) for item in raw_roles]
    if {item.role for item in manifests} != {"researcher", "capability-planner"}:
        raise R25WorkflowError("R2.5 manifest bundle must contain exactly two learning roles")
    for manifest in manifests:
        manifest_trust.verify(manifest)
        registry.verify_manifest(manifest)
    return {
        "wheel_trust_store": True,
        "duty_separation": True,
        "private_key_paths": True,
        "prompt_manifest_binding": True,
        "immutable_sandbox_image": True,
        "learning_root_isolated": True,
    }


__all__ = [
    name
    for name in globals()
    if name.endswith("_learning_run") or name.endswith("_learning_capability")
] + [
    "R25WorkflowError",
    "LearningStateV2",
    "learning_status_payload",
    "validate_learning_config",
    "start_learning_run",
]

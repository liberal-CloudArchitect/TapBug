"""R2.5 governed learning loop built on frozen V3 evidence and isolated wheels."""

from __future__ import annotations

import base64
import json
import stat
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any, cast

from .domain_contracts import canonical_digest
from .domain_contracts_v3 import RunPlanV3
from .evidence import EvidenceArtifactRef, EvidenceStore
from .learning_contracts import (
    CapabilityExecutionReceiptV2,
    CapabilitySpecV2,
    ContinuationOutcomeV1,
    LearningRequestV1,
    LearningStatusV1,
    ParsedLineObservation,
    ResearchFactsEnvelopeV1,
    ResearchSourceArtifactV1,
    ValidationReceiptV2,
    WheelActivationReceiptV2,
    WheelApprovalV2,
    WheelManifestV2,
)
from .learning_security import (
    LearningKeyUsage,
    LearningTrustStoreV1,
    match_learning_private_key,
)
from .prompts_r25 import PromptRegistryR25
from .runtime import RunContext
from .runtime.agents import RoleManifest, RoleTrustStore, RunnerHost, TaskEnvelope
from .security import sign_ed25519
from .vertical_v3 import VerticalStateV3
from .wheels import (
    CapabilityHost,
    DockerSandbox,
    RuntimeSelector,
    SourceRecord,
    ValidationReport,
    WheelKind,
    WheelManifest,
    WheelRegistry,
    WheelRegistryError,
    WheelStatus,
    WheelValidator,
    artifact_sha256_for_directory,
    ed25519_signature_verifier,
)
from .wheels.registry import _signature_payload

R25_ALLOWED_ROLES = frozenset({"researcher", "capability-planner"})
_WHEEL_VERSION = "0.1.0"
_SOURCE_BUNDLE_VERSION = "1"
_REQUIRED_STATUSES = {
    "research": {"started"},
    "plan": {"researched"},
    "generate": {"planned"},
    "validate": {"generated"},
    "approve": {"candidate"},
    "activate": {"approved"},
    "continue": {"active"},
}


class LearningError(RuntimeError):
    """The R2.5 governed learning flow rejected an operation."""


@dataclass(frozen=True)
class LearningRun:
    context: RunContext
    request: LearningRequestV1
    status: LearningStatusV1


@dataclass(frozen=True)
class SourceBundle:
    root: Path
    entries: tuple[dict[str, Any], ...]


@dataclass(frozen=True)
class GeneratedCapability:
    artifact_root: Path
    legacy_manifest: WheelManifest
    manifest_v2: WheelManifestV2
    distribution_path: Path


def learning_runs_root(config: dict[str, Any]) -> Path:
    return Path(config["runs_root"]) / "learning"


def parse_learning_scope(parent_scope: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(parent_scope, dict) or not parent_scope:
        raise LearningError("parent scope snapshot is missing or invalid")
    return parent_scope


def open_learning_run(config: dict[str, Any], run_id: str) -> LearningRun:
    root = learning_runs_root(config)
    scope_path = root / run_id / "scope.json"
    try:
        scope = json.loads(scope_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LearningError("learning run scope snapshot is missing or invalid") from exc
    context = RunContext.open_existing(root, parse_learning_scope(scope), run_id)
    request = LearningRequestV1.model_validate_json(
        context.artifact_path("plan/learning-request.json").read_bytes()
    )
    status = LearningStatusV1.model_validate_json(context.artifact_path("state.json").read_bytes())
    return LearningRun(context=context, request=request, status=status)


def _artifact_sha256(path: Path) -> str:
    return "sha256:" + sha256(path.read_bytes()).hexdigest()


def _ensure_absolute_private_key(path: Path, *, forbidden_roots: tuple[Path, ...]) -> None:
    if not path.is_absolute():
        raise LearningError("learning private key path must be absolute")
    if path.is_symlink():
        raise LearningError("learning private key path must not be a symlink")
    try:
        details = path.stat()
    except OSError as exc:
        raise LearningError("learning private key could not be inspected") from exc
    if not stat.S_ISREG(details.st_mode):
        raise LearningError("learning private key must be a regular file")
    if stat.S_IMODE(details.st_mode) != 0o600:
        raise LearningError("learning private key permissions must be 0600")
    resolved = path.resolve(strict=True)
    for root in forbidden_roots:
        if resolved == root or root in resolved.parents:
            raise LearningError("learning private keys must remain outside repo and run roots")


def _require_learning_state(status: LearningStatusV1, operation: str) -> None:
    allowed = _REQUIRED_STATUSES.get(operation)
    if allowed is None:
        return
    if status.state not in allowed:
        raise LearningError(f"learning run is not ready for {operation}: {status.state}")


def _write_status(
    run: LearningRun,
    *,
    state: str,
    wheel_manifest_digest: str | None = None,
    latest_continuation_digest: str | None = None,
) -> LearningStatusV1:
    current = run.status
    updated = current.model_copy(
        update={
            "state": state,
            "wheel_manifest_digest": wheel_manifest_digest
            if wheel_manifest_digest is not None
            else current.wheel_manifest_digest,
            "latest_continuation_digest": latest_continuation_digest
            if latest_continuation_digest is not None
            else current.latest_continuation_digest,
            "updated_at": datetime.now(UTC),
        }
    )
    run.context.write_json("state.json", updated.model_dump(mode="json"))
    return updated


def _parent_context(config: dict[str, Any], run_id: str) -> RunContext:
    root = Path(config["runs_root"])
    scope_path = root / run_id / "scope.json"
    try:
        scope = json.loads(scope_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LearningError("parent V3 scope snapshot is missing or invalid") from exc
    return RunContext.open_existing(root, parse_learning_scope(scope), run_id)


def _evidence_ref_from_parent(parent: RunContext, evidence_id: str) -> EvidenceArtifactRef:
    manifest_path = parent.artifact_path(f"evidence/{evidence_id}/manifest.json")
    if not manifest_path.is_file():
        raise LearningError("parent evidence manifest is missing")
    return EvidenceArtifactRef(
        evidence_id=evidence_id,
        manifest_path=f"evidence/{evidence_id}/manifest.json",
        manifest_sha256=_artifact_sha256(manifest_path),
    )


def _read_text_file(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise LearningError(f"could not read {path}") from exc


def start_learning_run(
    config: dict[str, Any],
    *,
    parent_run_id: str,
    evidence_id: str,
    observation_file: Path,
    risk_level: str = "low",
) -> LearningStatusV1:
    parent = _parent_context(config, parent_run_id)
    parent_plan = RunPlanV3.model_validate_json(
        parent.artifact_path("plan/run-v3.json").read_bytes()
    )
    _ = VerticalStateV3.model_validate_json(parent.artifact_path("state.json").read_bytes())
    evidence_ref = _evidence_ref_from_parent(parent, evidence_id)
    evidence_store = EvidenceStore(parent.path)
    manifest = evidence_store.verify(evidence_ref)
    analysis_path = parent.artifact_path(manifest.analysis.path)
    parent_scope = json.loads(parent.artifact_path("scope.json").read_text(encoding="utf-8"))
    context = RunContext(learning_runs_root(config), parse_learning_scope(parent_scope))
    request = LearningRequestV1(
        run_id=context.run_id,
        parent_run_id=parent.run_id,
        scope_digest=context.scope_digest,
        parent_run_plan_digest=canonical_digest(parent_plan),
        parent_evidence_manifest_digest=evidence_ref.manifest_sha256,
        parent_analysis_digest=_artifact_sha256(analysis_path),
        evidence_ref=evidence_ref,
        observation=_read_text_file(observation_file).strip(),
        risk_level=cast(Any, risk_level),
        local_profile=str(parent_scope.get("profile", "local-lab")),
        created_at=datetime.now(UTC),
    )
    context.write_json(
        "plan/learning-request.json", request.model_dump(mode="json"), immutable=True
    )
    context.write_json(
        "plan/parent-run-binding.json",
        {
            "parent_run_id": parent.run_id,
            "parent_run_plan_digest": request.parent_run_plan_digest,
            "parent_evidence_manifest_digest": request.parent_evidence_manifest_digest,
            "parent_analysis_digest": request.parent_analysis_digest,
        },
        immutable=True,
    )
    context.write_text(
        "knowledge/input-analysis.json",
        analysis_path.read_text(encoding="utf-8"),
        immutable=True,
    )
    status = LearningStatusV1(
        run_id=context.run_id,
        parent_run_id=parent.run_id,
        scope_digest=context.scope_digest,
        state="started",
        updated_at=datetime.now(UTC),
    )
    context.write_json("state.json", status.model_dump(mode="json"), immutable=True)
    return status


def _load_source_bundle(path: Path) -> SourceBundle:
    root = path.resolve()
    bundle_path = root / "bundle.json" if root.is_dir() else root
    base = bundle_path.parent
    try:
        document = json.loads(bundle_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LearningError("source bundle is missing or invalid") from exc
    if (
        not isinstance(document, dict)
        or document.get("version") != _SOURCE_BUNDLE_VERSION
        or not isinstance(document.get("sources"), list)
        or not document["sources"]
    ):
        raise LearningError("source bundle must be a non-empty versioned source list")
    entries: list[dict[str, Any]] = []
    for item in document["sources"]:
        if not isinstance(item, dict):
            raise LearningError("source bundle entries must be objects")
        body_path = item.get("body_path")
        if not isinstance(body_path, str) or not body_path:
            raise LearningError("source bundle entry omitted body_path")
        source_path = (base / body_path).resolve()
        try:
            source_path.relative_to(base.resolve())
        except ValueError as exc:
            raise LearningError("source bundle body_path escapes its root") from exc
        if not source_path.is_file():
            raise LearningError("source bundle body file is missing")
        entry = dict(item)
        entry["_body_path"] = source_path
        entries.append(entry)
    return SourceBundle(root=base, entries=tuple(entries))


def _archive_research_sources(
    run: LearningRun, bundle: SourceBundle
) -> tuple[ResearchSourceArtifactV1, ...]:
    artifacts: list[ResearchSourceArtifactV1] = []
    source_root = run.context.artifact_path("knowledge/research-sources")
    source_root.mkdir(parents=True, exist_ok=True)
    for index, entry in enumerate(bundle.entries, start=1):
        body_path = cast(Path, entry["_body_path"])
        payload = body_path.read_bytes()
        content_sha256 = "sha256:" + sha256(payload).hexdigest()
        projection_text = body_path.read_text(encoding="utf-8", errors="replace")[:4096]
        projection_sha256 = "sha256:" + sha256(projection_text.encode("utf-8")).hexdigest()
        source_id = str(entry.get("source_id") or f"source-{index}")
        archive_dir = source_root / source_id
        archive_dir.mkdir(parents=True, exist_ok=False)
        raw_name = body_path.name
        projection_name = f"{body_path.stem}.projection.txt"
        (archive_dir / raw_name).write_bytes(payload)
        (archive_dir / projection_name).write_text(projection_text, encoding="utf-8")
        artifact = ResearchSourceArtifactV1(
            run_id=run.context.run_id,
            scope_digest=run.context.scope_digest,
            generated_by_task_id="research-archive",
            source_id=source_id,
            url=str(entry.get("url")),
            license=str(entry.get("license")),
            source_version=str(entry["version"]) if entry.get("version") is not None else None,
            content_sha256=content_sha256,
            projection_sha256=projection_sha256,
            archived_path=(
                Path("knowledge") / "research-sources" / source_id / raw_name
            ).as_posix(),
            projection_path=(
                Path("knowledge") / "research-sources" / source_id / projection_name
            ).as_posix(),
            risk_flags=tuple(
                str(item) for item in entry.get("risk_flags", ()) if isinstance(item, str)
            ),
            citations=tuple(
                str(item) for item in entry.get("citations", ()) if isinstance(item, str)
            ),
            captured_at=datetime.now(UTC),
        )
        run.context.write_json(
            f"knowledge/research-source-{source_id}.json",
            artifact.model_dump(mode="json"),
            immutable=True,
        )
        artifacts.append(artifact)
    return tuple(artifacts)


def _r25_manifests(path: Path) -> dict[str, RoleManifest]:
    document = json.loads(path.read_text(encoding="utf-8"))
    entries = document.get("roles")
    if not isinstance(entries, list):
        raise LearningError("R2.5 role manifest bundle must contain a roles list")
    manifests = [RoleManifest.model_validate(entry) for entry in entries]
    mapped = {item.role: item for item in manifests}
    if set(mapped) != R25_ALLOWED_ROLES or len(mapped) != len(manifests):
        raise LearningError("R2.5 role manifest bundle must contain the exact two roles")
    return mapped


def build_learning_runner(
    config: dict[str, Any],
    run: LearningRun,
    *,
    policy: Any,
    model_handler: Any,
) -> RunnerHost:
    from .orchestrator import (  # local import to avoid cycle
        _evidence_artifact_validator,
        _evidence_validator,
    )

    docker_binary = Path(str(config.get("docker_binary", "docker")))
    return RunnerHost(
        manifests=_r25_manifests(Path(config["learn_role_manifests"])),
        trust_store=RoleTrustStore.from_file(Path(config["role_trust_store"])),
        gateway_handler=lambda _request, _task: (_ for _ in ()).throw(
            LearningError(
                "R2.5 learning roles may not request gateway actions in the local bundle flow"
            )
        ),
        model_handler=model_handler,
        evidence_validator=_evidence_validator(run.context),
        evidence_artifact_validator=_evidence_artifact_validator(
            run.context, EvidenceStore(run.context.path)
        ),
        prompt_registry=PromptRegistryR25(Path(config["prompt_root"])),
        sandbox=__import__(
            "hermes.runtime.agents", fromlist=["DockerRoleSandbox"]
        ).DockerRoleSandbox(
            docker_binary=str(docker_binary),
            labels={"com.hermes.run_id": run.context.run_id, "com.hermes.component": "role-r25"},
        ),
    )


def _role_result(
    runner: RunnerHost,
    run: LearningRun,
    *,
    role: str,
    operation: str,
    task_id: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    task = TaskEnvelope(
        version="3",
        run_id=run.context.run_id,
        task_id=task_id,
        role=role,
        scope_digest=run.context.scope_digest,
        payload={"operation": operation, **payload},
        timeout_seconds=180,
    )
    result = runner.run(task)
    if result.lifecycle != "completed" or result.handoff is None:
        raise LearningError(f"R2.5 role {role} failed: {result.error or result.lifecycle}")
    output = result.handoff.result
    if not hasattr(output, "payload"):
        raise LearningError("R2.5 role returned an untyped contract payload")
    return cast(dict[str, Any], output.payload.model_dump(mode="json"))


def research_learning_run(
    config: dict[str, Any],
    *,
    run_id: str,
    source_bundle: Path,
    model_handler: Any,
) -> LearningStatusV1:
    run = open_learning_run(config, run_id)
    _require_learning_state(run.status, "research")
    bundle = _load_source_bundle(source_bundle)
    artifacts = _archive_research_sources(run, bundle)
    parent_scope = json.loads(run.context.artifact_path("scope.json").read_text(encoding="utf-8"))
    runner = build_learning_runner(config, run, policy=parent_scope, model_handler=model_handler)
    projections = [
        {
            "source_id": item.source_id,
            "url": item.url,
            "license": item.license,
            "source_version": item.source_version,
            "projection_path": item.projection_path,
            "projection_text": _read_text_file(run.context.artifact_path(item.projection_path)),
            "citations": list(item.citations),
        }
        for item in artifacts
    ]
    payload = _role_result(
        runner,
        run,
        role="researcher",
        operation="research",
        task_id=f"learning-research-{run.context.run_id}",
        payload={
            "learning_request": run.request.model_dump(mode="json"),
            "source_artifacts": [item.model_dump(mode="json") for item in artifacts],
            "source_projections": projections,
        },
    )
    facts = ResearchFactsEnvelopeV1.model_validate(
        {
            "version": "1",
            "run_id": run.context.run_id,
            "scope_digest": run.context.scope_digest,
            "generated_by_task_id": f"learning-research-{run.context.run_id}",
            "facts": payload["facts"],
        }
    )
    run.context.write_json(
        "knowledge/research-facts.json", facts.model_dump(mode="json"), immutable=True
    )
    updated = _write_status(run, state="researched")
    return updated


def plan_learning_run(
    config: dict[str, Any],
    *,
    run_id: str,
    model_handler: Any,
) -> LearningStatusV1:
    run = open_learning_run(config, run_id)
    _require_learning_state(run.status, "plan")
    facts = ResearchFactsEnvelopeV1.model_validate_json(
        run.context.artifact_path("knowledge/research-facts.json").read_bytes()
    )
    parent_scope = json.loads(run.context.artifact_path("scope.json").read_text(encoding="utf-8"))
    runner = build_learning_runner(config, run, policy=parent_scope, model_handler=model_handler)
    payload = _role_result(
        runner,
        run,
        role="capability-planner",
        operation="specify",
        task_id=f"learning-plan-{run.context.run_id}",
        payload={
            "learning_request": run.request.model_dump(mode="json"),
            "research_facts": facts.model_dump(mode="json"),
        },
    )
    spec = CapabilitySpecV2.model_validate(payload)
    if spec.run_id != run.context.run_id or spec.scope_digest != run.context.scope_digest:
        raise LearningError("R2.5 capability spec crossed a run or scope boundary")
    run.context.write_json(
        "wheels/capability-spec-v2.json", spec.model_dump(mode="json"), immutable=True
    )
    updated = _write_status(run, state="planned")
    return updated


def _legacy_manifest_from_spec(
    spec: CapabilitySpecV2, sources: tuple[ResearchSourceArtifactV1, ...]
) -> WheelManifest:
    source_records = tuple(
        SourceRecord(
            url=item.url,
            retrieved_at=item.captured_at,
            content_sha256=item.content_sha256,
            license=item.license,
            version=item.source_version,
            applicability="offline archived learning source",
            risk_flags=item.risk_flags,
        )
        for item in sources
    )
    return WheelManifest(
        id=spec.wheel_id,
        version=_WHEEL_VERSION,
        kind=WheelKind.PASSIVE_PARSER,
        entrypoint="wheel:parse_response",
        input_schema=spec.input_schema_id,
        output_schema=spec.output_schema_id,
        capabilities=("parse_response",),
        profiles=(run_profile_from_spec(spec),),
        sources=source_records,
        tests=("tests/test_wheel.py",),
        status=WheelStatus.DRAFT,
    )


def run_profile_from_spec(spec: CapabilitySpecV2) -> str:
    return "local-lab"


def _parser_module_source(spec: CapabilitySpecV2) -> str:
    fixed = ", ".join(repr(item) for item in spec.fixed_fields)
    return (
        "import json\n\n"
        f"FIXED_FIELDS = {{{fixed}}}\n\n"
        "def parse_response(value: str) -> dict[str, object]:\n"
        "    payload = json.loads(value)\n"
        "    text = str(payload.get('analysis_text', ''))\n"
        "    observations = []\n"
        "    for line_number, line in enumerate(text.splitlines(), start=1):\n"
        "        raw = line.strip()\n"
        "        if not raw:\n"
        "            continue\n"
        "        separator = ':' if ':' in raw else ('=' if '=' in raw else None)\n"
        "        if separator is None:\n"
        "            continue\n"
        "        key, candidate = raw.split(separator, 1)\n"
        "        normalized = ''.join(\n"
        "            '_' if char in ' -' else char for char in key.strip().lower()\n"
        "        )\n"
        "        parsed = candidate.strip()\n"
        "        if not normalized or not parsed or normalized not in FIXED_FIELDS:\n"
        "            continue\n"
        "        observations.append({"
        "'line_number': line_number, 'key': normalized, 'value': parsed"
        "})\n"
        "    if not observations:\n"
        "        return {"
        "'status': 'no_match', 'observations': [], "
        "'summary': 'no matching key/value lines'"
        "}\n"
        "    return {"
        "'status': 'matched', 'observations': observations, "
        "'summary': f'parsed {len(observations)} key/value lines'"
        "}\n"
    )


def _test_module_source() -> str:
    return (
        "import json\n\n"
        "from wheel import parse_response\n\n\n"
        "def test_positive_fixture_resolves():\n"
        "    result = parse_response(\n"
        "        json.dumps({'analysis_text': 'Service: HERMES-LINE\\nVersion: 1\\n'})\n"
        "    )\n"
        "    assert result['status'] == 'matched'\n"
        "    assert result['observations']\n\n\n"
        "def test_negative_fixture_no_match():\n"
        "    result = parse_response(json.dumps({'analysis_text': 'no delimiters here'}))\n"
        "    assert result['status'] == 'no_match'\n"
    )


def _build_python_wheel(artifact_root: Path, wheel_id: str) -> Path:
    distribution = wheel_id.replace("-", "_")
    version = _WHEEL_VERSION
    dist_info = f"{distribution}-{version}.dist-info"
    wheel_path = artifact_root / "dist" / f"{distribution}-{version}-py3-none-any.whl"
    wheel_path.parent.mkdir(parents=True, exist_ok=True)
    members = {
        "wheel.py": (artifact_root / "wheel.py").read_bytes(),
        f"{dist_info}/WHEEL": (
            b"Wheel-Version: 1.0\n"
            b"Generator: hermes-learning\n"
            b"Root-Is-Purelib: true\n"
            b"Tag: py3-none-any\n"
        ),
        f"{dist_info}/METADATA": (
            f"Metadata-Version: 2.1\nName: {distribution}\nVersion: {version}\n\n".encode()
        ),
    }
    records = [
        f"{name},sha256={base64.urlsafe_b64encode(sha256(value).digest()).decode().rstrip('=')},{len(value)}"
        for name, value in sorted(members.items())
    ]
    members[f"{dist_info}/RECORD"] = ("\n".join(records + [f"{dist_info}/RECORD,,"]) + "\n").encode(
        "utf-8"
    )
    with zipfile.ZipFile(wheel_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, value in sorted(members.items()):
            member = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            member.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(member, value)
    return wheel_path


def generate_learning_capability(config: dict[str, Any], *, run_id: str) -> LearningStatusV1:
    run = open_learning_run(config, run_id)
    _require_learning_state(run.status, "generate")
    spec = CapabilitySpecV2.model_validate_json(
        run.context.artifact_path("wheels/capability-spec-v2.json").read_bytes()
    )
    source_paths = sorted(run.context.artifact_path("knowledge").glob("research-source-*.json"))
    sources = tuple(
        ResearchSourceArtifactV1.model_validate_json(path.read_bytes()) for path in source_paths
    )
    if not sources:
        raise LearningError("R2.5 generation requires archived research sources")
    artifact_root = run.context.artifact_path(f"wheels/{spec.wheel_id}-{_WHEEL_VERSION}")
    if artifact_root.exists():
        raise LearningError("learning wheel artifact root already exists")
    first_field = spec.fixed_fields[0]
    second_field = spec.fixed_fields[1] if len(spec.fixed_fields) > 1 else spec.fixed_fields[0]
    first_source = first_field.replace("_", " ").title()
    second_source = second_field.replace("_", " ").title()
    (artifact_root / "tests").mkdir(parents=True)
    (artifact_root / "fixtures").mkdir()
    (artifact_root / "wheel.py").write_text(_parser_module_source(spec), encoding="utf-8")
    (artifact_root / "tests" / "test_wheel.py").write_text(_test_module_source(), encoding="utf-8")
    (artifact_root / "fixtures" / "positive.json").write_text(
        json.dumps(
            {
                "analysis_text": (
                    f"{first_source}: {first_field}-value\n{second_source}: {second_field}-value\n"
                )
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    (artifact_root / "fixtures" / "negative.json").write_text(
        json.dumps({"analysis_text": f"{first_source}: {first_field}-value\n"}, ensure_ascii=False),
        encoding="utf-8",
    )
    (artifact_root / "rules.json").write_text(
        json.dumps(
            {
                "template_id": spec.template_id,
                "max_requests": spec.max_requests,
                "network_policy": spec.network_policy,
                "command_policy": spec.command_policy,
                "filesystem_policy": spec.filesystem_policy,
                "fixed_fields": list(spec.fixed_fields),
            },
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
        ),
        encoding="utf-8",
    )
    (artifact_root / "capability-spec.json").write_text(
        json.dumps(
            {"id": spec.wheel_id, "spec": spec.model_dump(mode="json")},
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
        ),
        encoding="utf-8",
    )
    (artifact_root / "requirements.lock").write_text(
        "# no third-party dependencies\n", encoding="utf-8"
    )
    (artifact_root / "SBOM.spdx.json").write_text(
        json.dumps(
            {
                "SPDXID": "SPDXRef-DOCUMENT",
                "spdxVersion": "SPDX-2.3",
                "name": spec.wheel_id,
                "packages": [
                    {
                        "SPDXID": "SPDXRef-Package",
                        "name": spec.wheel_id,
                        "versionInfo": _WHEEL_VERSION,
                    }
                ],
            },
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
        ),
        encoding="utf-8",
    )
    (artifact_root / "README.md").write_text(
        "# Passive Parser\n\nGenerated from a reviewed line_kv_parser/v1 capability spec.\n",
        encoding="utf-8",
    )
    legacy_manifest = _legacy_manifest_from_spec(spec, sources)
    wheel_path = _build_python_wheel(artifact_root, spec.wheel_id)
    legacy_manifest = legacy_manifest.model_copy(
        update={"artifact_sha256": artifact_sha256_for_directory(artifact_root)}
    )
    (artifact_root / "wheel-manifest.json").write_text(
        legacy_manifest.model_dump_json(indent=2), encoding="utf-8"
    )
    manifest_v2 = WheelManifestV2(
        run_id=run.context.run_id,
        scope_digest=run.context.scope_digest,
        generated_by_task_id=f"learning-generate-{run.context.run_id}",
        wheel_id=spec.wheel_id,
        wheel_version=_WHEEL_VERSION,
        capability_spec_digest=spec.digest,
        artifact_root_sha256=artifact_sha256_for_directory(artifact_root),
        distribution_sha256=_artifact_sha256(wheel_path),
        entrypoint=legacy_manifest.entrypoint,
        sandbox_image=str(config["wheel_sandbox_image"]),
        profile=run_profile_from_spec(spec),
        status="generated",
    )
    run.context.write_json(
        "wheels/wheel-manifest-v2.json", manifest_v2.model_dump(mode="json"), immutable=True
    )
    publisher_store = LearningTrustStoreV1.from_file(Path(config["wheel_trust_store"]))
    publisher_store.assert_role_separation()
    publisher_key_path = Path(config["wheel_publisher_key_file"]).resolve()
    _ensure_absolute_private_key(
        publisher_key_path,
        forbidden_roots=(Path(__file__).resolve().parents[2], learning_runs_root(config).resolve()),
    )
    journal_signer, journal_verifier, actor_roles = learning_registry_signing_context(
        publisher_store,
        {
            publisher_store.key_for(LearningKeyUsage.WHEEL_PUBLISHER).key_id: publisher_key_path,
        },
    )
    registry = WheelRegistry(
        ed25519_signature_verifier(
            __import__("base64").urlsafe_b64decode(
                publisher_store.key_for(LearningKeyUsage.WHEEL_APPROVER).public_key + "=="
            )
        ),
        context=run.context,
        journal_signer=journal_signer,
        journal_verifier=journal_verifier,
        actor_roles=actor_roles,
        require_signed_journal=True,
    )
    publisher_id = publisher_store.key_for(LearningKeyUsage.WHEEL_PUBLISHER).key_id
    registry.add(legacy_manifest, actor=publisher_id)
    registry.research(legacy_manifest.id, legacy_manifest.version, actor=publisher_id)
    registry.specify(legacy_manifest.id, legacy_manifest.version, actor=publisher_id)
    registry.record_generation(legacy_manifest.id, legacy_manifest.version, actor=publisher_id)
    updated = _write_status(run, state="generated", wheel_manifest_digest=manifest_v2.digest)
    return updated


def learning_registry_signing_context(
    store: LearningTrustStoreV1,
    key_paths: dict[str, Path],
) -> tuple[Any, Any, dict[str, str]]:
    actor_roles = {
        store.key_for(LearningKeyUsage.WHEEL_PUBLISHER).key_id: "publisher",
        store.key_for(LearningKeyUsage.WHEEL_VALIDATOR).key_id: "validator",
        store.key_for(LearningKeyUsage.WHEEL_APPROVER).key_id: "approver",
        store.key_for(LearningKeyUsage.WHEEL_OPERATOR).key_id: "operator",
        store.key_for(LearningKeyUsage.WHEEL_REVOKER).key_id: "revoker",
    }
    loaded_keys: dict[str, Any] = {}
    for key_id, path in key_paths.items():
        if path.exists():
            loaded_keys[key_id] = __import__(
                "hermes.security", fromlist=["load_ed25519_private_key"]
            ).load_ed25519_private_key(path)

    def sign_event(payload: bytes, actor: str) -> str:
        key = loaded_keys.get(actor)
        if key is None:
            raise WheelRegistryError("no private key is available for the requested learning actor")
        return sign_ed25519(key, payload)

    def verify_event(payload: bytes, signature: str, actor: str) -> bool:
        try:
            role = actor_roles[actor]
            usage = {
                "publisher": LearningKeyUsage.WHEEL_PUBLISHER,
                "validator": LearningKeyUsage.WHEEL_VALIDATOR,
                "approver": LearningKeyUsage.WHEEL_APPROVER,
                "operator": LearningKeyUsage.WHEEL_OPERATOR,
                "revoker": LearningKeyUsage.WHEEL_REVOKER,
            }[role]
            store.verify(usage=usage, payload=payload, signature=signature)
        except Exception:
            return False
        return True

    return sign_event, verify_event, actor_roles


def _load_generated_artifacts(
    run: LearningRun,
) -> tuple[CapabilitySpecV2, WheelManifestV2, WheelManifest, Path]:
    spec = CapabilitySpecV2.model_validate_json(
        run.context.artifact_path("wheels/capability-spec-v2.json").read_bytes()
    )
    manifest_v2 = WheelManifestV2.model_validate_json(
        run.context.artifact_path("wheels/wheel-manifest-v2.json").read_bytes()
    )
    artifact_root = run.context.artifact_path(f"wheels/{spec.wheel_id}-{_WHEEL_VERSION}")
    legacy_manifest = WheelManifest.model_validate_json(
        (artifact_root / "wheel-manifest.json").read_bytes()
    )
    return spec, manifest_v2, legacy_manifest, artifact_root


def validate_learning_capability(config: dict[str, Any], *, run_id: str) -> LearningStatusV1:
    run = open_learning_run(config, run_id)
    _require_learning_state(run.status, "validate")
    _spec, manifest_v2, legacy_manifest, artifact_root = _load_generated_artifacts(run)
    validator = WheelValidator()
    report = validator.validate(legacy_manifest, artifact_root)
    sandbox = DockerSandbox(str(config["wheel_sandbox_image"]))
    sandbox_tests = sandbox.execute(artifact_root)
    positive_input = _read_text_file(artifact_root / "fixtures" / "positive.json")
    negative_input = _read_text_file(artifact_root / "fixtures" / "negative.json")
    positive_result = sandbox.execute_json(
        artifact_root, entrypoint=legacy_manifest.entrypoint, input_json=positive_input
    )
    negative_result = sandbox.execute_json(
        artifact_root, entrypoint=legacy_manifest.entrypoint, input_json=negative_input
    )
    validator_store = LearningTrustStoreV1.from_file(Path(config["wheel_trust_store"]))
    validator_store.assert_role_separation()
    validator_key_path = Path(config["wheel_validator_key_file"]).resolve()
    _ensure_absolute_private_key(
        validator_key_path,
        forbidden_roots=(Path(__file__).resolve().parents[2], learning_runs_root(config).resolve()),
    )
    validator_id = validator_store.key_for(LearningKeyUsage.WHEEL_VALIDATOR).key_id
    receipt = ValidationReceiptV2(
        run_id=run.context.run_id,
        scope_digest=run.context.scope_digest,
        wheel_manifest_digest=manifest_v2.digest,
        validator_key_id=validator_id,
        static_passed=report.passed,
        sandbox_tests_passed=sandbox_tests.passed,
        positive_execution_passed=positive_result.passed
        and '"matched"' in positive_result.output_json,
        negative_execution_passed=negative_result.passed
        and '"no_match"' in negative_result.output_json,
        violations=tuple(report.violations),
        positive_output_sha256=(
            "sha256:" + sha256(positive_result.output_json.encode("utf-8")).hexdigest()
            if positive_result.passed
            else None
        ),
        negative_output_sha256=(
            "sha256:" + sha256(negative_result.output_json.encode("utf-8")).hexdigest()
            if negative_result.passed
            else None
        ),
        validated_at=datetime.now(UTC),
    )
    run.context.write_json(
        "wheels/validation-receipt-v2.json", receipt.model_dump(mode="json"), immutable=True
    )
    store = LearningTrustStoreV1.from_file(Path(config["wheel_trust_store"]))
    sign_event, verify_event, actor_roles = learning_registry_signing_context(
        store,
        {
            store.key_for(LearningKeyUsage.WHEEL_PUBLISHER).key_id: Path(
                config["wheel_publisher_key_file"]
            ).resolve(),
            store.key_for(LearningKeyUsage.WHEEL_VALIDATOR).key_id: validator_key_path,
        },
    )
    approver_public = store.key_for(LearningKeyUsage.WHEEL_APPROVER).public_key
    registry = WheelRegistry(
        ed25519_signature_verifier(__import__("base64").urlsafe_b64decode(approver_public + "==")),
        context=run.context,
        journal_signer=sign_event,
        journal_verifier=verify_event,
        actor_roles=actor_roles,
        require_signed_journal=True,
    )
    if not (
        receipt.static_passed
        and receipt.sandbox_tests_passed
        and receipt.positive_execution_passed
        and receipt.negative_execution_passed
    ):
        raise LearningError("learning capability validation failed closed")
    validator_report = ValidationReport(
        wheel_id=legacy_manifest.id,
        wheel_version=legacy_manifest.version,
        artifact_sha256=legacy_manifest.artifact_sha256,
        passed=True,
        violations=tuple(report.violations),
        checked_files=report.checked_files,
        imports=report.imports,
        sbom=report.sbom,
        validated_at=receipt.validated_at,
    )
    validator_id = store.key_for(LearningKeyUsage.WHEEL_VALIDATOR).key_id
    registry.record_validation(
        legacy_manifest.id, legacy_manifest.version, validator_report, actor=validator_id
    )
    publisher_id = store.key_for(LearningKeyUsage.WHEEL_PUBLISHER).key_id
    registry.nominate(legacy_manifest.id, legacy_manifest.version, actor=publisher_id)
    updated = _write_status(run, state="candidate", wheel_manifest_digest=manifest_v2.digest)
    return updated


def approve_learning_capability(
    config: dict[str, Any],
    *,
    run_id: str,
    key_path: Path,
    rationale: str,
    verdict: str = "approved",
) -> LearningStatusV1:
    run = open_learning_run(config, run_id)
    _require_learning_state(run.status, "approve")
    _spec, manifest_v2, legacy_manifest, _artifact_root = _load_generated_artifacts(run)
    receipt = ValidationReceiptV2.model_validate_json(
        run.context.artifact_path("wheels/validation-receipt-v2.json").read_bytes()
    )
    store = LearningTrustStoreV1.from_file(Path(config["wheel_trust_store"]))
    now = datetime.now(UTC)
    _ensure_absolute_private_key(
        key_path.resolve(),
        forbidden_roots=(Path(__file__).resolve().parents[2], learning_runs_root(config).resolve()),
    )
    approver_key_id, private_key = match_learning_private_key(
        store, LearningKeyUsage.WHEEL_APPROVER, key_path.resolve(), at=now
    )
    approval = WheelApprovalV2(
        run_id=run.context.run_id,
        scope_digest=run.context.scope_digest,
        wheel_manifest_digest=manifest_v2.digest,
        validation_receipt_digest=receipt.digest,
        verdict=cast(Any, verdict),
        approver_key_id=approver_key_id,
        rationale=rationale,
        signed_at=now,
        signature="placeholder-signature",
    )
    approval = approval.model_copy(
        update={"signature": sign_ed25519(private_key, canonical_digest(approval).encode("utf-8"))}
    )
    run.context.write_json(
        "wheels/approval-v2.json", approval.model_dump(mode="json"), immutable=True
    )
    if verdict != "approved":
        return _write_status(run, state="candidate", wheel_manifest_digest=manifest_v2.digest)
    sign_event, verify_event, actor_roles = learning_registry_signing_context(
        store,
        {
            store.key_for(LearningKeyUsage.WHEEL_PUBLISHER).key_id: Path(
                config["wheel_publisher_key_file"]
            ).resolve(),
            store.key_for(LearningKeyUsage.WHEEL_VALIDATOR).key_id: Path(
                config["wheel_validator_key_file"]
            ).resolve(),
            approver_key_id: key_path.resolve(),
        },
    )
    registry = WheelRegistry(
        ed25519_signature_verifier(
            decode_learning_public_key(store, LearningKeyUsage.WHEEL_APPROVER)
        ),
        context=run.context,
        journal_signer=sign_event,
        journal_verifier=verify_event,
        actor_roles=actor_roles,
        require_signed_journal=True,
    )
    manifest_signature = sign_ed25519(private_key, _signature_payload(legacy_manifest))
    registry.approve(
        legacy_manifest.id,
        legacy_manifest.version,
        approved_by=approver_key_id,
        signature=manifest_signature,
        actor=approver_key_id,
    )
    return _write_status(run, state="approved", wheel_manifest_digest=manifest_v2.digest)


def decode_learning_public_key(store: LearningTrustStoreV1, usage: LearningKeyUsage) -> bytes:
    import base64

    record = store.key_for(usage)
    return base64.urlsafe_b64decode(record.public_key + "=" * (-len(record.public_key) % 4))


def activate_learning_capability(
    config: dict[str, Any],
    *,
    run_id: str,
    key_path: Path,
) -> LearningStatusV1:
    run = open_learning_run(config, run_id)
    _require_learning_state(run.status, "activate")
    _spec, manifest_v2, legacy_manifest, _artifact_root = _load_generated_artifacts(run)
    approval = WheelApprovalV2.model_validate_json(
        run.context.artifact_path("wheels/approval-v2.json").read_bytes()
    )
    if approval.verdict != "approved":
        raise LearningError("learning wheel cannot activate after a rejected approval")
    store = LearningTrustStoreV1.from_file(Path(config["wheel_trust_store"]))
    now = datetime.now(UTC)
    _ensure_absolute_private_key(
        key_path.resolve(),
        forbidden_roots=(Path(__file__).resolve().parents[2], learning_runs_root(config).resolve()),
    )
    operator_key_id, private_key = match_learning_private_key(
        store, LearningKeyUsage.WHEEL_OPERATOR, key_path.resolve(), at=now
    )
    sign_event, verify_event, actor_roles = learning_registry_signing_context(
        store,
        {
            store.key_for(LearningKeyUsage.WHEEL_PUBLISHER).key_id: Path(
                config["wheel_publisher_key_file"]
            ).resolve(),
            store.key_for(LearningKeyUsage.WHEEL_VALIDATOR).key_id: Path(
                config["wheel_validator_key_file"]
            ).resolve(),
            store.key_for(LearningKeyUsage.WHEEL_APPROVER).key_id: key_path.resolve()
            if operator_key_id == store.key_for(LearningKeyUsage.WHEEL_APPROVER).key_id
            else Path(config["wheel_validator_key_file"]).resolve(),
            operator_key_id: key_path.resolve(),
        },
    )
    registry = WheelRegistry(
        ed25519_signature_verifier(
            decode_learning_public_key(store, LearningKeyUsage.WHEEL_APPROVER)
        ),
        context=run.context,
        journal_signer=sign_event,
        journal_verifier=verify_event,
        actor_roles=actor_roles,
        require_signed_journal=True,
    )
    registry.activate(legacy_manifest.id, legacy_manifest.version, actor=operator_key_id)
    activation = WheelActivationReceiptV2(
        run_id=run.context.run_id,
        scope_digest=run.context.scope_digest,
        wheel_manifest_digest=manifest_v2.digest,
        approval_digest=approval.digest,
        operator_key_id=operator_key_id,
        activated_at=now,
        signature="placeholder-signature",
    )
    activation = activation.model_copy(
        update={
            "signature": sign_ed25519(private_key, canonical_digest(activation).encode("utf-8"))
        }
    )
    run.context.write_json(
        "wheels/activation-receipt-v2.json", activation.model_dump(mode="json"), immutable=True
    )
    return _write_status(run, state="active", wheel_manifest_digest=manifest_v2.digest)


def continue_learning_run(config: dict[str, Any], *, run_id: str) -> LearningStatusV1:
    run = open_learning_run(config, run_id)
    _require_learning_state(run.status, "continue")
    spec, manifest_v2, legacy_manifest, artifact_root = _load_generated_artifacts(run)
    activation = WheelActivationReceiptV2.model_validate_json(
        run.context.artifact_path("wheels/activation-receipt-v2.json").read_bytes()
    )
    store = LearningTrustStoreV1.from_file(Path(config["wheel_trust_store"]))
    operator_key_path = Path(config["wheel_operator_key_file"]).resolve()
    _ensure_absolute_private_key(
        operator_key_path,
        forbidden_roots=(Path(__file__).resolve().parents[2], learning_runs_root(config).resolve()),
    )
    sign_event, verify_event, actor_roles = learning_registry_signing_context(
        store,
        {
            store.key_for(LearningKeyUsage.WHEEL_PUBLISHER).key_id: Path(
                config["wheel_publisher_key_file"]
            ).resolve(),
            store.key_for(LearningKeyUsage.WHEEL_VALIDATOR).key_id: Path(
                config["wheel_validator_key_file"]
            ).resolve(),
            store.key_for(LearningKeyUsage.WHEEL_OPERATOR).key_id: operator_key_path,
        },
    )
    operator_actor = store.key_for(LearningKeyUsage.WHEEL_OPERATOR).key_id
    capability_host_actor = "capability-host"
    actor_roles = dict(actor_roles)
    actor_roles[capability_host_actor] = capability_host_actor
    # This module is retained solely for historical artifact/audit compatibility.
    # Its signed journal uses the legacy operator key to persist the fixed host
    # usage event, so replay must recognise that actor as the compatibility host.
    # Formal R2.5 execution is implemented in ``r25_workflow`` with a separate
    # five-duty Wheel V2 trust store and never enters this code path.
    actor_roles[operator_actor] = capability_host_actor

    def usage_sign_event(payload: bytes, actor: str) -> str:
        return cast(
            str,
            sign_event(payload, operator_actor if actor == capability_host_actor else actor),
        )

    def usage_verify_event(payload: bytes, signature: str, actor: str) -> bool:
        return cast(
            bool,
            verify_event(
                payload,
                signature,
                operator_actor if actor == capability_host_actor else actor,
            ),
        )

    registry = WheelRegistry(
        ed25519_signature_verifier(
            decode_learning_public_key(store, LearningKeyUsage.WHEEL_APPROVER)
        ),
        context=run.context,
        journal_signer=usage_sign_event,
        journal_verifier=usage_verify_event,
        actor_roles=actor_roles,
        require_signed_journal=True,
    )
    selector = RuntimeSelector(registry, profile=run_profile_from_spec(spec))
    host = CapabilityHost(
        selector,
        DockerSandbox(str(config["wheel_sandbox_image"])),
        actor=capability_host_actor,
    )
    analysis_text = _read_text_file(run.context.artifact_path("knowledge/input-analysis.json"))
    continuation_context = RunContext(
        run.context.path / "continuations",
        parse_learning_scope(
            json.loads(run.context.artifact_path("scope.json").read_text(encoding="utf-8"))
        ),
    )
    continuation_context.write_json(
        "plan/parent-learning-binding.json",
        {
            "learning_run_id": run.context.run_id,
            "wheel_manifest_digest": manifest_v2.digest,
            "activation_digest": activation.digest,
        },
        immutable=True,
    )
    execution = host.execute(
        legacy_manifest.id,
        legacy_manifest.version,
        artifact_root=artifact_root,
        input_payload={"analysis_text": analysis_text},
        required_capability="parse_response",
    )
    output = execution.output
    observations = tuple(
        ParsedLineObservation.model_validate(item)
        for item in cast(list[dict[str, Any]], output.get("observations", []))
    )
    status = "resolved" if output.get("status") == "matched" and observations else "inconclusive"
    execution_receipt = CapabilityExecutionReceiptV2(
        continuation_run_id=continuation_context.run_id,
        parent_learning_run_id=run.context.run_id,
        scope_digest=continuation_context.scope_digest,
        wheel_manifest_digest=manifest_v2.digest,
        activation_digest=activation.digest,
        input_sha256="sha256:" + sha256(analysis_text.encode("utf-8")).hexdigest(),
        output_sha256=execution.output_sha256,
        outcome=cast(Any, status),
        executed_at=datetime.now(UTC),
    )
    continuation_context.write_json(
        "wheels/execution-receipt-v2.json",
        execution_receipt.model_dump(mode="json"),
        immutable=True,
    )
    outcome = ContinuationOutcomeV1(
        continuation_run_id=continuation_context.run_id,
        parent_learning_run_id=run.context.run_id,
        parent_run_id=run.request.parent_run_id,
        scope_digest=continuation_context.scope_digest,
        wheel_manifest_digest=manifest_v2.digest,
        execution_receipt_digest=execution_receipt.digest,
        status=cast(Any, status),
        observations=observations,
        summary=str(output.get("summary", "continuation completed without a structured summary")),
        produced_at=datetime.now(UTC),
    )
    continuation_context.write_json(
        "report/continuation-outcome-v1.json", outcome.model_dump(mode="json"), immutable=True
    )
    run.context.write_json(
        f"report/continuation-{continuation_context.run_id}.json",
        {"continuation_run_id": continuation_context.run_id, "outcome_digest": outcome.digest},
        immutable=True,
    )
    _write_status(
        run,
        state="continued",
        wheel_manifest_digest=manifest_v2.digest,
        latest_continuation_digest=outcome.digest,
    )
    return open_learning_run(config, run.context.run_id).status


def quarantine_or_revoke_learning_capability(
    config: dict[str, Any],
    *,
    run_id: str,
    key_path: Path,
    reason: str,
    revoke: bool,
) -> LearningStatusV1:
    run = open_learning_run(config, run_id)
    _spec, manifest_v2, legacy_manifest, _artifact_root = _load_generated_artifacts(run)
    store = LearningTrustStoreV1.from_file(Path(config["wheel_trust_store"]))
    now = datetime.now(UTC)
    usage = LearningKeyUsage.WHEEL_REVOKER
    _ensure_absolute_private_key(
        key_path.resolve(),
        forbidden_roots=(Path(__file__).resolve().parents[2], learning_runs_root(config).resolve()),
    )
    revoker_key_id, _private_key = match_learning_private_key(
        store, usage, key_path.resolve(), at=now
    )
    sign_event, verify_event, actor_roles = learning_registry_signing_context(
        store,
        {
            store.key_for(LearningKeyUsage.WHEEL_PUBLISHER).key_id: Path(
                config["wheel_publisher_key_file"]
            ).resolve(),
            store.key_for(LearningKeyUsage.WHEEL_VALIDATOR).key_id: Path(
                config["wheel_validator_key_file"]
            ).resolve(),
            revoker_key_id: key_path.resolve(),
        },
    )
    registry = WheelRegistry(
        ed25519_signature_verifier(
            decode_learning_public_key(store, LearningKeyUsage.WHEEL_APPROVER)
        ),
        context=run.context,
        journal_signer=sign_event,
        journal_verifier=verify_event,
        actor_roles=actor_roles,
        require_signed_journal=True,
    )
    if revoke:
        registry.revoke(
            legacy_manifest.id, legacy_manifest.version, actor=revoker_key_id, reason=reason
        )
        return _write_status(run, state="revoked", wheel_manifest_digest=manifest_v2.digest)
    registry.quarantine(
        legacy_manifest.id, legacy_manifest.version, actor=revoker_key_id, reason=reason
    )
    return _write_status(run, state="quarantined", wheel_manifest_digest=manifest_v2.digest)


def learning_status_payload(config: dict[str, Any], *, run_id: str) -> dict[str, Any]:
    run = open_learning_run(config, run_id)
    payload = run.status.model_dump(mode="json")
    payload["artifacts_root"] = str(run.context.path)
    payload["parent_evidence_id"] = run.request.evidence_ref.evidence_id
    return payload


def validate_learning_config(config: dict[str, Any]) -> dict[str, Any]:
    required = {
        "learn_role_manifests",
        "wheel_trust_store",
        "wheel_publisher_key_file",
        "wheel_validator_key_file",
        "wheel_operator_key_file",
        "wheel_sandbox_image",
        "prompt_root",
        "role_trust_store",
    }
    missing = sorted(name for name in required if name not in config)
    if missing:
        raise LearningError(f"R2.5 config is missing: {', '.join(missing)}")
    trust_store = LearningTrustStoreV1.from_file(Path(config["wheel_trust_store"]))
    trust_store.assert_role_separation()
    PromptRegistryR25(Path(config["prompt_root"]))
    _r25_manifests(Path(config["learn_role_manifests"]))
    for key_name in (
        "wheel_publisher_key_file",
        "wheel_validator_key_file",
        "wheel_operator_key_file",
    ):
        _ensure_absolute_private_key(
            Path(config[key_name]).resolve(),
            forbidden_roots=(
                Path(__file__).resolve().parents[2],
                learning_runs_root(config).resolve(),
            ),
        )
    image = str(config["wheel_sandbox_image"])
    if "@sha256:" not in image or len(image.rsplit("@sha256:", 1)[1]) != 64:
        raise LearningError("wheel sandbox image must be digest-pinned")
    return {
        "learning_prompt_registry": True,
        "learning_role_manifests": True,
        "learning_trust_store": True,
        "learning_wheel_sandbox_image": True,
    }

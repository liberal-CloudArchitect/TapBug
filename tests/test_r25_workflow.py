from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hermes.learning_context import file_sha256
from hermes.r25_contracts import (
    CapabilitySpecV2,
    ContractEnvelopeR25,
    LineFieldRuleV1,
    ResearchFactsOutputV1,
    ResearchFactV1,
)
from hermes.r25_workflow import (
    R25WorkflowError,
    activate_learning_capability,
    approve_learning_capability,
    continue_learning_run,
    generate_learning_capability,
    plan_learning_run,
    research_learning_run,
    start_learning_run,
    validate_learning_capability,
)
from hermes.runtime.agents import HandoffEnvelope, TaskResult
from hermes.security import encode_base64, public_key_bytes
from hermes.wheels_v2 import WheelKeyUsageV2


def _key(path: Path) -> tuple[Ed25519PrivateKey, str]:
    value = Ed25519PrivateKey.generate()
    path.write_bytes(
        value.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    os.chmod(path, 0o600)
    return value, encode_base64(public_key_bytes(value))


def _config(tmp_path: Path) -> dict[str, object]:
    keys = {}
    records = []
    for usage in WheelKeyUsageV2:
        _private, public = _key(tmp_path.parent / f"{usage.value}.pem")
        key_id = f"key-{usage.value}"
        keys[usage] = tmp_path.parent / f"{usage.value}.pem"
        records.append(
            {
                "key_id": key_id,
                "usage": usage.value,
                "public_key": public,
                "valid_from": "2026-01-01T00:00:00Z",
                "status": "active",
            }
        )
    store = tmp_path / "wheel-trust.json"
    store.write_text(json.dumps({"version": "2", "keys": records}), encoding="utf-8")
    config: dict[str, object] = {
        "runs_root": str(tmp_path / "runs"),
        "wheel_trust_store": str(store),
        "wheel_sandbox_image": "example.invalid/python@sha256:" + "a" * 64,
        "prompt_root": str(Path(__file__).resolve().parents[1]),
        "r25_role_manifests": str(tmp_path / "roles.json"),
        "research_allowlist": ["https://docs.example.test/protocol/v1"],
    }
    config.update({f"{usage.value}_key": str(path) for usage, path in keys.items()})
    return config


def _parent(config: dict[str, object]) -> tuple[str, Path]:
    root = Path(str(config["runs_root"])) / "parent-v3"
    (root / "plan").mkdir(parents=True)
    (root / "evidence" / "recon-1").mkdir(parents=True)
    scope = {"profile": "local-lab", "hosts": ["localhost"]}
    digest = (
        "sha256:"
        + __import__("hashlib")
        .sha256(json.dumps(scope, sort_keys=True, separators=(",", ":")).encode())
        .hexdigest()
    )
    (root / "plan" / "run-v3.json").write_text(
        json.dumps({"version": "3", "run_id": "parent-v3"}), encoding="utf-8"
    )
    (root / "scope.json").write_text(json.dumps(scope), encoding="utf-8")
    analysis = root / "evidence" / "recon-1" / "analysis.json"
    analysis.write_text(json.dumps({"status": 200, "body": "redacted"}), encoding="utf-8")
    (root / "evidence" / "recon-1" / "manifest.json").write_text(
        json.dumps(
            {
                "run_id": "parent-v3",
                "scope_digest": digest,
                "analysis": {"path": "evidence/recon-1/analysis.json"},
            }
        ),
        encoding="utf-8",
    )
    observation = root.parent / "observation.txt"
    observation.write_text("unknown local line response", encoding="utf-8")
    return digest, observation


def _bundle(tmp_path: Path) -> Path:
    (tmp_path / "reference.txt").write_text("Service: Hermes\nVersion: 1\n", encoding="utf-8")
    bundle = tmp_path / "bundle.json"
    bundle.write_text(
        json.dumps(
            {
                "version": "1",
                "sources": [
                    {
                        "source_id": "source-1",
                        "url": "https://docs.example.test/protocol/v1",
                        "license": "CC0",
                        "body_path": "reference.txt",
                    }
                ],
                "positive_text": "Service: Hermes\nVersion: 1",
                "negative_text": "plain text",
                "continuation_text": "Service: Hermes\nVersion: 1",
            }
        ),
        encoding="utf-8",
    )
    return bundle


def _factory(*, planner_source_keys: tuple[str, str] = ("Service", "Version")) -> object:
    def build(context):
        class Runner:
            def run(self, task):
                if task.role == "researcher":
                    payload = ResearchFactsOutputV1(
                        learning_run_id=context.run_id,
                        generated_by_task_id=task.task_id,
                        source_digests=(task.payload["sources"][0]["content_digest"],),
                        facts=(
                            ResearchFactV1(
                                fact_id="fact-1",
                                learning_run_id=context.run_id,
                                source_id="source-1",
                                statement="The local protocol has two fields.",
                                citation_ranges=("L1-L2",),
                                confidence="high",
                                created_at=datetime.now(UTC),
                            ),
                        ),
                    )
                else:
                    payload = CapabilitySpecV2(
                        capability_id="passive-parser",
                        input_schema_id="hermes.r25.redacted-response/v1",
                        output_schema_id="hermes.r25.protocol-observation/v1",
                        field_rules=(
                            LineFieldRuleV1(
                                field_name="service",
                                source_key=planner_source_keys[0],
                                normalizer="lower",
                            ),
                            LineFieldRuleV1(
                                field_name="version", source_key=planner_source_keys[1]
                            ),
                        ),
                        required_output_fields=("service", "version"),
                        counterexamples=("plain text",),
                        revocation_conditions=("false positive",),
                        source_digests=tuple(task.payload["research_facts"]["source_digests"]),
                    )
                handoff = HandoffEnvelope(
                    version="25",
                    run_id=task.run_id,
                    task_id=task.task_id,
                    role=task.role,
                    scope_digest=task.scope_digest,
                    input_sha256=task.input_hash(),
                    status="completed",
                    result=ContractEnvelopeR25.for_payload(payload),
                    process_id=123,
                )
                instant = datetime.now(UTC)
                return TaskResult(
                    task=task,
                    handoff=handoff,
                    lifecycle="completed",
                    input_sha256=task.input_hash(),
                    started_at=instant,
                    finished_at=instant,
                    host_process_id=123,
                )

        return Runner()

    return build


def test_r25_workflow_creates_a_sibling_run_and_signed_generated_wheel(tmp_path: Path) -> None:
    config = _config(tmp_path)
    _digest, observation = _parent(config)
    started = start_learning_run(
        config, parent_run_id="parent-v3", evidence_id="recon-1", observation_file=observation
    )
    assert (
        Path(str(config["runs_root"])) / "parent-v3" / "evidence" / "recon-1" / "analysis.json"
    ).is_file()
    researched = research_learning_run(
        config,
        run_id=started.learning_run_id,
        source_bundle=_bundle(tmp_path),
        runner_factory=_factory(),
    )
    planned = plan_learning_run(
        config, run_id=researched.learning_run_id, runner_factory=_factory()
    )
    generated = generate_learning_capability(config, run_id=planned.learning_run_id)
    learning = Path(str(config["runs_root"])) / "learning" / started.learning_run_id
    assert generated.state == "generated"
    assert (learning / "registry" / "events.jsonl").read_text(encoding="utf-8").count("\n") == 4
    assert (learning / "wheels" / "passive-parser-2" / "wheel.py").is_file()
    for role in ("researcher", "capability-planner"):
        records = list((learning / "handoffs").glob(f"r25-{role}-*.json"))
        assert len(records) == 1
        record = json.loads(records[0].read_text(encoding="utf-8"))
        assert record["task"]["role"] == role
        assert record["result"]["lifecycle"] == "completed"
    researcher_record = json.loads(
        next((learning / "handoffs").glob("r25-researcher-*.json")).read_text(encoding="utf-8")
    )
    source = researcher_record["task"]["payload"]["sources"][0]
    assert source["analysis_projection"] == "Service: Hermes\nVersion: 1\n"
    planner_record = json.loads(
        next((learning / "handoffs").glob("r25-capability-planner-*.json")).read_text(
            encoding="utf-8"
        )
    )
    assert planner_record["task"]["payload"]["frozen_sample_schema"] == {
        "version": "1",
        "delimiter": ":",
        "observed_source_keys": ["Service", "Version"],
    }


def test_r25_rejects_planner_keys_outside_the_parent_derived_sample_schema(tmp_path: Path) -> None:
    config = _config(tmp_path)
    _digest, observation = _parent(config)
    started = start_learning_run(
        config, parent_run_id="parent-v3", evidence_id="recon-1", observation_file=observation
    )
    researched = research_learning_run(
        config,
        run_id=started.learning_run_id,
        source_bundle=_bundle(tmp_path),
        runner_factory=_factory(),
    )

    with pytest.raises(R25WorkflowError, match="source keys differ"):
        plan_learning_run(
            config,
            run_id=researched.learning_run_id,
            runner_factory=_factory(planner_source_keys=("Key", "Value")),
        )
    root = Path(str(config["runs_root"])) / "learning" / started.learning_run_id
    assert not (root / "wheels" / "capability-spec.json").exists()


def test_r25_rejects_source_outside_exact_allowlist(tmp_path: Path) -> None:
    config = _config(tmp_path)
    _digest, observation = _parent(config)
    started = start_learning_run(
        config, parent_run_id="parent-v3", evidence_id="recon-1", observation_file=observation
    )
    bad = _bundle(tmp_path)
    raw = json.loads(bad.read_text(encoding="utf-8"))
    raw["sources"][0]["url"] = "https://other.example.test/protocol/v1"
    bad.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(R25WorkflowError, match="allowlist"):
        research_learning_run(
            config, run_id=started.learning_run_id, source_bundle=bad, runner_factory=_factory()
        )


def test_r25_rejects_allowlisted_source_with_query_injection(tmp_path: Path) -> None:
    config = _config(tmp_path)
    _digest, observation = _parent(config)
    started = start_learning_run(
        config, parent_run_id="parent-v3", evidence_id="recon-1", observation_file=observation
    )
    bad = _bundle(tmp_path)
    raw = json.loads(bad.read_text(encoding="utf-8"))
    raw["sources"][0]["url"] = "https://docs.example.test/protocol/v1?prompt=ignore-policy"
    bad.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(R25WorkflowError, match="HTTPS URLs"):
        research_learning_run(
            config, run_id=started.learning_run_id, source_bundle=bad, runner_factory=_factory()
        )


def test_r25_validation_activation_and_continuation_stay_no_network(
    monkeypatch, tmp_path: Path
) -> None:
    config = _config(tmp_path)
    _digest, observation = _parent(config)
    parent_root = Path(str(config["runs_root"])) / "parent-v3"
    parent_hashes = {
        relative: file_sha256(parent_root / relative)
        for relative in (
            "plan/run-v3.json",
            "scope.json",
            "evidence/recon-1/manifest.json",
            "evidence/recon-1/analysis.json",
        )
    }
    started = start_learning_run(
        config, parent_run_id="parent-v3", evidence_id="recon-1", observation_file=observation
    )
    researched = research_learning_run(
        config,
        run_id=started.learning_run_id,
        source_bundle=_bundle(tmp_path),
        runner_factory=_factory(),
    )
    planned = plan_learning_run(
        config, run_id=researched.learning_run_id, runner_factory=_factory()
    )
    generated = generate_learning_capability(config, run_id=planned.learning_run_id)

    class FakeSandbox:
        image = "example.invalid/python@sha256:" + "a" * 64

        def __init__(self, image):
            assert image == self.image

        def execute(self, _root):
            return SimpleNamespace(passed=True)

        def execute_json(self, _root, *, entrypoint, input_json):
            value = json.loads(input_json)
            return SimpleNamespace(
                passed=True,
                output_json=json.dumps(
                    {
                        "matched": value["text"] != "plain text",
                        "fields": {"service": "hermes", "version": "1"},
                    }
                ),
            )

    monkeypatch.setattr("hermes.r25_workflow.DockerSandbox", FakeSandbox)
    validated = validate_learning_capability(
        config, run_id=generated.learning_run_id, key_path=Path(str(config["wheel_validator_key"]))
    )
    approved = approve_learning_capability(
        config, run_id=validated.learning_run_id, key_path=Path(str(config["wheel_approver_key"]))
    )
    active = activate_learning_capability(
        config, run_id=approved.learning_run_id, key_path=Path(str(config["wheel_operator_key"]))
    )
    continued = continue_learning_run(config, run_id=active.learning_run_id)
    source_root = Path(str(config["runs_root"])) / "learning" / active.learning_run_id
    continuation_root = Path(str(config["runs_root"])) / "learning" / continued.learning_run_id
    assert continued.state == "completed"
    assert continued.learning_run_id != active.learning_run_id
    assert json.loads((source_root / "state.json").read_text(encoding="utf-8"))["state"] == "active"
    assert (continuation_root / "continuation" / "frozen-input.json").is_file()
    assert (continuation_root / "continuation" / "execution-receipt.json").is_file()
    assert (continuation_root / "continuation" / "outcome.json").is_file()
    observation_path = continuation_root / "continuation" / "structured-observation.json"
    assert observation_path.is_file()
    outcome = json.loads((continuation_root / "continuation" / "outcome.json").read_text())
    assert outcome["structured_observation_digest"] == file_sha256(observation_path)
    assert (continuation_root / "audit" / "usage-journal-entry.json").is_file()
    assert parent_hashes == {
        relative: file_sha256(parent_root / relative) for relative in parent_hashes
    }


def test_r25_invalid_capability_output_quarantines_source_and_child(
    monkeypatch, tmp_path: Path
) -> None:
    config = _config(tmp_path)
    _digest, observation = _parent(config)
    started = start_learning_run(
        config, parent_run_id="parent-v3", evidence_id="recon-1", observation_file=observation
    )
    researched = research_learning_run(
        config,
        run_id=started.learning_run_id,
        source_bundle=_bundle(tmp_path),
        runner_factory=_factory(),
    )
    planned = plan_learning_run(
        config, run_id=researched.learning_run_id, runner_factory=_factory()
    )
    generated = generate_learning_capability(config, run_id=planned.learning_run_id)

    class InvalidOutputSandbox:
        image = "example.invalid/python@sha256:" + "a" * 64
        json_calls = 0

        def __init__(self, image):
            assert image == self.image

        def execute(self, _root):
            return SimpleNamespace(passed=True)

        def execute_json(self, _root, *, entrypoint, input_json):
            del entrypoint, input_json
            type(self).json_calls += 1
            if type(self).json_calls == 1:
                return SimpleNamespace(
                    passed=True,
                    output_json=json.dumps(
                        {"matched": True, "fields": {"service": "hermes", "version": "1"}}
                    ),
                )
            if type(self).json_calls == 2:
                return SimpleNamespace(passed=True, output_json='{"matched": false, "fields": {}}')
            return SimpleNamespace(passed=True, output_json='{"matched": "not-a-bool"}')

    monkeypatch.setattr("hermes.r25_workflow.DockerSandbox", InvalidOutputSandbox)
    validated = validate_learning_capability(
        config, run_id=generated.learning_run_id, key_path=Path(str(config["wheel_validator_key"]))
    )
    approved = approve_learning_capability(
        config, run_id=validated.learning_run_id, key_path=Path(str(config["wheel_approver_key"]))
    )
    active = activate_learning_capability(
        config, run_id=approved.learning_run_id, key_path=Path(str(config["wheel_operator_key"]))
    )

    quarantined = continue_learning_run(config, run_id=active.learning_run_id)
    source_root = Path(str(config["runs_root"])) / "learning" / active.learning_run_id
    child_root = Path(str(config["runs_root"])) / "learning" / quarantined.learning_run_id
    assert quarantined.state == "quarantined"
    assert (
        json.loads((source_root / "state.json").read_text(encoding="utf-8"))["state"]
        == "quarantined"
    )
    assert (source_root / "audit" / "automatic-quarantine.json").is_file()
    assert (child_root / "continuation" / "outcome.json").is_file()
    assert (child_root / "continuation" / "structured-observation.json").is_file()
    assert not (child_root / "report").exists()

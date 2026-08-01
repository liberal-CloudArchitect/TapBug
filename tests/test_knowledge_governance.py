from __future__ import annotations

import hashlib
import subprocess

import pytest

from hermes.knowledge import (
    CapabilityPlanner,
    GatewayResearcher,
    KnowledgeBroker,
    ProblemCardStatus,
    ResearchFact,
    ResearchPolicy,
    WheelGenerator,
)
from hermes.wheels import DockerSandbox, WheelKind, WheelValidator


def _fact(broker: KnowledgeBroker) -> ResearchFact:
    source = broker.record_gateway_source(
        "https://docs.example.test/spec/v1",
        "offline parser rules",
        policy=ResearchPolicy(allowed_hosts=frozenset({"docs.example.test"})),
        license="CC-BY-4.0",
    )
    return ResearchFact(claim="Parse JSON only.", source=source, confidence="high")


def test_gateway_research_preflights_before_it_makes_a_request(tmp_path) -> None:
    class UnexpectedGateway:
        def request(self, method: str, url: str) -> tuple[object, object]:
            raise AssertionError("gateway must not be reached for a rejected source")

    researcher = GatewayResearcher(
        UnexpectedGateway(),
        KnowledgeBroker(tmp_path),
        ResearchPolicy(allowed_hosts=frozenset({"docs.example.test"})),
    )
    with pytest.raises(ValueError, match="allowlist"):
        researcher.fetch("https://other.example.test/spec", license="CC-BY-4.0")


def test_broker_stores_content_addressed_sources_and_fails_closed_on_corruption(tmp_path) -> None:
    broker = KnowledgeBroker(tmp_path)
    fact = _fact(broker)
    source_blob = tmp_path / "blobs" / f"{fact.source.content_sha256}.blob"
    assert source_blob.read_text(encoding="utf-8") == "offline parser rules"

    broker.store_fact(fact)
    next((tmp_path / "facts").glob("*.json")).write_text("not json", encoding="utf-8")
    with pytest.raises(ValueError, match="corrupt"):
        broker.list_facts()


def test_problem_cards_deduplicate_and_remain_in_human_spec_state(tmp_path) -> None:
    broker = KnowledgeBroker(tmp_path)
    card = broker.create_problem_card(
        observation="Unexpected content type from passive fixture",
        scope_digest="sha256:" + "a" * 64,
        profile="recon-only",
        evidence_refs=("sha256:" + "b" * 64,),
        risk_level="low",
        status=ProblemCardStatus.REQUIRES_HUMAN_SPEC,
    )
    same_card = broker.create_problem_card(
        observation="Unexpected content type from passive fixture",
        scope_digest="sha256:" + "a" * 64,
        profile="recon-only",
        evidence_refs=("sha256:" + "b" * 64,),
        risk_level="low",
        status=ProblemCardStatus.REQUIRES_HUMAN_SPEC,
    )
    assert same_card.id == card.id
    assert broker.get_problem_card(card.id).status is ProblemCardStatus.REQUIRES_HUMAN_SPEC


@pytest.mark.parametrize("kind", list(WheelKind))
def test_generator_emits_deterministic_declarative_artifacts_for_every_allowed_kind(
    tmp_path, kind: WheelKind
) -> None:
    broker = KnowledgeBroker(tmp_path / "knowledge")
    spec = CapabilityPlanner().plan(
        wheel_id=f"{kind.value.replace('_', '-')}-cap",
        kind=kind,
        facts=[_fact(broker)],
        input_schema="input.json",
        output_schema="output.json",
    )
    generated = WheelGenerator().generate(spec, tmp_path / "artifacts")
    assert (generated.root / "capability-spec.json").exists()
    assert (generated.root / "SBOM.spdx.json").exists()
    assert (generated.root / "requirements.lock").exists()
    assert (generated.root / "wheel-manifest.json").exists()
    assert len(list((generated.root / "dist").glob("*.whl"))) == 1
    assert WheelValidator().validate(generated.manifest, generated.root).passed


def test_validator_rejects_symlink_escape_and_reflection(tmp_path) -> None:
    root = tmp_path / "artifact"
    (root / "tests").mkdir(parents=True)
    (root / "wheel.py").write_text("value = getattr(object, '__class__')\n", encoding="utf-8")
    (root / "tests" / "test_wheel.py").write_text("assert True\n", encoding="utf-8")
    broker = KnowledgeBroker(tmp_path / "knowledge")
    spec = CapabilityPlanner().plan(
        wheel_id="reflection-test",
        kind=WheelKind.PASSIVE_PARSER,
        facts=[_fact(broker)],
        input_schema="input.json",
        output_schema="output.json",
    )
    generated = WheelGenerator().generate(spec, tmp_path / "generated")
    manifest = generated.manifest.model_copy(
        update={"tests": ("../outside.py",), "artifact_sha256": "sha256:" + "0" * 64}
    )
    report = WheelValidator().validate(manifest, root)
    assert not report.passed
    assert any("escapes artifact root" in violation for violation in report.violations)
    assert any("reflection" in violation for violation in report.violations)


def test_docker_execution_fails_closed_when_daemon_is_unavailable(tmp_path, monkeypatch) -> None:
    root = tmp_path / "artifact"
    root.mkdir()
    monkeypatch.setattr("hermes.wheels.sandbox.shutil.which", lambda _: None)
    result = DockerSandbox().execute(root)
    assert not result.passed
    assert result.failure_reason == "docker CLI is unavailable"
    assert result.stdout_sha256 == "sha256:" + hashlib.sha256(b"").hexdigest()


def test_docker_json_host_uses_fixed_isolated_protocol(tmp_path, monkeypatch) -> None:
    root = tmp_path / "artifact"
    root.mkdir()
    monkeypatch.setattr("hermes.wheels.sandbox.shutil.which", lambda _: "docker")
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["input"] = kwargs["input"]
        return subprocess.CompletedProcess(command, 0, b'{"ok":true}', b"")

    monkeypatch.setattr("hermes.wheels.sandbox.subprocess.run", fake_run)
    result = DockerSandbox().execute_json(
        root, entrypoint="wheel:parse_response", input_json='{"value":"fixture"}'
    )

    assert result.passed
    assert result.output_json == '{"ok":true}'
    assert captured["input"] == b'{"value":"fixture"}'
    assert ("--network", "none") == captured["command"][
        captured["command"].index("--network") : captured["command"].index("--network") + 2
    ]

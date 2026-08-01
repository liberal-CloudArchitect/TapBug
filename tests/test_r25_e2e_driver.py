from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


def _driver_module():
    path = Path(__file__).resolve().parents[1] / "scripts" / "run_r25_e2e.py"
    spec = importlib.util.spec_from_file_location("r25_e2e_driver", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_executable_path_preserves_virtualenv_symlink(tmp_path: Path) -> None:
    target = tmp_path / "base-python"
    target.write_text("runtime", encoding="utf-8")
    virtualenv_python = tmp_path / "venv" / "bin" / "python"
    virtualenv_python.parent.mkdir(parents=True)
    virtualenv_python.symlink_to(target)

    actual = _driver_module().executable_path(virtualenv_python)

    assert actual == virtualenv_python.absolute()
    assert actual != target.resolve()


def test_wheel_sandbox_gate_requires_every_non_bypassable_docker_control() -> None:
    driver = _driver_module()
    command = (
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--user",
        "65534:65534",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--volume",
        "/tmp/generated:/wheel:ro",
    )

    driver._assert_sandbox_command(command)

    with pytest.raises(driver.E2EFailure, match="omitted --network"):
        driver._assert_sandbox_command(tuple(item for item in command if item != "--network"))


def test_registry_gate_reads_active_lifecycle_from_append_only_record() -> None:
    driver = _driver_module()
    manifest = SimpleNamespace(
        wheel_id="line-kv-passive",
        manifest_version="2.0.0",
        artifact_digest="sha256:artifact",
        digest="sha256:manifest",
        # A WheelManifest intentionally retains its immutable draft descriptor.
        lifecycle="draft",
    )

    class Registry:
        events = tuple(range(8))

        def select_active(self, *_args, **_kwargs):
            return manifest

        def get(self, *_args):
            return SimpleNamespace(lifecycle="active")

    driver._assert_active_registry_lifecycle(Registry(), manifest)


def test_completed_artifact_replay_writes_a_summary_without_model_calls(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    driver = _driver_module()
    root = tmp_path / "real-e2e"
    runs = root / "runs"
    parent = runs / "frozen-parent-v3"
    source = runs / "learning" / "source"
    child = runs / "learning" / "child"
    for relative in (
        "plan/run-v3.json",
        "scope.json",
        "state.json",
        "evidence/recon-local-line/analysis.json",
        "evidence/recon-local-line/manifest.json",
    ):
        path = parent / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}", encoding="utf-8")
    (source / "state.json").parent.mkdir(parents=True)
    (child / "plan").mkdir(parents=True)
    (source / "state.json").write_text('{"state":"active"}', encoding="utf-8")
    (child / "state.json").write_text('{"state":"completed"}', encoding="utf-8")
    (child / "plan" / "continuation-parent-binding.json").write_text(
        '{"source_learning_run_id":"source"}', encoding="utf-8"
    )
    (root / "r25-config.json").write_text(
        json.dumps({"wheel_sandbox_image": "wheel@sha256:test", "model": "test-model"}),
        encoding="utf-8",
    )
    observed: dict[str, object] = {}

    def fake_verify(**kwargs: object) -> dict[str, object]:
        observed.update(kwargs)
        return {"positive_matched": True, "wheel_network_requests": 0}

    monkeypatch.setattr(driver, "verify_learning_run", fake_verify)

    result = driver.replay_completed_artifact(root)

    assert result["mode"] == "artifact_replay"
    assert observed["learning_run_id"] == "source"
    assert observed["continuation_run_id"] == "child"
    assert observed["model"] == "test-model"
    assert json.loads((root / "replay-summary.json").read_text()) == result


def test_acceptance_refuses_to_trust_a_continuation_without_real_parent_and_role_artifacts(
    tmp_path: Path,
) -> None:
    driver = _driver_module()

    with pytest.raises(driver.E2EFailure, match="distinct child run"):
        driver.verify_learning_run(
            runs_root=tmp_path / "runs",
            learning_run_id="source",
            continuation_run_id="child",
            parent_hashes={},
            wheel_sandbox_image="example.test/python@sha256:" + "a" * 64,
            model="test-model",
        )


def test_driver_requires_a_digest_pinned_default_base() -> None:
    driver = _driver_module()

    assert driver.DEFAULT_BASE.startswith("python:3.11-slim@sha256:")
    assert set(driver.WHEEL_CHECKS) == {
        "--network",
        "--read-only",
        "--user",
        "--cap-drop",
        "--security-opt",
    }

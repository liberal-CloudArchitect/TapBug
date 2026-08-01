from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest


def _driver_module() -> ModuleType:
    path = Path(__file__).resolve().parents[1] / "scripts" / "run_phase4_resilience_e2e.py"
    spec = importlib.util.spec_from_file_location("phase4_resilience_e2e_driver", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_resilience_driver_exposes_the_four_hard_gates() -> None:
    driver = _driver_module()

    assert set(driver.TAMPER_TARGETS) == {
        "route",
        "dedup_provenance",
        "cross_review",
        "approval",
        "consumption",
        "evidence",
        "action_ledger",
        "budget_ledger",
        "coverage",
        "human_signature",
        "reporter_receipt",
        "reporter_ack",
    }
    parsed = driver.parser().parse_args(
        ["--hermes-cli", "/tmp/hermes", "--hermes-python", "/tmp/python", "--model", "lab"]
    )
    assert parsed.scenario == "all"
    assert parsed.source_run is None


def test_fault_module_is_test_only_and_contains_no_network_or_shell_escape() -> None:
    driver = _driver_module()
    hook = driver._fault_sitecustomize()

    assert "api-assessment-failure" in hook
    assert "crash-after-mutation" in hook
    assert "cleanup-failure" in hook
    assert "os.kill" in hook
    assert "subprocess" not in hook
    assert "socket" not in hook
    assert "requests" not in hook


def test_tamper_targets_choose_real_leaf_artifacts(tmp_path: Path) -> None:
    driver = _driver_module()
    evidence = tmp_path / "evidence" / "one"
    evidence.mkdir(parents=True)
    (evidence / "manifest.json").write_text('{"value":"original"}\n', encoding="utf-8")
    consumption = tmp_path / "approvals_v3" / "consumptions"
    consumption.mkdir(parents=True)
    (consumption / "one.json").write_text('{"value":"original"}\n', encoding="utf-8")

    assert driver._target_file(tmp_path, "evidence") == evidence / "manifest.json"
    assert driver._target_file(tmp_path, "consumption") == consumption / "one.json"


def test_mutate_file_changes_valid_json_without_rendering_it_invalid(tmp_path: Path) -> None:
    driver = _driver_module()
    artifact = tmp_path / "artifact.json"
    artifact.write_text('{"nested":{"value":"original"}}\n', encoding="utf-8")

    driver._mutate_file(artifact)

    assert "tampered" in artifact.read_text(encoding="utf-8")


def test_missing_tamper_artifact_fails_closed(tmp_path: Path) -> None:
    driver = _driver_module()

    with pytest.raises(driver.E2EFailure, match="tamper target is missing"):
        driver._target_file(tmp_path, "route")

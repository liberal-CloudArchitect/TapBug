from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


def _driver_module():
    path = Path(__file__).resolve().parents[1] / "scripts" / "run_phase4_e2e.py"
    spec = importlib.util.spec_from_file_location("phase4_e2e_driver", path)
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


def test_expected_fixture_campaign_is_exactly_fifteen_requests() -> None:
    driver = _driver_module()

    assert sum(driver.EXPECTED_FIXTURE_REQUESTS.values()) == 15
    assert driver.EXPECTED_FIXTURE_REQUESTS["/candidate"] == 2
    assert driver.EXPECTED_FIXTURE_REQUESTS["/graphql"] == 2
    assert driver.EXPECTED_FIXTURE_REQUESTS["/authz/status"] == 2


def test_approval_scenarios_preserve_the_fixed_v3_budget_boundaries() -> None:
    driver = _driver_module()

    assert driver._SCENARIO_DECISIONS["accepted-full"] == (
        ("readonly", "approve"),
        ("mutation", "approve"),
    )
    assert driver._SCENARIO_DECISIONS["web-infra"] == (("readonly", "approve"),)
    assert driver._SCENARIO_EXPECTATIONS["web-infra"]["tasks"] == 10
    assert driver._SCENARIO_EXPECTATIONS["web-infra"]["requests"] == 5
    assert driver._SCENARIO_EXPECTATIONS["mutation-rejected"]["requests"] == 5
    assert driver._SCENARIO_EXPECTATIONS["readonly-rejected"]["requests"] == 11
    assert driver._SCENARIO_EXPECTATIONS["all-rejected"]["requests"] == 1
    assert driver._SCENARIO_EXPECTATIONS["all-rejected"]["report"] is False


def test_offline_acceptance_fails_before_trusting_incomplete_run(tmp_path: Path) -> None:
    driver = _driver_module()
    run_root = tmp_path / "runs" / "run-v3"
    run_root.mkdir(parents=True)
    (run_root / "state.json").write_text(
        '{"version":"3","execution_state":"completed","requests_used":15,"requests_planned":15}\n',
        encoding="utf-8",
    )

    with pytest.raises(driver.E2EFailure, match="expected 16 agent tasks"):
        driver.verify_accepted_run(
            run_root,
            fixture_stats={
                "requests": {},
                "state_hash": "sha256:" + "a" * 64,
                "max_active": 0,
            },
            initial_state_hash="sha256:" + "a" * 64,
        )

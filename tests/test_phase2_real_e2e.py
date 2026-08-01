"""Acceptance of a real pre-executed Phase 2 run; fixture runners are not allowed."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from hermes.acceptance import verify_phase2_rejected_run, verify_phase2_run
from hermes.cli import _config
from hermes.prompts import PromptRegistry
from hermes.runtime import RunContext
from hermes.runtime.agents import RoleTrustStore
from hermes.security import TrustStoreV2


@pytest.mark.provider_e2e
def test_real_docker_acp_vertical_run() -> None:
    raw = os.environ.get("HERMES_PHASE2_RUN_DIR")
    config_raw = os.environ.get("HERMES_PHASE2_CONFIG")
    if not raw:
        if os.environ.get("HERMES_REQUIRE_PHASE2_E2E") == "1":
            pytest.fail("HERMES_PHASE2_RUN_DIR is required by the Phase 2 completion gate")
        pytest.skip("set HERMES_PHASE2_RUN_DIR to a completed real Docker+ACP run")
    if not config_raw:
        pytest.fail("HERMES_PHASE2_CONFIG is required with the completed run")
    run_dir = Path(raw).resolve()
    config = _config(Path(config_raw))
    scope = json.loads((run_dir / "scope.json").read_text(encoding="utf-8"))
    context = RunContext.open_existing(run_dir.parent, scope, run_dir.name)

    result = verify_phase2_run(
        context,
        publisher_store=RoleTrustStore.from_file(Path(config["role_trust_store"])),
        approval_store=TrustStoreV2.from_file(Path(config["approval_trust_store"])),
        review_store=TrustStoreV2.from_file(Path(config["review_trust_store"])),
        prompt_registry=PromptRegistry(Path(config["prompt_root"])),
    )

    assert result["roles"] == result["containers"] == result["acp_sessions"] == 6
    assert result["http_evidence"] == 3
    assert result["approval_consumptions"] == 2


@pytest.mark.provider_e2e
def test_real_docker_acp_reject_run() -> None:
    raw = os.environ.get("HERMES_PHASE2_REJECT_RUN_DIR")
    config_raw = os.environ.get("HERMES_PHASE2_CONFIG")
    if not raw:
        if os.environ.get("HERMES_REQUIRE_PHASE2_E2E") == "1":
            pytest.fail("HERMES_PHASE2_REJECT_RUN_DIR is required by the Phase 2 completion gate")
        pytest.skip("set HERMES_PHASE2_REJECT_RUN_DIR to a rejected real Docker+ACP run")
    if not config_raw:
        pytest.fail("HERMES_PHASE2_CONFIG is required with the rejected run")
    run_dir = Path(raw).resolve()
    config = _config(Path(config_raw))
    scope = json.loads((run_dir / "scope.json").read_text(encoding="utf-8"))
    context = RunContext.open_existing(run_dir.parent, scope, run_dir.name)

    result = verify_phase2_rejected_run(
        context,
        approval_store=TrustStoreV2.from_file(Path(config["approval_trust_store"])),
    )

    assert result["state"] == "rejected"
    assert result["http_evidence"] == 1

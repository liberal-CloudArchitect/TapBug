"""Real Docker boundary check; CI must supply its reviewed immutable image."""

from __future__ import annotations

import os

import pytest

from hermes.wheels import DockerSandbox


@pytest.mark.integration
def test_candidate_fixture_executes_in_real_no_network_docker_boundary(tmp_path) -> None:
    image = os.environ.get("HERMES_SANDBOX_IMAGE")
    if not image:
        if os.environ.get("CI"):
            pytest.fail("CI requires a reviewed HERMES_SANDBOX_IMAGE image@sha256 digest")
        pytest.skip("set HERMES_SANDBOX_IMAGE to run the real Docker sandbox integration")
    root = tmp_path / "wheel"
    (root / "tests").mkdir(parents=True)
    (root / "wheel.py").write_text("def parse(value): return value\n", encoding="utf-8")
    (root / "tests" / "test_wheel.py").write_text(
        "def test_fixture(): assert True\n", encoding="utf-8"
    )

    result = DockerSandbox(image).execute(root)

    assert result.passed, result.stderr_preview
    assert "--network" in result.command
    assert result.command[result.command.index("--network") + 1] == "none"

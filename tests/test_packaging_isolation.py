from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_main_distribution_packages_only_src_hermes() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

    assert 'packages = ["src/hermes"]' in pyproject
    assert 'hermes-security = "hermes.cli:main"' in pyproject
    assert '\nhermes = "hermes.' not in pyproject
    assert "extensions/hermes_ctf_lab" not in pyproject
    assert not (ROOT / "hermes").exists()


def test_ctf_and_dynamic_attack_modules_are_not_in_main_package() -> None:
    prohibited = {
        "ctf.py",
        "exploit_agent.py",
        "synth.py",
        "pwn.py",
        "crypto.py",
        "solve.py",
        "meta.py",
        "outcome.py",
        "research.py",
        "bintriage.py",
        "skills.py",
    }
    shipped = {path.name for path in (ROOT / "src" / "hermes").glob("*.py")}

    assert prohibited.isdisjoint(shipped)
    assert all(
        (ROOT / "extensions" / "hermes_ctf_lab" / "src" / "hermes_ctf_lab" / name).exists()
        for name in prohibited
    )
    assert not (ROOT / "src" / "hermes" / "benchmarks").exists()
    assert (
        ROOT / "extensions" / "hermes_ctf_lab" / "src" / "hermes_ctf_lab" / "benchmarks"
    ).is_dir()
    assert not (ROOT / "labs").exists()
    assert not (ROOT / "bench").exists()
    assert (ROOT / "extensions" / "hermes_ctf_lab" / "labs").is_dir()
    assert (ROOT / "extensions" / "hermes_ctf_lab" / "bench-results").is_dir()


def test_ctf_extension_is_not_importable_from_default_source_layout() -> None:
    assert importlib.util.find_spec("hermes_ctf_lab") is None

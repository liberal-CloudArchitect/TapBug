from __future__ import annotations

import importlib.util
from pathlib import Path


def _driver_module():
    path = Path(__file__).resolve().parents[1] / "scripts" / "run_phase2_e2e.py"
    spec = importlib.util.spec_from_file_location("phase2_e2e_driver", path)
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

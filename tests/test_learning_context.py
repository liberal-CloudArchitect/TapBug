from __future__ import annotations

import pytest

from hermes.learning_context import LearningContext, file_sha256


def test_learning_context_is_a_sibling_of_assessment_runs_and_is_immutable(tmp_path) -> None:
    context = LearningContext(tmp_path / "runs", run_id="learning-a")

    assert context.path == tmp_path / "runs" / "learning" / "learning-a"
    artifact = context.write_json("plan/request.json", {"value": "one"}, immutable=True)
    assert file_sha256(artifact).startswith("sha256:")
    with pytest.raises(FileExistsError):
        context.write_json("plan/request.json", {"value": "two"}, immutable=True)

    reopened = LearningContext.open_existing(tmp_path / "runs", "learning-a")
    assert reopened.path == context.path


def test_learning_context_rejects_path_escape_and_bad_run_ids(tmp_path) -> None:
    with pytest.raises(ValueError):
        LearningContext(tmp_path, run_id="../escape")

    context = LearningContext(tmp_path, run_id="learning-b")
    with pytest.raises(ValueError):
        context.write_json("../assessment/state.json", {"bad": True})

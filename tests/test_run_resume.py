from __future__ import annotations

import threading

import pytest

from hermes.runtime import RunContext


def test_open_existing_requires_the_original_immutable_scope(tmp_path) -> None:
    context = RunContext(tmp_path / "runs", {"scope": "fixture"}, run_id="resume-run")

    resumed = RunContext.open_existing(tmp_path / "runs", {"scope": "fixture"}, "resume-run")

    assert resumed.path == context.path
    assert resumed.scope_digest == context.scope_digest
    with pytest.raises(ValueError, match="scope snapshot"):
        RunContext.open_existing(tmp_path / "runs", {"scope": "different"}, "resume-run")


def test_exclusive_artifact_claim_cannot_be_replaced(tmp_path) -> None:
    context = RunContext(tmp_path / "runs", {"scope": "fixture"}, run_id="claim-run")
    context.write_json_exclusive("approvals/consumed/bundle/action.json", {"owner": 1})

    with pytest.raises(FileExistsError):
        context.write_json_exclusive("approvals/consumed/bundle/action.json", {"owner": 2})

    assert (
        context.artifact_path("approvals/consumed/bundle/action.json").read_text() == '{"owner":1}'
    )


def test_run_lock_is_reentrant_and_serializes_threads(tmp_path) -> None:
    context = RunContext(tmp_path / "runs", {"scope": "fixture"}, run_id="thread-lock-run")
    first_entered = threading.Event()
    release_first = threading.Event()
    second_entered = threading.Event()

    def first() -> None:
        with context.lock():
            with context.lock():
                first_entered.set()
                assert release_first.wait(timeout=2)

    def second() -> None:
        assert first_entered.wait(timeout=2)
        with context.lock():
            second_entered.set()

    first_thread = threading.Thread(target=first)
    second_thread = threading.Thread(target=second)
    first_thread.start()
    second_thread.start()
    assert first_entered.wait(timeout=2)
    assert not second_entered.wait(timeout=0.05)
    release_first.set()
    first_thread.join(timeout=2)
    second_thread.join(timeout=2)

    assert not first_thread.is_alive()
    assert not second_thread.is_alive()
    assert second_entered.is_set()


def test_reopened_context_initializes_process_lock(tmp_path) -> None:
    RunContext(tmp_path / "runs", {"scope": "fixture"}, run_id="reopened-lock-run")
    resumed = RunContext.open_existing(tmp_path / "runs", {"scope": "fixture"}, "reopened-lock-run")

    with resumed.lock():
        resumed.write_json("provider/nested-write.json", {"ok": True})

    assert resumed.artifact_path("provider/nested-write.json").read_text() == '{"ok":true}'

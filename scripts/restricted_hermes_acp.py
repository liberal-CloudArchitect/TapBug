#!/usr/bin/env python3
"""Launch Hermes ACP with no tool surface and run-local persistent state."""

from __future__ import annotations

import argparse
import asyncio
import os
import re
from pathlib import Path


def _prepare_home(run_dir: Path, task_id: str | None = None) -> Path:
    run_root = run_dir.resolve(strict=True)
    if not run_root.is_dir():
        raise ValueError("--run-dir must be a directory")
    if task_id is None:
        # Retain the original location for direct bridge diagnostics.  The
        # project provider always supplies a task id and therefore uses the
        # isolated sessions layout below.
        state = run_root / "provider" / "hermes-acp"
    else:
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", task_id) is None:
            raise ValueError("HERMES_ACP_TASK_ID must be a safe path segment")
        state = run_root / "provider" / "sessions" / task_id
    state.mkdir(parents=True, exist_ok=True)
    if state.is_symlink() or run_root not in state.resolve().parents:
        raise ValueError("Hermes ACP state must remain inside the run directory")
    state.chmod(0o700)
    return state


def _prepare_environment(run_dir: Path) -> Path:
    state = _prepare_home(run_dir, os.environ.get("HERMES_ACP_TASK_ID"))
    # Keep Hermes' normal home solely for its existing provider authentication.
    # Session persistence is injected separately below and never uses global state.db.
    os.environ["HERMES_TOOLSETS"] = ""
    os.environ["HERMES_TOOLS"] = ""
    os.environ["HERMES_ACP_TOOLSETS"] = ""
    return state


def _patch_hermes_tool_surface(state_dir: Path, model: str) -> None:
    """Patch the upstream ACP preset before it constructs an AIAgent."""
    import model_tools

    model_tools.get_tool_definitions = lambda *args, **kwargs: []
    try:
        import agent.memory_manager as memory_manager

        memory_manager.inject_memory_provider_tools = lambda *args, **kwargs: None
    except ImportError:
        pass
    import acp_adapter.session as session

    session._expand_acp_enabled_toolsets = lambda *args, **kwargs: []
    original_make_agent = session.SessionManager._make_agent

    def make_restricted_agent(self, *args, **kwargs):
        from agent.iteration_budget import IterationBudget

        # ACP ``session/new`` has no model field.  The stock SessionManager
        # consequently reads the user's global config and would otherwise
        # ignore the model committed by the parent provider.  Bind this bridge
        # process to its explicit argv model before constructing every session.
        kwargs["model"] = model
        agent = original_make_agent(self, *args, **kwargs)
        # SessionManager owns construction and may apply configuration after the
        # AIAgent subclass initializer. Reset both counters at this final
        # boundary so one provider response is always possible, but no tool loop
        # can continue afterward.
        agent.max_iterations = 8
        agent.iteration_budget = IterationBudget(8)
        return agent

    session.SessionManager._make_agent = make_restricted_agent
    # server imports the helper by value, so patch that binding as well.
    import acp_adapter.server as server

    server._expand_acp_enabled_toolsets = lambda *args, **kwargs: []
    import run_agent

    run_agent._hermes_home = state_dir
    import agent.agent_init as agent_init

    agent_init.get_hermes_home = lambda: state_dir
    original_agent = run_agent.AIAgent

    class RestrictedAIAgent(original_agent):
        def __init__(self, *args, **kwargs):
            kwargs.update(
                {
                    "enabled_toolsets": [],
                    "skip_context_files": True,
                    "load_soul_identity": False,
                    "skip_memory": True,
                    "checkpoints_enabled": False,
                    # The ACP adapter uses an internal shared iteration budget
                    # for setup and completion handling. Eight leaves room for
                    # the initial structured response and one schema-repair
                    # prompt; the empty tool surface still prevents action loops.
                    "max_iterations": 8,
                }
            )
            super().__init__(*args, **kwargs)

    run_agent.AIAgent = RestrictedAIAgent


def _set_model_override(model: str) -> None:
    """Apply the parent-selected model after the upstream environment load."""
    if not model or len(model) > 256:
        raise ValueError("--model must be a non-empty bounded identifier")
    os.environ["HERMES_MODEL"] = model
    os.environ["HERMES_INFERENCE_MODEL"] = model


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument(
        "--model",
        required=True,
        help="Exact model selected by the parent provider; never infer a global default.",
    )
    args = parser.parse_args(argv)
    state_dir = _prepare_environment(args.run_dir)
    _patch_hermes_tool_surface(state_dir, args.model)
    import acp
    from acp_adapter.entry import _load_env, _setup_logging
    from acp_adapter.server import HermesACPAgent
    from acp_adapter.session import SessionManager
    from hermes_state import SessionDB

    _setup_logging()
    _load_env()
    # ``_load_env`` intentionally imports the operator's normal Hermes
    # credentials, but it must not silently replace the model recorded in a
    # governed run.  Set both upstream aliases *after* that load so the ACP
    # session resolves the exact model included in provider metadata.
    _set_model_override(args.model)
    session_db = SessionDB(db_path=state_dir / "state.db")
    manager = SessionManager(db=session_db)
    agent = HermesACPAgent(session_manager=manager)
    asyncio.run(acp.run_agent(agent, use_unstable_protocol=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

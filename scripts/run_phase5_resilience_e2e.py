#!/usr/bin/env python3
"""Exercise V4 resilience gates with real localhost Docker and Hermes ACP.

This acceptance driver deliberately keeps its faults outside product source.
For each faulted CLI child it places a short-lived ``sitecustomize`` module at
the front of that child's ``PYTHONPATH``.  The module records its action in the
run before changing control flow, so the resulting artifacts remain auditable.
No role container, production configuration, V4 contract, or fixture receives
a test-only escape hatch.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import signal
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any, Literal, cast

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))


def _load_baseline_driver() -> ModuleType:
    path = PROJECT_ROOT / "scripts" / "run_phase5_e2e.py"
    spec = importlib.util.spec_from_file_location("hermes_phase5_e2e_base", path)
    if spec is None or spec.loader is None:  # pragma: no cover - corrupt checkout
        raise RuntimeError("could not load the Phase 5 E2E driver")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_BASE = _load_baseline_driver()
E2EFailure = _BASE.E2EFailure
DEFAULT_BASE = _BASE.DEFAULT_BASE
FINAL_REPORTS = _BASE.FINAL_REPORTS

Scenario = Literal[
    "api-branch-failure",
    "mutation-crash-recovery",
    "cleanup-failure",
    "tamper-matrix",
    "all",
]
Fault = Literal["api-assessment-failure", "crash-after-mutation", "cleanup-failure"]


def _json(path: Path) -> dict[str, Any]:
    value = _BASE._json(path)
    if not isinstance(value, dict):  # defensive; baseline has already checked it
        raise E2EFailure(f"artifact is not an object: {path}")
    return cast(dict[str, Any], value)


def _fault_sitecustomize() -> str:
    """Return the host-only injection module for one CLI process.

    The mutation hook executes the genuine action first, including ledger,
    consumption, evidence and execution-result commits, then kills the parent
    before it can progress the state machine.  This proves recovery cannot
    replay an already-transmitted forward action.
    """

    return r'''
import os
import signal

fault = os.environ.get("HERMES_P5_RESILIENCE_FAULT")

if fault == "api-assessment-failure":
    from hermes.vertical_v4 import VerticalWorkflowV4, VerticalWorkflowV4Error
    _original = VerticalWorkflowV4._run_role

    def _faulted_role(self, role, task_id, operation, payload):
        if role == "api" and operation == "assessment":
            self.events.record(
                "resilience_fault_injected",
                fault="api-assessment-failure",
                branch="api",
                task_id=task_id,
            )
            raise VerticalWorkflowV4Error("injected API assessment failure")
        return _original(self, role, task_id, operation, payload)

    VerticalWorkflowV4._run_role = _faulted_role

elif fault in {"crash-after-mutation", "cleanup-failure"}:
    from hermes.execution_v4 import GovernedExecutionV4Error, GovernedExecutorV4
    _original = GovernedExecutorV4.execute

    def _faulted_execute(self, action, *, task_id):
        if fault == "cleanup-failure" and action.purpose in {"cleanup", "cleanup_check"}:
            self.context.write_json_exclusive(
                f"resilience_faults/{action.action_id}.json",
                {"fault": fault, "action_id": action.action_id, "task_id": task_id},
            )
            raise GovernedExecutionV4Error("injected cleanup transport failure")
        result = _original(self, action, task_id=task_id)
        if (
            fault == "crash-after-mutation"
            and action.purpose == "candidate"
            and action.risk_group == "mutation"
        ):
            marker = self.context.artifact_path("resilience_faults/crash-after-mutation.json")
            if not marker.exists():
                self.context.write_json_exclusive(
                    "resilience_faults/crash-after-mutation.json",
                    {"fault": fault, "action_id": action.action_id, "task_id": task_id},
                )
                os.kill(os.getpid(), signal.SIGKILL)
        return result

    GovernedExecutorV4.execute = _faulted_execute
'''


class ResilienceDriver(_BASE.Driver):  # type: ignore[name-defined, misc]
    """Reuse V4 provisioning while keeping fault injection external to Hermes."""

    def __init__(self, args: argparse.Namespace) -> None:
        super().__init__(args)
        self.fault_dir = self.root / "fault-injection"
        self.fault_enabled = False
        self.session: dict[str, Any] | None = None
        self.branch_accepted_run: str | None = None

    def enable_fault(self, fault: Fault) -> None:
        self.fault_dir.mkdir(exist_ok=True)
        (self.fault_dir / "sitecustomize.py").write_text(
            _fault_sitecustomize(), encoding="utf-8"
        )
        (self.fault_dir / "mode.json").write_text(
            json.dumps({"fault": fault}, sort_keys=True) + "\n", encoding="utf-8"
        )
        current = self.env.get("PYTHONPATH", "")
        self.env["PYTHONPATH"] = str(self.fault_dir) + (
            os.pathsep + current if current else ""
        )
        self.env["HERMES_P5_RESILIENCE_FAULT"] = fault
        self.fault_enabled = True

    def disable_fault(self) -> None:
        if not self.fault_enabled:
            return
        self.env["PYTHONPATH"] = os.pathsep.join(
            value
            for value in self.env.get("PYTHONPATH", "").split(os.pathsep)
            if value and Path(value) != self.fault_dir
        )
        self.env.pop("HERMES_P5_RESILIENCE_FAULT", None)
        self.fault_enabled = False

    def _bootstrap(self) -> dict[str, Any]:
        if self.session is not None:
            return self.session
        config, scope, target, approver, reviewer, initial_hash = self.prepare()
        self.command(
            [
                sys.executable,
                "-m",
                "hermes",
                "validate-config",
                "--schema-version",
                "4",
                "--config",
                str(config),
                "--scope",
                str(scope),
            ],
            expected={0},
        )
        self.command(
            [
                sys.executable,
                "-m",
                "hermes",
                "doctor",
                "--schema-version",
                "4",
                "--config",
                str(config),
            ],
            expected={0},
        )
        self.session = {
            "config": config,
            "scope": scope,
            "target": target,
            "approver": approver,
            "reviewer": reviewer,
            "initial_hash": initial_hash,
        }
        return self.session

    def _start_session(self, *, fault: Fault | None = None) -> dict[str, Any]:
        session = dict(self._bootstrap())
        if fault is not None:
            self.enable_fault(fault)
        run_id = self._start(session["config"], session["scope"], session["target"])
        session["run_id"] = run_id
        return session

    def _decision(
        self,
        session: dict[str, Any],
        group: str,
        decision: Literal["approve", "reject"],
        *,
        expected: set[int],
    ) -> dict[str, Any]:
        challenge = _json(
            self.runs / str(session["run_id"]) / "approvals_v4" / f"challenge-{group}.json"
        )
        return self.cli(
            [
                decision,
                "--config",
                str(session["config"]),
                "--run-id",
                str(session["run_id"]),
                "--challenge-id",
                str(challenge["challenge_id"]),
                "--risk-group",
                group,
                "--key",
                str(session["approver"]),
                "--reason",
                f"{decision} exact V4 resilience {group} localhost action graph",
            ],
            expected=expected,
        )

    def _resume(self, session: dict[str, Any], *, expected: set[int]) -> dict[str, Any]:
        return self.cli(
            ["resume", "--config", str(session["config"]), "--run-id", str(session["run_id"])],
            expected=expected,
            timeout=2400,
        )

    def _assert_no_reporter(self, root: Path) -> None:
        if (root / "handoffs_v4/phase5-reporter.json").exists() or (
            root / "provider/phase5-reporter.json"
        ).exists():
            raise E2EFailure("Reporter started during a V4 resilience failure")
        if any((root / item).exists() for item in FINAL_REPORTS):
            raise E2EFailure("formal V4 report output exists during a resilience failure")

    def _sign_and_finish_with_gaps(self, session: dict[str, Any]) -> dict[str, Any]:
        self.cli(
            [
                "review",
                "sign",
                "--config",
                str(session["config"]),
                "--run-id",
                str(session["run_id"]),
                "--outcome-id",
                "phase5-findings",
                "--verdict",
                "accepted_with_gaps",
                "--key",
                str(session["reviewer"]),
                "--rationale",
                "Independent reviewer accepts explicitly declared local-lab gaps.",
            ],
            expected={21},
        )
        state = self._resume(session, expected={0})
        if state.get("execution_state") != "completed_with_gaps":
            raise E2EFailure("V4 gap review did not reach completed_with_gaps")
        return state

    def api_branch_failure(self) -> dict[str, Any]:
        if self.branch_accepted_run is not None:
            return {"scenario": "api-branch-failure", "run_id": self.branch_accepted_run}
        session = self._start_session(fault="api-assessment-failure")
        self.disable_fault()
        run_id = str(session["run_id"])
        root = self.runs / run_id
        state = _json(root / "state.json")
        if state.get("failed_branches") != ["api"] or state.get("succeeded_branches") != [
            "web",
            "authz",
            "infra",
        ]:
            raise E2EFailure("API assessment failure was not isolated to that branch")
        branch = _json(root / "collaboration_v4/branch-results.json")
        if branch.get("gaps") != ["branch:api:failed"]:
            raise E2EFailure("API branch gap is not persisted exactly")
        if (root / "handoffs_v4/phase5-assessment-api.json").exists():
            raise E2EFailure("failed API branch published an unauthorized handoff")

        self._decision(session, "readonly", "approve", expected={20})
        awaiting_mutation = self._resume(session, expected={20})
        if awaiting_mutation.get("execution_state") != "awaiting_mutation_approval":
            raise E2EFailure("isolated branch run did not reach mutation approval")
        self._decision(session, "mutation", "approve", expected={20})
        awaiting_review = self._resume(session, expected={21})
        if awaiting_review.get("execution_state") != "awaiting_review":
            raise E2EFailure("isolated branch run did not reach human review")
        completed = self._sign_and_finish_with_gaps(session)

        coverage = _json(root / "report/coverage-v4.json")
        evidence = list((root / "evidence").glob("*/manifest.json"))
        consumptions = list((root / "governance_v4/consumptions").glob("*.json"))
        outcomes = list((root / "verification_v4/outcomes").glob("*.json"))
        providers = list((root / "provider").glob("phase5-*.json"))
        ca_file = _json(session["config"])["v4_fixture_ca_file"]
        stats = self.fixture_json(session["target"], "/fixture/stats", ca_file)
        observed = sum(value for key, value in stats["requests"].items() if key != "/fixture/stats")
        if (
            coverage.get("completion") != "completed_with_gaps"
            or coverage.get("gaps") != ["branch:api:failed"]
            or len(evidence) != 23
            or len(consumptions) != 21
            or len(outcomes) != 7
            or len(providers) != 21
            or observed != 23
            or stats.get("state_hash") != session["initial_hash"]
        ):
            raise E2EFailure("isolated V4 API branch did not preserve its exact governed boundary")
        self.assert_no_role_containers(run_id)
        self.branch_accepted_run = run_id
        return {
            "scenario": "api-branch-failure",
            "run_id": run_id,
            "execution_state": completed["execution_state"],
            "network_requests": 23,
            "approval_consumptions": 21,
            "reporter_started_after_gap_review": True,
        }

    def mutation_crash_recovery(self) -> dict[str, Any]:
        session = self._start_session()
        self._decision(session, "readonly", "approve", expected={20})
        self._resume(session, expected={20})
        self.enable_fault("crash-after-mutation")
        self._decision(session, "mutation", "approve", expected={20})
        self.command(
            [
                sys.executable,
                "-m",
                "hermes",
                "--json",
                "resume",
                "--config",
                str(session["config"]),
                "--run-id",
                str(session["run_id"]),
            ],
            expected={-signal.SIGKILL, 137},
            timeout=900,
        )
        self.disable_fault()
        root = self.runs / str(session["run_id"])
        crashed = _json(root / "state.json")
        marker = _json(root / "resilience_faults/crash-after-mutation.json")
        if crashed.get("execution_state") != "verifying_mutation" or marker.get("fault") != (
            "crash-after-mutation"
        ):
            raise E2EFailure("crash did not persist the V4 mutation recovery boundary")
        before = self.fixture_json(
            session["target"], "/fixture/stats", _json(session["config"])["v4_fixture_ca_file"]
        )
        recovered = self._resume(session, expected={23})
        after = self.fixture_json(
            session["target"], "/fixture/stats", _json(session["config"])["v4_fixture_ca_file"]
        )
        if recovered.get("execution_state") != "cleanup_required":
            raise E2EFailure("crash recovery did not require a new cleanup-only approval")
        for path in ("/graphql/mutate", "/authz/elevate", "/workflow/direct-approve"):
            if before["requests"].get(path, 0) != after["requests"].get(path, 0):
                raise E2EFailure("crash recovery replayed a mutation forward action")
        self._assert_no_reporter(root)
        self._decision(session, "cleanup", "approve", expected={23})
        cleaned = self._resume(session, expected={1})
        if cleaned.get("cleanup_state") != "restored" or cleaned.get("failure_code") != (
            "interrupted_mutation_recovered"
        ):
            raise E2EFailure("approved cleanup-only recovery did not restore the fixture safely")
        final = self.fixture_json(
            session["target"], "/fixture/stats", _json(session["config"])["v4_fixture_ca_file"]
        )
        if final.get("state_hash") != session["initial_hash"]:
            raise E2EFailure("cleanup-only recovery did not restore initial fixture state")
        self._assert_no_reporter(root)
        self.assert_no_role_containers(str(session["run_id"]))
        return {
            "scenario": "mutation-crash-recovery",
            "run_id": session["run_id"],
            "execution_state": cleaned["execution_state"],
            "forward_actions_replayed": False,
            "cleanup_state": "restored",
        }

    def cleanup_failure(self) -> dict[str, Any]:
        session = self._start_session()
        self._decision(session, "readonly", "approve", expected={20})
        self._resume(session, expected={20})
        self.enable_fault("cleanup-failure")
        self._decision(session, "mutation", "approve", expected={20})
        failed = self._resume(session, expected={23})
        self.disable_fault()
        root = self.runs / str(session["run_id"])
        if failed.get("execution_state") != "cleanup_required":
            raise E2EFailure("cleanup fault did not reach cleanup_required")
        if not list((root / "resilience_faults").glob("*.json")):
            raise E2EFailure("cleanup fault lacks an auditable artifact")
        self._assert_no_reporter(root)
        self._decision(session, "cleanup", "approve", expected={23})
        cleaned = self._resume(session, expected={1})
        if cleaned.get("cleanup_state") != "restored":
            raise E2EFailure("cleanup-only action did not restore the fixture after failure")
        self._assert_no_reporter(root)
        self.assert_no_role_containers(str(session["run_id"]))
        return {
            "scenario": "cleanup-failure",
            "run_id": session["run_id"],
            "execution_state": cleaned["execution_state"],
            "reporter_launches": 0,
            "cleanup_state": "restored",
        }

    def tamper_matrix(self) -> dict[str, Any]:
        self.api_branch_failure()
        assert self.branch_accepted_run is not None
        blocked = self.tamper_cases(self._bootstrap()["config"], self.branch_accepted_run)
        expected = {
            "approval_signature",
            "review_signature",
            "consumption_action",
            "coverage",
            "outcome",
            "action_ledger",
            "budget_ledger",
            "evidence_manifest",
            "quality_dataset",
            "quality_receipt",
            "cleanup",
            "branch_result",
            "cross_review",
        }
        if set(blocked) != expected or any(
            value != "blocked_before_reporter" for value in blocked.values()
        ):
            raise E2EFailure("V4 tamper matrix did not fail closed before Reporter")
        return {
            "scenario": "tamper-matrix",
            "source_run_id": self.branch_accepted_run,
            "tamper_cases": sorted(blocked),
            "reporter_launches": 0,
        }

    def execute(self) -> dict[str, Any]:
        handlers: dict[str, Callable[[], dict[str, Any]]] = {
            "api-branch-failure": self.api_branch_failure,
            "mutation-crash-recovery": self.mutation_crash_recovery,
            "cleanup-failure": self.cleanup_failure,
            "tamper-matrix": self.tamper_matrix,
        }
        scenario = cast(Scenario, self.args.scenario)
        if scenario == "all":
            return {
                "scenario": "all",
                "results": [handler() for handler in handlers.values()],
                "artifact_root": str(self.root),
            }
        return handlers[scenario]()

    def cleanup(self) -> None:
        self.disable_fault()
        super().cleanup()


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--hermes-cli", type=Path, required=True)
    result.add_argument("--hermes-python", type=Path, required=True)
    result.add_argument("--model", required=True)
    result.add_argument(
        "--scenario",
        choices=(
            "api-branch-failure",
            "mutation-crash-recovery",
            "cleanup-failure",
            "tamper-matrix",
            "all",
        ),
        default="all",
    )
    result.add_argument("--base-image", default=DEFAULT_BASE)
    result.add_argument(
        "--artifact-root", type=Path, default=PROJECT_ROOT / "artifacts" / "phase5-resilience-e2e"
    )
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    driver = ResilienceDriver(args)
    try:
        summary = driver.execute()
        (driver.root / "summary.json").write_text(
            json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
        return 0
    except (E2EFailure, subprocess.TimeoutExpired, OSError, ValueError) as exc:
        print(f"phase5-resilience-e2e: {exc}", file=sys.stderr)
        return 1
    finally:
        driver.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())

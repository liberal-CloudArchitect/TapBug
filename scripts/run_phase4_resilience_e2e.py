#!/usr/bin/env python3
"""Exercise the Phase 4 resilience gates against real Docker/ACP runs.

This is deliberately an *acceptance driver*, not another V3 workflow.  It
imports the normal Phase 4 driver, creates the same localhost-only lab and
roles, then adds narrowly-scoped, auditable test faults through a temporary
``sitecustomize`` module.  The fault module is outside the product source tree
and is enabled only for the one host CLI process under test.

The driver is intentionally fail-closed: a scenario is successful only when
its expected recovery boundary is persisted and when the relevant Reporter
artifacts are absent.  It never promotes a faulted run into an acceptance
record merely because a command exited successfully.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
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
    """Load the existing driver without assuming ``scripts`` is on sys.path."""

    path = PROJECT_ROOT / "scripts" / "run_phase4_e2e.py"
    spec = importlib.util.spec_from_file_location("hermes_phase4_e2e_base", path)
    if spec is None or spec.loader is None:  # pragma: no cover - corrupt checkout
        raise RuntimeError("could not load the Phase 4 E2E driver")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_BASE = _load_baseline_driver()
E2EFailure = _BASE.E2EFailure
DEFAULT_BASE = _BASE.DEFAULT_BASE

ResilienceScenario = Literal[
    "api-branch-failure",
    "mutation-crash-recovery",
    "cleanup-failure",
    "tamper-matrix",
    "all",
]
FaultMode = Literal["api-assessment-failure", "crash-after-mutation", "cleanup-failure"]

REPORTER_CHAIN_PATHS = (
    "report/reporter-launch-v3.json",
    "report/reporter-ack-v3.json",
    "report/report-v3.md",
    "report/findings-v3.json",
    "report/report-write-receipt-v3.json",
    "report/formal-v3",
)

# The receipt and acknowledgement are retained only in the two tamper cases
# that mutate them; they are historic inputs, not proof that the copied run
# launched a new Reporter.  These are the paths whose creation is forbidden
# after a failed fresh preflight.
FORMAL_RENDERED_PATHS = (
    "report/report-v3.md",
    "report/findings-v3.json",
    "report/report-write-receipt-v3.json",
    "report/formal-v3",
)

# The tamper paths intentionally cover the trust chain rather than only files
# rendered into the final Markdown report.  Each target is a frozen V3 input
# that fresh preflight must re-read before it can reserve Reporter capacity.
TAMPER_TARGETS: dict[str, str] = {
    "route": "collaboration_v3/route.json",
    "dedup_provenance": "collaboration_v3/candidates.json",
    "cross_review": "collaboration_v3/cross-reviews.json",
    "approval": "approvals_v3/readonly.json",
    "consumption": "approvals_v3/consumptions",
    "evidence": "evidence",
    "action_ledger": "governance_v3/action_ledger/events.jsonl",
    "budget_ledger": "governance_v3/budget_ledger/events.jsonl",
    "coverage": "report/coverage-v3.json",
    "human_signature": "reviews/signed-v3.json",
    "reporter_receipt": "report/reporter-launch-v3.json",
    "reporter_ack": "report/reporter-ack-v3.json",
}


def _json(path: Path) -> dict[str, Any]:
    value = _BASE._json(path)
    if not isinstance(value, dict):  # defensive; baseline already enforces it
        raise E2EFailure(f"artifact must be a JSON object: {path}")
    return cast(dict[str, Any], value)


def _mutate_file(path: Path) -> None:
    """Change one byte while retaining a syntactically readable JSON-like file.

    Hash-chain and signature verification must detect either form of mutation.
    For JSON documents we alter a string scalar; journals and binary-ish
    artifacts receive a final newline.  The latter is enough to invalidate
    canonical hashes without accidentally repairing a signed payload.
    """

    if not path.is_file():
        raise E2EFailure(f"tamper fixture cannot find {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        path.write_bytes(path.read_bytes() + b"\n# tampered\n")
        return

    def replace_first_string(item: Any) -> bool:
        if isinstance(item, dict):
            for key, nested in item.items():
                if isinstance(nested, str) and nested:
                    item[key] = nested + "-tampered"
                    return True
                if replace_first_string(nested):
                    return True
        elif isinstance(item, list):
            for nested in item:
                if replace_first_string(nested):
                    return True
        return False

    if not replace_first_string(value):
        raise E2EFailure(f"tamper fixture has no mutable scalar: {path}")
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")


def _target_file(run_root: Path, tamper_class: str) -> Path:
    relative = TAMPER_TARGETS[tamper_class]
    path = run_root / relative
    if path.is_file():
        return path
    if not path.is_dir():
        raise E2EFailure(f"tamper target is missing: {relative}")
    if tamper_class == "consumption":
        matches = sorted(path.glob("*.json"))
    elif tamper_class == "evidence":
        matches = sorted(path.glob("*/manifest.json"))
    else:
        matches = sorted(candidate for candidate in path.rglob("*") if candidate.is_file())
    if not matches:
        raise E2EFailure(f"tamper target contains no artifact: {relative}")
    return matches[0]


def _fault_sitecustomize() -> str:
    """Return the test-only host injection module.

    It has no production import path.  ``api-assessment-failure`` raises before
    the API container is created; the remaining three branches therefore prove
    real Docker/ACP failure isolation.  The mutation and cleanup faults are
    injected at the parent-owned gateway boundary and leave an immutable audit
    artifact under the run before changing control flow.
    """

    return r"""
import os
import signal
from datetime import UTC, datetime

fault = os.environ.get("HERMES_P4_RESILIENCE_FAULT")
if fault == "api-assessment-failure":
    from hermes.collaboration_v3 import ParallelCollaborationV3, _BranchFailure
    _original = ParallelCollaborationV3._run_assessment
    def _api_failure(self, branch, task, blueprints):
        if branch != "api":
            return _original(self, branch, task, blueprints)
        now = datetime.now(UTC)
        self.events.record(
            "resilience_fault_injected",
            fault="api-assessment-failure",
            branch=branch,
            task_id=task.task_id,
        )
        raise _BranchFailure("failed", now, now, "injected API assessment failure")
    ParallelCollaborationV3._run_assessment = _api_failure
elif fault in {"crash-after-mutation", "cleanup-failure"}:
    from hermes.execution_v3 import GovernedExecutionError, GovernedGatewayV3
    _parent_action = GovernedGatewayV3.execute_parent_action
    _execute = GovernedGatewayV3._execute

    def _crash_after_forward(self, *, task, action, batch, request_id):
        result = _execute(
            self,
            task=task,
            action=action,
            batch=batch,
            request_id=request_id,
        )
        if (
            fault == "crash-after-mutation"
            and action.risk_group == "mutation"
            and action.purpose == "candidate"
        ):
            marker = self.context.artifact_path("resilience_faults/crash-after-mutation.json")
            if not marker.exists():
                self.context.write_json_exclusive(
                    "resilience_faults/crash-after-mutation.json",
                    {"fault": fault, "action_id": action.action_id, "task_id": task.task_id},
                )
                os.kill(os.getpid(), signal.SIGKILL)
        return result

    def _cleanup_failure(self, *, action, batch, task_id):
        fault_dir = self.context.artifact_path("resilience_faults")
        fault_dir.mkdir(parents=True, exist_ok=True)
        if fault == "cleanup-failure" and action.purpose in {"cleanup", "cleanup_check"}:
            self.context.write_json_exclusive(
                f"resilience_faults/{action.action_id}.json",
                {"fault": fault, "action_id": action.action_id, "task_id": task_id},
            )
            raise GovernedExecutionError("injected cleanup transport failure")
        return _parent_action(self, action=action, batch=batch, task_id=task_id)

    GovernedGatewayV3._execute = _crash_after_forward
    GovernedGatewayV3.execute_parent_action = _cleanup_failure
"""


class ResilienceDriver(_BASE.Driver):  # type: ignore[name-defined, misc]
    """Reuse Phase 4 provisioning and add no product-facing test hooks."""

    def __init__(self, args: argparse.Namespace) -> None:
        super().__init__(args)
        self.fault_dir = self.root / "fault-injection"
        self._fault_enabled = False

    def enable_fault(self, fault: FaultMode) -> None:
        self.fault_dir.mkdir(exist_ok=True)
        hook = self.fault_dir / "sitecustomize.py"
        hook.write_text(_fault_sitecustomize(), encoding="utf-8")
        (self.fault_dir / "mode.json").write_text(
            json.dumps({"fault": fault}, sort_keys=True) + "\n", encoding="utf-8"
        )
        current = self.env.get("PYTHONPATH", "")
        self.env["PYTHONPATH"] = str(self.fault_dir) + (os.pathsep + current if current else "")
        self.env["HERMES_P4_RESILIENCE_FAULT"] = fault
        self._fault_enabled = True

    def disable_fault(self) -> None:
        if not self._fault_enabled:
            return
        values = self.env.get("PYTHONPATH", "").split(os.pathsep)
        self.env["PYTHONPATH"] = os.pathsep.join(
            value for value in values if value and Path(value) != self.fault_dir
        )
        self.env.pop("HERMES_P4_RESILIENCE_FAULT", None)
        self._fault_enabled = False

    def _start(self, *, fault: FaultMode | None = None) -> dict[str, Any]:
        config, port, scope, approver_key, reviewer_key, initial_hash = self.prepare()
        self.command(
            [
                sys.executable,
                "-m",
                "hermes",
                "validate-config",
                "--schema-version",
                "3",
                "--config",
                str(config),
                "--scope",
                str(scope),
            ]
        )
        self.command(
            [
                sys.executable,
                "-m",
                "hermes",
                "doctor",
                "--schema-version",
                "3",
                "--config",
                str(config),
            ]
        )
        if fault is not None:
            self.enable_fault(fault)
        state = self.cli(
            [
                "run",
                "--schema-version",
                "3",
                "--config",
                str(config),
                "--scope",
                str(scope),
                "--target",
                f"http://localhost:{port}/candidate",
            ],
            expected={20},
        )
        run_id = str(state["run_id"])
        self.run_ids.append(run_id)
        return {
            "config": config,
            "port": port,
            "scope": scope,
            "approver_key": approver_key,
            "reviewer_key": reviewer_key,
            "initial_hash": initial_hash,
            "run_id": run_id,
            "state": state,
        }

    def _decide(
        self,
        session: dict[str, Any],
        risk_group: Literal["readonly", "mutation", "cleanup"],
        *,
        expected: set[int] = {20},
    ) -> dict[str, Any]:
        run_id = str(session["run_id"])
        challenge = _json(self.runs / run_id / "approvals_v3" / f"challenge-{risk_group}.json")
        return cast(
            dict[str, Any],
            self.cli(
                [
                    "approve",
                    "--config",
                    str(session["config"]),
                    "--run-id",
                    run_id,
                    "--challenge-id",
                    str(challenge["challenge_id"]),
                    "--risk-group",
                    risk_group,
                    "--key",
                    str(session["approver_key"]),
                    "--reason",
                    f"Approve exact Phase 4 resilience {risk_group} graph.",
                ],
                expected=expected,
            ),
        )

    def _resume(self, session: dict[str, Any], *, expected: set[int]) -> dict[str, Any]:
        return cast(
            dict[str, Any],
            self.cli(
                [
                    "resume",
                    "--config",
                    str(session["config"]),
                    "--run-id",
                    str(session["run_id"]),
                ],
                expected=expected,
            ),
        )

    def _sign_and_finish(
        self,
        session: dict[str, Any],
        *,
        verdict: Literal["accepted", "accepted_with_gaps"],
        state: Literal["completed", "completed_with_gaps"],
    ) -> dict[str, Any]:
        self.cli(
            [
                "review",
                "sign",
                "--config",
                str(session["config"]),
                "--run-id",
                str(session["run_id"]),
                "--outcome-id",
                "phase4-outcomes",
                "--verdict",
                verdict,
                "--key",
                str(session["reviewer_key"]),
                "--rationale",
                "Independent local-lab resilience review.",
            ],
            expected={21},
        )
        completed = self._resume(session, expected={0})
        if completed.get("execution_state") != state:
            raise E2EFailure(f"reviewed resilience run did not reach {state}")
        return completed

    def _assert_no_reporter(self, run_root: Path) -> None:
        if (run_root / "handoffs" / "phase4-reporter.json").exists() or (
            run_root / "provider" / "phase4-reporter.json"
        ).exists():
            raise E2EFailure("Reporter was invoked during a resilience fault")
        if any((run_root / relative).exists() for relative in REPORTER_CHAIN_PATHS):
            raise E2EFailure("formal report was written during a resilience fault")

    def api_branch_failure(self) -> dict[str, Any]:
        session = self._start(fault="api-assessment-failure")
        self.disable_fault()
        run_root = self.runs / str(session["run_id"])
        state = _json(run_root / "state.json")
        if state.get("failed_branches") != ["api"] or state.get("succeeded_branches") != [
            "web",
            "authz",
            "infra",
        ]:
            raise E2EFailure("API fault did not isolate exactly the API assessment branch")
        branch = _json(run_root / "collaboration_v3" / "branch-results" / "api.json")
        if branch.get("status") != "failed" or "injected API" not in str(branch.get("reason")):
            raise E2EFailure("API assessment fault was not persisted as an auditable branch gap")
        if (run_root / "handoffs" / "phase4-assessment-api.json").exists():
            raise E2EFailure("failed API branch unexpectedly published a handoff")

        self._decide(session, "readonly")
        self._resume(session, expected={20})
        self._decide(session, "mutation")
        awaiting_review = self._resume(session, expected={21})
        if awaiting_review.get("execution_state") != "awaiting_review":
            raise E2EFailure("isolated API branch did not reach human review")
        completed = self._sign_and_finish(
            session, verdict="accepted_with_gaps", state="completed_with_gaps"
        )
        coverage = _json(run_root / "report" / "coverage-v3.json")
        stats = self.fixture_json(int(session["port"]), "/fixture/stats")
        requests = stats.get("requests", {})
        if (
            coverage.get("completion") != "completed_with_gaps"
            or sum(value for key, value in requests.items() if key != "/fixture/stats") != 10
            or len(list((run_root / "approvals_v3" / "consumptions").glob("*.json"))) != 9
        ):
            raise E2EFailure(
                "API branch gap did not preserve the 10-request/9-consumption boundary"
            )
        self.assert_no_role_containers(str(session["run_id"]))
        return {
            "scenario": "api-branch-failure",
            "run_id": session["run_id"],
            "execution_state": completed["execution_state"],
            "network_requests": 10,
            "approval_consumptions": 9,
            "artifact_root": str(self.root),
        }

    def cleanup_failure(self) -> dict[str, Any]:
        session = self._start()
        self._decide(session, "readonly")
        self._resume(session, expected={20})
        self.enable_fault("cleanup-failure")
        self._decide(session, "mutation")
        failed = self._resume(session, expected={23})
        self.disable_fault()
        run_root = self.runs / str(session["run_id"])
        if failed.get("execution_state") != "cleanup_required":
            raise E2EFailure("injected cleanup failure did not enter cleanup_required")
        if not list((run_root / "resilience_faults").glob("*.json")):
            raise E2EFailure("cleanup fault is not persisted as an auditable artifact")
        self._assert_no_reporter(run_root)
        if not (run_root / "approvals_v3" / "challenge-cleanup.json").is_file():
            raise E2EFailure("cleanup failure did not issue a cleanup-only challenge")
        # The signed decision is stored successfully but the run remains in
        # ``cleanup_required`` until the parent executes it, so CLI correctly
        # preserves exit 23 at this intermediate point.
        self._decide(session, "cleanup", expected={23})
        awaiting_review = self._resume(session, expected={21})
        if awaiting_review.get("execution_state") != "awaiting_review":
            raise E2EFailure("approved cleanup-only recovery did not reach review")
        completed = self._sign_and_finish(session, verdict="accepted", state="completed")
        self.assert_no_role_containers(str(session["run_id"]))
        return {
            "scenario": "cleanup-failure",
            "run_id": session["run_id"],
            "execution_state": completed["execution_state"],
            "cleanup_recovered": True,
            "artifact_root": str(self.root),
        }

    def mutation_crash_recovery(self) -> dict[str, Any]:
        session = self._start()
        self._decide(session, "readonly")
        self._resume(session, expected={20})
        self.enable_fault("crash-after-mutation")
        self._decide(session, "mutation")
        # SIGKILL is intentional: it proves that a persisted transport boundary
        # cannot be repaired by replaying a forward action in the next process.
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
        )
        self.disable_fault()
        run_root = self.runs / str(session["run_id"])
        crashed = _json(run_root / "state.json")
        if crashed.get("execution_state") != "verifying_mutation":
            raise E2EFailure("fault process did not persist the mutation-stage crash boundary")
        marker = _json(run_root / "resilience_faults" / "crash-after-mutation.json")
        action_id = marker.get("action_id")
        task_id = marker.get("task_id")
        if (
            marker.get("fault") != "crash-after-mutation"
            or not isinstance(action_id, str)
            or not isinstance(task_id, str)
            or not task_id.startswith("phase4-verifier-")
        ):
            raise E2EFailure("crash marker is not bound to a verifier mutation action")
        event_path = run_root / "governance_v3" / "action_ledger" / "events.jsonl"
        events = [
            json.loads(line) for line in event_path.read_text(encoding="utf-8").splitlines() if line
        ]
        if not any(
            item.get("action_id") == action_id and item.get("state") == "evidence_committed"
            for item in events
            if isinstance(item, dict)
        ):
            raise E2EFailure("crash marker was not written after durable evidence/ledger commit")
        before = self.fixture_json(int(session["port"]), "/fixture/stats")
        recovered = self._resume(session, expected={23})
        after = self.fixture_json(int(session["port"]), "/fixture/stats")
        if recovered.get("execution_state") != "cleanup_required":
            raise E2EFailure("crash recovery did not enter cleanup-only approval")
        for path in ("/graphql/mutate", "/authz/elevate"):
            if before.get("requests", {}).get(path, 0) != after.get("requests", {}).get(path, 0):
                raise E2EFailure("crash recovery replayed a mutation forward action")
        if not (run_root / "approvals_v3" / "challenge-cleanup.json").is_file():
            raise E2EFailure("crash recovery did not issue a cleanup-only challenge")
        self._assert_no_reporter(run_root)
        self.assert_no_role_containers(str(session["run_id"]))
        return {
            "scenario": "mutation-crash-recovery",
            "run_id": session["run_id"],
            "execution_state": recovered["execution_state"],
            "forward_actions_replayed": False,
            "artifact_root": str(self.root),
        }

    def _baseline_accepted_run(self) -> tuple[Path, Path, str]:
        """Run the existing 15-request acceptance path in a sibling artifact root."""

        source_run = self.args.source_run
        if source_run is not None:
            run = source_run.resolve()
            state = _json(run / "state.json")
            config = run.parent.parent / "config.json"
            if (
                state.get("version") != "3"
                or state.get("execution_state") != "completed"
                or not (run / "report" / "report-v3.md").is_file()
                or not config.is_file()
            ):
                raise E2EFailure("--source-run must be a completed V3 run with a formal report")
            return run.parent, config, run.name

        root = self.root / "baseline"
        result = self.command(
            [
                sys.executable,
                str(PROJECT_ROOT / "scripts" / "run_phase4_e2e.py"),
                "--hermes-cli",
                str(self.args.hermes_cli),
                "--hermes-python",
                str(self.args.hermes_python),
                "--model",
                str(self.args.model),
                "--base-image",
                str(self.args.base_image),
                "--artifact-root",
                str(root),
                "--scenario",
                "accepted-full",
            ],
            timeout=1800,
        )
        try:
            summary = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise E2EFailure("baseline Phase 4 driver did not emit JSON") from exc
        if not isinstance(summary, dict):
            raise E2EFailure("baseline Phase 4 driver summary is not an object")
        run_id = str(summary.get("run_id", ""))
        roots = sorted(root.glob("*/runs"))
        if len(roots) != 1 or not run_id:
            raise E2EFailure("baseline Phase 4 driver did not leave an accepted run root")
        config_paths = sorted(root.glob("*/config.json"))
        if len(config_paths) != 1:
            raise E2EFailure("baseline Phase 4 driver did not leave configuration")
        return roots[0], config_paths[0], run_id

    def _preflight_rejects_tamper(
        self,
        runs_root: Path,
        config_path: Path,
        scope_path: Path,
        run_id: str,
        tamper_class: str,
    ) -> str:
        """Run the actual fresh V3 preflight without permitting a Reporter runner."""

        from hermes.cli import _evidence_store, _stores
        from hermes.domain_contracts_v3 import ReporterAckV3
        from hermes.orchestrator import load_scope_policy
        from hermes.preflight_v3 import ReportPreflightV3Error, ReportPreflightVerifierV3
        from hermes.runtime import RunContext
        from hermes.security_v3 import verify_approval_batch_v3, verify_review_batch_v3

        config = _json(config_path)
        config["runs_root"] = str(runs_root)
        scope = _json(runs_root / run_id / "scope.json")
        context = RunContext.open_existing(runs_root, scope, run_id)
        policy, _ = load_scope_policy(scope_path)
        approval_store, review_store = _stores(
            {key: Path(value) if key.endswith("_store") else value for key, value in config.items()}
        )

        def approval_verifier(batch: Any, campaign: Any) -> None:
            verify_approval_batch_v3(batch, campaign, approval_store)

        def review_verifier(review: Any, findings: Any, coverage: Any) -> None:
            from hermes.promotion import file_sha256

            approvals = tuple(
                _json(path)
                for path in sorted((context.artifact_path("approvals_v3")).glob("*.json"))
                if not path.name.startswith("challenge-")
            )
            from hermes.domain_contracts_v3 import ApprovalBatchV3

            verify_review_batch_v3(
                review,
                findings,
                coverage,
                review_store,
                report_draft_digest=file_sha256(context.artifact_path("report/draft-v3.md")),
                approval_batches=tuple(ApprovalBatchV3.model_validate(item) for item in approvals),
                approval_trust_store=approval_store,
            )

        verifier = ReportPreflightVerifierV3(
            context,
            approval_signature_verifier=approval_verifier,
            review_signature_verifier=review_verifier,
            evidence_store=_evidence_store(config, context, policy),
        )
        # Every branch below is a fresh canonical verification path and has no
        # AgentRunner.  Receipt/ack artifacts must remain present in their own
        # tamper cases so the verifier can prove their integrity, while all
        # other cases exercise pre-launch authorization.
        try:
            if tamper_class == "reporter_receipt":
                verifier.verify_launch()
            elif tamper_class == "reporter_ack":
                ack = ReporterAckV3.model_validate_json(
                    context.artifact_path("report/reporter-ack-v3.json").read_bytes()
                )
                verifier.verify_for_write(ack)
            else:
                verifier.authorize_reporter()
        except (OSError, ValueError, ReportPreflightV3Error) as exc:
            return str(exc)
        raise E2EFailure("tampered V3 copy incorrectly authorized Reporter")

    def tamper_matrix(self) -> dict[str, Any]:
        baseline_runs, config_path, run_id = self._baseline_accepted_run()
        baseline_run = baseline_runs / run_id
        outcomes: dict[str, str] = {}
        for tamper_class in TAMPER_TARGETS:
            copy_root = self.root / "tamper" / tamper_class / "runs"
            copy_run = copy_root / run_id
            shutil.copytree(baseline_run, copy_run)
            # Reporter ran in the source acceptance run.  Remove only its own
            # products so the copied run exercises fresh launch authorization.
            for relative in FORMAL_RENDERED_PATHS:
                path = copy_run / relative
                if path.is_dir():
                    shutil.rmtree(path)
                else:
                    path.unlink(missing_ok=True)
            if tamper_class not in {"reporter_receipt", "reporter_ack"}:
                for relative in (
                    "report/reporter-launch-v3.json",
                    "report/reporter-ack-v3.json",
                    "handoffs/phase4-reporter.json",
                    "provider/phase4-reporter.json",
                    "provider/sessions/phase4-reporter",
                ):
                    path = copy_run / relative
                    if path.is_dir():
                        shutil.rmtree(path)
                    else:
                        path.unlink(missing_ok=True)
            _mutate_file(_target_file(copy_run, tamper_class))
            outcome = self._preflight_rejects_tamper(
                copy_root,
                config_path,
                baseline_runs.parent / "scope.yaml",
                run_id,
                tamper_class,
            )
            if any((copy_run / relative).exists() for relative in FORMAL_RENDERED_PATHS):
                raise E2EFailure(f"{tamper_class} produced formal report output")
            outcomes[tamper_class] = outcome
        return {
            "scenario": "tamper-matrix",
            "source_run_id": run_id,
            "tamper_cases": sorted(outcomes),
            "reporter_launches": 0,
            "artifact_root": str(self.root),
        }

    def execute(self) -> dict[str, Any]:
        scenario = cast(ResilienceScenario, self.args.scenario)
        handlers: dict[str, Callable[[], dict[str, Any]]] = {
            "api-branch-failure": self.api_branch_failure,
            "mutation-crash-recovery": self.mutation_crash_recovery,
            "cleanup-failure": self.cleanup_failure,
            "tamper-matrix": self.tamper_matrix,
        }
        if scenario == "all":
            return {
                "scenario": "all",
                "results": [handlers[name]() for name in handlers],
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
        help="Run one real P4-resilience acceptance gate, or all four.",
    )
    result.add_argument("--base-image", default=DEFAULT_BASE)
    result.add_argument(
        "--artifact-root", type=Path, default=PROJECT_ROOT / "artifacts" / "phase4-resilience-e2e"
    )
    result.add_argument(
        "--source-run",
        type=Path,
        help=(
            "Use this completed real V3 run as the read-only source for tamper-matrix. "
            "Other scenarios ignore it."
        ),
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
        print(f"phase4-resilience-e2e: {exc}", file=sys.stderr)
        return 1
    finally:
        driver.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())

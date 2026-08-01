from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from hermes.campaign_v4 import VerificationCampaignPlanV4, campaign_candidate_ids
from hermes.domain_contracts_v4 import RunPlanV4
from hermes.runtime import RunContext
from hermes.runtime.agents import AgentRunner, HandoffEnvelope, TaskEnvelope, TaskResult
from hermes.vertical_v4 import ExecutionStateV4, VerticalWorkflowV4


def _digest(character: str) -> str:
    return "sha256:" + character * 64


class _BranchFailureRunner(AgentRunner):
    """A non-fixture runner surface used only to exercise parent scheduling.

    The test deliberately returns lifecycle facts, not agent content: the V4
    coordinator must make its branch-isolation decision from the runner result
    before any candidate or network authority is created.
    """

    def __init__(self) -> None:
        self.tasks: list[TaskEnvelope] = []

    def run(self, task: TaskEnvelope) -> TaskResult:
        self.tasks.append(task)
        now = datetime.now(UTC)
        if task.role == "api" and task.payload.get("operation") == "assessment":
            return TaskResult(
                task=task,
                lifecycle="failed",
                input_sha256=task.input_hash(),
                started_at=now,
                finished_at=now,
                error="injected API branch timeout",
                failure_layer="provider",
                failure_code="timeout",
            )
        return TaskResult(
            task=task,
            lifecycle="completed",
            input_sha256=task.input_hash(),
            started_at=now,
            finished_at=now,
            handoff=HandoffEnvelope.model_construct(
                version="1",
                run_id=task.run_id,
                task_id=task.task_id,
                role=task.role,
                scope_digest=task.scope_digest,
                input_sha256=task.input_hash(),
                status="completed",
                result={},
            ),
        )


def _plan(context: RunContext) -> RunPlanV4:
    return RunPlanV4(
        run_id=context.run_id,
        target="https://localhost:8443/candidate",
        scope_digest=context.scope_digest,
        provider_id="hermes-acp-restricted",
        model_id="test-model",
        prompt_registry_digest=_digest("1"),
        role_manifest_set_digest=_digest("2"),
        roles=(
            "gatekeeper",
            "recon",
            "mapper",
            "web-vuln",
            "api",
            "authz",
            "infra",
            "verifier",
            "reporter",
        ),
        identity_binding_digests={
            "alice": _digest("3"),
            "bob": _digest("4"),
            "fixture-admin": _digest("5"),
        },
        created_at=datetime.now(UTC),
    )


def test_api_branch_failure_isolated_before_candidate_campaign(tmp_path: Path) -> None:
    context = RunContext(tmp_path / "runs", {"profile": "local-lab"}, run_id="v4-branch")
    runner = _BranchFailureRunner()

    state = VerticalWorkflowV4(context, runner).start(_plan(context))

    assert state.execution_state is ExecutionStateV4.AWAITING_READONLY_APPROVAL
    assert state.failed_branches == ("api",)
    assert state.succeeded_branches == ("web", "authz", "infra")
    assert state.requests_planned == 23
    campaign = json.loads(context.artifact_path("verification_v4/campaign.json").read_text())
    assert "api-graphql" not in campaign_candidate_ids(
        VerificationCampaignPlanV4.model_validate(campaign)
    )
    review = json.loads(context.artifact_path("collaboration_v4/review-plan.json").read_text())
    assert set(review["candidate_ids"]) == set(review["reviewers"])
    assert all(value != "api" for value in review["reviewers"].values())
    branches = json.loads(context.artifact_path("collaboration_v4/branch-results.json").read_text())
    assert branches["gaps"] == ["branch:api:failed"]
    # 3 serial foundation roles + 4 assessments + 7 independent reviews.
    assert len(runner.tasks) == 14

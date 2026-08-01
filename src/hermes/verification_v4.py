"""Independent, evidence-bound V4 verifier-role handoffs.

The parent runtime performs the approved HTTP requests and commits evidence.
This module then asks the isolated verifier role to attest to exactly one
candidate's already-bound observations.  It deliberately cannot add actions,
credentials, evidence, or network authority.
"""

from __future__ import annotations

import json
from collections import defaultdict
from concurrent.futures import Future, ThreadPoolExecutor, as_completed

from .campaign_v4 import VerificationCampaignPlanV4, campaign_candidate_ids
from .domain_contracts_v4 import ContractEnvelopeV4, ExecutionBudgetV4, VerificationOutcomeSetV4
from .execution_v4 import ExecutionResultV4
from .runtime import RunContext
from .runtime.agents import AgentRunner, TaskEnvelope, TaskResult
from .security_v4 import ApprovalBatchV4


class VerificationV4Error(RuntimeError):
    """A verifier handoff does not exactly attest the parent-owned evidence."""


def run_verifier_tasks_v4(
    context: RunContext,
    runner: AgentRunner,
    campaign: VerificationCampaignPlanV4,
    results: tuple[ExecutionResultV4, ...],
    approvals: tuple[ApprovalBatchV4, ...],
    *,
    max_workers: int = 4,
) -> dict[str, VerificationOutcomeSetV4]:
    """Run one independent ACP/Docker verifier task per canonical candidate.

    All task inputs are reconstructed from immutable parent artifacts.  An
    existing handoff can be replayed only if its task input remains byte-for-
    byte equivalent; a partial provider record without a handoff is treated as
    indeterminate rather than retried.
    """

    if (campaign.run_id, campaign.scope_digest) != (context.run_id, context.scope_digest):
        raise VerificationV4Error("verification campaign crosses the current run or scope")
    grouped: dict[str, list[ExecutionResultV4]] = defaultdict(list)
    for result in results:
        grouped[result.candidate_id].append(result)
    expected_candidates = campaign_candidate_ids(campaign)
    if set(grouped) != set(expected_candidates):
        raise VerificationV4Error("verifier tasks require results for every canonical candidate")
    approval_by_candidate: dict[str, list[ApprovalBatchV4]] = defaultdict(list)
    for batch in approvals:
        if batch.verdict != "approved":
            continue
        for candidate_id in batch.candidate_ids:
            approval_by_candidate[candidate_id].append(batch)

    def execute(candidate_id: str) -> tuple[str, VerificationOutcomeSetV4]:
        candidate_results = tuple(grouped[candidate_id])
        candidate_actions = tuple(
            action for action in campaign.actions if action.candidate_id == candidate_id
        )
        if tuple(item.action_id for item in candidate_results) != tuple(
            item.action_id for item in candidate_actions
        ):
            raise VerificationV4Error(
                f"execution result ordering or action graph changed for {candidate_id}"
            )
        batches = tuple(approval_by_candidate.get(candidate_id, ()))
        if not batches:
            raise VerificationV4Error(f"candidate {candidate_id} has no approved batch")
        task_id = f"phase5-verifier-{candidate_id}"
        task = TaskEnvelope(
            version="4",
            run_id=context.run_id,
            task_id=task_id,
            role="verifier",
            scope_digest=context.scope_digest,
            payload={
                "operation": "verification",
                "campaign_digest": campaign.digest,
                "approval_batch_digests": [batch.digest for batch in batches],
                "candidate_id": candidate_id,
                "expected_outcome": {
                    "outcome_id": f"phase5-outcome-{candidate_id}",
                    "candidate_id": candidate_id,
                    "verifier_task_id": task_id,
                    "status": "validated",
                    "action_digests": [item.action_digest for item in candidate_results],
                    "evidence": [
                        item.evidence.model_dump(mode="json") for item in candidate_results
                    ],
                    "assertion_summary": (
                        "Parent-owned approved evidence for the fixed localhost "
                        f"teaching candidate {candidate_id} was supplied for independent review."
                    ),
                },
            },
            request_budget=0,
            allowed_actions=(),
            evidence_required=False,
            timeout_seconds=ExecutionBudgetV4().max_role_seconds,
        )
        relative = f"handoffs_v4/{task_id}.json"
        handoff_path = context.artifact_path(relative)
        provider_path = context.artifact_path(f"provider/{task_id}.json")
        if handoff_path.exists():
            try:
                stored = json.loads(handoff_path.read_text(encoding="utf-8"))
                persisted = TaskEnvelope.model_validate(stored["task"])
                result = TaskResult.model_validate(stored["result"])
            except (OSError, TypeError, KeyError, ValueError, json.JSONDecodeError) as exc:
                raise VerificationV4Error(
                    f"persisted verifier handoff is invalid: {task_id}"
                ) from exc
            if persisted.input_hash() != task.input_hash():
                raise VerificationV4Error(f"persisted verifier task input changed: {task_id}")
        else:
            if provider_path.exists():
                raise VerificationV4Error(
                    f"verifier task {task_id} has provider metadata without a handoff"
                )
            result = runner.run(task)
            context.write_json(
                relative,
                {"task": task.model_dump(mode="json"), "result": result.model_dump(mode="json")},
                immutable=True,
            )
        if result.lifecycle != "completed" or result.handoff is None:
            raise VerificationV4Error(f"verifier role did not complete: {task_id}")
        envelope = result.handoff.result
        payload = envelope.payload if isinstance(envelope, ContractEnvelopeV4) else None
        if not isinstance(payload, VerificationOutcomeSetV4):
            raise VerificationV4Error(
                f"verifier role returned an invalid outcome contract: {task_id}"
            )
        _verify_outcome(
            payload,
            task=task,
            campaign=campaign,
            batches=batches,
            results=candidate_results,
        )
        context.write_json(
            f"verification_v4/outcomes/{candidate_id}.json",
            payload.model_dump(mode="json"),
            immutable=True,
        )
        return candidate_id, payload

    outcomes: dict[str, VerificationOutcomeSetV4] = {}
    with ThreadPoolExecutor(max_workers=max(1, min(4, max_workers))) as pool:
        futures: dict[Future[tuple[str, VerificationOutcomeSetV4]], str] = {
            pool.submit(execute, candidate_id): candidate_id for candidate_id in expected_candidates
        }
        for future in as_completed(futures):
            candidate_id, outcome = future.result()
            outcomes[candidate_id] = outcome
    return {candidate_id: outcomes[candidate_id] for candidate_id in expected_candidates}


def _verify_outcome(
    outcome_set: VerificationOutcomeSetV4,
    *,
    task: TaskEnvelope,
    campaign: VerificationCampaignPlanV4,
    batches: tuple[ApprovalBatchV4, ...],
    results: tuple[ExecutionResultV4, ...],
) -> None:
    candidate_id = str(task.payload["candidate_id"])
    if (
        outcome_set.run_id != task.run_id
        or outcome_set.scope_digest != task.scope_digest
        or outcome_set.generated_by_task_id != task.task_id
        or outcome_set.outcome_set_id != f"phase5-outcomes-{candidate_id}"
        or outcome_set.campaign_digest != campaign.digest
        or tuple(outcome_set.approval_batch_digests) != tuple(batch.digest for batch in batches)
        or len(outcome_set.outcomes) != 1
    ):
        raise VerificationV4Error("verifier outcome set crosses its parent authority")
    outcome = outcome_set.outcomes[0]
    if (
        outcome.outcome_id != f"phase5-outcome-{candidate_id}"
        or outcome.candidate_id != candidate_id
        or outcome.verifier_task_id != task.task_id
        or outcome.status != "validated"
        or outcome.action_digests != tuple(item.action_digest for item in results)
        or outcome.evidence != tuple(item.evidence for item in results)
    ):
        raise VerificationV4Error("verifier outcome does not exactly bind the supplied evidence")


__all__ = ["VerificationV4Error", "run_verifier_tasks_v4"]

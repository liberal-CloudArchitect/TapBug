"""Evidence-derived compensation receipt for the fixed V4 teaching fixture."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from .campaign_v4 import VerificationCampaignPlanV4
from .domain_contracts import canonical_digest
from .domain_contracts_v3 import CleanupActionResult, CleanupReceipt
from .evidence import EvidenceStore
from .execution_v4 import ExecutionResultV4
from .runtime import RunContext


class CleanupV4Error(RuntimeError):
    """Mutation cleanup did not prove restoration of the fixed fixture state."""


_MUTATION_CANDIDATES = ("api-graphql", "authz-privilege", "workflow-bypass")


def build_cleanup_receipt_v4(
    context: RunContext,
    campaign: VerificationCampaignPlanV4,
    results: tuple[ExecutionResultV4, ...],
    *,
    evidence_store: EvidenceStore,
) -> CleanupReceipt:
    """Compare baseline and cleanup-check analysis projections before promotion.

    The fixture exposes only three mutable teaching values.  We derive both
    state hashes from immutable, approval-bound analysis artifacts instead of
    trusting a transport status or a caller-supplied boolean.
    """

    by_action = {item.action_id: item for item in results}
    required = {
        "api-graphql": (
            "api-graphql-baseline",
            "api-graphql-forward",
            "api-graphql-cleanup",
            "api-graphql-cleanup-check",
        ),
        "authz-privilege": (
            "authz-privilege-baseline",
            "authz-privilege-forward",
            "authz-privilege-cleanup",
            "authz-privilege-cleanup-check",
        ),
        "workflow-bypass": (
            "workflow-baseline",
            "workflow-forward",
            "workflow-cleanup",
            "workflow-cleanup-check",
        ),
    }
    active = {
        candidate_id: names
        for candidate_id, names in required.items()
        if any(item.candidate_id == candidate_id for item in campaign.actions)
    }
    if not active:
        raise CleanupV4Error("cleanup receipt requires a mutation candidate")
    if any(any(action not in by_action for action in names) for names in active.values()):
        raise CleanupV4Error("cleanup receipt requires every active mutation graph result")
    baseline: dict[str, Any] = {}
    final: dict[str, Any] = {}
    for candidate_id, (baseline_id, _forward, _cleanup, check_id) in active.items():
        if candidate_id == "api-graphql":
            baseline["graphql_value"] = _body_value(
                context, evidence_store, by_action[baseline_id]
            )["data"]["fixtureValue"]
            final["graphql_value"] = _body_value(
                context, evidence_store, by_action[check_id]
            )["data"]["fixtureValue"]
        elif candidate_id == "authz-privilege":
            baseline["alice_privileged"] = _body_value(
                context, evidence_store, by_action[baseline_id]
            )["privileged"]
            final["alice_privileged"] = _body_value(
                context, evidence_store, by_action[check_id]
            )["privileged"]
        else:
            baseline["workflow_state"] = _body_value(
                context, evidence_store, by_action[baseline_id]
            )["state"]
            final["workflow_state"] = _body_value(
                context, evidence_store, by_action[check_id]
            )["state"]
    initial_hash = canonical_digest(baseline)
    final_hash = canonical_digest(final)
    actions = {item.action_id: item for item in campaign.actions}
    cleanup_results = []
    for candidate_id, (_, forward, cleanup, check) in active.items():
        forward_result = by_action[forward]
        cleanup_result = by_action[cleanup]
        check_result = by_action[check]
        cleaned = (
            forward_result.status_code < 400
            and cleanup_result.status_code < 400
            and check_result.status_code < 400
            and initial_hash == final_hash
        )
        cleanup_results.append(
            CleanupActionResult(
                forward_action_digest=actions[forward].action_digest,
                cleanup_action_digest=actions[cleanup].action_digest,
                cleanup_check_action_digest=actions[check].action_digest,
                status="cleaned" if cleaned else "cleanup_required",
                evidence=(cleanup_result.evidence, check_result.evidence),
            )
        )
    restored = all(item.status == "cleaned" for item in cleanup_results)
    return CleanupReceipt(
        run_id=context.run_id,
        scope_digest=context.scope_digest,
        generated_by_task_id="phase5-compensation",
        receipt_id="phase5-cleanup",
        campaign_digest=campaign.digest,
        results=tuple(cleanup_results),
        initial_state_sha256=initial_hash,
        final_state_sha256=final_hash,
        state_restored=restored,
        completed_at=datetime.now(UTC),
    )


def _body_value(
    context: RunContext, evidence_store: EvidenceStore, result: ExecutionResultV4
) -> dict[str, Any]:
    manifest = evidence_store.verify(result.evidence)
    try:
        analysis = json.loads(
            context.artifact_path(manifest.analysis.path).read_text(encoding="utf-8")
        )
        response = analysis["response"]
        body = response["body"]
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise CleanupV4Error("cleanup evidence has no valid structured analysis body") from exc
    if not isinstance(body, dict):
        raise CleanupV4Error("cleanup evidence body is not a JSON object")
    return body


__all__ = ["CleanupV4Error", "build_cleanup_receipt_v4"]

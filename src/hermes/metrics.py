"""Canonical pre-Reporter model and timing metrics for the fixed V2 chain."""

from __future__ import annotations

import json
from dataclasses import dataclass

from .runtime import RunContext
from .runtime.agents import TaskResult

ASSESSMENT_TASK_IDS = frozenset(
    {
        "phase3-gatekeeper",
        "phase3-recon",
        "phase3-mapper",
        "phase3-web-vuln",
        "phase3-verifier",
    }
)


class MetricsError(ValueError):
    """Provider or handoff metrics are missing, malformed, or cross-run."""


@dataclass(frozen=True)
class PreReportMetrics:
    model_calls: int
    elapsed_ms: int
    cost_microusd: int | None


def collect_pre_report_metrics(context: RunContext) -> PreReportMetrics:
    """Measure the five assessment model calls completed before Reporter starts."""

    provider_records: list[dict[str, object]] = []
    try:
        for path in sorted(context.artifact_path("provider").glob("*.json")):
            value = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(value, dict):
                raise ValueError("provider record is not an object")
            if value.get("task_id") in ASSESSMENT_TASK_IDS:
                provider_records.append(value)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise MetricsError("provider metrics are invalid") from exc
    task_ids = {str(item.get("task_id", "")) for item in provider_records}
    if task_ids != ASSESSMENT_TASK_IDS or any(
        item.get("run_id") != context.run_id for item in provider_records
    ):
        raise MetricsError("provider metrics do not match the assessment role set")

    results: list[TaskResult] = []
    try:
        for task_id in sorted(ASSESSMENT_TASK_IDS):
            handoff = json.loads(
                context.artifact_path(f"handoffs/{task_id}.json").read_text(encoding="utf-8")
            )
            result = TaskResult.model_validate(handoff["result"])
            if result.task.task_id != task_id or result.task.run_id != context.run_id:
                raise ValueError("handoff timing belongs to another task or run")
            results.append(result)
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise MetricsError("provider task timing records are invalid") from exc
    elapsed_ms = max(
        1,
        sum(
            max(1, int((item.finished_at - item.started_at).total_seconds() * 1000))
            for item in results
        ),
    )
    prompt_attempts: list[int] = []
    for item in provider_records:
        value = item.get("prompt_attempts")
        if type(value) is not int or value not in {1, 2}:
            raise MetricsError("provider prompt attempt count is invalid")
        prompt_attempts.append(value)
    costs = [
        usage.get("cost_microusd")
        for item in provider_records
        if isinstance((usage := item.get("token_usage")), dict)
    ]
    cost = (
        sum(value for value in costs if isinstance(value, int))
        if len(costs) == len(provider_records) and all(isinstance(value, int) for value in costs)
        else None
    )
    return PreReportMetrics(
        model_calls=sum(prompt_attempts),
        elapsed_ms=elapsed_ms,
        cost_microusd=cost,
    )


__all__ = [
    "ASSESSMENT_TASK_IDS",
    "MetricsError",
    "PreReportMetrics",
    "collect_pre_report_metrics",
]

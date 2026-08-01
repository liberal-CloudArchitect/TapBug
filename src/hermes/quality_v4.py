"""Frozen, detector-independent quality data for the localhost V4 fixture.

The quality gate deliberately evaluates saved, declarative observations rather
than asking the same model that produced a run to grade its own output.  It is
not a substitute for a broader benchmark; it is the reproducible quality floor
that must pass before a V4 local-lab report may be written.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .campaign_v4 import CandidateTypeV4, VerificationCampaignPlanV4
from .domain_contracts import canonical_digest
from .domain_contracts_v4 import FamilyV4, QualityFamilyMetricsV4
from .execution_v4 import ExecutionResultV4
from .runtime import RunContext

QualityExpectedV4 = Literal["none", "verified"]
QualityMeasuredFamilyV4 = Literal["web", "api", "authz", "infra", "workflow"]
_MEASURED_FAMILIES: tuple[QualityMeasuredFamilyV4, ...] = (
    "web",
    "api",
    "authz",
    "infra",
    "workflow",
)

_FAMILY_BY_CANDIDATE: Mapping[CandidateTypeV4, QualityMeasuredFamilyV4] = {
    "missing_x_content_type_options": "web",
    "insecure_session_cookie": "web",
    "unvalidated_redirect": "web",
    "exposed_debug_endpoint": "infra",
    "unauthorized_graphql_mutation": "api",
    "privilege_escalation": "authz",
    "cross_tenant_object_read": "authz",
    "workflow_transition_bypass": "workflow",
}
_CANDIDATE_BY_ID: Mapping[str, CandidateTypeV4] = {
    "web-xcto": "missing_x_content_type_options",
    "web-cookie": "insecure_session_cookie",
    "web-open-redirect": "unvalidated_redirect",
    "infra-debug": "exposed_debug_endpoint",
    "api-graphql": "unauthorized_graphql_mutation",
    "authz-privilege": "privilege_escalation",
    "authz-bola": "cross_tenant_object_read",
    "workflow-bypass": "workflow_transition_bypass",
}


class QualityCaseV4(BaseModel):
    """One explicit, non-network ground-truth observation.

    ``observation`` contains the reduced signal consumed by the deterministic
    local-fixture oracle.  It is intentionally independent of agent handoffs,
    Campaign results and the expected label, so changing a label alone cannot
    make the detector appear correct.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(min_length=1, max_length=128)
    candidate_type: CandidateTypeV4
    family: FamilyV4
    expected: QualityExpectedV4
    observation: dict[str, str | int | bool | None] = Field(min_length=1)

    @model_validator(mode="after")
    def coherent_family(self) -> QualityCaseV4:
        if self.family != _FAMILY_BY_CANDIDATE[self.candidate_type]:
            raise ValueError("quality case family does not match its detector")
        return self


class QualityDatasetV4(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: str = Field(min_length=1, max_length=128)
    cases: tuple[QualityCaseV4, ...] = Field(min_length=1)

    @field_validator("cases")
    @classmethod
    def unique_case_ids(cls, value: tuple[QualityCaseV4, ...]) -> tuple[QualityCaseV4, ...]:
        if len({case.id for case in value}) != len(value):
            raise ValueError("quality case IDs must be unique")
        return value

    @property
    def digest(self) -> str:
        return canonical_digest(self)


@dataclass(frozen=True, slots=True)
class QualityOperationalMetricsV4:
    """Observed run metrics attached to a family-quality result."""

    requests_used: int = 0
    elapsed_ms: int = 0
    model_attempts: int = 0
    estimated_cost_microusd: int | None = None


def load_fixture_dataset_v4(path: Path) -> tuple[str, list[QualityCaseV4]]:
    """Load only explicit cases; legacy count expansion is not accepted."""

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("could not load V4 quality dataset") from exc
    try:
        dataset = QualityDatasetV4.model_validate(payload)
    except ValueError as exc:
        raise ValueError("V4 quality dataset schema is invalid") from exc
    return dataset.version, list(dataset.cases)


def load_quality_dataset_v4(path: Path) -> QualityDatasetV4:
    """Load a fully typed dataset for validation or a run-local receipt."""

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("could not load V4 quality dataset") from exc
    try:
        return QualityDatasetV4.model_validate(payload)
    except ValueError as exc:
        raise ValueError("V4 quality dataset schema is invalid") from exc


def validate_quality_dataset_v4(dataset: QualityDatasetV4) -> None:
    """Enforce the frozen local quality floor for every V4 detector.

    A count-only manifest is deliberately insufficient: every case must have a
    concrete reduced observation and every detector must own at least twenty
    positive and twenty negative observations.
    """

    counts: dict[CandidateTypeV4, dict[QualityExpectedV4, int]] = defaultdict(
        lambda: {"none": 0, "verified": 0}
    )
    for case in dataset.cases:
        counts[case.candidate_type][case.expected] += 1
    missing = set(_FAMILY_BY_CANDIDATE).difference(counts)
    if missing:
        raise ValueError(
            "quality dataset is missing detector families: " + ", ".join(sorted(missing))
        )
    for candidate_type in sorted(_FAMILY_BY_CANDIDATE):
        values = counts[candidate_type]
        if values["verified"] < 20 or values["none"] < 20:
            raise ValueError(
                f"quality dataset requires 20 positive and 20 negative cases for {candidate_type}"
            )


def _detector_matches(case: QualityCaseV4) -> bool:
    """Apply the local fixture's independently specified reduced predicate."""

    observation = case.observation
    value: object
    if case.candidate_type == "missing_x_content_type_options":
        value = observation.get("x_content_type_options")
        return value is None or str(value).strip().lower() != "nosniff"
    if case.candidate_type == "insecure_session_cookie":
        return observation.get("secure") is not True or observation.get("http_only") is not True
    if case.candidate_type == "exposed_debug_endpoint":
        return (
            observation.get("status_code") == 200
            and observation.get("requires_admin") is not True
        )
    if case.candidate_type == "unauthorized_graphql_mutation":
        return observation.get("low_privilege_mutation") == "accepted"
    if case.candidate_type == "privilege_escalation":
        return observation.get("self_role_change") == "accepted"
    if case.candidate_type == "cross_tenant_object_read":
        return observation.get("cross_tenant_read") == "returned"
    if case.candidate_type == "unvalidated_redirect":
        value = observation.get("location")
        return isinstance(value, str) and value.startswith("https://redirect.invalid")
    if case.candidate_type == "workflow_transition_bypass":
        return observation.get("draft_to_approved") == "accepted"
    raise AssertionError(f"unhandled V4 quality detector: {case.candidate_type}")


def evaluate_quality_dataset_v4(
    dataset: QualityDatasetV4,
    *,
    operational: Mapping[FamilyV4, QualityOperationalMetricsV4] | None = None,
) -> tuple[QualityFamilyMetricsV4, ...]:
    """Evaluate the frozen ground truth without model or network input."""

    validate_quality_dataset_v4(dataset)
    operational = operational or {}
    reports: list[QualityFamilyMetricsV4] = []
    for family in _MEASURED_FAMILIES:
        cases = tuple(case for case in dataset.cases if case.family == family)
        positives = tuple(case for case in cases if case.expected == "verified")
        detected = tuple(case for case in cases if _detector_matches(case))
        hits = len({case.id for case in positives}.intersection(case.id for case in detected))
        false_positive = len(
            {case.id for case in detected}.difference(case.id for case in positives)
        )
        false_negative = len(
            {case.id for case in positives}.difference(case.id for case in detected)
        )
        recall = hits / len(positives) if positives else None
        precision = hits / len(detected) if detected else None
        metrics = operational.get(family, QualityOperationalMetricsV4())
        passed = (
            recall is not None
            and recall >= 0.95
            and precision == 1.0
            and false_positive == 0
        )
        reports.append(
            QualityFamilyMetricsV4(
                family=family,
                dataset_version=dataset.version,
                dataset_digest=dataset.digest,
                positives=len(positives),
                negatives=len(cases) - len(positives),
                candidate_recall=recall,
                verified_precision=precision,
                false_positive_candidates=false_positive,
                false_negative_candidates=false_negative,
                requests_used=metrics.requests_used,
                elapsed_ms=metrics.elapsed_ms,
                model_attempts=metrics.model_attempts,
                estimated_cost_microusd=metrics.estimated_cost_microusd,
                passed=passed,
            )
        )
    return tuple(reports)


def operational_metrics_v4(
    context: RunContext,
    campaign: VerificationCampaignPlanV4,
    results: Sequence[ExecutionResultV4],
) -> Mapping[FamilyV4, QualityOperationalMetricsV4]:
    """Derive request and ACP-attempt accounting from canonical run artifacts.

    Provider price is deliberately ``None`` unless an adapter begins emitting a
    verified cost value; reservations are ceilings, not observed spend.
    """

    candidate_types = {
        action.candidate_id: action.candidate_type for action in campaign.actions
    }
    requests: dict[QualityMeasuredFamilyV4, int] = defaultdict(int)
    for result in results:
        candidate_type = candidate_types.get(result.candidate_id)
        if candidate_type is not None:
            requests[_FAMILY_BY_CANDIDATE[candidate_type]] += 1

    attempts: dict[QualityMeasuredFamilyV4, int] = defaultdict(int)
    spans: dict[QualityMeasuredFamilyV4, list[int]] = defaultdict(list)
    provider_root = context.artifact_path("provider")
    for path in sorted(provider_root.glob("*.json")) if provider_root.is_dir() else ():
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            task_id = value["task_id"]
            run_id = value["run_id"]
            prompt_attempts = value["prompt_attempts"]
        except (OSError, TypeError, ValueError, KeyError) as exc:
            raise ValueError("provider metadata is invalid for V4 quality accounting") from exc
        if (
            run_id != context.run_id
            or not isinstance(task_id, str)
            or type(prompt_attempts) is not int
        ):
            raise ValueError("provider metadata crosses a V4 quality run boundary")
        candidate_type = next(
            (
                kind
                for candidate_id, kind in _CANDIDATE_BY_ID.items()
                if candidate_id in task_id
            ),
            None,
        )
        if candidate_type is None and task_id.startswith("phase5-assessment-"):
            branch = task_id.removeprefix("phase5-assessment-")
            candidate_type = cast(CandidateTypeV4 | None, {
                "web": "missing_x_content_type_options",
                "api": "unauthorized_graphql_mutation",
                "authz": "privilege_escalation",
                "infra": "exposed_debug_endpoint",
            }.get(branch))
        if candidate_type is None:
            continue
        family = _FAMILY_BY_CANDIDATE[candidate_type]
        attempts[family] += prompt_attempts
        spans[family].append(path.stat().st_mtime_ns)

    output: dict[FamilyV4, QualityOperationalMetricsV4] = {}
    for family in _MEASURED_FAMILIES:
        output[family] = QualityOperationalMetricsV4(
            requests_used=requests[family],
            elapsed_ms=(max(spans[family]) - min(spans[family])) // 1_000_000
            if spans[family]
            else 0,
            model_attempts=attempts[family],
            estimated_cost_microusd=None,
        )
    return output


def quality_dataset_payload_v4(dataset: QualityDatasetV4) -> dict[str, object]:
    """Return canonical JSON-safe data for the immutable run-local copy."""

    return dataset.model_dump(mode="json")


def quality_dataset_sha256_v4(dataset: QualityDatasetV4) -> str:
    """A conventional content hash for operator-facing inventory output."""

    encoded = json.dumps(
        quality_dataset_payload_v4(dataset),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


__all__ = [
    "QualityCaseV4",
    "QualityDatasetV4",
    "QualityOperationalMetricsV4",
    "evaluate_quality_dataset_v4",
    "load_fixture_dataset_v4",
    "load_quality_dataset_v4",
    "operational_metrics_v4",
    "quality_dataset_payload_v4",
    "quality_dataset_sha256_v4",
    "validate_quality_dataset_v4",
]

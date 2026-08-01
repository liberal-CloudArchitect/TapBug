"""Versioned-fixture quality metrics that do not overstate scanner performance."""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, Field


class FixtureCase(BaseModel):
    id: str
    expected: str = Field(pattern=r"^(none|candidate|verified)$")


class QualityReport(BaseModel):
    dataset_version: str = "fixture-v1"
    candidate_recall: float | None
    verified_precision: float | None
    false_positive_candidates: int
    false_negative_candidates: int
    verified_count: int


def evaluate_candidate_quality(
    cases: list[FixtureCase], *, candidate_ids: set[str], verified_ids: set[str]
) -> QualityReport:
    expected_candidates = {case.id for case in cases if case.expected in {"candidate", "verified"}}
    expected_verified = {case.id for case in cases if case.expected == "verified"}
    hits = len(expected_candidates.intersection(candidate_ids))
    candidate_recall = hits / len(expected_candidates) if expected_candidates else None
    verified_hits = len(expected_verified.intersection(verified_ids))
    verified_precision = verified_hits / len(verified_ids) if verified_ids else None
    return QualityReport(
        candidate_recall=candidate_recall,
        verified_precision=verified_precision,
        false_positive_candidates=len(candidate_ids.difference(expected_candidates)),
        false_negative_candidates=len(expected_candidates.difference(candidate_ids)),
        verified_count=len(verified_ids),
    )


def load_fixture_dataset(path: Path) -> tuple[str, list[FixtureCase]]:
    """Load versioned, detector-independent expected labels from a frozen fixture."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("version"), str):
        raise ValueError("quality fixture must contain a version")
    raw_cases = payload.get("cases")
    if not isinstance(raw_cases, list):
        raise ValueError("quality fixture must contain a case list")
    return payload["version"], [FixtureCase.model_validate(case) for case in raw_cases]

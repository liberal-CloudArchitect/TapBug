"""N7 — ValidatedFinding -> Bugcrowd VRT/CVSS report *draft* (human-submitted).

docs/19 node N7, the last capability node. A verified, reviewed finding (N4)
becomes a Bugcrowd-shaped report draft: a VRT category (validated against the real
Bugcrowd taxonomy, cloned under ``vulnerability-rating-taxonomy``), a CVSS v3.1
vector + computed base score, a priority (P1–P5), and a human-authored narrative
(title / summary / steps / impact) that Hermes formats but never fabricates.

Two hard rules:

* **Hermes never submits.** A draft's ``submitted`` is ``Literal[False]`` and
  :func:`require_human_submission` always raises. There is no ``submit()``: a
  human reviews the draft and submits it themselves (docs/19 N7 red line — auto
  or batch submission gets researchers banned and violates Hermes' governance).
* **No fabrication.** The classification (VRT/CVSS) is validated, not invented,
  and the narrative fields are supplied by the operator from the verified
  evidence — Hermes assembles and binds provenance, it does not embellish.

Every draft binds the finding/plan/outcome digests, so a report is traceable back
through N4 → N3 → N2 → N1 to the signed scope that authorized the assessment.

Scope of this module: the frozen draft contract, the VRT taxonomy loader, the
CVSS v3.1 base-score computation, the assembler, and a markdown renderer — fully
unit-tested offline.
"""

from __future__ import annotations

import json
import math
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .classification import CvssV31Input
from .domain_contracts import canonical_digest
from .evidence import EvidenceArtifactRef
from .verification import ValidatedFindingV1, VerificationOutcomeV1, VerificationPlanV1

_ID = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
_SLUG = r"^[a-z0-9][a-z0-9._-]{0,119}$"
_DIGEST = r"^sha256:[0-9a-f]{64}$"

Priority = Literal["P1", "P2", "P3", "P4", "P5"]
CvssSeverity = Literal["none", "low", "medium", "high", "critical"]


class ReportDraftError(RuntimeError):
    """A ValidatedFinding could not be turned into a valid report draft."""


# --------------------------------------------------------------------------- #
# CVSS v3.1 base score (standard formula)
# --------------------------------------------------------------------------- #

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"N": 0.0, "L": 0.22, "H": 0.56}


def _roundup(value: float) -> float:
    # CVSS v3.1 Appendix A roundup: nearest 0.1, rounding up.
    return math.ceil(round(value * 100000) / 10000.0) / 10.0


def cvss_v31_base_score(metrics: CvssV31Input) -> float:
    """Compute the CVSS v3.1 base score from the vector metrics."""

    iss = 1 - (
        (1 - _CIA[metrics.confidentiality])
        * (1 - _CIA[metrics.integrity])
        * (1 - _CIA[metrics.availability])
    )
    if metrics.scope == "U":
        impact = 6.42 * iss
        pr = _PR_U[metrics.privileges_required]
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        pr = _PR_C[metrics.privileges_required]
    exploitability = (
        8.22
        * _AV[metrics.attack_vector]
        * _AC[metrics.attack_complexity]
        * pr
        * _UI[metrics.user_interaction]
    )
    if impact <= 0:
        return 0.0
    if metrics.scope == "U":
        return _roundup(min(impact + exploitability, 10.0))
    return _roundup(min(1.08 * (impact + exploitability), 10.0))


def cvss_severity(score: float) -> CvssSeverity:
    if score == 0.0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def parse_cvss_vector(vector: str) -> CvssV31Input:
    """Parse a ``CVSS:3.1/...`` base vector into CvssV31Input (fail-closed)."""

    if not vector.startswith("CVSS:3.1/"):
        raise ReportDraftError("only CVSS:3.1 base vectors are supported")
    parts = dict(
        piece.split(":", 1) for piece in vector.removeprefix("CVSS:3.1/").split("/") if ":" in piece
    )
    try:
        return CvssV31Input(
            attack_vector=parts["AV"],  # type: ignore[arg-type]
            attack_complexity=parts["AC"],  # type: ignore[arg-type]
            privileges_required=parts["PR"],  # type: ignore[arg-type]
            user_interaction=parts["UI"],  # type: ignore[arg-type]
            scope=parts["S"],  # type: ignore[arg-type]
            confidentiality=parts["C"],  # type: ignore[arg-type]
            integrity=parts["I"],  # type: ignore[arg-type]
            availability=parts["A"],  # type: ignore[arg-type]
        )
    except (KeyError, ValueError) as exc:
        raise ReportDraftError(f"invalid CVSS:3.1 base vector: {exc}") from exc


# --------------------------------------------------------------------------- #
# VRT taxonomy (real, cloned)
# --------------------------------------------------------------------------- #


def load_vrt_priorities(taxonomy_path: Path) -> dict[str, int]:
    """Index every VRT node that carries a priority (id -> 1..5) from the taxonomy."""

    document: dict[str, Any] = json.loads(taxonomy_path.read_text(encoding="utf-8"))
    priorities: dict[str, int] = {}

    def walk(nodes: list[dict[str, Any]], prefix: str) -> None:
        for node in nodes:
            node_id = str(node.get("id", ""))
            full = f"{prefix}.{node_id}" if prefix else node_id
            priority = node.get("priority")
            if isinstance(priority, int) and 1 <= priority <= 5:
                priorities[full] = priority
                priorities.setdefault(node_id, priority)
            children = node.get("children")
            if isinstance(children, list):
                walk(children, full)

    content = document.get("content")
    if not isinstance(content, list):
        raise ReportDraftError("VRT taxonomy has no 'content' list")
    walk(content, "")
    if not priorities:
        raise ReportDraftError("VRT taxonomy yielded no prioritized nodes")
    return priorities


def priority_label(priority: int) -> Priority:
    if not 1 <= priority <= 5:
        raise ReportDraftError(f"VRT priority out of range: {priority}")
    return f"P{priority}"  # type: ignore[return-value]


# --------------------------------------------------------------------------- #
# Draft
# --------------------------------------------------------------------------- #


class ReportNarrativeV1(BaseModel):
    """Operator-authored narrative — assembled by Hermes, never fabricated by it."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    title: str = Field(min_length=1, max_length=300)
    summary: str = Field(min_length=1, max_length=4_000)
    steps_to_reproduce: tuple[str, ...] = Field(min_length=1)
    impact: str = Field(min_length=1, max_length=4_000)


class ReportDraftV1(BaseModel):
    """A Bugcrowd-shaped report draft — never submitted by Hermes."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"] = "1"
    platform: Literal["bugcrowd"] = "bugcrowd"
    program_handle: str = Field(pattern=_ID)
    finding_id: str = Field(pattern=_ID)
    candidate_id: str = Field(pattern=_ID)
    target_url: str = Field(min_length=1, max_length=2_048)
    candidate_type: str = Field(pattern=_SLUG)
    title: str = Field(min_length=1, max_length=300)
    vrt_category_id: str = Field(min_length=1, max_length=200)
    priority: Priority
    cvss_vector: str = Field(min_length=1, max_length=200)
    cvss_base_score: float = Field(ge=0.0, le=10.0)
    cvss_severity: CvssSeverity
    summary: str = Field(min_length=1, max_length=4_000)
    steps_to_reproduce: tuple[str, ...] = Field(min_length=1)
    impact: str = Field(min_length=1, max_length=4_000)
    evidence: tuple[EvidenceArtifactRef, ...] = Field(min_length=1)
    finding_digest: str = Field(pattern=_DIGEST)
    plan_digest: str = Field(pattern=_DIGEST)
    outcome_digest: str = Field(pattern=_DIGEST)
    created_at: datetime
    submitted: Literal[False] = False

    @model_validator(mode="after")
    def _tz(self) -> ReportDraftV1:
        if self.created_at.tzinfo is None:
            raise ValueError("created_at must be timezone-aware")
        return self

    def digest(self) -> str:
        return canonical_digest(self)


def build_report_draft(
    finding: ValidatedFindingV1,
    plan: VerificationPlanV1,
    outcome: VerificationOutcomeV1,
    *,
    vrt_category_id: str,
    vrt_priorities: dict[str, int],
    cvss: CvssV31Input,
    narrative: ReportNarrativeV1,
    now: datetime,
) -> ReportDraftV1:
    """Assemble a report draft from a validated finding (fail-closed on provenance).

    The VRT category must exist in the taxonomy (priority derived from it); the
    CVSS vector is scored deterministically; the finding must be bound to exactly
    this plan and validated outcome.
    """

    if finding.plan_digest != plan.digest() or finding.outcome_digest != outcome.digest():
        raise ReportDraftError("finding is not bound to the given plan and outcome")
    if outcome.verdict != "validated":
        raise ReportDraftError("only a validated outcome may be reported")
    if vrt_category_id not in vrt_priorities:
        raise ReportDraftError(f"VRT category {vrt_category_id!r} is not in the taxonomy")
    priority = priority_label(vrt_priorities[vrt_category_id])
    score = cvss_v31_base_score(cvss)
    evidence = outcome.candidate_evidence + outcome.control_evidence
    return ReportDraftV1(
        program_handle=finding.program_handle,
        finding_id=finding.finding_id,
        candidate_id=finding.candidate_id,
        target_url=finding.target_url,
        candidate_type=finding.candidate_type,
        title=narrative.title,
        vrt_category_id=vrt_category_id,
        priority=priority,
        cvss_vector=cvss.vector,
        cvss_base_score=score,
        cvss_severity=cvss_severity(score),
        summary=narrative.summary,
        steps_to_reproduce=narrative.steps_to_reproduce,
        impact=narrative.impact,
        evidence=evidence,
        finding_digest=finding.digest(),
        plan_digest=plan.digest(),
        outcome_digest=outcome.digest(),
        created_at=now,
    )


def render_markdown(draft: ReportDraftV1) -> str:
    """Render a Bugcrowd-style report a human reviews and submits themselves."""

    steps = "\n".join(f"{i}. {s}" for i, s in enumerate(draft.steps_to_reproduce, 1))
    evidence = "\n".join(f"- `{e.evidence_id}` ({e.manifest_sha256})" for e in draft.evidence)
    return (
        f"# {draft.title}\n\n"
        f"> DRAFT — reviewed and submitted by a human, never by Hermes.\n\n"
        f"- **Program:** {draft.program_handle}\n"
        f"- **Target:** {draft.target_url}\n"
        f"- **VRT:** `{draft.vrt_category_id}` (**{draft.priority}**)\n"
        f"- **CVSS v3.1:** `{draft.cvss_vector}` = **{draft.cvss_base_score} "
        f"({draft.cvss_severity})**\n"
        f"- **Finding:** `{draft.finding_id}`  ·  digest `{draft.finding_digest}`\n\n"
        f"## Summary\n{draft.summary}\n\n"
        f"## Steps to reproduce\n{steps}\n\n"
        f"## Impact\n{draft.impact}\n\n"
        f"## Evidence\n{evidence}\n\n"
        f"## Provenance\n"
        f"- plan digest `{draft.plan_digest}`\n"
        f"- outcome digest `{draft.outcome_digest}`\n"
    )


def require_human_submission() -> None:
    """The N7 red line, callable as an explicit assertion.

    Hermes has no submit path: a human reviews the rendered draft and submits it
    to Bugcrowd themselves. This exists so any caller tempted to automate
    submission fails loudly.
    """

    raise ReportDraftError(
        "report submission is a human action; Hermes never submits to Bugcrowd automatically"
    )

"""Parent-owned promotion from verified V3 outcomes to formal findings.

Agent handoffs are deliberately not accepted here.  The parent runtime reloads
the closed V3 contracts and deterministically derives the only ``FindingSet``
that reporting is allowed to consume.
"""

from __future__ import annotations

from typing import Literal

from .domain_contracts_v3 import (
    CandidateCollection,
    CandidateTypeV3,
    CleanupReceipt,
    CrossReviewSet,
    FindingSet,
    FindingV3,
    VerificationOutcomeSet,
)


class PromotionV3Error(ValueError):
    """The verified collaboration chain cannot be promoted safely."""


_MUTATION_TYPES = frozenset({"unauthorized_graphql_mutation", "privilege_escalation"})

SeverityV3 = Literal["informational", "low", "medium", "high", "critical"]

_PRESENTATION: dict[CandidateTypeV3, tuple[str, str, SeverityV3]] = {
    "missing_x_content_type_options": (
        "Missing X-Content-Type-Options response header",
        "The candidate response omitted X-Content-Type-Options while the matched "
        "negative control returned nosniff.",
        "low",
    ),
    "unauthorized_graphql_mutation": (
        "Unauthorized GraphQL state change",
        "The local fixture accepted a state-changing GraphQL operation without the "
        "required authorization while its strict control rejected it.",
        "high",
    ),
    "privilege_escalation": (
        "Privilege escalation accepted",
        "The local fixture allowed the lower-privileged identity to gain elevated "
        "access while the protected control remained restricted.",
        "high",
    ),
    "exposed_debug_endpoint": (
        "Debug endpoint exposed",
        "The local fixture exposed diagnostic output while the matched control endpoint did not.",
        "medium",
    ),
}


def promote_findings_v3(
    candidates: CandidateCollection,
    reviews: CrossReviewSet,
    outcomes: VerificationOutcomeSet,
    cleanup: CleanupReceipt | None,
    *,
    generated_by_task_id: str = "phase4-promotion",
) -> FindingSet:
    """Recompute a ``FindingSet`` from canonical, independently reviewed facts.

    A finding is emitted only for a canonical candidate whose independent review
    concurred and whose verifier outcome is ``validated``.  Evidence is copied
    verbatim from that outcome; callers cannot add, remove, or replace evidence.
    """

    _require_same_context(candidates, reviews, outcomes, cleanup)
    if reviews.candidate_collection_digest != candidates.digest:
        raise PromotionV3Error("cross reviews do not bind the candidate collection")

    candidate_by_id = {item.candidate_id: item for item in candidates.canonical_candidates}
    review_by_id = {item.candidate_id: item for item in reviews.reviews}
    outcome_by_id = {item.candidate_id: item for item in outcomes.outcomes}

    if set(review_by_id) != set(candidate_by_id):
        raise PromotionV3Error("cross-review set must cover every canonical candidate exactly")
    if not set(outcome_by_id).issubset(candidate_by_id):
        raise PromotionV3Error("verification outcome references an unknown candidate")
    for candidate_id in outcome_by_id:
        if review_by_id[candidate_id].verdict != "concur":
            raise PromotionV3Error("a rejected or inconclusive review cannot be verified")

    promotable_ids = tuple(
        item.candidate_id
        for item in candidates.canonical_candidates
        if review_by_id[item.candidate_id].verdict == "concur"
        and (outcome := outcome_by_id.get(item.candidate_id)) is not None
        and outcome.status == "validated"
    )
    mutation_ids = tuple(
        candidate_id
        for candidate_id in promotable_ids
        if candidate_by_id[candidate_id].candidate_type in _MUTATION_TYPES
    )
    _verify_cleanup(outcomes, cleanup, mutation_ids)

    findings: list[FindingV3] = []
    for candidate_id in promotable_ids:
        candidate = candidate_by_id[candidate_id]
        review = review_by_id[candidate_id]
        outcome = outcome_by_id[candidate_id]
        title, summary, severity = _PRESENTATION[candidate.candidate_type]
        findings.append(
            FindingV3(
                finding_id=candidate_id,
                candidate_id=candidate_id,
                candidate_type=candidate.candidate_type,
                verification_outcome_digest=outcome.digest,
                cross_review_digest=review.digest,
                evidence=outcome.evidence,
                title=title,
                summary=summary,
                severity=severity,
            )
        )

    return FindingSet(
        run_id=candidates.run_id,
        scope_digest=candidates.scope_digest,
        generated_by_task_id=generated_by_task_id,
        finding_set_id="phase4-findings",
        candidate_collection_digest=candidates.digest,
        cross_review_set_digest=reviews.digest,
        verification_outcome_set_digest=outcomes.digest,
        cleanup_receipt_digest=None if cleanup is None else cleanup.digest,
        findings=tuple(findings),
    )


def _require_same_context(
    candidates: CandidateCollection,
    reviews: CrossReviewSet,
    outcomes: VerificationOutcomeSet,
    cleanup: CleanupReceipt | None,
) -> None:
    expected = (candidates.run_id, candidates.scope_digest)
    records = (reviews, outcomes) if cleanup is None else (reviews, outcomes, cleanup)
    if any((record.run_id, record.scope_digest) != expected for record in records):
        raise PromotionV3Error("promotion artifacts cross a run or scope boundary")


def _verify_cleanup(
    outcomes: VerificationOutcomeSet,
    cleanup: CleanupReceipt | None,
    mutation_candidate_ids: tuple[str, ...],
) -> None:
    if not mutation_candidate_ids:
        return
    if cleanup is None:
        raise PromotionV3Error("validated mutation findings require a cleanup receipt")
    if cleanup.campaign_digest != outcomes.campaign_digest:
        raise PromotionV3Error("cleanup receipt does not continue the verification campaign")
    if not cleanup.state_restored:
        raise PromotionV3Error("mutation fixture state was not restored")
    if len(cleanup.results) < len(mutation_candidate_ids):
        raise PromotionV3Error("cleanup receipt does not cover every mutation finding")
    if any(result.status != "cleaned" for result in cleanup.results):
        raise PromotionV3Error("cleanup receipt contains an unresolved mutation")


__all__ = ["PromotionV3Error", "promote_findings_v3"]

"""Host-owned verification campaign and coverage construction for Phase 4 V3.

Agents may propose candidates and review them, but they do not get to choose the
network action graph or report coverage counts.  This module turns the trusted
fan-in artifacts into those two parent-runtime-owned records deterministically.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Literal
from urllib.parse import urljoin, urlsplit, urlunsplit

from .domain_contracts import canonical_digest
from .domain_contracts_v3 import (
    ActionLedgerEntry,
    Branch,
    BranchCandidateV3,
    BranchResult,
    CandidateCollection,
    CanonicalCandidateV3,
    CoverageReportV3,
    CrossReviewSet,
    FindingSet,
    VerificationActionV3,
    VerificationCampaignPlan,
    VerificationOutcomeSet,
)

_BRANCH_ORDER: tuple[Branch, ...] = ("web", "api", "authz", "infra")
_CAMPAIGN_ORDER = (
    "missing_x_content_type_options",
    "exposed_debug_endpoint",
    "unauthorized_graphql_mutation",
    "privilege_escalation",
)
_DIGEST_PREFIX = "sha256:"


class CampaignV3Error(RuntimeError):
    """Trusted V3 artifacts cannot produce a safe deterministic campaign."""


@dataclass(frozen=True, slots=True)
class ActionLedgerSummary:
    """Coverage-safe projection of the final state of every campaign action."""

    actions_planned: int
    actions_executed: int
    actions_blocked: int
    actions_skipped: int
    requests_used: int
    gaps: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if (
            min(
                self.actions_planned,
                self.actions_executed,
                self.actions_blocked,
                self.actions_skipped,
                self.requests_used,
            )
            < 0
        ):
            raise ValueError("action-ledger coverage counts cannot be negative")
        if self.actions_planned != (
            self.actions_executed + self.actions_blocked + self.actions_skipped
        ):
            raise ValueError("action-ledger summary does not conserve planned actions")
        if self.requests_used > self.actions_planned:
            raise ValueError("action-ledger requests cannot exceed planned actions")
        if len(self.gaps) != len(set(self.gaps)):
            raise ValueError("action-ledger gaps must be unique")


@dataclass(frozen=True, slots=True)
class BudgetCoverageSummary:
    """Budget facts already verified by the persistent BudgetLedger."""

    attempts_reserved: int
    attempts_used: int
    estimated_cost_microusd: int
    actual_cost_microusd: int | None = None

    def __post_init__(self) -> None:
        if not 1 <= self.attempts_reserved <= 40:
            raise ValueError("reserved model attempts must be between one and 40")
        if not 1 <= self.attempts_used <= self.attempts_reserved:
            raise ValueError("used model attempts must be covered by reservations")
        if not 0 <= self.estimated_cost_microusd <= 10_000_000:
            raise ValueError("estimated cost exceeds the V3 hard cap")
        if self.actual_cost_microusd is not None and self.actual_cost_microusd < 0:
            raise ValueError("actual cost cannot be negative")


def build_verification_campaign(
    collection: CandidateCollection,
    reviews: CrossReviewSet,
    *,
    endpoint_base: str,
    identity_binding_digests: Mapping[str, str],
    generated_by_task_id: str,
    created_at: datetime,
    expires_at: datetime,
    campaign_id: str = "phase4-campaign",
) -> VerificationCampaignPlan:
    """Build the fixed localhost action graph for independently concurred candidates."""

    _require_same_run(collection, reviews, "cross-review set")
    if reviews.candidate_collection_digest != collection.digest:
        raise CampaignV3Error("cross-review set is not bound to the candidate collection")
    base = _canonical_base(endpoint_base)
    review_by_candidate = {item.candidate_id: item for item in reviews.reviews}
    canonical_by_id = {item.candidate_id: item for item in collection.canonical_candidates}
    if set(review_by_candidate) != set(canonical_by_id):
        raise CampaignV3Error("every canonical candidate requires exactly one cross review")

    raw_by_id = {item.candidate_id: item for item in collection.raw_candidates}
    approved: list[tuple[CanonicalCandidateV3, BranchCandidateV3]] = []
    for canonical in collection.canonical_candidates:
        review = review_by_candidate[canonical.candidate_id]
        if review.producer_branches != canonical.provenance:
            raise CampaignV3Error("cross-review provenance does not match canonical candidate")
        if canonical.status != "candidate" or review.verdict != "concur":
            continue
        source = raw_by_id.get(canonical.source_candidate_ids[0])
        if source is None or source.candidate_type != canonical.candidate_type:
            raise CampaignV3Error("canonical candidate lost its authoritative raw source")
        approved.append((canonical, source))

    actions: list[VerificationActionV3] = []
    for canonical, source in sorted(
        approved,
        key=lambda item: (_CAMPAIGN_ORDER.index(item[0].candidate_type), item[0].candidate_id),
    ):
        actions.extend(
            _candidate_actions(
                run_id=collection.run_id,
                scope_digest=collection.scope_digest,
                candidate_id=canonical.candidate_id,
                candidate_type=canonical.candidate_type,
                source=source,
                base=base,
                identities=identity_binding_digests,
            )
        )
    if len(actions) > 14:
        raise CampaignV3Error("fixed Phase 4 campaign exceeds its 14-action budget")
    return VerificationCampaignPlan(
        run_id=collection.run_id,
        scope_digest=collection.scope_digest,
        generated_by_task_id=generated_by_task_id,
        campaign_id=campaign_id,
        candidate_collection_digest=collection.digest,
        cross_review_set_digest=reviews.digest,
        actions=tuple(actions),
        request_budget=len(actions),
        created_at=created_at,
        expires_at=expires_at,
    )


def summarize_action_ledger(
    campaign: VerificationCampaignPlan,
    entries: tuple[ActionLedgerEntry, ...],
) -> ActionLedgerSummary:
    """Derive conservative final execution counts from a campaign ledger history."""

    known = {item.action_id: item for item in campaign.actions}
    histories: dict[str, list[ActionLedgerEntry]] = {action_id: [] for action_id in known}
    for entry in entries:
        if entry.run_id != campaign.run_id or entry.scope_digest != campaign.scope_digest:
            raise CampaignV3Error("action-ledger entry crosses run or scope")
        action = known.get(entry.action_id)
        if action is None or action.action_digest != entry.action_digest:
            raise CampaignV3Error("action-ledger entry is outside the campaign")
        histories[entry.action_id].append(entry)

    executed = blocked = skipped = requests_used = 0
    gaps: list[str] = []
    transport_states = {
        "transport_started",
        "evidence_committed",
        "failed_after_transport",
        "indeterminate",
        "cleanup_required",
        "cleaned",
    }
    blocked_states = {
        "transport_started",
        "failed_before_transport",
        "failed_after_transport",
        "indeterminate",
        "cleanup_required",
    }
    for action in campaign.actions:
        history = sorted(histories[action.action_id], key=lambda item: item.sequence)
        if not history:
            skipped += 1
            gaps.append(f"action:{action.action_id}:not_started")
            continue
        if len({item.sequence for item in history}) != len(history):
            raise CampaignV3Error("action-ledger sequence is ambiguous")
        final = history[-1]
        if any(item.state in transport_states for item in history):
            requests_used += 1
        if final.state in {"evidence_committed", "cleaned"}:
            if final.state == "cleaned" and not any(
                item.state == "evidence_committed" for item in history
            ):
                raise CampaignV3Error("cleaned action has no committed evidence history")
            executed += 1
        elif final.state in blocked_states:
            blocked += 1
            gaps.append(f"action:{action.action_id}:{final.state}")
        else:
            skipped += 1
            gaps.append(f"action:{action.action_id}:{final.state}")
    return ActionLedgerSummary(
        actions_planned=len(campaign.actions),
        actions_executed=executed,
        actions_blocked=blocked,
        actions_skipped=skipped,
        requests_used=requests_used,
        gaps=tuple(gaps),
    )


def build_coverage_report(
    *,
    collection: CandidateCollection,
    reviews: CrossReviewSet,
    campaign: VerificationCampaignPlan,
    branch_results: tuple[BranchResult, ...],
    outcomes: VerificationOutcomeSet,
    findings: FindingSet,
    action_ledger: ActionLedgerSummary,
    budget: BudgetCoverageSummary,
    active_elapsed_ms: int,
    generated_by_task_id: str,
    cleanup_receipt_digest: str | None = None,
    report_id: str = "phase4-coverage",
) -> CoverageReportV3:
    """Recompute the reportable coverage projection from canonical artifacts."""

    for artifact, label in (
        (reviews, "cross-review set"),
        (campaign, "campaign"),
        (outcomes, "outcome set"),
        (findings, "finding set"),
    ):
        _require_same_run(collection, artifact, label)
    if reviews.candidate_collection_digest != collection.digest:
        raise CampaignV3Error("coverage cross reviews do not bind the collection")
    if (
        campaign.candidate_collection_digest != collection.digest
        or campaign.cross_review_set_digest != reviews.digest
    ):
        raise CampaignV3Error("coverage campaign digest chain is broken")
    if outcomes.campaign_digest != campaign.digest:
        raise CampaignV3Error("coverage outcome set does not bind the campaign")
    if (
        findings.candidate_collection_digest != collection.digest
        or findings.cross_review_set_digest != reviews.digest
        or findings.verification_outcome_set_digest != outcomes.digest
    ):
        raise CampaignV3Error("coverage finding digest chain is broken")
    effective_cleanup = cleanup_receipt_digest or findings.cleanup_receipt_digest
    if findings.cleanup_receipt_digest != effective_cleanup:
        raise CampaignV3Error("coverage cleanup receipt does not match findings")
    if action_ledger.actions_planned != len(campaign.actions):
        raise CampaignV3Error("action-ledger summary does not cover the exact campaign")

    if tuple(item.branch for item in branch_results) != _BRANCH_ORDER:
        raise CampaignV3Error("coverage requires branch results in canonical order")
    if tuple(item.digest for item in branch_results) != collection.branch_result_digests:
        raise CampaignV3Error("coverage branch results do not match candidate fan-in")
    for result in branch_results:
        if result.run_id != collection.run_id or result.scope_digest != collection.scope_digest:
            raise CampaignV3Error("branch result crosses run or scope")
    successful = {item.branch for item in branch_results if item.status == "succeeded"}
    if any(
        not set(item.provenance).issubset(successful) for item in collection.canonical_candidates
    ):
        raise CampaignV3Error("failed or unrouted branch contributed a canonical candidate")

    review_by_candidate = {item.candidate_id: item for item in reviews.reviews}
    outcome_by_candidate = {item.candidate_id: item for item in outcomes.outcomes}
    canonical_ids = {item.candidate_id for item in collection.canonical_candidates}
    if set(review_by_candidate) != canonical_ids:
        raise CampaignV3Error("coverage requires one cross review per canonical candidate")
    if not set(outcome_by_candidate).issubset(canonical_ids):
        raise CampaignV3Error("outcome set contains an unknown candidate")

    status_counts = {name: 0 for name in ("validated", "disproved", "inconclusive", "blocked")}
    gaps: list[str] = []
    for result in sorted(branch_results, key=lambda item: _BRANCH_ORDER.index(item.branch)):
        if result.status in {"failed", "timed_out"}:
            gaps.append(f"branch:{result.branch}:{result.status}:{result.reason}")
    for candidate in collection.canonical_candidates:
        review = review_by_candidate[candidate.candidate_id]
        if review.verdict == "reject":
            status_counts["blocked"] += 1
            gaps.append(f"candidate:{candidate.candidate_id}:cross_review_rejected")
            continue
        if review.verdict == "needs_more_evidence":
            status_counts["inconclusive"] += 1
            gaps.append(f"candidate:{candidate.candidate_id}:needs_more_evidence")
            continue
        outcome = outcome_by_candidate.get(candidate.candidate_id)
        if outcome is None:
            status_counts["blocked"] += 1
            gaps.append(f"candidate:{candidate.candidate_id}:missing_outcome")
            continue
        status_counts[outcome.status] += 1
        if outcome.status in {"blocked", "inconclusive"}:
            gaps.append(f"candidate:{candidate.candidate_id}:{outcome.status}")

    validated_ids = {
        candidate_id
        for candidate_id, outcome in outcome_by_candidate.items()
        if outcome.status == "validated"
    }
    if {item.candidate_id for item in findings.findings} != validated_ids:
        raise CampaignV3Error("findings must exactly match validated candidate outcomes")
    gaps.extend(action_ledger.gaps)
    gaps_tuple = tuple(dict.fromkeys(gaps))
    routed = [item for item in branch_results if item.status != "not_routed"]
    duplicates = sum(len(item.merged_candidate_ids) - 1 for item in collection.dedup_decisions)
    return CoverageReportV3(
        run_id=collection.run_id,
        scope_digest=collection.scope_digest,
        generated_by_task_id=generated_by_task_id,
        report_id=report_id,
        route_decision_digest=collection.route_decision_digest,
        candidate_collection_digest=collection.digest,
        cross_review_set_digest=reviews.digest,
        campaign_digest=campaign.digest,
        outcome_set_digest=outcomes.digest,
        finding_set_digest=findings.digest,
        cleanup_receipt_digest=effective_cleanup,
        branches_routed=len(routed),
        branches_succeeded=sum(item.status == "succeeded" for item in routed),
        branches_failed=sum(item.status == "failed" for item in routed),
        branches_timed_out=sum(item.status == "timed_out" for item in routed),
        raw_candidates=len(collection.raw_candidates),
        canonical_candidates=len(collection.canonical_candidates),
        duplicate_candidates=duplicates,
        raw_blocked_or_inconclusive=collection.raw_blocked_or_inconclusive,
        candidates_validated=status_counts["validated"],
        candidates_disproved=status_counts["disproved"],
        candidates_inconclusive=status_counts["inconclusive"],
        candidates_blocked=status_counts["blocked"],
        actions_planned=action_ledger.actions_planned,
        actions_executed=action_ledger.actions_executed,
        actions_blocked=action_ledger.actions_blocked,
        actions_skipped=action_ledger.actions_skipped,
        requests_planned=campaign.request_budget + 1,
        requests_used=action_ledger.requests_used + 1,
        model_attempts_reserved=budget.attempts_reserved,
        model_attempts_used=budget.attempts_used,
        estimated_cost_microusd=budget.estimated_cost_microusd,
        actual_cost_microusd=budget.actual_cost_microusd,
        active_elapsed_ms=active_elapsed_ms,
        completion="completed_with_gaps" if gaps_tuple else "completed",
        gaps=gaps_tuple,
    )


def _candidate_actions(
    *,
    run_id: str,
    scope_digest: str,
    candidate_id: str,
    candidate_type: str,
    source: BranchCandidateV3,
    base: str,
    identities: Mapping[str, str],
) -> tuple[VerificationActionV3, ...]:
    _require_same_origin(base, source.target_url)
    if candidate_type == "missing_x_content_type_options":
        return _readonly_pair(
            run_id,
            scope_digest,
            candidate_id,
            source.target_url,
            urljoin(base, "control"),
        )
    if candidate_type == "exposed_debug_endpoint":
        return _readonly_pair(
            run_id,
            scope_digest,
            candidate_id,
            source.target_url,
            urljoin(base, "debug-control"),
        )
    member = _identity(identities, "member")
    administrator = _identity(identities, "fixture-admin")
    if candidate_type == "unauthorized_graphql_mutation":
        return _api_actions(
            run_id=run_id,
            scope_digest=scope_digest,
            candidate_id=candidate_id,
            base=base,
            member_identity=member,
            administrator_identity=administrator,
            source=source,
        )
    if candidate_type == "privilege_escalation":
        return _authz_actions(
            run_id=run_id,
            scope_digest=scope_digest,
            candidate_id=candidate_id,
            base=base,
            member_identity=member,
            administrator_identity=administrator,
            source=source,
        )
    raise CampaignV3Error(f"unsupported Phase 4 candidate type: {candidate_type}")


def _readonly_pair(
    run_id: str,
    scope_digest: str,
    candidate_id: str,
    target_url: str,
    control_url: str,
) -> tuple[VerificationActionV3, ...]:
    target_id = f"verify-{candidate_id}-candidate"
    target = _action(
        run_id,
        scope_digest,
        target_id,
        candidate_id,
        "candidate",
        "readonly",
        "GET",
        target_url,
    )
    control = _action(
        run_id,
        scope_digest,
        f"verify-{candidate_id}-negative-control",
        candidate_id,
        "negative_control",
        "readonly",
        "GET",
        control_url,
        depends_on=(target_id,),
    )
    return target, control


def _api_actions(
    *,
    run_id: str,
    scope_digest: str,
    candidate_id: str,
    base: str,
    member_identity: str,
    administrator_identity: str,
    source: BranchCandidateV3,
) -> tuple[VerificationActionV3, ...]:
    state_url = urljoin(base, "graphql")
    forward_url = urljoin(base, "graphql/mutate")
    if source.target_url != forward_url:
        raise CampaignV3Error("GraphQL candidate does not bind the fixed fixture mutation endpoint")
    if source.request_body_sha256 != materialized_body_digest(
        "unauthorized_graphql_mutation", "candidate"
    ):
        raise CampaignV3Error("GraphQL candidate body does not match the parent materializer")
    baseline_id = f"verify-{candidate_id}-baseline"
    forward_id = f"verify-{candidate_id}-candidate"
    negative_id = f"verify-{candidate_id}-negative-control"
    cleanup_id = f"verify-{candidate_id}-cleanup"
    baseline = _action(
        run_id,
        scope_digest,
        baseline_id,
        candidate_id,
        "baseline",
        "mutation",
        "GET",
        state_url,
        identity=member_identity,
    )
    forward = _action(
        run_id,
        scope_digest,
        forward_id,
        candidate_id,
        "candidate",
        "mutation",
        "POST",
        forward_url,
        body=materialized_body_digest("unauthorized_graphql_mutation", "candidate"),
        identity=member_identity,
        depends_on=(baseline_id,),
    )
    negative = _action(
        run_id,
        scope_digest,
        negative_id,
        candidate_id,
        "negative_control",
        "mutation",
        "POST",
        urljoin(base, "graphql/control"),
        body=materialized_body_digest("unauthorized_graphql_mutation", "negative_control"),
        identity=member_identity,
        depends_on=(forward_id,),
    )
    cleanup = _action(
        run_id,
        scope_digest,
        cleanup_id,
        candidate_id,
        "cleanup",
        "mutation",
        "POST",
        urljoin(base, "graphql/cleanup"),
        body=materialized_body_digest("unauthorized_graphql_mutation", "cleanup"),
        identity=administrator_identity,
        depends_on=(forward_id,),
        cleanup_of=forward_id,
    )
    cleanup_check = _action(
        run_id,
        scope_digest,
        f"verify-{candidate_id}-cleanup-check",
        candidate_id,
        "cleanup_check",
        "mutation",
        "GET",
        state_url,
        identity=member_identity,
        depends_on=(cleanup_id,),
    )
    return baseline, forward, negative, cleanup, cleanup_check


def _authz_actions(
    *,
    run_id: str,
    scope_digest: str,
    candidate_id: str,
    base: str,
    member_identity: str,
    administrator_identity: str,
    source: BranchCandidateV3,
) -> tuple[VerificationActionV3, ...]:
    state_url = urljoin(base, "authz/status")
    forward_url = urljoin(base, "authz/elevate")
    if source.target_url != forward_url:
        raise CampaignV3Error("Authz candidate does not bind the fixed fixture elevation endpoint")
    if source.request_body_sha256 != materialized_body_digest("privilege_escalation", "candidate"):
        raise CampaignV3Error("Authz candidate body does not match the parent materializer")
    baseline_id = f"verify-{candidate_id}-baseline"
    forward_id = f"verify-{candidate_id}-candidate"
    cleanup_id = f"verify-{candidate_id}-cleanup"
    baseline = _action(
        run_id,
        scope_digest,
        baseline_id,
        candidate_id,
        "baseline",
        "mutation",
        "GET",
        state_url,
        identity=member_identity,
    )
    forward = _action(
        run_id,
        scope_digest,
        forward_id,
        candidate_id,
        "candidate",
        "mutation",
        "POST",
        forward_url,
        body=materialized_body_digest("privilege_escalation", "candidate"),
        identity=member_identity,
        depends_on=(baseline_id,),
    )
    negative = _action(
        run_id,
        scope_digest,
        f"verify-{candidate_id}-negative-control",
        candidate_id,
        "negative_control",
        "mutation",
        "GET",
        urljoin(base, "authz/admin"),
        identity=member_identity,
        depends_on=(forward_id,),
    )
    cleanup = _action(
        run_id,
        scope_digest,
        cleanup_id,
        candidate_id,
        "cleanup",
        "mutation",
        "POST",
        urljoin(base, "authz/revoke"),
        body=materialized_body_digest("privilege_escalation", "cleanup"),
        identity=administrator_identity,
        depends_on=(forward_id,),
        cleanup_of=forward_id,
    )
    cleanup_check = _action(
        run_id,
        scope_digest,
        f"verify-{candidate_id}-cleanup-check",
        candidate_id,
        "cleanup_check",
        "mutation",
        "GET",
        state_url,
        identity=member_identity,
        depends_on=(cleanup_id,),
    )
    return baseline, forward, negative, cleanup, cleanup_check


def _action(
    run_id: str,
    scope_digest: str,
    action_id: str,
    candidate_id: str,
    purpose: Literal["baseline", "candidate", "negative_control", "cleanup", "cleanup_check"],
    risk_group: Literal["readonly", "mutation"],
    method: Literal["GET", "POST"],
    target_url: str,
    *,
    body: str | None = None,
    identity: str | None = None,
    depends_on: tuple[str, ...] = (),
    cleanup_of: str | None = None,
) -> VerificationActionV3:
    authority = {
        "run_id": run_id,
        "scope_digest": scope_digest,
        "candidate_consumers": (candidate_id,),
        "purpose": purpose,
        "risk_group": risk_group,
        "method": method,
        "target_url": target_url,
        "body_sha256": body,
        "identity_binding_digest": identity,
        "depends_on": depends_on,
        "cleanup_of": cleanup_of,
    }
    return VerificationActionV3(
        action_id=action_id,
        candidate_id=candidate_id,
        candidate_consumers=(candidate_id,),
        purpose=purpose,
        risk_group=risk_group,
        action_kind="validation_http_get" if method == "GET" else "validation_http_request",
        method=method,
        target_url=target_url,
        body_sha256=body,
        identity_binding_digest=identity,
        action_digest=canonical_digest(authority),
        depends_on=depends_on,
        cleanup_of=cleanup_of,
    )


def _canonical_base(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname != "localhost"
        or parsed.port is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise CampaignV3Error("campaign endpoint base must be an absolute localhost URL")
    return urlunsplit((parsed.scheme, parsed.netloc, "/", "", ""))


def _require_same_origin(base: str, target: str) -> None:
    expected = urlsplit(base)
    observed = urlsplit(target)
    if (observed.scheme, observed.hostname, observed.port) != (
        expected.scheme,
        expected.hostname,
        expected.port,
    ):
        raise CampaignV3Error("candidate target crosses the campaign fixture origin")


def _identity(values: Mapping[str, str], alias: str) -> str:
    value = values.get(alias)
    if value is None or not _valid_digest(value):
        raise CampaignV3Error(f"mutation campaign requires a valid {alias} identity binding")
    return value


def materialize_request_body(candidate_type: str, purpose: str) -> bytes | None:
    """Return the only request bytes authorized by the fixed Phase 4 fixture graph."""

    payloads: dict[tuple[str, str], dict[str, str]] = {
        ("unauthorized_graphql_mutation", "candidate"): {"value": "mutated"},
        ("unauthorized_graphql_mutation", "negative_control"): {"value": "blocked"},
        ("unauthorized_graphql_mutation", "cleanup"): {},
        ("privilege_escalation", "candidate"): {},
        ("privilege_escalation", "cleanup"): {},
    }
    payload = payloads.get((candidate_type, purpose))
    if payload is None:
        return None
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def materialized_body_digest(candidate_type: str, purpose: str) -> str | None:
    """Hash canonical body bytes exactly as the transport materializer emits them."""

    body = materialize_request_body(candidate_type, purpose)
    if body is None:
        return None
    return _DIGEST_PREFIX + hashlib.sha256(body).hexdigest()


def _valid_digest(value: str) -> bool:
    return (
        len(value) == 71
        and value.startswith(_DIGEST_PREFIX)
        and all(item in "0123456789abcdef" for item in value[7:])
    )


def _require_same_run(collection: CandidateCollection, artifact: object, label: str) -> None:
    run_id = getattr(artifact, "run_id", None)
    scope_digest = getattr(artifact, "scope_digest", None)
    if run_id != collection.run_id or scope_digest != collection.scope_digest:
        raise CampaignV3Error(f"{label} crosses run or scope")


__all__ = [
    "ActionLedgerSummary",
    "BudgetCoverageSummary",
    "CampaignV3Error",
    "build_coverage_report",
    "build_verification_campaign",
    "materialize_request_body",
    "materialized_body_digest",
    "summarize_action_ledger",
]

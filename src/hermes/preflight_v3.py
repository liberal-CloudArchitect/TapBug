"""Fail-closed Phase 4 report authorization and atomic formal output.

V3 reporting is deliberately a two-stage boundary.  The launch preflight
reconstructs the canonical collaboration campaign and reserves the Reporter
model attempt.  After the Reporter returns, the write preflight repeats the
same checks and supplies the already-atomic reporting boundary with only fresh,
verified records.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TypeVar

from pydantic import BaseModel

from .campaign_v3 import (
    ActionLedgerSummary,
    BudgetCoverageSummary,
    CampaignV3Error,
    build_coverage_report,
    build_verification_campaign,
)
from .collaboration_v3 import (
    BRANCH_ORDER,
    CandidateFanIn,
    CollaborationV3Error,
    RoutePolicy,
    assign_cross_reviewers,
)
from .domain_contracts import canonical_digest
from .domain_contracts_v3 import (
    ApprovalBatchV3,
    Branch,
    BranchAssessment,
    BranchResult,
    CandidateCollection,
    CleanupReceipt,
    CoverageReportV3,
    CrossReviewSet,
    EndpointInventoryV3,
    FindingSet,
    ReporterAckV3,
    ReporterLaunchReceiptV3,
    RiskGroup,
    RouteDecision,
    RunPlanV3,
    SignedReviewBatchV3,
    VerificationCampaignPlan,
    VerificationOutcomeSet,
)
from .evidence import EvidenceArtifactManifest, EvidenceArtifactRef, EvidenceStore
from .execution_v3 import ApprovalConsumptionV3, ExecutionResultV3
from .ledgers_v3 import (
    ActionLedger,
    ActiveTimeLedger,
    BudgetLedger,
    BudgetReservation,
    LedgerError,
)
from .promotion_v3 import PromotionV3Error, promote_findings_v3
from .providers.acp import provider_metadata_authority_digest
from .reporting_v3 import VerifiedReportWriteV3, write_report_v3
from .runtime import RunContext
from .security_v3 import (
    approval_actions_v3,
    cleanup_challenge_payload_v3,
    coverage_gap_digests,
)

_Model = TypeVar("_Model", bound=BaseModel)
ApprovalSignatureVerifier = Callable[[ApprovalBatchV3, VerificationCampaignPlan], None]
ReviewSignatureVerifier = Callable[[SignedReviewBatchV3, FindingSet, CoverageReportV3], None]


class ReportPreflightV3Error(ValueError):
    """Canonical V3 artifacts do not authorize Reporter or formal output."""


@dataclass(frozen=True, slots=True)
class VerifiedReportBundleV3:
    plan: RunPlanV3
    endpoints: EndpointInventoryV3
    route: RouteDecision
    branch_results: tuple[BranchResult, ...]
    assessments: Mapping[Branch, BranchAssessment]
    candidates: CandidateCollection
    reviews: CrossReviewSet
    campaign: VerificationCampaignPlan
    approvals: tuple[ApprovalBatchV3, ...]
    outcomes: VerificationOutcomeSet
    cleanup: CleanupReceipt | None
    findings: FindingSet
    coverage: CoverageReportV3
    signed_review: SignedReviewBatchV3
    evidence: tuple[EvidenceArtifactManifest, ...]
    action_ledger_head: str
    budget_ledger_head: str
    reporter_reservation: BudgetReservation


class ReportPreflightVerifierV3:
    """Recompute the V3 authority graph from one canonical run directory."""

    RUN_PLAN = "plan/run-v3.json"
    ENDPOINTS = "endpoints/inventory-v3.json"
    ROUTE = "collaboration_v3/route.json"
    ASSESSMENTS = "collaboration_v3/assessments"
    BRANCH_RESULTS = "collaboration_v3/branch-results"
    CANDIDATES = "collaboration_v3/candidates.json"
    REVIEWS = "collaboration_v3/cross-reviews.json"
    CAMPAIGN = "verification_v3/campaign.json"
    APPROVALS = "approvals_v3"
    OUTCOMES = "verification_v3/outcomes.json"
    CLEANUP = "verification_v3/cleanup.json"
    FINDINGS = "report/finding-set-v3.json"
    COVERAGE = "report/coverage-v3.json"
    DRAFT = "report/draft-v3.md"
    SIGNED_REVIEW = "reviews/signed-v3.json"
    LAUNCH_RECEIPT = "report/reporter-launch-v3.json"
    REPORTER_ACK = "report/reporter-ack-v3.json"
    FORMAL_DIR = "report/formal-v3"
    REPORTER_TASK_ID = "phase4-reporter"
    REPORTER_RESERVATION_ID = "phase4-reporter:reporter"

    def __init__(
        self,
        context: RunContext,
        *,
        approval_signature_verifier: ApprovalSignatureVerifier,
        review_signature_verifier: ReviewSignatureVerifier,
        evidence_store: EvidenceStore | None = None,
        route_policy: RoutePolicy | None = None,
    ) -> None:
        self.context = context
        self.approval_signature_verifier = approval_signature_verifier
        self.review_signature_verifier = review_signature_verifier
        self.evidence_store = evidence_store or EvidenceStore(context.path)
        self.route_policy = route_policy or RoutePolicy()

    def authorize_reporter(self) -> ReporterLaunchReceiptV3:
        """Reserve Reporter only after all non-Reporter authority has verified."""

        try:
            # This pass intentionally permits the Reporter reservation to be absent.
            self._verify_pre_reservation()
            reservation = BudgetLedger(self.context).reserve_prompt(
                task_id=self.REPORTER_TASK_ID,
                role="reporter",
                attempt_kind="reporter",
                reservation_id=self.REPORTER_RESERVATION_ID,
            )
            bundle = self._verify_core(reservation)
            receipt = self._launch_receipt(bundle)
            self.context.write_json(
                self.LAUNCH_RECEIPT,
                receipt.model_dump(mode="json"),
                immutable=True,
            )
            return receipt
        except ReportPreflightV3Error:
            raise
        except (OSError, ValueError, LedgerError, CampaignV3Error, CollaborationV3Error) as exc:
            raise ReportPreflightV3Error(f"V3 Reporter launch preflight failed: {exc}") from exc

    def verify_launch(self) -> VerifiedReportBundleV3:
        """Recheck a previously authorized launch without mutating artifacts."""

        try:
            stored = self._read(self.LAUNCH_RECEIPT, ReporterLaunchReceiptV3)
            reservation = self._reporter_reservation()
            bundle = self._verify_core(
                reservation,
                allow_reporter_provider=self.context.artifact_path(
                    f"provider/{self.REPORTER_TASK_ID}.json"
                ).exists(),
            )
            budget_events = BudgetLedger(self.context).events()
            self._verify_launch_budget_ancestor(stored, budget_events)
            launch_bundle = replace(bundle, budget_ledger_head=stored.budget_ledger_head_digest)
            expected = self._launch_receipt(launch_bundle, verified_at=stored.verified_at)
            if stored != expected:
                raise ReportPreflightV3Error(
                    "Reporter launch receipt does not match a fresh V3 preflight"
                )
            return bundle
        except ReportPreflightV3Error:
            raise
        except (OSError, ValueError, LedgerError, CampaignV3Error, CollaborationV3Error) as exc:
            raise ReportPreflightV3Error(f"V3 Reporter launch verification failed: {exc}") from exc

    def write_report(self, reporter_ack: ReporterAckV3 | None = None) -> Path:
        """Compatibility convenience over the canonical V3 report writer."""

        ack = reporter_ack or self._read(self.REPORTER_ACK, ReporterAckV3)
        return write_report_v3(self.context, self, ack)

    def verify_for_write(self, reporter_ack: ReporterAckV3) -> VerifiedReportWriteV3:
        """Implement the reporting boundary's fresh final-preflight protocol."""

        try:
            canonical_ack = self._read(self.REPORTER_ACK, ReporterAckV3)
            if reporter_ack != canonical_ack:
                raise ReportPreflightV3Error(
                    "caller Reporter acknowledgement differs from the canonical artifact"
                )
            bundle = self.verify_launch()
            launch = self._read(self.LAUNCH_RECEIPT, ReporterLaunchReceiptV3)
            self._verify_reporter_ack(bundle, launch, reporter_ack)

            # Reporter metadata settlement changes the budget journal head.  Re-read
            # every ledger after acknowledgement verification and before rendering.
            action_events = ActionLedger(self.context).events()
            budget = BudgetLedger(self.context)
            budget_events = budget.events()
            self._verify_reporter_budget_settled(budget_events, reporter_ack)
            self._verify_no_orphans(bundle, include_reporter=True)
            # Preserve the action read as a final integrity assertion.  A concurrent
            # action mutation would be visible through the run lock at commit time.
            if _journal_head(action_events, "action") != bundle.action_ledger_head:
                raise ReportPreflightV3Error("action ledger changed after launch preflight")
            return VerifiedReportWriteV3(
                launch_receipt=launch,
                finding_set=bundle.findings,
                coverage=bundle.coverage,
                provider_metadata_digest=reporter_ack.provider_metadata_digest,
                final_budget_ledger_head_digest=_journal_head(budget_events, "budget"),
            )
        except ReportPreflightV3Error:
            raise
        except (
            OSError,
            ValueError,
            LedgerError,
            CampaignV3Error,
            CollaborationV3Error,
        ) as exc:
            raise ReportPreflightV3Error(f"V3 final report preflight failed: {exc}") from exc

    def _verify_pre_reservation(self) -> None:
        """Verify the graph before creating the sole allowed missing reservation."""

        budget = BudgetLedger(self.context)
        events = budget.events()
        reporter = _reservation_event(events, self.REPORTER_RESERVATION_ID)
        if reporter is not None:
            self._verify_core(self._reservation_from_event(reporter))
            return
        self._verify_graph(
            action_events=ActionLedger(self.context).events(),
            budget_events=events,
            reporter_reservation=None,
        )

    def _verify_core(
        self,
        reservation: BudgetReservation,
        *,
        allow_reporter_provider: bool = False,
    ) -> VerifiedReportBundleV3:
        bundle = self._verify_graph(
            action_events=ActionLedger(self.context).events(),
            budget_events=BudgetLedger(self.context).events(),
            reporter_reservation=reservation,
            allow_reporter_provider=allow_reporter_provider,
        )
        if bundle is None:  # pragma: no cover - reporter reservation makes this impossible
            raise ReportPreflightV3Error("Reporter reservation was not reflected in preflight")
        return bundle

    def _verify_graph(
        self,
        *,
        action_events: tuple[dict[str, Any], ...],
        budget_events: tuple[dict[str, Any], ...],
        reporter_reservation: BudgetReservation | None,
        allow_reporter_provider: bool = False,
    ) -> VerifiedReportBundleV3 | None:
        plan = self._read(self.RUN_PLAN, RunPlanV3)
        endpoints = self._read(self.ENDPOINTS, EndpointInventoryV3)
        route = self._read(self.ROUTE, RouteDecision)
        branch_results = tuple(
            self._read(f"{self.BRANCH_RESULTS}/{branch}.json", BranchResult)
            for branch in BRANCH_ORDER
        )
        candidates = self._read(self.CANDIDATES, CandidateCollection)
        reviews = self._read(self.REVIEWS, CrossReviewSet)
        campaign = self._read(self.CAMPAIGN, VerificationCampaignPlan)
        outcomes = self._read(self.OUTCOMES, VerificationOutcomeSet)
        findings = self._read(self.FINDINGS, FindingSet)
        coverage = self._read(self.COVERAGE, CoverageReportV3)
        signed_review = self._read(self.SIGNED_REVIEW, SignedReviewBatchV3)
        cleanup = self._read_optional(self.CLEANUP, CleanupReceipt)
        approvals = self._load_approvals(campaign)
        assessments = self._load_assessments(branch_results)

        run_bound: Sequence[object] = (
            endpoints,
            route,
            *branch_results,
            *assessments.values(),
            candidates,
            reviews,
            campaign,
            *approvals,
            outcomes,
            findings,
            coverage,
            signed_review,
            *(() if cleanup is None else (cleanup,)),
        )
        if plan.run_id != self.context.run_id or plan.scope_digest != self.context.scope_digest:
            raise ReportPreflightV3Error("V3 RunPlan crosses the canonical run or scope")
        for artifact in run_bound:
            if (
                getattr(artifact, "run_id", None) != self.context.run_id
                or getattr(artifact, "scope_digest", None) != self.context.scope_digest
            ):
                raise ReportPreflightV3Error("a V3 artifact crosses the run or scope boundary")

        self._verify_active_time(plan, coverage)

        expected_route = self.route_policy.decide(
            endpoints,
            run_id=self.context.run_id,
            scope_digest=self.context.scope_digest,
            generated_by_task_id=route.generated_by_task_id,
            identity_binding_digests=tuple(sorted(plan.identity_binding_digests.values())),
        )
        if route != expected_route:
            raise ReportPreflightV3Error("RouteDecision is not reproducible from trusted inputs")

        expected_candidates = CandidateFanIn().merge(
            route=route,
            inventory=endpoints,
            identity_binding_digests=plan.identity_binding_digests,
            branch_results=branch_results,
            assessments=dict(assessments),
            generated_by_task_id=candidates.generated_by_task_id,
        )
        if candidates != expected_candidates:
            raise ReportPreflightV3Error("candidate fan-in or deduplication cannot be reproduced")
        self._verify_cross_reviews(candidates, reviews)

        expected_campaign = build_verification_campaign(
            candidates,
            reviews,
            endpoint_base=plan.target,
            identity_binding_digests=plan.identity_binding_digests,
            generated_by_task_id=campaign.generated_by_task_id,
            created_at=campaign.created_at,
            expires_at=campaign.expires_at,
            campaign_id=campaign.campaign_id,
        )
        if campaign != expected_campaign:
            raise ReportPreflightV3Error("verification campaign is not deterministically derived")
        self._verify_approvals(approvals, campaign, outcomes)
        self._verify_cleanup(campaign, outcomes, cleanup, findings, coverage)
        self._verify_findings(candidates, reviews, outcomes, cleanup, findings)

        evidence_refs = self._expected_evidence_refs(endpoints, outcomes, cleanup, findings)
        manifests = tuple(self.evidence_store.verify(ref) for ref in evidence_refs)
        consumptions = self._load_consumptions()
        self._verify_evidence_bindings(
            campaign,
            approvals,
            outcomes,
            action_events,
            evidence_refs,
            manifests,
            consumptions,
            cleanup,
        )
        self._verify_execution_artifacts(campaign, action_events)

        action_summary = self._action_summary(campaign, action_events)
        budget_summary = self._budget_summary(plan, budget_events, reporter_reservation)
        expected_coverage = build_coverage_report(
            collection=candidates,
            reviews=reviews,
            campaign=campaign,
            branch_results=branch_results,
            outcomes=outcomes,
            findings=findings,
            action_ledger=action_summary,
            budget=budget_summary,
            active_elapsed_ms=coverage.active_elapsed_ms,
            generated_by_task_id=coverage.generated_by_task_id,
            cleanup_receipt_digest=None if cleanup is None else cleanup.digest,
            report_id=coverage.report_id,
        )
        if coverage != expected_coverage:
            raise ReportPreflightV3Error("CoverageReportV3 cannot be recomputed from ledgers")
        self._verify_human_review(findings, coverage, signed_review)
        self._verify_provider_metadata(
            endpoints, branch_results, assessments, reviews, outcomes, budget_events
        )

        if reporter_reservation is None:
            self._verify_no_orphans_partial(
                branch_results, assessments, approvals, evidence_refs, allow_launch=False
            )
            return None
        action_head = _journal_head(action_events, "action")
        budget_head = _journal_head(budget_events, "budget")
        bundle = VerifiedReportBundleV3(
            plan=plan,
            endpoints=endpoints,
            route=route,
            branch_results=branch_results,
            assessments=assessments,
            candidates=candidates,
            reviews=reviews,
            campaign=campaign,
            approvals=approvals,
            outcomes=outcomes,
            cleanup=cleanup,
            findings=findings,
            coverage=coverage,
            signed_review=signed_review,
            evidence=manifests,
            action_ledger_head=action_head,
            budget_ledger_head=budget_head,
            reporter_reservation=reporter_reservation,
        )
        self._verify_no_orphans(bundle, include_reporter=allow_reporter_provider)
        return bundle

    def _verify_active_time(self, plan: RunPlanV3, coverage: CoverageReportV3) -> None:
        try:
            active_time = ActiveTimeLedger(
                self.context, max_active_seconds=plan.budget.max_active_seconds
            )
            active_time.assert_within_budget()
            coverage_snapshot = active_time.snapshot("coverage-v3")
        except LedgerError as exc:
            raise ReportPreflightV3Error(
                "active execution time ledger is invalid or exhausted"
            ) from exc
        if coverage.active_elapsed_ms != coverage_snapshot.active_elapsed_ms:
            raise ReportPreflightV3Error(
                "CoverageReportV3 active elapsed time does not match its ledger snapshot"
            )

    def _verify_cross_reviews(
        self, candidates: CandidateCollection, reviews: CrossReviewSet
    ) -> None:
        if reviews.candidate_collection_digest != candidates.digest:
            raise ReportPreflightV3Error("cross reviews do not bind the candidate collection")
        assignments = assign_cross_reviewers(candidates)
        by_candidate = {item.candidate_id: item for item in reviews.reviews}
        expected_ids = {item.candidate_id for item in candidates.canonical_candidates}
        if set(by_candidate) != expected_ids:
            raise ReportPreflightV3Error("cross reviews must cover every canonical candidate")
        for candidate in candidates.canonical_candidates:
            review = by_candidate[candidate.candidate_id]
            if (
                review.producer_branches != candidate.provenance
                or review.reviewer_branch != assignments[candidate.candidate_id]
                or review.reviewer_task_id != f"phase4-review-{candidate.candidate_id}"
            ):
                raise ReportPreflightV3Error("cross-review assignment or provenance was altered")

    def _verify_approvals(
        self,
        approvals: tuple[ApprovalBatchV3, ...],
        campaign: VerificationCampaignPlan,
        outcomes: VerificationOutcomeSet,
    ) -> None:
        approved = tuple(item for item in approvals if item.verdict == "approved")
        for batch in approvals:
            if batch.campaign_digest != campaign.digest:
                raise ReportPreflightV3Error("approval batch is bound to another campaign")
            self.approval_signature_verifier(batch, campaign)
        expected = tuple(sorted(item.digest for item in approved if item.risk_group != "cleanup"))
        if tuple(sorted(outcomes.approval_batch_digests)) != expected:
            raise ReportPreflightV3Error("outcomes do not bind the exact approved batch set")
        action_by_digest = {item.action_digest: item for item in campaign.actions}
        approved_actions: set[str] = set()
        for batch in approved:
            eligible = approval_actions_v3(campaign, batch.risk_group)
            selected = {item.candidate_id for item in eligible} & set(batch.candidate_ids)
            exact = {item.action_digest for item in eligible if item.candidate_id in selected}
            if set(batch.action_digests) != exact:
                raise ReportPreflightV3Error("approval does not bind an all-or-none action graph")
            approved_actions.update(batch.action_digests)
        for outcome in outcomes.outcomes:
            if not set(outcome.action_digests) <= approved_actions:
                raise ReportPreflightV3Error("outcome contains an unapproved action")
            if any(value not in action_by_digest for value in outcome.action_digests):
                raise ReportPreflightV3Error("outcome action is outside the campaign")

    def _verify_cleanup(
        self,
        campaign: VerificationCampaignPlan,
        outcomes: VerificationOutcomeSet,
        cleanup: CleanupReceipt | None,
        findings: FindingSet,
        coverage: CoverageReportV3,
    ) -> None:
        mutation_attempted = any(
            action.risk_group in {"mutation", "cleanup"}
            and action.action_digest
            in {digest for outcome in outcomes.outcomes for digest in outcome.action_digests}
            for action in campaign.actions
        )
        if mutation_attempted:
            if cleanup is None or not cleanup.state_restored:
                raise ReportPreflightV3Error("mutation reporting requires proven state restoration")
            if cleanup.campaign_digest != campaign.digest:
                raise ReportPreflightV3Error("cleanup receipt is bound to another campaign")
            action_by_digest = {item.action_digest: item for item in campaign.actions}
            outcome_actions = {
                digest for outcome in outcomes.outcomes for digest in outcome.action_digests
            }
            expected_forwards = {
                item.action_digest
                for item in campaign.actions
                if item.risk_group == "mutation"
                and item.purpose == "candidate"
                and item.action_digest in outcome_actions
            }
            by_forward = {item.forward_action_digest: item for item in cleanup.results}
            if set(by_forward) != expected_forwards:
                raise ReportPreflightV3Error(
                    "cleanup receipt does not exactly cover attempted mutation candidates"
                )
            for forward_digest, result in by_forward.items():
                forward = action_by_digest.get(forward_digest)
                cleanup_action = action_by_digest.get(result.cleanup_action_digest)
                check_action = action_by_digest.get(result.cleanup_check_action_digest)
                if (
                    forward is None
                    or cleanup_action is None
                    or check_action is None
                    or cleanup_action.candidate_id != forward.candidate_id
                    or check_action.candidate_id != forward.candidate_id
                    or cleanup_action.purpose != "cleanup"
                    or check_action.purpose != "cleanup_check"
                    or cleanup_action.cleanup_of != forward.action_id
                ):
                    raise ReportPreflightV3Error("cleanup receipt action graph was altered")
        expected = None if cleanup is None else cleanup.digest
        if (
            findings.cleanup_receipt_digest != expected
            or coverage.cleanup_receipt_digest != expected
        ):
            raise ReportPreflightV3Error("cleanup receipt digest chain is broken")

    def _verify_findings(
        self,
        candidates: CandidateCollection,
        reviews: CrossReviewSet,
        outcomes: VerificationOutcomeSet,
        cleanup: CleanupReceipt | None,
        findings: FindingSet,
    ) -> None:
        if (
            findings.candidate_collection_digest != candidates.digest
            or findings.cross_review_set_digest != reviews.digest
            or findings.verification_outcome_set_digest != outcomes.digest
        ):
            raise ReportPreflightV3Error("FindingSet digest chain is broken")
        review_by_id = {item.candidate_id: item for item in reviews.reviews}
        outcome_by_id = {item.candidate_id: item for item in outcomes.outcomes}
        expected = {item.candidate_id for item in outcomes.outcomes if item.status == "validated"}
        if {item.candidate_id for item in findings.findings} != expected:
            raise ReportPreflightV3Error("findings do not exactly match validated outcomes")
        try:
            recomputed = promote_findings_v3(
                candidates,
                reviews,
                outcomes,
                cleanup,
                generated_by_task_id=findings.generated_by_task_id,
            )
        except PromotionV3Error as exc:
            raise ReportPreflightV3Error("FindingSet cannot be promoted safely") from exc
        if findings != recomputed:
            raise ReportPreflightV3Error("FindingSet is not the parent-owned promotion result")
        for finding in findings.findings:
            outcome = outcome_by_id[finding.candidate_id]
            review = review_by_id[finding.candidate_id]
            if (
                review.verdict != "concur"
                or finding.verification_outcome_digest != canonical_digest(outcome)
                or finding.cross_review_digest != canonical_digest(review)
                or {ref.evidence_id for ref in finding.evidence}
                != {ref.evidence_id for ref in outcome.evidence}
            ):
                raise ReportPreflightV3Error("finding is not bound to reviewed verified evidence")

    def _verify_human_review(
        self,
        findings: FindingSet,
        coverage: CoverageReportV3,
        review: SignedReviewBatchV3,
    ) -> None:
        draft = self.context.artifact_path(self.DRAFT)
        if not draft.is_file():
            raise ReportPreflightV3Error("canonical V3 report draft is missing")
        if (
            review.finding_set_digest != findings.digest
            or review.coverage_report_digest != coverage.digest
            or review.report_draft_digest != _sha256(draft.read_bytes())
        ):
            raise ReportPreflightV3Error("human review digest chain is broken")
        expected_gaps = coverage_gap_digests(coverage)
        if coverage.completion == "completed":
            valid = review.verdict == "accepted" and not review.gap_digests
        else:
            valid = (
                review.verdict == "accepted_with_gaps"
                and tuple(sorted(review.gap_digests)) == expected_gaps
            )
        if not valid:
            raise ReportPreflightV3Error("human verdict does not authorize the coverage state")
        self.review_signature_verifier(review, findings, coverage)

    def _expected_evidence_refs(
        self,
        endpoints: EndpointInventoryV3,
        outcomes: VerificationOutcomeSet,
        cleanup: CleanupReceipt | None,
        findings: FindingSet,
    ) -> tuple[EvidenceArtifactRef, ...]:
        refs = [ref for endpoint in endpoints.endpoints for ref in endpoint.evidence]
        refs.extend(ref for outcome in outcomes.outcomes for ref in outcome.evidence)
        if cleanup is not None:
            refs.extend(ref for result in cleanup.results for ref in result.evidence)
        refs.extend(ref for finding in findings.findings for ref in finding.evidence)
        by_id: dict[str, EvidenceArtifactRef] = {}
        for ref in refs:
            prior = by_id.setdefault(ref.evidence_id, ref)
            if prior != ref:
                raise ReportPreflightV3Error("one evidence ID has conflicting references")
        return tuple(by_id[key] for key in sorted(by_id))

    def _verify_evidence_bindings(
        self,
        campaign: VerificationCampaignPlan,
        approvals: tuple[ApprovalBatchV3, ...],
        outcomes: VerificationOutcomeSet,
        action_events: tuple[dict[str, Any], ...],
        refs: tuple[EvidenceArtifactRef, ...],
        manifests: tuple[EvidenceArtifactManifest, ...],
        consumptions: Mapping[str, ApprovalConsumptionV3],
        cleanup: CleanupReceipt | None,
    ) -> None:
        if len(refs) != len(manifests):
            raise ReportPreflightV3Error("evidence manifest set is incomplete")
        approved = {batch.digest: batch for batch in approvals if batch.verdict == "approved"}
        action_by_digest = {item.action_digest: item for item in campaign.actions}
        latest = _latest_action_events(action_events)
        outcome_task: dict[str, str] = {}
        for outcome in outcomes.outcomes:
            for action_digest, ledger_digest, ref in zip(
                outcome.action_digests,
                outcome.action_ledger_entry_digests,
                outcome.evidence,
                strict=True,
            ):
                if ref.evidence_id in outcome_task:
                    raise ReportPreflightV3Error("evidence is shared across verifier outcomes")
                outcome_task[ref.evidence_id] = outcome.verifier_task_id
                committed = next(
                    (
                        item
                        for item in action_events
                        if item.get("action_digest") == action_digest
                        and item.get("state") == "evidence_committed"
                        and item.get("evidence_digest") == ref.manifest_sha256
                    ),
                    None,
                )
                if committed is None or committed.get("event_hash") != ledger_digest:
                    raise ReportPreflightV3Error(
                        "VerificationOutcomeSet does not bind the committed ledger event"
                    )
        cleanup_evidence_ids = (
            set()
            if cleanup is None
            else {ref.evidence_id for result in cleanup.results for ref in result.evidence}
        )
        for ref, manifest in zip(refs, manifests, strict=True):
            binding = manifest.binding
            if (
                binding.run_id != self.context.run_id
                or binding.scope_digest != self.context.scope_digest
            ):
                raise ReportPreflightV3Error("evidence crosses run or scope")
            action = action_by_digest.get(binding.action_digest)
            if action is None:
                # The sole unapproved observation is Recon/Mapper input evidence.
                if any(
                    value is not None
                    for value in (
                        binding.plan_digest,
                        binding.approval_bundle_id,
                        binding.approval_bundle_digest,
                        binding.approval_consumption_digest,
                    )
                ):
                    raise ReportPreflightV3Error("non-campaign evidence carries approval bindings")
                continue
            if binding.action_id != action.action_id or binding.plan_digest != campaign.digest:
                raise ReportPreflightV3Error("evidence does not bind the exact campaign action")
            expected_task = outcome_task.get(ref.evidence_id)
            if expected_task is not None:
                if binding.task_id != expected_task:
                    raise ReportPreflightV3Error("verifier evidence task binding is incorrect")
            elif (
                ref.evidence_id not in cleanup_evidence_ids
                or action.purpose not in {"cleanup", "cleanup_check"}
                or not binding.task_id.startswith("phase4-cleanup-")
            ):
                raise ReportPreflightV3Error("evidence has no outcome or cleanup task authority")
            if binding.approval_bundle_digest not in approved:
                raise ReportPreflightV3Error("evidence references an untrusted approval batch")
            batch = approved[binding.approval_bundle_digest]
            if (
                binding.approval_bundle_id != batch.approval_id
                or binding.action_digest not in batch.action_digests
                or binding.approval_consumption_digest is None
            ):
                raise ReportPreflightV3Error("evidence approval or consumption is incomplete")
            consumption = consumptions.get(binding.approval_consumption_digest)
            if consumption is None:
                raise ReportPreflightV3Error("evidence consumption artifact is missing")
            expected_consumption = (
                self.context.run_id,
                self.context.scope_digest,
                campaign.campaign_id,
                campaign.digest,
                batch.approval_id,
                batch.digest,
                action.candidate_id,
                action.action_id,
                action.action_digest,
                binding.task_id,
                binding.task_input_sha256,
                binding.request_id,
                binding.evidence_id,
            )
            actual_consumption = (
                consumption.run_id,
                consumption.scope_digest,
                consumption.campaign_id,
                consumption.campaign_digest,
                consumption.approval_id,
                consumption.approval_batch_digest,
                consumption.candidate_id,
                consumption.action_id,
                consumption.action_digest,
                consumption.task_id,
                consumption.task_input_sha256,
                consumption.request_id,
                consumption.evidence_id,
            )
            if actual_consumption != expected_consumption:
                raise ReportPreflightV3Error("approval consumption crosses an execution binding")
            event = latest.get(action.action_id)
            if (
                event is None
                or event.get("approval_batch_digest") != batch.digest
                or event.get("consumption_digest") != binding.approval_consumption_digest
                or not _history_has_evidence(action_events, action.action_id, ref.manifest_sha256)
            ):
                raise ReportPreflightV3Error("ActionLedger and evidence bindings disagree")
        referenced_consumptions = {
            manifest.binding.approval_consumption_digest
            for manifest in manifests
            if manifest.binding.approval_consumption_digest is not None
        }
        if set(consumptions) != referenced_consumptions:
            raise ReportPreflightV3Error("consumption directory contains missing or orphan files")

    def _action_summary(
        self,
        campaign: VerificationCampaignPlan,
        events: tuple[dict[str, Any], ...],
    ) -> ActionLedgerSummary:
        known = {action.action_id: action for action in campaign.actions}
        histories: dict[str, list[dict[str, Any]]] = {key: [] for key in known}
        for event in events:
            action_id = event.get("action_id")
            if not isinstance(action_id, str):
                raise ReportPreflightV3Error("ActionLedger event has no action ID")
            action = known.get(action_id)
            if action is None or event.get("action_digest") != action.action_digest:
                raise ReportPreflightV3Error("ActionLedger contains an orphan campaign action")
            histories[action_id].append(event)
        executed = blocked = skipped = requests = 0
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
            history = histories[action.action_id]
            if not history:
                skipped += 1
                gaps.append(f"action:{action.action_id}:not_started")
                continue
            if any(item.get("state") in transport_states for item in history):
                requests += 1
            state = history[-1].get("state")
            if state in {"evidence_committed", "cleaned"}:
                executed += 1
            elif state in blocked_states:
                blocked += 1
                gaps.append(f"action:{action.action_id}:{state}")
            else:
                skipped += 1
                gaps.append(f"action:{action.action_id}:{state}")
        return ActionLedgerSummary(
            actions_planned=len(campaign.actions),
            actions_executed=executed,
            actions_blocked=blocked,
            actions_skipped=skipped,
            requests_used=requests,
            gaps=tuple(gaps),
        )

    def _verify_execution_artifacts(
        self,
        campaign: VerificationCampaignPlan,
        events: tuple[dict[str, Any], ...],
    ) -> None:
        expected: dict[str, tuple[str, str]] = {}
        for event in events:
            if event.get("state") != "evidence_committed":
                continue
            action_digest = event.get("action_digest")
            evidence_digest = event.get("evidence_digest")
            if not isinstance(action_digest, str) or not isinstance(evidence_digest, str):
                raise ReportPreflightV3Error("committed execution event is malformed")
            expected[action_digest] = (str(event.get("action_id")), evidence_digest)
        known = {item.action_digest: item for item in campaign.actions}
        if not set(expected) <= set(known):
            raise ReportPreflightV3Error("execution artifact references an unknown action")
        root = self.context.artifact_path("governance_v3/executions")
        observed = _json_names(root)
        expected_names = {f"{digest[7:]}.json" for digest in expected}
        if observed != expected_names:
            raise ReportPreflightV3Error("execution directory contains missing or orphan files")
        for action_digest, (action_id, evidence_digest) in expected.items():
            result = ExecutionResultV3.model_validate_json(
                (root / f"{action_digest[7:]}.json").read_bytes()
            )
            if (
                result.action_id != action_id
                or result.action_digest != action_digest
                or result.evidence_artifact_ref.manifest_sha256 != evidence_digest
            ):
                raise ReportPreflightV3Error("execution result binding is invalid")

    def _budget_summary(
        self,
        plan: RunPlanV3,
        events: tuple[dict[str, Any], ...],
        reporter_reservation: BudgetReservation | None,
    ) -> BudgetCoverageSummary:
        reservations = [item for item in events if item.get("event_type") == "reserved"]
        reporter = [
            item
            for item in reservations
            if item.get("reservation_id") == self.REPORTER_RESERVATION_ID
        ]
        if reporter_reservation is None:
            if reporter:
                raise ReportPreflightV3Error("unexpected Reporter reservation")
            coverage_reservations = reservations
            reserved_count = len(coverage_reservations) + 1
            reserved_cost = sum(int(item["reserved_microusd"]) for item in coverage_reservations)
            reserved_cost += plan.budget.reservation_per_attempt_microusd
        else:
            if len(reporter) != 1:
                raise ReportPreflightV3Error("Reporter requires one exact budget reservation")
            persisted = self._reservation_from_event(reporter[0])
            if persisted != reporter_reservation:
                raise ReportPreflightV3Error("Reporter reservation binding changed")
            coverage_reservations = [
                item
                for item in reservations
                if item.get("task_id") != self.REPORTER_TASK_ID
                or item.get("reservation_id") == self.REPORTER_RESERVATION_ID
            ]
            reserved_count = len(coverage_reservations)
            reserved_cost = sum(int(item["reserved_microusd"]) for item in coverage_reservations)
        non_reporter_ids = {
            str(item["reservation_id"])
            for item in coverage_reservations
            if item.get("task_id") != self.REPORTER_TASK_ID
        }
        used = {
            str(item["reservation_id"])
            for item in events
            if item.get("event_type") == "settled"
            and item.get("reservation_id") in non_reporter_ids
        }
        if reserved_count > plan.budget.max_model_attempts:
            raise ReportPreflightV3Error("budget ledger exceeds RunPlan model attempts")
        if reserved_cost > plan.budget.max_estimated_cost_microusd:
            raise ReportPreflightV3Error("budget ledger exceeds RunPlan cost cap")
        return BudgetCoverageSummary(
            attempts_reserved=reserved_count,
            attempts_used=len(used),
            estimated_cost_microusd=reserved_cost,
            actual_cost_microusd=None,
        )

    def _verify_provider_metadata(
        self,
        endpoints: EndpointInventoryV3,
        branch_results: tuple[BranchResult, ...],
        assessments: Mapping[Branch, BranchAssessment],
        reviews: CrossReviewSet,
        outcomes: VerificationOutcomeSet,
        budget_events: tuple[dict[str, Any], ...],
    ) -> None:
        tasks = {
            "phase4-gatekeeper",
            "phase4-recon",
            endpoints.generated_by_task_id,
        }
        tasks.update(item.generated_by_task_id for item in assessments.values())
        for review in reviews.reviews:
            metadata_exists = self.context.artifact_path(
                f"provider/{review.reviewer_task_id}.json"
            ).is_file()
            if metadata_exists:
                tasks.add(review.reviewer_task_id)
            elif review.verdict != "needs_more_evidence":
                raise ReportPreflightV3Error("completed cross review has no provider metadata")
        tasks.update(item.verifier_task_id for item in outcomes.outcomes)
        reservations = {
            str(item["reservation_id"]): item
            for item in budget_events
            if item.get("event_type") == "reserved"
        }
        settled = {
            str(item["reservation_id"])
            for item in budget_events
            if item.get("event_type") == "settled"
        }
        sessions: set[str] = set()
        for task_id in sorted(tasks):
            metadata = self._provider_metadata(task_id)
            if metadata.get("run_id") != self.context.run_id or metadata.get("task_id") != task_id:
                raise ReportPreflightV3Error("provider metadata crosses task or run")
            session = metadata.get("session_id")
            if not isinstance(session, str) or not session or session in sessions:
                raise ReportPreflightV3Error("provider sessions must be non-empty and independent")
            sessions.add(session)
            metadata_reservations = metadata.get("budget_reservations", [])
            if (
                not isinstance(metadata_reservations, list)
                or metadata.get("prompt_attempts") != len(metadata_reservations)
                or len(metadata_reservations) not in {1, 2}
            ):
                raise ReportPreflightV3Error(
                    "provider prompt attempts do not match budget reservations"
                )
            for reservation in metadata_reservations:
                if not isinstance(reservation, dict):
                    raise ReportPreflightV3Error("provider budget metadata is malformed")
                reservation_id = str(reservation.get("reservation_id"))
                event = reservations.get(reservation_id)
                if (
                    event is None
                    or event.get("task_id") != task_id
                    or reservation_id not in settled
                ):
                    raise ReportPreflightV3Error("provider call has no matching budget reservation")
        successful = {item.branch for item in branch_results if item.status == "succeeded"}
        if set(assessments) != successful:
            raise ReportPreflightV3Error("assessment/provider set does not match branch results")

    def _verify_reporter_ack(
        self,
        bundle: VerifiedReportBundleV3,
        launch: ReporterLaunchReceiptV3,
        ack: ReporterAckV3,
    ) -> None:
        metadata_path = self.context.artifact_path(f"provider/{self.REPORTER_TASK_ID}.json")
        metadata = self._provider_metadata(self.REPORTER_TASK_ID)
        authority_digest = metadata.get("authority_digest")
        if authority_digest is not None:
            if authority_digest != provider_metadata_authority_digest(metadata):
                raise ReportPreflightV3Error("Reporter provider authority digest is invalid")
            provider_digest = str(authority_digest)
        else:  # Compatibility for synthetic preflight fixtures.
            provider_digest = _file_sha256(metadata_path)
        expected = (
            self.context.run_id,
            self.context.scope_digest,
            self.REPORTER_TASK_ID,
            launch.digest,
            bundle.findings.digest,
            bundle.coverage.digest,
            provider_digest,
            True,
        )
        actual = (
            ack.run_id,
            ack.scope_digest,
            ack.generated_by_task_id,
            ack.launch_receipt_digest,
            ack.finding_set_digest,
            ack.coverage_report_digest,
            ack.provider_metadata_digest,
            ack.accepted,
        )
        if actual != expected:
            raise ReportPreflightV3Error("Reporter acknowledgement binding is invalid")

    def _verify_reporter_budget_settled(
        self, events: tuple[dict[str, Any], ...], ack: ReporterAckV3
    ) -> None:
        metadata = self._provider_metadata(self.REPORTER_TASK_ID)
        reservations = metadata.get("budget_reservations")
        if not isinstance(reservations, list) or not 1 <= len(reservations) <= 2:
            raise ReportPreflightV3Error(
                "Reporter provider metadata needs one initial and at most one repair reservation"
            )
        expected_ids = [self.REPORTER_RESERVATION_ID]
        if len(reservations) == 2:
            expected_ids.append(f"{self.REPORTER_TASK_ID}:schema_repair")
        observed_ids = [item.get("reservation_id") for item in reservations]
        if observed_ids != expected_ids:
            raise ReportPreflightV3Error("Reporter used a different budget reservation")
        settled_ids = {
            str(item.get("reservation_id"))
            for item in events
            if item.get("event_type") == "settled"
        }
        if not set(expected_ids) <= settled_ids:
            raise ReportPreflightV3Error("Reporter budget reservations are not settled")
        authority_digest = metadata.get("authority_digest")
        expected_digest = (
            provider_metadata_authority_digest(metadata)
            if authority_digest is not None
            else _file_sha256(self.context.artifact_path(f"provider/{self.REPORTER_TASK_ID}.json"))
        )
        if authority_digest is not None and authority_digest != expected_digest:
            raise ReportPreflightV3Error("Reporter provider authority digest is invalid")
        if ack.provider_metadata_digest != expected_digest:
            raise ReportPreflightV3Error("Reporter metadata changed after acknowledgement")

    def _verify_launch_budget_ancestor(
        self,
        launch: ReporterLaunchReceiptV3,
        events: tuple[dict[str, Any], ...],
    ) -> None:
        index = next(
            (
                offset
                for offset, event in enumerate(events)
                if event.get("event_hash") == launch.budget_ledger_head_digest
            ),
            None,
        )
        if index is None:
            raise ReportPreflightV3Error("launch budget head is not in the canonical ledger")
        for event in events[index + 1 :]:
            if (
                event.get("event_type") not in {"reserved", "settled"}
                or event.get("task_id") != self.REPORTER_TASK_ID
                or event.get("attempt_kind") not in {"reporter", "schema_repair"}
            ):
                raise ReportPreflightV3Error(
                    "budget ledger changed outside the authorized Reporter task"
                )

    def _verify_no_orphans(self, bundle: VerifiedReportBundleV3, *, include_reporter: bool) -> None:
        evidence_refs = self._expected_evidence_refs(
            bundle.endpoints, bundle.outcomes, bundle.cleanup, bundle.findings
        )
        self._verify_no_orphans_partial(
            bundle.branch_results,
            bundle.assessments,
            bundle.approvals,
            evidence_refs,
            allow_launch=True,
        )
        allowed_provider = {bundle.endpoints.generated_by_task_id}
        allowed_provider.update(item.generated_by_task_id for item in bundle.assessments.values())
        allowed_provider.update(item.reviewer_task_id for item in bundle.reviews.reviews)
        allowed_provider.update(item.verifier_task_id for item in bundle.outcomes.outcomes)
        if include_reporter:
            allowed_provider.add(self.REPORTER_TASK_ID)
        observed = {path.stem for path in self.context.artifact_path("provider").glob("*.json")}
        # Gatekeeper and Recon provider records precede the typed EndpointInventory
        # and use fixed V3 task IDs.  They are accepted but never inferred from an
        # agent-produced result.
        allowed_provider.update({"phase4-gatekeeper", "phase4-recon"})
        if observed - allowed_provider:
            raise ReportPreflightV3Error("orphan provider metadata exists")

    def _verify_no_orphans_partial(
        self,
        branch_results: tuple[BranchResult, ...],
        assessments: Mapping[Branch, BranchAssessment],
        approvals: tuple[ApprovalBatchV3, ...],
        evidence_refs: tuple[EvidenceArtifactRef, ...],
        *,
        allow_launch: bool,
    ) -> None:
        expected_assessments = {f"{branch}.json" for branch in assessments}
        if _json_names(self.context.artifact_path(self.ASSESSMENTS)) != expected_assessments:
            raise ReportPreflightV3Error("assessment directory contains missing or orphan files")
        expected_results = {f"{branch}.json" for branch in BRANCH_ORDER}
        if _json_names(self.context.artifact_path(self.BRANCH_RESULTS)) != expected_results:
            raise ReportPreflightV3Error("branch-result directory is not the exact four-branch set")
        expected_approvals = {f"{item.risk_group}.json" for item in approvals}
        expected_approvals.update(f"challenge-{item.risk_group}.json" for item in approvals)
        if _json_names(self.context.artifact_path(self.APPROVALS)) != expected_approvals:
            raise ReportPreflightV3Error("approval directory contains missing or orphan batches")
        evidence_ids = {item.evidence_id for item in evidence_refs}
        observed_evidence = {
            path.name for path in self.context.artifact_path("evidence").iterdir() if path.is_dir()
        }
        if observed_evidence != evidence_ids:
            raise ReportPreflightV3Error("evidence directory contains missing or orphan artifacts")
        formal_paths = (
            "report/report-v3.md",
            "report/findings-v3.json",
            "report/report-write-receipt-v3.json",
        )
        if any(self.context.artifact_path(path).exists() for path in formal_paths):
            raise ReportPreflightV3Error("formal report exists before final write preflight")
        if not allow_launch and self.context.artifact_path(self.LAUNCH_RECEIPT).exists():
            raise ReportPreflightV3Error("launch receipt exists before Reporter reservation")

    def _load_assessments(
        self, branch_results: tuple[BranchResult, ...]
    ) -> dict[Branch, BranchAssessment]:
        values: dict[Branch, BranchAssessment] = {}
        for result in branch_results:
            path = self.context.artifact_path(f"{self.ASSESSMENTS}/{result.branch}.json")
            if result.status == "succeeded":
                assessment = self._read(
                    f"{self.ASSESSMENTS}/{result.branch}.json", BranchAssessment
                )
                if assessment.digest != result.assessment_digest:
                    raise ReportPreflightV3Error("branch result assessment digest is incorrect")
                metadata = self.context.artifact_path(
                    f"provider/{assessment.generated_by_task_id}.json"
                )
                if result.provider_metadata_digest != _file_sha256(metadata):
                    raise ReportPreflightV3Error("branch provider metadata digest is incorrect")
                values[result.branch] = assessment
            elif path.exists():
                raise ReportPreflightV3Error("unsuccessful branch published an assessment")
        return values

    def _load_approvals(self, campaign: VerificationCampaignPlan) -> tuple[ApprovalBatchV3, ...]:
        root = self.context.artifact_path(self.APPROVALS)
        if not root.is_dir():
            raise ReportPreflightV3Error("V3 approval directory is missing")
        values = tuple(
            ApprovalBatchV3.model_validate_json(path.read_bytes())
            for path in sorted(root.glob("*.json"))
            if path.stem in {"readonly", "mutation", "cleanup"}
        )
        groups = tuple(item.risk_group for item in values)
        if len(groups) != len(set(groups)):
            raise ReportPreflightV3Error("duplicate approval risk group")
        campaign_groups: set[RiskGroup] = {
            item.risk_group for item in campaign.actions if item.risk_group != "cleanup"
        }
        if "cleanup" in groups:
            campaign_groups.add("cleanup")
        for risk_group in sorted(campaign_groups):
            path = root / f"challenge-{risk_group}.json"
            try:
                challenge = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise ReportPreflightV3Error(
                    f"canonical {risk_group} approval challenge is missing"
                ) from exc
            actions = approval_actions_v3(campaign, risk_group)
            if risk_group == "cleanup":
                try:
                    issued_at = datetime.fromisoformat(str(challenge["issued_at"]))
                except (KeyError, TypeError, ValueError) as exc:
                    raise ReportPreflightV3Error(
                        "cleanup approval challenge has invalid timestamps"
                    ) from exc
                expected = cleanup_challenge_payload_v3(campaign, issued_at)
            else:
                expected = {
                    "version": "3",
                    "challenge_id": f"phase4-{risk_group}",
                    "run_id": self.context.run_id,
                    "scope_digest": self.context.scope_digest,
                    "campaign_digest": campaign.digest,
                    "risk_group": risk_group,
                    "candidate_ids": sorted({item.candidate_id for item in actions}),
                    "action_digests": [item.action_digest for item in actions],
                    "expires_at": campaign.expires_at.isoformat(),
                }
            if challenge != expected:
                raise ReportPreflightV3Error("approval challenge was altered")
        return values

    def _provider_metadata(self, task_id: str) -> dict[str, Any]:
        path = self.context.artifact_path(f"provider/{task_id}.json")
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ReportPreflightV3Error(f"provider metadata is missing for {task_id}") from exc
        if not isinstance(value, dict):
            raise ReportPreflightV3Error("provider metadata must be a JSON object")
        return value

    def _load_consumptions(self) -> dict[str, ApprovalConsumptionV3]:
        root = self.context.artifact_path(f"{self.APPROVALS}/consumptions")
        if not root.is_dir():
            raise ReportPreflightV3Error("approval consumption directory is missing")
        values: dict[str, ApprovalConsumptionV3] = {}
        for path in sorted(root.glob("*.json")):
            try:
                consumption = ApprovalConsumptionV3.model_validate_json(path.read_bytes())
            except (OSError, ValueError) as exc:
                raise ReportPreflightV3Error("approval consumption is invalid") from exc
            if path.name != f"{consumption.action_digest[7:]}.json":
                raise ReportPreflightV3Error("approval consumption path is non-canonical")
            if consumption.digest in values:
                raise ReportPreflightV3Error("duplicate approval consumption digest")
            values[consumption.digest] = consumption
        return values

    def _reporter_reservation(self) -> BudgetReservation:
        events = BudgetLedger(self.context).events()
        event = _reservation_event(events, self.REPORTER_RESERVATION_ID)
        if event is None:
            raise ReportPreflightV3Error("Reporter budget has not been reserved")
        return self._reservation_from_event(event)

    @staticmethod
    def _reservation_from_event(event: Mapping[str, Any]) -> BudgetReservation:
        return BudgetReservation(
            reservation_id=str(event["reservation_id"]),
            task_id=str(event["task_id"]),
            role=str(event["role"]),
            attempt_kind=event["attempt_kind"],
            attempt_number=int(event["attempt_number"]),
            reserved_microusd=int(event["reserved_microusd"]),
            sequence=int(event["sequence"]),
        )

    def _launch_receipt(
        self,
        bundle: VerifiedReportBundleV3,
        *,
        verified_at: datetime | None = None,
    ) -> ReporterLaunchReceiptV3:
        reservation_event = _reservation_event(
            BudgetLedger(self.context).events(), self.REPORTER_RESERVATION_ID
        )
        if reservation_event is None:
            raise ReportPreflightV3Error("Reporter reservation disappeared")
        return ReporterLaunchReceiptV3(
            run_id=self.context.run_id,
            scope_digest=self.context.scope_digest,
            generated_by_task_id="phase4-preflight-launch",
            receipt_id="phase4-reporter-launch",
            finding_set_digest=bundle.findings.digest,
            coverage_report_digest=bundle.coverage.digest,
            signed_review_digest=bundle.signed_review.digest,
            action_ledger_head_digest=bundle.action_ledger_head,
            budget_ledger_head_digest=bundle.budget_ledger_head,
            reporter_budget_reservation_digest=canonical_digest(reservation_event),
            verified_at=verified_at or datetime.now(UTC),
        )

    def _read(self, relative: str, model: type[_Model]) -> _Model:
        path = self.context.artifact_path(relative)
        try:
            return model.model_validate_json(path.read_bytes())
        except (OSError, ValueError) as exc:
            raise ReportPreflightV3Error(
                f"canonical artifact is missing or invalid: {relative}"
            ) from exc

    def _read_optional(self, relative: str, model: type[_Model]) -> _Model | None:
        path = self.context.artifact_path(relative)
        return None if not path.exists() else self._read(relative, model)


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _file_sha256(path: Path) -> str:
    try:
        return _sha256(path.read_bytes())
    except OSError as exc:
        raise ReportPreflightV3Error(f"required artifact is missing: {path.name}") from exc


def _journal_head(events: Sequence[Mapping[str, Any]], label: str) -> str:
    if not events:
        raise ReportPreflightV3Error(f"{label} ledger is empty")
    value = events[-1].get("event_hash")
    if not isinstance(value, str) or not value.startswith("sha256:"):
        raise ReportPreflightV3Error(f"{label} ledger has no valid head digest")
    return value


def _reservation_event(
    events: Sequence[Mapping[str, Any]], reservation_id: str
) -> Mapping[str, Any] | None:
    return next(
        (
            event
            for event in events
            if event.get("event_type") == "reserved"
            and event.get("reservation_id") == reservation_id
        ),
        None,
    )


def _latest_action_events(
    events: Sequence[Mapping[str, Any]],
) -> dict[str, Mapping[str, Any]]:
    values: dict[str, Mapping[str, Any]] = {}
    for event in events:
        action_id = event.get("action_id")
        if isinstance(action_id, str):
            values[action_id] = event
    return values


def _history_has_evidence(
    events: Sequence[Mapping[str, Any]], action_id: str, evidence_digest: str
) -> bool:
    return any(
        item.get("action_id") == action_id
        and item.get("state") == "evidence_committed"
        and item.get("evidence_digest") == evidence_digest
        for item in events
    )


def _json_names(path: Path) -> set[str]:
    if not path.is_dir():
        return set()
    return {item.name for item in path.iterdir() if item.is_file() and item.suffix == ".json"}


__all__ = [
    "ApprovalSignatureVerifier",
    "ReportPreflightV3Error",
    "ReportPreflightVerifierV3",
    "ReviewSignatureVerifier",
    "VerifiedReportBundleV3",
]

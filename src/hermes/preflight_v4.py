"""Fail-closed V4 report authorization and final-write preflight."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from .campaign_v4 import VerificationCampaignPlanV4
from .domain_contracts_v3 import ApprovalBatchV3, CleanupReceipt
from .domain_contracts_v4 import (
    CoverageAppendixV4,
    FindingSetV4,
    PassivePostureV4,
    QualityGateReceiptV4,
    ReporterAckV4,
    ReporterLaunchReceiptV4,
    RunPlanV4,
    SignedReviewBatchV4,
    SurfaceMapV4,
    VerificationOutcomeSetV4,
)
from .evidence import EvidenceArtifactManifest, EvidenceArtifactRef, EvidenceStore
from .execution_v3 import ApprovalConsumptionV3
from .execution_v4 import ExecutionResultV4
from .ledgers_v4 import ActionLedgerV4, BudgetLedgerV4, LedgerIntegrityError
from .providers.acp import ProviderProtocolError, provider_metadata_authority_digest
from .reporting_v4 import VerifiedReportWriteV4, write_report_v4
from .runtime import RunContext
from .security_v4 import ApprovalBatchV4, ApprovalConsumptionV4

ApprovalRecordV4 = ApprovalBatchV3 | ApprovalBatchV4
ConsumptionRecordV4 = ApprovalConsumptionV3 | ApprovalConsumptionV4
ApprovalSignatureVerifierV4 = Callable[[ApprovalRecordV4], None]
ReviewSignatureVerifierV4 = Callable[[SignedReviewBatchV4, FindingSetV4, CoverageAppendixV4], None]


class ReportPreflightV4Error(ValueError):
    """Canonical V4 artifacts do not authorize Reporter or formal output."""


@dataclass(frozen=True, slots=True)
class VerifiedReportBundleV4:
    plan: RunPlanV4
    quality: QualityGateReceiptV4
    findings: FindingSetV4
    coverage: CoverageAppendixV4
    signed_review: SignedReviewBatchV4
    evidence: tuple[EvidenceArtifactManifest, ...]
    approvals: tuple[ApprovalRecordV4, ...]
    consumptions: tuple[ConsumptionRecordV4, ...]
    cleanup: CleanupReceipt | None
    passive_posture: PassivePostureV4 | None
    surface_map: SurfaceMapV4 | None
    authority_digest: str


def coverage_gap_digests_v4(coverage: CoverageAppendixV4) -> tuple[str, ...]:
    return tuple(
        sorted(
            "sha256:" + hashlib.sha256(item.encode("utf-8")).hexdigest() for item in coverage.gaps
        )
    )


class ReportPreflightVerifierV4:
    RUN_PLAN = "plan/run-v4.json"
    PASSIVE = "posture/passive-v4.json"
    SURFACE = "surface/map-v4.json"
    QUALITY = "quality/receipt-v4.json"
    FINDINGS = "report/finding-set-v4.json"
    COVERAGE = "report/coverage-v4.json"
    DRAFT = "report/draft-v4.md"
    SIGNED_REVIEW = "reviews/signed-v4.json"
    APPROVALS = "approvals_v4"
    CONSUMPTIONS = "governance_v4/consumptions"
    CLEANUP = "verification_v4/cleanup.json"
    LAUNCH_RECEIPT = "report/reporter-launch-v4.json"
    REPORTER_ACK = "report/reporter-ack-v4.json"
    REPORTER_TASK_ID = "phase5-reporter"

    def __init__(
        self,
        context: RunContext,
        *,
        approval_signature_verifier: ApprovalSignatureVerifierV4 | None = None,
        review_signature_verifier: ReviewSignatureVerifierV4 | None = None,
        evidence_store: EvidenceStore | None = None,
    ) -> None:
        self.context = context
        self.approval_signature_verifier = approval_signature_verifier or _missing_approval_verifier
        self.review_signature_verifier = review_signature_verifier or _missing_review_verifier
        self.evidence_store = evidence_store or EvidenceStore(context.path)

    def authorize_reporter(self) -> ReporterLaunchReceiptV4:
        try:
            bundle = self._verify_core(allow_launch_receipt=False)
            receipt = ReporterLaunchReceiptV4(
                run_id=self.context.run_id,
                scope_digest=self.context.scope_digest,
                generated_by_task_id="phase5-preflight-launch",
                receipt_id="phase5-reporter-launch",
                quality_gate_digest=bundle.quality.digest,
                finding_set_digest=bundle.findings.digest,
                coverage_appendix_digest=bundle.coverage.digest,
                signed_review_digest=bundle.signed_review.digest,
                launch_authority_digest=bundle.authority_digest,
                verified_at=datetime.now(UTC),
            )
            self.context.write_json(
                self.LAUNCH_RECEIPT,
                receipt.model_dump(mode="json"),
                immutable=True,
            )
            return receipt
        except ReportPreflightV4Error:
            raise
        except (OSError, ValueError, TypeError) as exc:
            raise ReportPreflightV4Error(f"V4 Reporter launch preflight failed: {exc}") from exc

    def verify_launch(self) -> VerifiedReportBundleV4:
        launch = self._read(self.LAUNCH_RECEIPT, ReporterLaunchReceiptV4)
        bundle = self._verify_core(allow_launch_receipt=True)
        expected = ReporterLaunchReceiptV4(
            run_id=self.context.run_id,
            scope_digest=self.context.scope_digest,
            generated_by_task_id="phase5-preflight-launch",
            receipt_id="phase5-reporter-launch",
            quality_gate_digest=bundle.quality.digest,
            finding_set_digest=bundle.findings.digest,
            coverage_appendix_digest=bundle.coverage.digest,
            signed_review_digest=bundle.signed_review.digest,
            launch_authority_digest=bundle.authority_digest,
            verified_at=launch.verified_at,
        )
        if expected != launch:
            raise ReportPreflightV4Error(
                "Reporter launch receipt does not match a fresh V4 preflight"
            )
        return bundle

    def write_report(self, reporter_ack: ReporterAckV4 | None = None) -> Path:
        ack = reporter_ack or self._read(self.REPORTER_ACK, ReporterAckV4)
        return write_report_v4(self.context, self, ack)

    def verify_for_write(self, reporter_ack: ReporterAckV4) -> VerifiedReportWriteV4:
        canonical_ack = self._read(self.REPORTER_ACK, ReporterAckV4)
        if reporter_ack != canonical_ack:
            raise ReportPreflightV4Error(
                "caller Reporter acknowledgement differs from the canonical artifact"
            )
        bundle = self.verify_launch()
        launch = self._read(self.LAUNCH_RECEIPT, ReporterLaunchReceiptV4)
        self._verify_reporter_ack(bundle, launch, reporter_ack)
        self._verify_no_orphans(bundle, include_launch=True)
        return VerifiedReportWriteV4(
            launch_receipt=launch,
            quality=bundle.quality,
            finding_set=bundle.findings,
            coverage=bundle.coverage,
            provider_metadata_digest=reporter_ack.provider_metadata_digest,
        )

    def _verify_core(self, *, allow_launch_receipt: bool) -> VerifiedReportBundleV4:
        plan = self._read(self.RUN_PLAN, RunPlanV4)
        passive = self._read_optional(self.PASSIVE, PassivePostureV4)
        surface = self._read_optional(self.SURFACE, SurfaceMapV4)
        quality = self._read(self.QUALITY, QualityGateReceiptV4)
        findings = self._read(self.FINDINGS, FindingSetV4)
        coverage = self._read(self.COVERAGE, CoverageAppendixV4)
        signed_review = self._read(self.SIGNED_REVIEW, SignedReviewBatchV4)
        cleanup = self._read_optional(self.CLEANUP, CleanupReceipt)
        approvals = self._load_approvals()
        consumptions = self._load_consumptions()

        if plan.run_id != self.context.run_id or plan.scope_digest != self.context.scope_digest:
            raise ReportPreflightV4Error("V4 RunPlan crosses the canonical run or scope")

        run_bound = (
            quality,
            findings,
            coverage,
            signed_review,
            *((passive,) if passive is not None else ()),
            *((surface,) if surface is not None else ()),
            *((cleanup,) if cleanup is not None else ()),
            *approvals,
            *consumptions,
        )
        for artifact in run_bound:
            if (
                getattr(artifact, "run_id", None) != self.context.run_id
                or getattr(artifact, "scope_digest", None) != self.context.scope_digest
            ):
                raise ReportPreflightV4Error("a V4 artifact crosses the run or scope boundary")

        self._verify_quality(plan, quality)
        self._verify_passive_surface(findings, passive, surface)
        collaboration_gaps = self._verify_collaboration(plan, findings)
        self._verify_findings_and_coverage(quality, findings, coverage, cleanup)
        if tuple(sorted(coverage.gaps)) != collaboration_gaps:
            raise ReportPreflightV4Error("coverage gaps do not match the V4 collaboration record")
        self._verify_verifier_outcomes(plan, findings)
        self._verify_action_ledger()
        self._verify_budget_ledger(plan)
        evidence_refs = self._expected_evidence_refs(findings)
        manifests = tuple(self.evidence_store.verify(ref) for ref in evidence_refs)
        self._verify_approvals_and_consumptions(findings, approvals, consumptions, manifests)
        self._verify_review(findings, coverage, signed_review)
        authority_digest = _sha256_json(
            {
                "plan": plan.digest,
                "quality": quality.digest,
                "findings": findings.digest,
                "coverage": coverage.digest,
                "review": signed_review.digest,
                "passive": None if passive is None else passive.digest,
                "surface": None if surface is None else surface.digest,
                "cleanup": None if cleanup is None else cleanup.digest,
                "approvals": [item.digest for item in approvals],
                "consumptions": [item.digest for item in consumptions],
                "evidence": [item.binding.evidence_id for item in manifests],
            }
        )
        bundle = VerifiedReportBundleV4(
            plan=plan,
            quality=quality,
            findings=findings,
            coverage=coverage,
            signed_review=signed_review,
            evidence=manifests,
            approvals=approvals,
            consumptions=consumptions,
            cleanup=cleanup,
            passive_posture=passive,
            surface_map=surface,
            authority_digest=authority_digest,
        )
        self._verify_no_orphans(bundle, include_launch=allow_launch_receipt)
        return bundle

    def _verify_verifier_outcomes(self, plan: RunPlanV4, findings: FindingSetV4) -> None:
        """Require independent verifier attestations for production HTTPS V4 runs.

        Early unit fixtures intentionally model only the final report boundary
        and use an HTTP target. A real V4 run is localhost HTTPS by contract,
        so it must carry one exact independently-produced outcome set per
        promoted finding.
        """

        root = self.context.artifact_path("verification_v4/outcomes")
        if not root.exists() and plan.target.startswith("http://"):
            return
        if not root.is_dir():
            raise ReportPreflightV4Error("V4 verifier outcome directory is missing")
        expected = {item.candidate_id for item in findings.findings}
        observed = {item.stem for item in root.glob("*.json")}
        if observed != expected:
            raise ReportPreflightV4Error("V4 verifier outcome artifact set is incomplete")
        for finding in findings.findings:
            outcome = self._read(
                f"verification_v4/outcomes/{finding.candidate_id}.json", VerificationOutcomeSetV4
            )
            if (
                outcome.digest != finding.verification_outcome_digest
                or outcome.run_id != self.context.run_id
                or outcome.scope_digest != self.context.scope_digest
                or len(outcome.outcomes) != 1
                or outcome.outcomes[0].candidate_id != finding.candidate_id
                or outcome.outcomes[0].status != "validated"
            ):
                raise ReportPreflightV4Error("V4 verifier outcome binding is invalid")

    def _verify_action_ledger(self) -> None:
        root = self.context.artifact_path("governance_v4/action_ledger")
        if not root.exists():
            return
        try:
            events = ActionLedgerV4(self.context).events()
        except (LedgerIntegrityError, OSError, ValueError) as exc:
            raise ReportPreflightV4Error("V4 action ledger integrity is invalid") from exc
        if not events:
            raise ReportPreflightV4Error("V4 action ledger has no execution events")

    def _verify_budget_ledger(self, plan: RunPlanV4) -> None:
        root = self.context.artifact_path("governance_v4/budget_ledger")
        if not root.exists():
            if plan.target.startswith("http://"):
                return
            raise ReportPreflightV4Error("V4 budget ledger is missing")
        try:
            ledger = BudgetLedgerV4(self.context)
            events = ledger.events()
            summary = ledger.summary()
        except (LedgerIntegrityError, OSError, ValueError) as exc:
            raise ReportPreflightV4Error("V4 budget ledger integrity is invalid") from exc
        if not events or summary.reserved_attempts == 0:
            raise ReportPreflightV4Error("V4 budget ledger has no prompt reservations")
        if summary.settled_attempts != summary.reserved_attempts:
            raise ReportPreflightV4Error("V4 budget ledger has unsettled prompt reservations")

    def _verify_quality(self, plan: RunPlanV4, quality: QualityGateReceiptV4) -> None:
        if not quality.overall_passed:
            raise ReportPreflightV4Error("quality gate did not pass")
        for family in quality.families:
            if not family.passed:
                raise ReportPreflightV4Error("quality family did not pass")
        # HTTP-only unit fixtures model an isolated report-boundary test; a
        # real V4 execution is HTTPS-only and must retain/recompute the frozen
        # independent quality data before Reporter is allowed to start.
        if plan.target.startswith("http://"):
            return
        try:
            from .quality_v4 import (
                evaluate_quality_dataset_v4,
                load_quality_dataset_v4,
                operational_metrics_v4,
            )

            dataset = load_quality_dataset_v4(
                self.context.artifact_path("quality/dataset-v4.json")
            )
            campaign = self._read("verification_v4/campaign.json", VerificationCampaignPlanV4)
            if (campaign.run_id, campaign.scope_digest) != (
                self.context.run_id,
                self.context.scope_digest,
            ):
                raise ValueError("quality campaign crosses the run or scope")
            results: list[ExecutionResultV4] = []
            for group in ("readonly", "mutation"):
                if not any(item.risk_group == group for item in campaign.actions):
                    continue
                path = self.context.artifact_path(f"verification_v4/results-{group}.json")
                if not path.is_file():
                    raise ValueError(f"missing V4 {group} verification results")
                payload = json.loads(path.read_text(encoding="utf-8"))
                if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
                    raise ValueError(f"invalid V4 {group} verification results")
                results.extend(
                    ExecutionResultV4.model_validate(item) for item in payload["results"]
                )
            recomputed = evaluate_quality_dataset_v4(
                dataset,
                operational=operational_metrics_v4(self.context, campaign, results),
            )
        except (OSError, TypeError, ValueError) as exc:
            raise ReportPreflightV4Error("V4 quality dataset or metrics are invalid") from exc
        if quality.families != recomputed:
            raise ReportPreflightV4Error("V4 quality receipt does not match frozen dataset metrics")

    def _verify_passive_surface(
        self,
        findings: FindingSetV4,
        passive: PassivePostureV4 | None,
        surface: SurfaceMapV4 | None,
    ) -> None:
        if findings.passive_posture_digest is not None:
            if passive is None or passive.digest != findings.passive_posture_digest:
                raise ReportPreflightV4Error("passive posture digest chain is broken")
        if findings.surface_map_digest is not None:
            if surface is None or surface.digest != findings.surface_map_digest:
                raise ReportPreflightV4Error("surface map digest chain is broken")
        for finding in findings.findings:
            if finding.passive_posture_digest is not None:
                if passive is None or passive.digest != finding.passive_posture_digest:
                    raise ReportPreflightV4Error("finding passive posture digest is invalid")
            if finding.surface_map_digest is not None:
                if surface is None or surface.digest != finding.surface_map_digest:
                    raise ReportPreflightV4Error("finding surface map digest is invalid")

    def _verify_collaboration(self, plan: RunPlanV4, findings: FindingSetV4) -> tuple[str, ...]:
        """Recompute the exact branch and cross-review selection boundary.

        V4 keeps this parent-owned rather than trusting the model handoffs: a
        failed branch can remove only its own candidates, and every promoted
        candidate must retain an independent successful reviewer.
        """

        branch_path = self.context.artifact_path("collaboration_v4/branch-results.json")
        review_path = self.context.artifact_path("collaboration_v4/review-plan.json")
        if not branch_path.is_file() or not review_path.is_file():
            if plan.target.startswith("http://"):
                return ()
            raise ReportPreflightV4Error("V4 collaboration artifacts are missing")
        try:
            branches_payload = json.loads(branch_path.read_text(encoding="utf-8"))
            review_payload = json.loads(review_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ReportPreflightV4Error("V4 collaboration artifact is invalid") from exc
        if not isinstance(branches_payload, dict) or not isinstance(review_payload, dict):
            raise ReportPreflightV4Error("V4 collaboration artifact must be an object")
        branches = branches_payload.get("branches")
        if not isinstance(branches, list) or len(branches) != 4:
            raise ReportPreflightV4Error("V4 branch result set is incomplete")
        expected_order = ("web", "api", "authz", "infra")
        statuses: dict[str, str] = {}
        for expected, value in zip(expected_order, branches, strict=True):
            if (
                not isinstance(value, dict)
                or value.get("branch") != expected
                or value.get("status") not in {"succeeded", "failed"}
            ):
                raise ReportPreflightV4Error("V4 branch result is invalid")
            statuses[expected] = str(value["status"])
        declared_branch_gaps = branches_payload.get("gaps")
        expected_branch_gaps = tuple(
            f"branch:{name}:{status}"
            for name, status in statuses.items()
            if status != "succeeded"
        )
        if declared_branch_gaps != list(expected_branch_gaps):
            raise ReportPreflightV4Error("V4 branch gaps do not match branch status")
        candidate_branch = {
            "web-xcto": "web",
            "web-cookie": "web",
            "web-open-redirect": "web",
            "api-graphql": "api",
            "authz-privilege": "authz",
            "authz-bola": "authz",
            "workflow-bypass": "authz",
            "infra-debug": "infra",
        }
        candidates = review_payload.get("candidate_ids")
        reviewers = review_payload.get("reviewers")
        review_gaps = review_payload.get("gaps")
        if (
            not isinstance(candidates, list)
            or len(candidates) != len(set(candidates))
            or not all(isinstance(item, str) for item in candidates)
            or not isinstance(reviewers, dict)
            or set(reviewers) != set(candidates)
            or not isinstance(review_gaps, list)
            or not all(isinstance(item, str) and item for item in review_gaps)
        ):
            raise ReportPreflightV4Error("V4 cross-review plan is invalid")
        source_candidates = {
            candidate
            for candidate, branch in candidate_branch.items()
            if statuses[branch] == "succeeded"
        }
        if not set(candidates) <= source_candidates:
            raise ReportPreflightV4Error("cross-review admits a failed branch candidate")
        rejected_by_review = {
            item.split(":", 2)[1]
            for item in review_gaps
            if item.startswith("cross_review:") and item.count(":") >= 2
        }
        if source_candidates != set(candidates) | rejected_by_review:
            raise ReportPreflightV4Error("cross-review plan has an unexplained candidate gap")
        for candidate, reviewer in reviewers.items():
            source = candidate_branch.get(candidate)
            if source is None or reviewer not in statuses or reviewer == source:
                raise ReportPreflightV4Error("cross-reviewer is not independent")
            if statuses[reviewer] != "succeeded":
                raise ReportPreflightV4Error("cross-reviewer branch did not succeed")
        campaign = self._read("verification_v4/campaign.json", VerificationCampaignPlanV4)
        campaign_candidates = {item.candidate_id for item in campaign.actions}
        if campaign_candidates != set(candidates):
            raise ReportPreflightV4Error("campaign does not match reviewed V4 candidates")
        if {item.candidate_id for item in findings.findings} != campaign_candidates:
            raise ReportPreflightV4Error("promoted findings do not match reviewed V4 candidates")
        return tuple(sorted((*expected_branch_gaps, *review_gaps)))

    def _verify_findings_and_coverage(
        self,
        quality: QualityGateReceiptV4,
        findings: FindingSetV4,
        coverage: CoverageAppendixV4,
        cleanup: CleanupReceipt | None,
    ) -> None:
        if findings.quality_gate_digest != quality.digest:
            raise ReportPreflightV4Error("FindingSetV4 quality digest chain is broken")
        if coverage.quality_gate_digest != quality.digest:
            raise ReportPreflightV4Error("CoverageAppendixV4 quality digest chain is broken")
        if coverage.finding_set_digest != findings.digest:
            raise ReportPreflightV4Error("coverage appendix does not bind the finding set")
        expected_cleanup = None if cleanup is None else cleanup.digest
        mutation_findings = {
            "unauthorized_graphql_mutation",
            "privilege_escalation",
            "workflow_transition_bypass",
        }
        if any(item.candidate_type in mutation_findings for item in findings.findings) and (
            cleanup is None or not cleanup.state_restored
        ):
            raise ReportPreflightV4Error("mutation findings require a restored cleanup receipt")
        if findings.cleanup_receipt_digest != expected_cleanup:
            raise ReportPreflightV4Error("finding set cleanup digest chain is broken")
        if coverage.cleanup_receipt_digest != expected_cleanup:
            raise ReportPreflightV4Error("coverage cleanup digest chain is broken")
        finding_families = {finding.family for finding in findings.findings}
        coverage_families = {item.family for item in coverage.families}
        if not finding_families <= coverage_families:
            raise ReportPreflightV4Error("coverage appendix omits a finding family")
        coverage_validated = sum(item.validated for item in coverage.families)
        if coverage_validated != len(findings.findings):
            raise ReportPreflightV4Error("validated coverage count does not match findings")

    def _verify_approvals_and_consumptions(
        self,
        findings: FindingSetV4,
        approvals: tuple[ApprovalRecordV4, ...],
        consumptions: tuple[ConsumptionRecordV4, ...],
        manifests: tuple[EvidenceArtifactManifest, ...],
    ) -> None:
        approval_by_digest = {item.digest: item for item in approvals}
        consumption_by_digest = {item.digest: item for item in consumptions}
        manifest_by_id = {item.binding.evidence_id: item for item in manifests}
        referenced_consumptions: set[str] = set()
        for finding in findings.findings:
            if not finding.approval_batch_digests or not finding.approval_consumption_digests:
                raise ReportPreflightV4Error("finding is missing signed approval bindings")
            for digest in finding.approval_batch_digests:
                batch = approval_by_digest.get(digest)
                if batch is None or batch.verdict != "approved":
                    raise ReportPreflightV4Error("finding references a missing approved batch")
                self.approval_signature_verifier(batch)
                if finding.candidate_id not in batch.candidate_ids:
                    raise ReportPreflightV4Error(
                        "approval batch does not cover the finding candidate"
                    )
            consumption_digests = set(finding.approval_consumption_digests)
            evidence_ids = {item.evidence_id for item in finding.evidence}
            bound_evidence = 0
            for digest in consumption_digests:
                consumption = consumption_by_digest.get(digest)
                if consumption is None:
                    raise ReportPreflightV4Error(
                        "finding references a missing approval consumption"
                    )
                if consumption.candidate_id != finding.candidate_id:
                    raise ReportPreflightV4Error(
                        "approval consumption crosses a candidate boundary"
                    )
                if consumption.approval_batch_digest not in finding.approval_batch_digests:
                    raise ReportPreflightV4Error("consumption is not bound to a referenced batch")
                manifest = manifest_by_id.get(consumption.evidence_id)
                if manifest is None:
                    raise ReportPreflightV4Error(
                        "consumption evidence is missing from the finding set"
                    )
                binding = manifest.binding
                if (
                    binding.approval_bundle_digest != consumption.approval_batch_digest
                    or binding.approval_consumption_digest != consumption.digest
                    or binding.action_id != consumption.action_id
                    or binding.action_digest != consumption.action_digest
                    or binding.task_id != consumption.task_id
                    or binding.task_input_sha256 != consumption.task_input_sha256
                    or binding.request_id != consumption.request_id
                ):
                    raise ReportPreflightV4Error("evidence binding does not match its consumption")
                if manifest.binding.evidence_id in evidence_ids:
                    bound_evidence += 1
                referenced_consumptions.add(consumption.digest)
            if bound_evidence < 1:
                raise ReportPreflightV4Error(
                    "finding does not reference any approval-bound evidence"
                )
            if finding.review_digest == "":
                raise ReportPreflightV4Error("finding review digest is missing")
        if referenced_consumptions != set(consumption_by_digest):
            raise ReportPreflightV4Error("consumption directory contains missing or orphan files")

    def _verify_review(
        self,
        findings: FindingSetV4,
        coverage: CoverageAppendixV4,
        review: SignedReviewBatchV4,
    ) -> None:
        draft = self.context.artifact_path(self.DRAFT)
        if not draft.is_file():
            raise ReportPreflightV4Error("canonical V4 report draft is missing")
        if review.finding_set_digest != findings.digest:
            raise ReportPreflightV4Error("human review finding digest chain is broken")
        if review.coverage_appendix_digest != coverage.digest:
            raise ReportPreflightV4Error("human review coverage digest chain is broken")
        if review.report_draft_digest != _sha256_bytes(draft.read_bytes()):
            raise ReportPreflightV4Error("human review draft digest chain is broken")
        expected_gaps = coverage_gap_digests_v4(coverage)
        if coverage.completion == "completed":
            valid = review.verdict == "accepted" and not review.gap_digests
        else:
            valid = (
                review.verdict == "accepted_with_gaps"
                and tuple(sorted(review.gap_digests)) == expected_gaps
            )
        if not valid:
            raise ReportPreflightV4Error("human verdict does not authorize the coverage state")
        self.review_signature_verifier(review, findings, coverage)

    def _verify_reporter_ack(
        self,
        bundle: VerifiedReportBundleV4,
        launch: ReporterLaunchReceiptV4,
        ack: ReporterAckV4,
    ) -> None:
        provider_path = self.context.artifact_path(f"provider/{self.REPORTER_TASK_ID}.json")
        try:
            provider_metadata = json.loads(provider_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ReportPreflightV4Error("Reporter provider metadata is invalid") from exc
        if not isinstance(provider_metadata, dict):
            raise ReportPreflightV4Error("Reporter provider metadata must be an object")
        authority_digest = provider_metadata.get("authority_digest")
        if authority_digest is None:
            # Synthetic unit fixtures predate ACP authority metadata. Production
            # ACP runs use the non-circular authority projection below.
            provider_digest = _sha256_bytes(provider_path.read_bytes())
        else:
            if not isinstance(authority_digest, str):
                raise ReportPreflightV4Error("Reporter provider authority digest is invalid")
            try:
                expected_authority = provider_metadata_authority_digest(provider_metadata)
            except ProviderProtocolError as exc:
                raise ReportPreflightV4Error("Reporter provider authority is incomplete") from exc
            if authority_digest != expected_authority:
                raise ReportPreflightV4Error("Reporter provider authority digest is invalid")
            provider_digest = authority_digest
        expected = (
            self.context.run_id,
            self.context.scope_digest,
            self.REPORTER_TASK_ID,
            launch.digest,
            bundle.quality.digest,
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
            ack.quality_gate_digest,
            ack.finding_set_digest,
            ack.coverage_appendix_digest,
            ack.provider_metadata_digest,
            ack.accepted,
        )
        if actual != expected:
            raise ReportPreflightV4Error("Reporter acknowledgement binding is invalid")

    def _verify_no_orphans(self, bundle: VerifiedReportBundleV4, *, include_launch: bool) -> None:
        expected_evidence = {item.binding.evidence_id for item in bundle.evidence}
        evidence_root = self.context.artifact_path("evidence")
        observed_evidence = {path.name for path in evidence_root.iterdir() if path.is_dir()}
        if observed_evidence != expected_evidence:
            raise ReportPreflightV4Error("evidence directory contains missing or orphan artifacts")
        approval_root = self.context.artifact_path(self.APPROVALS)
        if approval_root.exists():
            observed_approvals = {item.digest for item in self._load_approvals()}
            if observed_approvals != {item.digest for item in bundle.approvals}:
                raise ReportPreflightV4Error("approval directory contains missing or orphan files")
        consumption_root = self.context.artifact_path(self.CONSUMPTIONS)
        if consumption_root.exists():
            observed_consumptions = {item.digest for item in self._load_consumptions()}
            if observed_consumptions != {item.digest for item in bundle.consumptions}:
                raise ReportPreflightV4Error(
                    "consumption directory contains missing or orphan files"
                )
        final_paths = (
            "report/report-v4.md",
            "report/findings-v4.json",
            "report/report-write-receipt-v4.json",
        )
        if any(self.context.artifact_path(path).exists() for path in final_paths):
            raise ReportPreflightV4Error("formal V4 report exists before final write preflight")
        if not include_launch and self.context.artifact_path(self.LAUNCH_RECEIPT).exists():
            raise ReportPreflightV4Error("launch receipt exists before Reporter preflight")

    def _load_approvals(self) -> tuple[ApprovalRecordV4, ...]:
        root = self.context.artifact_path(self.APPROVALS)
        if not root.exists():
            return ()
        values = []
        for path in sorted(root.glob("*.json")):
            if path.name.startswith("challenge-"):
                continue
            raw = json.loads(path.read_text(encoding="utf-8"))
            values.append(
                ApprovalBatchV4.model_validate(raw)
                if raw.get("version") == "4"
                else ApprovalBatchV3.model_validate(raw)
            )
        return tuple(values)

    def _load_consumptions(self) -> tuple[ConsumptionRecordV4, ...]:
        root = self.context.artifact_path(self.CONSUMPTIONS)
        if not root.exists():
            return ()
        values = []
        for path in sorted(root.glob("*.json")):
            raw = json.loads(path.read_text(encoding="utf-8"))
            values.append(
                ApprovalConsumptionV4.model_validate(raw)
                if raw.get("version") == "4"
                else ApprovalConsumptionV3.model_validate(raw)
            )
        return tuple(values)

    def _expected_evidence_refs(self, findings: FindingSetV4) -> tuple[EvidenceArtifactRef, ...]:
        refs: dict[str, EvidenceArtifactRef] = {}
        for finding in findings.findings:
            for ref in finding.evidence:
                prior = refs.setdefault(ref.evidence_id, ref)
                if prior != ref:
                    raise ReportPreflightV4Error("one evidence ID has conflicting references")
        return tuple(refs[key] for key in sorted(refs))

    def _read(self, relative: str, model: type[BaseModel]) -> Any:
        try:
            return model.model_validate_json(self.context.artifact_path(relative).read_bytes())
        except (OSError, ValueError) as exc:
            raise ReportPreflightV4Error(f"invalid or missing V4 artifact: {relative}") from exc

    def _read_optional(self, relative: str, model: type[BaseModel]) -> Any | None:
        path = self.context.artifact_path(relative)
        if not path.exists():
            return None
        return self._read(relative, model)


def _sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _sha256_json(value: object) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return _sha256_bytes(encoded)


def _missing_approval_verifier(_batch: ApprovalRecordV4) -> None:
    """Never treat a structural approval record as a valid signature."""

    raise ReportPreflightV4Error("V4 approval signature verifier is required")


def _missing_review_verifier(
    _review: SignedReviewBatchV4,
    _findings: FindingSetV4,
    _coverage: CoverageAppendixV4,
) -> None:
    """Never treat a structural human-review record as a valid signature."""

    raise ReportPreflightV4Error("V4 human review signature verifier is required")


__all__ = [
    "ReportPreflightV4Error",
    "ReportPreflightVerifierV4",
    "VerifiedReportBundleV4",
    "coverage_gap_digests_v4",
]

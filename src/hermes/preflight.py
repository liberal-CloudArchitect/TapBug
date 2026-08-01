"""Fail-closed authorization gate for V2 report generation.

The renderer is intentionally not trusted to discover or reconcile artifacts.  It
may consume only a :class:`VerifiedReportBundle` produced here from the canonical
run directory after every domain, approval, review, coverage, and evidence edge
has been re-verified.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field

from .domain_contracts import (
    AssetInventory,
    CandidateSet,
    CoverageReport,
    EndpointInventory,
    ValidatedFinding,
    VerificationOutcome,
    VerificationPlan,
    canonical_digest,
)
from .evidence import (
    EvidenceArtifactManifest,
    EvidenceArtifactRef,
    EvidenceStore,
    EvidenceStoreError,
    require_negative_control_link,
    verify_fixed_header_differential,
)
from .legacy import LegacyRunReadOnlyError, require_v2_run
from .metrics import ASSESSMENT_TASK_IDS, MetricsError, collect_pre_report_metrics
from .prompts import PromptRegistry
from .runtime import RunContext
from .runtime.agents import RoleManifest, RoleTrustStore, TaskEnvelope
from .security import TrustStoreV2
from .vertical_contracts import (
    ApprovalBundle,
    ApprovalConsumptionV2,
    RunPlan,
    SignedHumanReview,
    verify_approval_bundle,
    verify_human_review,
)

_DIGEST = r"^sha256:[0-9a-f]{64}$"
_ID = r"^[A-Za-z0-9._-]{1,128}$"
_Model = TypeVar("_Model", bound=BaseModel)


class ReportPreflightError(ValueError):
    """Canonical run artifacts do not authorize a formal report."""


class ReportAuthorizationReceipt(BaseModel):
    """Recomputable hash inventory for one exact report input set."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["2"] = "2"
    verifier_id: Literal["hermes.report-preflight"] = "hermes.report-preflight"
    verifier_schema_version: Literal["2"] = "2"
    verified_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    run_id: str = Field(pattern=_ID)
    scope_digest: str = Field(pattern=_DIGEST)
    asset_inventory_digest: str = Field(pattern=_DIGEST)
    endpoint_inventory_digest: str = Field(pattern=_DIGEST)
    candidate_set_digest: str = Field(pattern=_DIGEST)
    verification_plan_digest: str = Field(pattern=_DIGEST)
    verification_outcome_digest: str = Field(pattern=_DIGEST)
    validated_finding_digest: str = Field(pattern=_DIGEST)
    coverage_report_digest: str = Field(pattern=_DIGEST)
    approval_bundle_id: str = Field(pattern=_ID)
    approval_bundle_digest: str = Field(pattern=_DIGEST)
    approval_consumption_digests: tuple[str, str]
    signed_review_id: str = Field(pattern=_ID)
    signed_review_digest: str = Field(pattern=_DIGEST)
    report_draft_digest: str = Field(pattern=_DIGEST)
    evidence_ids: tuple[str, str, str]
    evidence_manifest_digests: tuple[str, str, str]

    @property
    def digest(self) -> str:
        return canonical_digest(self)

    @property
    def authorization_input_digest(self) -> str:
        """Stable digest used to compare independently recomputed receipts."""

        return canonical_digest(self.model_dump(mode="json", exclude={"verified_at"}))


class VerifiedReportBundle(BaseModel):
    """Fully typed inputs that have passed the report authorization hard gate."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    assets: AssetInventory
    endpoints: EndpointInventory
    candidates: CandidateSet
    verification_plan: VerificationPlan
    outcome: VerificationOutcome
    finding: ValidatedFinding
    coverage: CoverageReport
    approval: ApprovalBundle
    consumptions: tuple[ApprovalConsumptionV2, ApprovalConsumptionV2]
    review: SignedHumanReview
    evidence_manifests: tuple[
        EvidenceArtifactManifest,
        EvidenceArtifactManifest,
        EvidenceArtifactManifest,
    ]
    authorization: ReportAuthorizationReceipt


class ReportPreflightVerifier:
    """Reconstruct and authorize the one fixed V2 localhost finding chain."""

    ASSETS = "assets/inventory.json"
    ENDPOINTS = "endpoints/inventory.json"
    CANDIDATES = "candidates/set.json"
    PLAN = "plan/verification.json"
    OUTCOME = "report/outcome.json"
    FINDING = "report/finding.json"
    COVERAGE = "report/coverage.json"
    DRAFT = "report/draft.md"
    APPROVAL = "approvals/decision.json"
    REVIEW = "reviews/signed.json"

    def __init__(
        self,
        context: RunContext,
        *,
        approval_store: TrustStoreV2,
        review_store: TrustStoreV2,
        publisher_store: RoleTrustStore,
        prompt_registry: PromptRegistry,
        evidence_store: EvidenceStore | None = None,
        historical_manifest_verification: bool = False,
    ) -> None:
        self.context = context
        self.approval_store = approval_store
        self.review_store = review_store
        self.publisher_store = publisher_store
        self.prompt_registry = prompt_registry
        self.evidence_store = evidence_store or EvidenceStore(context.path)
        # This flag is only for offline retained-artifact audits.  A live
        # promotion/report path must continue to require a currently active
        # publisher key before it launches any role or creates a report.
        self.historical_manifest_verification = historical_manifest_verification

    def verify(self) -> VerifiedReportBundle:
        try:
            return self._verify()
        except ReportPreflightError:
            raise
        except (OSError, ValueError, EvidenceStoreError, LegacyRunReadOnlyError) as exc:
            raise ReportPreflightError(f"report preflight failed: {exc}") from exc

    def authorize(self) -> ReportAuthorizationReceipt:
        """Return only the deterministic receipt for callers that do not render yet."""

        return self.verify().authorization

    def _verify(self) -> VerifiedReportBundle:
        require_v2_run(self.context)
        assets = self._read(self.ASSETS, AssetInventory)
        endpoints = self._read(self.ENDPOINTS, EndpointInventory)
        candidates = self._read(self.CANDIDATES, CandidateSet)
        plan = self._read(self.PLAN, VerificationPlan)
        outcome = self._read(self.OUTCOME, VerificationOutcome)
        finding = self._read(self.FINDING, ValidatedFinding)
        coverage = self._read(self.COVERAGE, CoverageReport)
        approval = self._read(self.APPROVAL, ApprovalBundle)
        review = self._read(self.REVIEW, SignedHumanReview)

        self._verify_supply_chain(assets)

        run_bound: tuple[BaseModel, ...] = (
            assets,
            endpoints,
            candidates,
            plan,
            outcome,
            finding,
            coverage,
        )
        for artifact in run_bound:
            if (
                getattr(artifact, "run_id", None) != self.context.run_id
                or getattr(artifact, "scope_digest", None) != self.context.scope_digest
            ):
                raise ReportPreflightError("a domain artifact crosses the run or scope boundary")

        self._verify_domain_chain(assets, endpoints, candidates, plan, outcome, finding, coverage)
        self._verify_provider_metrics(coverage)
        self._verify_approval(approval, plan, outcome)
        consumptions = self._load_consumptions(approval, plan)
        self._verify_consumptions(consumptions, approval, plan, outcome, finding)

        review_digest = canonical_digest(review)
        if review.version != "2" or review.verdict != "accepted":
            raise ReportPreflightError("formal reporting requires an accepted human review")
        draft_path = self.context.artifact_path(self.DRAFT)
        try:
            draft_digest = "sha256:" + hashlib.sha256(draft_path.read_bytes()).hexdigest()
        except OSError as exc:
            raise ReportPreflightError("canonical report draft is missing") from exc
        if review.outcome_digest != outcome.digest or review.report_draft_digest != draft_digest:
            raise ReportPreflightError("human review is not bound to the V2 outcome and draft")
        verify_human_review(
            review,
            self.review_store,
            run_id=self.context.run_id,
            scope_digest=self.context.scope_digest,
            finding_id=finding.finding_id,
            evidence_digest=outcome.digest,
        )
        if (
            finding.signed_review_id != review.review_id
            or finding.signed_review_digest != review_digest
        ):
            raise ReportPreflightError("finding review identity or digest does not match")

        refs = finding.evidence
        verified_manifests = tuple(self.evidence_store.verify(ref) for ref in refs)
        manifests = (
            verified_manifests[0],
            verified_manifests[1],
            verified_manifests[2],
        )
        self._verify_evidence_set(
            assets,
            endpoints,
            candidates,
            plan,
            outcome,
            consumptions,
            refs,
            manifests,
        )

        receipt = ReportAuthorizationReceipt(
            run_id=self.context.run_id,
            scope_digest=self.context.scope_digest,
            asset_inventory_digest=assets.digest,
            endpoint_inventory_digest=endpoints.digest,
            candidate_set_digest=candidates.digest,
            verification_plan_digest=plan.digest,
            verification_outcome_digest=outcome.digest,
            validated_finding_digest=finding.digest,
            coverage_report_digest=coverage.digest,
            approval_bundle_id=approval.bundle_id,
            approval_bundle_digest=approval.digest,
            approval_consumption_digests=(
                consumptions[0].digest,
                consumptions[1].digest,
            ),
            signed_review_id=review.review_id,
            signed_review_digest=review_digest,
            report_draft_digest=draft_digest,
            evidence_ids=(refs[0].evidence_id, refs[1].evidence_id, refs[2].evidence_id),
            evidence_manifest_digests=(
                refs[0].manifest_sha256,
                refs[1].manifest_sha256,
                refs[2].manifest_sha256,
            ),
        )
        return VerifiedReportBundle(
            assets=assets,
            endpoints=endpoints,
            candidates=candidates,
            verification_plan=plan,
            outcome=outcome,
            finding=finding,
            coverage=coverage,
            approval=approval,
            consumptions=consumptions,
            review=review,
            evidence_manifests=manifests,
            authorization=receipt,
        )

    def _verify_supply_chain(self, assets: AssetInventory) -> None:
        plan = self._read("plan/run-plan.json", RunPlan)
        if (
            plan.version != "2"
            or plan.run_id != self.context.run_id
            or plan.scope_digest != self.context.scope_digest
            or plan.target != assets.target
            or plan.prompt_registry_digest != self.prompt_registry.digest
        ):
            raise ReportPreflightError("run plan is not bound to the trusted V2 supply chain")

        try:
            registry_snapshot = json.loads(
                self.context.artifact_path("plan/prompt-registry.json").read_text(encoding="utf-8")
            )
            manifest_snapshot = json.loads(
                self.context.artifact_path("plan/role-manifests.json").read_text(encoding="utf-8")
            )
            manifest_values = manifest_snapshot["roles"]
        except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
            raise ReportPreflightError("prompt or role manifest snapshot is missing") from exc
        if (
            not isinstance(registry_snapshot, dict)
            or registry_snapshot.get("version") != "1"
            or registry_snapshot.get("roles") != self.prompt_registry.roles
            or not isinstance(manifest_values, list)
        ):
            raise ReportPreflightError("prompt registry snapshot differs from trusted content")
        manifests = tuple(RoleManifest.model_validate(item) for item in manifest_values)
        if tuple(sorted(item.role for item in manifests)) != tuple(sorted(plan.roles)):
            raise ReportPreflightError(
                "role manifest snapshot does not contain the exact run roles"
            )
        for manifest in manifests:
            if self.historical_manifest_verification:
                self.publisher_store.verify_historical(manifest)
            else:
                self.publisher_store.verify(manifest)
            self.prompt_registry.verify_manifest(manifest)

    def _read(self, relative: str, model: type[_Model]) -> _Model:
        path = self.context.artifact_path(relative)
        try:
            return model.model_validate_json(path.read_bytes())
        except OSError as exc:
            raise ReportPreflightError(f"canonical artifact is missing: {relative}") from exc
        except ValueError as exc:
            raise ReportPreflightError(f"canonical artifact is invalid: {relative}") from exc

    @staticmethod
    def _verify_domain_chain(
        assets: AssetInventory,
        endpoints: EndpointInventory,
        candidates: CandidateSet,
        plan: VerificationPlan,
        outcome: VerificationOutcome,
        finding: ValidatedFinding,
        coverage: CoverageReport,
    ) -> None:
        candidate = candidates.candidates[0]
        endpoint_by_id = {item.endpoint_id: item for item in endpoints.endpoints}
        target_endpoint = endpoint_by_id.get(candidate.target_endpoint_id)
        control_endpoint = endpoint_by_id.get(candidate.control_endpoint_id)
        if target_endpoint is None or control_endpoint is None:
            raise ReportPreflightError("candidate refers to an endpoint outside the inventory")
        expected_steps = (target_endpoint, control_endpoint)
        if endpoints.asset_inventory_digest != assets.digest:
            raise ReportPreflightError("endpoint inventory is not bound to the asset inventory")
        if candidates.endpoint_inventory_digest != endpoints.digest:
            raise ReportPreflightError("candidate set is not bound to the endpoint inventory")
        if (
            plan.candidate_set_digest != candidates.digest
            or plan.endpoint_inventory_digest != endpoints.digest
            or plan.candidate_id != candidate.candidate_id
        ):
            raise ReportPreflightError("verification plan is not bound to the candidate chain")
        for step, endpoint in zip(plan.steps, expected_steps, strict=True):
            assert endpoint is not None
            if (
                step.endpoint_id != endpoint.endpoint_id
                or step.target_url != endpoint.canonical_url
            ):
                raise ReportPreflightError("verification step changed its canonical endpoint")
        if (
            outcome.status != "validated"
            or outcome.candidate_id != candidate.candidate_id
            or outcome.verification_plan_digest != plan.digest
        ):
            raise ReportPreflightError("verification outcome is not a validated plan result")
        for step, result in zip(plan.steps, outcome.step_outcomes, strict=True):
            if (
                result.status != "passed"
                or result.action_id != step.action_id
                or result.action_digest != step.action_digest
            ):
                raise ReportPreflightError("verification result does not match its planned action")
        if (
            finding.candidate_id != candidate.candidate_id
            or finding.candidate_set_digest != candidates.digest
            or finding.verification_plan_digest != plan.digest
            or finding.verification_outcome_digest != outcome.digest
            or finding.target != target_endpoint.canonical_url
        ):
            raise ReportPreflightError("validated finding is not bound to the typed result chain")
        expected_coverage = (
            coverage.asset_inventory_digest == assets.digest
            and coverage.endpoint_inventory_digest == endpoints.digest
            and coverage.candidate_set_digest == candidates.digest
            and coverage.verification_plan_digest == plan.digest
            and coverage.verification_outcome_digest == outcome.digest
            and coverage.validated_finding_digest == finding.digest
            and coverage.steps_planned == 2
            and coverage.steps_tested == 2
            and coverage.steps_blocked == 0
            and coverage.steps_skipped == 0
            and coverage.findings_validated == 1
            and coverage.candidates_inconclusive == 0
            and coverage.candidates_disproved == 0
            and coverage.requests_planned == 3
            and coverage.requests_used == 3
        )
        if not expected_coverage:
            raise ReportPreflightError("coverage does not exactly describe the validated chain")

    def _verify_approval(
        self,
        approval: ApprovalBundle,
        plan: VerificationPlan,
        outcome: VerificationOutcome,
    ) -> None:
        if approval.version != "2" or any(
            decision.decision != "approved" for decision in approval.decisions
        ):
            raise ReportPreflightError("verification requires two explicitly approved actions")
        verify_approval_bundle(approval, plan, self.approval_store, at=approval.issued_at)
        if (
            outcome.approval_bundle_id != approval.bundle_id
            or outcome.approval_bundle_digest != approval.digest
        ):
            raise ReportPreflightError("outcome is not bound to the signed approval bundle")

    def _load_consumptions(
        self, approval: ApprovalBundle, plan: VerificationPlan
    ) -> tuple[ApprovalConsumptionV2, ApprovalConsumptionV2]:
        root = self.context.artifact_path("approvals/consumed")
        expected_paths = {
            self.context.artifact_path(
                f"approvals/consumed/{approval.bundle_id}/{step.action_id}.json"
            )
            for step in plan.steps
        }
        actual_paths = set(root.glob("*/*.json")) if root.is_dir() else set()
        if actual_paths != expected_paths:
            raise ReportPreflightError("approval consumption set is missing or contains extras")
        values = tuple(
            ApprovalConsumptionV2.model_validate_json(path.read_bytes())
            for path in (
                self.context.artifact_path(
                    f"approvals/consumed/{approval.bundle_id}/{step.action_id}.json"
                )
                for step in plan.steps
            )
        )
        return values  # type: ignore[return-value]

    def _verify_consumptions(
        self,
        consumptions: tuple[ApprovalConsumptionV2, ApprovalConsumptionV2],
        approval: ApprovalBundle,
        plan: VerificationPlan,
        outcome: VerificationOutcome,
        finding: ValidatedFinding,
    ) -> None:
        expected_digests: list[str] = []
        for step, result, consumption in zip(
            plan.steps, outcome.step_outcomes, consumptions, strict=True
        ):
            verify_approval_bundle(approval, plan, self.approval_store, at=consumption.consumed_at)
            if (
                consumption.bundle_id != approval.bundle_id
                or consumption.bundle_digest != approval.digest
                or consumption.plan_digest != plan.digest
                or consumption.run_id != self.context.run_id
                or consumption.scope_digest != self.context.scope_digest
                or consumption.action_id != step.action_id
                or consumption.action_digest != step.action_digest
                or consumption.evidence_id != result.evidence.evidence_id
                or result.consumption_digest != consumption.digest
            ):
                raise ReportPreflightError("approval consumption crosses an action binding")
            expected_digests.append(consumption.digest)
        if set(finding.approval_consumption_digests) != set(expected_digests):
            raise ReportPreflightError("finding approval consumption set does not match")
        if (
            finding.approval_bundle_id != approval.bundle_id
            or finding.approval_bundle_digest != approval.digest
        ):
            raise ReportPreflightError("finding is not bound to the signed approval bundle")

    def _verify_evidence_set(
        self,
        assets: AssetInventory,
        endpoints: EndpointInventory,
        candidates: CandidateSet,
        plan: VerificationPlan,
        outcome: VerificationOutcome,
        consumptions: tuple[ApprovalConsumptionV2, ApprovalConsumptionV2],
        refs: tuple[EvidenceArtifactRef, ...],
        manifests: tuple[EvidenceArtifactManifest, ...],
    ) -> None:
        expected_refs = {assets.source_evidence[0], *outcome.evidence}
        if set(refs) != expected_refs:
            raise ReportPreflightError("finding evidence is missing or contains extras")
        if any(
            set(endpoint.evidence) != set(assets.source_evidence)
            for endpoint in endpoints.endpoints
        ):
            raise ReportPreflightError("endpoint evidence does not match Recon evidence")
        if set(candidates.candidates[0].required_evidence) != set(assets.source_evidence):
            raise ReportPreflightError("candidate evidence does not match Recon evidence")
        if any(
            not set(step.evidence_prerequisites).issubset(set(assets.source_evidence))
            for step in plan.steps
        ):
            raise ReportPreflightError("verification prerequisite evidence is not from Recon")

        expected_paths = {self.context.artifact_path(ref.manifest_path) for ref in refs}
        actual_paths = set(self.context.artifact_path("evidence").glob("*/manifest.json"))
        if actual_paths != expected_paths:
            raise ReportPreflightError("run evidence set is missing or contains extras")
        expected_directories = {path.parent for path in expected_paths}
        actual_directories = {
            path for path in self.context.artifact_path("evidence").iterdir() if path.is_dir()
        }
        if actual_directories != expected_directories:
            raise ReportPreflightError("run evidence directory set contains an orphan artifact")

        by_id = {manifest.binding.evidence_id: manifest for manifest in manifests}
        recon = by_id[assets.source_evidence[0].evidence_id]
        self._verify_task_binding(recon)
        if (
            recon.binding.run_id != self.context.run_id
            or recon.binding.scope_digest != self.context.scope_digest
            or recon.binding.task_id != assets.generated_by_task_id
            or recon.binding.role != "recon"
            or recon.binding.plan_digest is not None
            or recon.binding.approval_bundle_id is not None
        ):
            raise ReportPreflightError("Recon evidence binding is invalid")
        if recon.request_method != "GET" or recon.target != assets.target:
            raise ReportPreflightError("Recon evidence does not describe the inventory target")

        for step, result, consumption in zip(
            plan.steps, outcome.step_outcomes, consumptions, strict=True
        ):
            manifest = by_id[result.evidence.evidence_id]
            self._verify_task_binding(manifest)
            if (
                manifest.binding.run_id != self.context.run_id
                or manifest.binding.scope_digest != self.context.scope_digest
                or manifest.binding.task_id != outcome.generated_by_task_id
                or manifest.binding.role != "verifier"
                or manifest.binding.request_id != consumption.request_id
                or manifest.binding.action_id != step.action_id
                or manifest.binding.action_digest != step.action_digest
                or manifest.binding.plan_digest != plan.digest
                or manifest.binding.approval_bundle_id != consumption.bundle_id
                or manifest.binding.approval_bundle_digest != consumption.bundle_digest
                or manifest.binding.approval_consumption_digest != consumption.digest
                or manifest.request_method != "GET"
                or manifest.target != step.target_url
            ):
                raise ReportPreflightError("Verifier evidence crosses an approved action binding")

        candidate = candidates.candidates[0]
        endpoint_by_id = {item.endpoint_id: item for item in endpoints.endpoints}
        target_url = endpoint_by_id[candidate.target_endpoint_id].canonical_url
        control_url = endpoint_by_id[candidate.control_endpoint_id].canonical_url
        trusted_projection = require_negative_control_link(
            self.evidence_store,
            assets.source_evidence[0],
            target_url=target_url,
            control_url=control_url,
        )
        if assets.assets[0].header_projection != trusted_projection:
            raise ReportPreflightError("asset header projection differs from Recon evidence")
        verify_fixed_header_differential(
            self.evidence_store,
            recon_ref=assets.source_evidence[0],
            candidate_ref=outcome.step_outcomes[0].evidence,
            control_ref=outcome.step_outcomes[1].evidence,
            target_url=target_url,
            control_url=control_url,
        )

        allowed_report_json = {
            "outcome.json",
            "finding.json",
            "coverage.json",
            "authorization.json",
            "reporter-acknowledgement.json",
            "findings.json",
        }
        actual_report_json = {
            path.name for path in self.context.artifact_path("report").glob("*.json")
        }
        if not actual_report_json.issubset(allowed_report_json):
            raise ReportPreflightError("report directory contains an orphan formal artifact")

    def _verify_provider_metrics(self, coverage: CoverageReport) -> None:
        provider_tasks = {
            path.stem for path in self.context.artifact_path("provider").glob("*.json")
        }
        allowed_sets = (
            set(ASSESSMENT_TASK_IDS),
            {*ASSESSMENT_TASK_IDS, "phase3-reporter"},
        )
        if provider_tasks not in allowed_sets:
            raise ReportPreflightError("provider artifact set is missing or contains extras")
        try:
            metrics = collect_pre_report_metrics(self.context)
        except MetricsError as exc:
            raise ReportPreflightError("provider metrics cannot be recomputed") from exc
        if (
            coverage.model_calls != metrics.model_calls
            or coverage.elapsed_ms != metrics.elapsed_ms
            or coverage.cost_microusd != metrics.cost_microusd
        ):
            raise ReportPreflightError("coverage provider metrics do not match run artifacts")

    def _verify_task_binding(self, manifest: EvidenceArtifactManifest) -> None:
        task_id = manifest.binding.task_id
        path = self.context.artifact_path(f"handoffs/{task_id}.json")
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
            task = TaskEnvelope.model_validate(document["task"])
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ReportPreflightError("evidence producer TaskEnvelope is missing") from exc
        if (
            task.run_id != manifest.binding.run_id
            or task.scope_digest != manifest.binding.scope_digest
            or task.task_id != task_id
            or task.role != manifest.binding.role
            or task.input_hash() != manifest.binding.task_input_sha256
        ):
            raise ReportPreflightError("evidence binding does not match its producer TaskEnvelope")

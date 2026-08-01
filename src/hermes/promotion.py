"""Parent-owned promotion from a verified V2 outcome to reportable artifacts."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import TypeVar

from pydantic import BaseModel

from .domain_contracts import (
    AssetInventory,
    CandidateSet,
    CoverageReport,
    EndpointInventory,
    ValidatedFinding,
    VerificationOutcome,
    VerificationPlan,
)
from .evidence import (
    EvidenceArtifactManifest,
    EvidenceArtifactRef,
    EvidenceStore,
    EvidenceStoreError,
    verify_fixed_header_differential,
)
from .legacy import require_v2_run
from .metrics import MetricsError, collect_pre_report_metrics
from .runtime import RunContext
from .security import SecurityContractError, TrustStoreV2
from .vertical_contracts import (
    ApprovalBundle,
    ApprovalConsumptionV2,
    SignedHumanReview,
    verify_approval_bundle,
    verify_human_review,
)


class PromotionError(RuntimeError):
    """The candidate cannot be promoted from the stored canonical artifacts."""


def file_sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


_ModelT = TypeVar("_ModelT", bound=BaseModel)


class PromotionService:
    """Create a finding and coverage only after re-verifying every V2 binding."""

    def __init__(
        self,
        context: RunContext,
        *,
        approval_store: TrustStoreV2,
        review_store: TrustStoreV2,
        evidence_store: EvidenceStore,
    ) -> None:
        self.context = context
        self.approval_store = approval_store
        self.review_store = review_store
        self.evidence_store = evidence_store

    def promote(self) -> tuple[ValidatedFinding, CoverageReport]:
        require_v2_run(self.context)
        assets = self._model("assets/inventory.json", AssetInventory)
        endpoints = self._model("endpoints/inventory.json", EndpointInventory)
        candidates = self._model("candidates/set.json", CandidateSet)
        plan = self._model("plan/verification.json", VerificationPlan)
        bundle = self._model("approvals/decision.json", ApprovalBundle)
        outcome = self._model("report/outcome.json", VerificationOutcome)
        review = self._model("reviews/signed.json", SignedHumanReview)
        consumptions = self._consumptions(bundle)

        self._run_scope(assets, endpoints, candidates, plan, outcome)
        self._domain_chain(assets, endpoints, candidates, plan, outcome)
        try:
            verify_approval_bundle(bundle, plan, self.approval_store, at=bundle.issued_at)
        except SecurityContractError as exc:
            raise PromotionError("approval bundle is invalid") from exc
        if bundle.digest != outcome.approval_bundle_digest:
            raise PromotionError("outcome approval digest does not match the signed bundle")
        if bundle.bundle_id != outcome.approval_bundle_id:
            raise PromotionError("outcome approval ID does not match the signed bundle")

        draft_path = self.context.artifact_path("report/draft.md")
        if not draft_path.is_file():
            raise PromotionError("signed report draft is missing")
        if review.version != "2":
            raise PromotionError("only a V2 signed human review may promote a finding")
        if review.outcome_digest != outcome.digest:
            raise PromotionError("human review is bound to another outcome")
        if review.report_draft_digest != file_sha256(draft_path):
            raise PromotionError("human review is bound to another report draft")
        if review.verdict != "accepted" or outcome.status != "validated":
            raise PromotionError("only an accepted validated outcome may be promoted")
        try:
            verify_human_review(
                review,
                self.review_store,
                run_id=self.context.run_id,
                scope_digest=self.context.scope_digest,
                finding_id=outcome.candidate_id,
                evidence_digest=outcome.digest,
            )
        except SecurityContractError as exc:
            raise PromotionError("human review signature is invalid") from exc

        manifests = self._evidence_chain(assets, plan, bundle, outcome, consumptions)
        candidate = candidates.candidates[0]
        endpoint_by_id = {item.endpoint_id: item for item in endpoints.endpoints}
        target_url = endpoint_by_id[candidate.target_endpoint_id].canonical_url
        control_url = endpoint_by_id[candidate.control_endpoint_id].canonical_url
        try:
            verify_fixed_header_differential(
                self.evidence_store,
                recon_ref=manifests[0].ref,
                candidate_ref=manifests[1].ref,
                control_ref=manifests[2].ref,
                target_url=target_url,
                control_url=control_url,
            )
        except EvidenceStoreError as exc:
            raise PromotionError(
                "validated outcome is not supported by the HTTP differential"
            ) from exc
        try:
            metrics = collect_pre_report_metrics(self.context)
        except MetricsError as exc:
            raise PromotionError("provider metrics are invalid") from exc
        finding = ValidatedFinding(
            finding_id=candidate.candidate_id,
            candidate_id=candidate.candidate_id,
            run_id=self.context.run_id,
            scope_digest=self.context.scope_digest,
            generated_by_task_id="host-promotion",
            candidate_set_digest=candidates.digest,
            verification_plan_digest=plan.digest,
            verification_outcome_digest=outcome.digest,
            approval_bundle_id=bundle.bundle_id,
            approval_bundle_digest=bundle.digest,
            approval_consumption_digests=tuple(item.digest for item in consumptions),
            signed_review_id=review.review_id,
            signed_review_digest=review.digest,
            evidence=tuple(manifest.ref for manifest in manifests),
            title="Missing X-Content-Type-Options on local teaching endpoint",
            target=target_url,
            summary="The candidate endpoint omits nosniff while its matched control includes it.",
            prerequisites=("Local Docker teaching fixture",),
            reproduction_steps=(
                "GET the candidate endpoint once.",
                "GET the linked negative-control endpoint once and compare headers.",
            ),
            impact="The local candidate lacks the browser MIME-sniffing defense.",
            remediation="Set X-Content-Type-Options: nosniff consistently.",
            severity="informational",
        )
        coverage = CoverageReport(
            report_id="coverage-1",
            run_id=self.context.run_id,
            scope_digest=self.context.scope_digest,
            generated_by_task_id="host-coverage",
            asset_inventory_digest=assets.digest,
            endpoint_inventory_digest=endpoints.digest,
            candidate_set_digest=candidates.digest,
            verification_plan_digest=plan.digest,
            verification_outcome_digest=outcome.digest,
            validated_finding_digest=finding.digest,
            steps_planned=2,
            steps_tested=2,
            steps_blocked=0,
            steps_skipped=0,
            findings_validated=1,
            candidates_inconclusive=0,
            candidates_disproved=0,
            model_calls=metrics.model_calls,
            elapsed_ms=metrics.elapsed_ms,
            cost_microusd=metrics.cost_microusd,
        )
        self.context.write_json(
            "report/finding.json", finding.model_dump(mode="json"), immutable=True
        )
        self.context.write_json(
            "report/coverage.json", coverage.model_dump(mode="json"), immutable=True
        )
        return finding, coverage

    def _model(self, relative: str, model: type[_ModelT]) -> _ModelT:
        path = self.context.artifact_path(relative)
        if not path.is_file():
            raise PromotionError(f"required artifact is missing: {relative}")
        try:
            return model.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise PromotionError(f"required artifact is invalid: {relative}") from exc

    def _run_scope(self, *records: object) -> None:
        for record in records:
            if (
                getattr(record, "run_id", None) != self.context.run_id
                or getattr(record, "scope_digest", None) != self.context.scope_digest
            ):
                raise PromotionError("domain artifact crosses its run or scope boundary")

    @staticmethod
    def _domain_chain(
        assets: AssetInventory,
        endpoints: EndpointInventory,
        candidates: CandidateSet,
        plan: VerificationPlan,
        outcome: VerificationOutcome,
    ) -> None:
        candidate = candidates.candidates[0]
        endpoint_by_id = {item.endpoint_id: item for item in endpoints.endpoints}
        if endpoints.asset_inventory_digest != assets.digest:
            raise PromotionError("endpoint inventory is not bound to asset inventory")
        if candidates.endpoint_inventory_digest != endpoints.digest:
            raise PromotionError("candidate set is not bound to endpoint inventory")
        if (
            plan.candidate_set_digest != candidates.digest
            or plan.endpoint_inventory_digest != endpoints.digest
            or plan.candidate_id != candidate.candidate_id
        ):
            raise PromotionError("verification plan is not bound to its candidate chain")
        if (
            outcome.verification_plan_digest != plan.digest
            or outcome.candidate_id != candidate.candidate_id
        ):
            raise PromotionError("verification outcome is not bound to its plan")
        expected_endpoints = (candidate.target_endpoint_id, candidate.control_endpoint_id)
        if tuple(step.endpoint_id for step in plan.steps) != expected_endpoints:
            raise PromotionError("verification plan changed the candidate endpoint order")
        if any(endpoint_id not in endpoint_by_id for endpoint_id in expected_endpoints):
            raise PromotionError("candidate references an unknown endpoint")

    def _consumptions(self, bundle: ApprovalBundle) -> tuple[ApprovalConsumptionV2, ...]:
        root = self.context.artifact_path(f"approvals/consumed/{bundle.bundle_id}")
        if not root.is_dir():
            raise PromotionError("approval consumptions are missing")
        paths = tuple(sorted(root.glob("*.json")))
        if len(paths) != 2:
            raise PromotionError("the exact two approval consumptions are required")
        try:
            return tuple(
                ApprovalConsumptionV2.model_validate_json(path.read_text(encoding="utf-8"))
                for path in paths
            )
        except (OSError, ValueError) as exc:
            raise PromotionError("approval consumption is invalid") from exc

    def _evidence_chain(
        self,
        assets: AssetInventory,
        plan: VerificationPlan,
        bundle: ApprovalBundle,
        outcome: VerificationOutcome,
        consumptions: tuple[ApprovalConsumptionV2, ...],
    ) -> tuple[_VerifiedEvidence, ...]:
        refs = (*assets.source_evidence, *outcome.evidence)
        if len({item.evidence_id for item in refs}) != 3:
            raise PromotionError("the exact three unique evidence artifacts are required")
        all_manifest_paths = {
            path.relative_to(self.context.path).as_posix()
            for path in self.context.artifact_path("evidence").glob("*/manifest.json")
        }
        if all_manifest_paths != {item.manifest_path for item in refs}:
            raise PromotionError("evidence directory contains missing or orphaned artifacts")
        try:
            manifests = tuple(self.evidence_store.verify(item) for item in refs)
        except ValueError as exc:
            raise PromotionError("evidence artifact integrity verification failed") from exc

        recon = manifests[0]
        if (
            recon.binding.run_id != self.context.run_id
            or recon.binding.scope_digest != self.context.scope_digest
            or recon.binding.task_id != assets.generated_by_task_id
            or recon.binding.role != "recon"
            or recon.binding.plan_digest is not None
            or recon.binding.approval_bundle_id is not None
            or recon.binding.approval_bundle_digest is not None
            or recon.binding.approval_consumption_digest is not None
        ):
            raise PromotionError("Recon evidence binding is invalid")

        consumption_by_action = {item.action_id: item for item in consumptions}
        if len(consumption_by_action) != 2:
            raise PromotionError("approval consumptions contain a duplicate action")
        for step, step_outcome, manifest in zip(
            plan.steps, outcome.step_outcomes, manifests[1:], strict=True
        ):
            consumption = consumption_by_action.get(step.action_id)
            if consumption is None:
                raise PromotionError("verification action has no approval consumption")
            if (
                step_outcome.action_id != step.action_id
                or step_outcome.action_digest != step.action_digest
                or step_outcome.consumption_digest != consumption.digest
                or step_outcome.evidence.evidence_id != manifest.binding.evidence_id
            ):
                raise PromotionError("verification outcome changed its action evidence chain")
            binding = manifest.binding
            if (
                binding.run_id != self.context.run_id
                or binding.scope_digest != self.context.scope_digest
                or binding.task_id != outcome.generated_by_task_id
                or binding.role != "verifier"
                or binding.action_id != step.action_id
                or binding.action_digest != step.action_digest
                or binding.plan_digest != plan.digest
                or binding.approval_bundle_id != bundle.bundle_id
                or binding.approval_bundle_digest != bundle.digest
                or binding.approval_consumption_digest != consumption.digest
                or consumption.bundle_id != bundle.bundle_id
                or consumption.bundle_digest != bundle.digest
                or consumption.plan_digest != plan.digest
                or consumption.run_id != self.context.run_id
                or consumption.scope_digest != self.context.scope_digest
                or consumption.task_id != outcome.generated_by_task_id
                or consumption.request_id != binding.request_id
                or consumption.evidence_id != binding.evidence_id
                or consumption.action_digest != step.action_digest
            ):
                raise PromotionError("Verifier evidence or consumption binding is invalid")
        return tuple(
            _VerifiedEvidence(ref=ref, manifest=manifest)
            for ref, manifest in zip(refs, manifests, strict=True)
        )


class _VerifiedEvidence:
    """Small internal pair that keeps an already-verified ref with its manifest."""

    def __init__(self, *, ref: EvidenceArtifactRef, manifest: EvidenceArtifactManifest) -> None:
        self.ref = ref
        self.manifest = manifest


__all__ = ["PromotionError", "PromotionService", "file_sha256"]

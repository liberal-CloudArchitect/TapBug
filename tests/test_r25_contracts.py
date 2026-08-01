from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from hermes.r25_contracts import (
    CAPABILITY_SPEC_CONTRACT_ID,
    RESEARCH_FACTS_CONTRACT_ID,
    CapabilityExecutionReceiptV2,
    CapabilitySpecV2,
    ContinuationOutcomeV1,
    ContractEnvelopeR25,
    LearningRequestV1,
    LineFieldRuleV1,
    ResearchFactsOutputV1,
    ResearchFactV1,
    ResearchSourceArtifactV1,
    ValidationReceiptV2,
    WheelActivationReceiptV2,
    WheelApprovalV2,
    WheelManifestV2,
)
from hermes.runtime.agents.contracts import HandoffEnvelope


def test_learning_request_is_frozen_and_has_digest() -> None:
    contract = LearningRequestV1(
        learning_run_id="learn-run-1",
        parent_run_id="parent-run-1",
        scope_digest="sha256:" + "a" * 64,
        parent_run_plan_digest="sha256:" + "b" * 64,
        evidence_manifest_digest="sha256:" + "c" * 64,
        analysis_digest="sha256:" + "d" * 64,
        generated_by_task_id="task-1",
        operator_observation="unknown line protocol with key/value fields",
        created_at=datetime.now(UTC),
    )
    assert contract.digest.startswith("sha256:")
    with pytest.raises(Exception):
        contract.learning_run_id = "other"


def test_research_source_requires_https_and_fact_requires_unique_citations() -> None:
    with pytest.raises(ValueError, match="HTTPS"):
        ResearchSourceArtifactV1(
            source_id="source-1",
            learning_run_id="learn-run-1",
            source_url="http://example.test/spec",
            license="CC-BY-4.0",
            content_digest="sha256:" + "a" * 64,
            projection_digest="sha256:" + "b" * 64,
            source_bundle_digest="sha256:" + "c" * 64,
            retrieved_at=datetime.now(UTC),
        )
    source = ResearchSourceArtifactV1(
        source_id="source-1",
        learning_run_id="learn-run-1",
        source_url="https://example.test/spec",
        license="CC-BY-4.0",
        content_digest="sha256:" + "a" * 64,
        projection_digest="sha256:" + "b" * 64,
        source_bundle_digest="sha256:" + "c" * 64,
        retrieved_at=datetime.now(UTC),
    )
    assert source.digest.startswith("sha256:")
    with pytest.raises(ValueError, match="unique"):
        ResearchFactV1(
            fact_id="fact-1",
            learning_run_id="learn-run-1",
            source_id=source.source_id,
            statement="lines use colon separators",
            citation_ranges=("L1-L5", "L1-L5"),
            confidence="high",
            created_at=datetime.now(UTC),
        )


def test_capability_spec_is_locked_to_line_kv_parser() -> None:
    rule = LineFieldRuleV1(field_name="status", source_key="Status", required=True)
    spec = CapabilitySpecV2(
        capability_id="line-kv-status",
        input_schema_id="learning/input@v1",
        output_schema_id="learning/output@v1",
        field_rules=(rule,),
        required_output_fields=("status",),
        counterexamples=("free-form paragraph",),
        revocation_conditions=("field collision with nested keys",),
        source_digests=("sha256:" + "f" * 64,),
    )
    assert spec.max_requests == 0
    assert spec.network_policy == "deny"
    with pytest.raises(ValueError, match="exactly match"):
        CapabilitySpecV2(
            capability_id="line-kv-status",
            input_schema_id="learning/input@v1",
            output_schema_id="learning/output@v1",
            field_rules=(rule,),
            required_output_fields=("status", "reason"),
            counterexamples=("free-form paragraph",),
            revocation_conditions=("field collision with nested keys",),
            source_digests=("sha256:" + "f" * 64,),
        )


def test_r25_contract_envelope_matches_payload_contract() -> None:
    fact = ResearchFactV1(
        fact_id="fact-1",
        learning_run_id="learn-run-1",
        source_id="source-1",
        statement="lines use colon separators",
        citation_ranges=("L1-L5",),
        confidence="high",
        created_at=datetime.now(UTC),
    )
    output = ResearchFactsOutputV1(
        learning_run_id="learn-run-1",
        generated_by_task_id="task-1",
        source_digests=("sha256:" + "1" * 64,),
        facts=(fact,),
    )
    envelope = ContractEnvelopeR25.for_payload(output)
    assert envelope.contract_id == RESEARCH_FACTS_CONTRACT_ID
    assert envelope.payload_sha256 == output.digest

    spec = CapabilitySpecV2(
        capability_id="line-kv-status",
        input_schema_id="learning/input@v1",
        output_schema_id="learning/output@v1",
        field_rules=(LineFieldRuleV1(field_name="status", source_key="Status"),),
        required_output_fields=("status",),
        counterexamples=("free-form paragraph",),
        revocation_conditions=("field collision with nested keys",),
        source_digests=("sha256:" + "2" * 64,),
    )
    planned = ContractEnvelopeR25.for_payload(spec)
    assert planned.contract_id == CAPABILITY_SPEC_CONTRACT_ID

    with pytest.raises(ValueError, match="payload type"):
        ContractEnvelopeR25(
            contract_id=CAPABILITY_SPEC_CONTRACT_ID,
            contract_version="2",
            payload=output,
            payload_sha256=output.digest,
        )


def test_manifest_and_signed_receipts_require_valid_temporal_order() -> None:
    now = datetime.now(UTC)
    manifest = WheelManifestV2(
        wheel_id="line-kv-status",
        manifest_version="1.0.0",
        capability_spec_digest="sha256:" + "a" * 64,
        entrypoint="wheel.entry:parse",
        artifact_digest="sha256:" + "b" * 64,
        sbom_digest="sha256:" + "c" * 64,
        readme_digest="sha256:" + "d" * 64,
        lock_digest="sha256:" + "e" * 64,
        generated_at=now,
    )
    validation = ValidationReceiptV2(
        receipt_id="validation-1",
        learning_run_id="learn-run-1",
        wheel_manifest_digest=manifest.digest,
        validator_key_id="validator-1",
        static_checks=("ast",),
        docker_checks=("sandbox",),
        sandbox_image="wheel-sandbox:1",
        sandbox_image_digest="sha256:" + "1" * 64,
        fixture_positive_digest="sha256:" + "2" * 64,
        fixture_negative_digest="sha256:" + "3" * 64,
        validated_at=now,
        signature_b64="a" * 32,
    )
    approval = WheelApprovalV2(
        approval_id="approval-1",
        learning_run_id="learn-run-1",
        wheel_manifest_digest=manifest.digest,
        validation_receipt_digest=validation.digest,
        approver_key_id="approver-1",
        approved_at=now,
        expires_at=now + timedelta(minutes=5),
        signature_b64="b" * 32,
    )
    activation = WheelActivationReceiptV2(
        activation_id="activation-1",
        learning_run_id="learn-run-1",
        wheel_manifest_digest=manifest.digest,
        wheel_approval_digest=approval.digest,
        operator_key_id="operator-1",
        activated_at=now,
        signature_b64="c" * 32,
    )
    execution = CapabilityExecutionReceiptV2(
        execution_id="execution-1",
        continuation_run_id="continue-1",
        learning_run_id="learn-run-1",
        wheel_manifest_digest=manifest.digest,
        wheel_activation_digest=activation.digest,
        input_digest="sha256:" + "4" * 64,
        output_digest="sha256:" + "5" * 64,
        outcome="resolved",
        executed_at=now,
    )
    outcome = ContinuationOutcomeV1(
        continuation_run_id="continue-1",
        learning_run_id="learn-run-1",
        parent_run_id="parent-run-1",
        scope_digest="sha256:" + "6" * 64,
        wheel_manifest_digest=manifest.digest,
        wheel_activation_digest=activation.digest,
        execution_receipt_digest=execution.digest,
        structured_observation_digest="sha256:" + "7" * 64,
        outcome="resolved",
        generated_at=now,
    )
    assert outcome.execution_receipt_digest == execution.digest

    with pytest.raises(ValueError, match="must follow"):
        WheelApprovalV2(
            approval_id="approval-2",
            learning_run_id="learn-run-1",
            wheel_manifest_digest=manifest.digest,
            validation_receipt_digest=validation.digest,
            approver_key_id="approver-1",
            approved_at=now,
            expires_at=now,
            signature_b64="b" * 32,
        )


def test_r25_handoff_rejects_untyped_or_cross_role_payloads() -> None:
    output = ResearchFactsOutputV1(
        learning_run_id="learn-run-1",
        generated_by_task_id="research-task",
        source_digests=("sha256:" + "1" * 64,),
        facts=(
            ResearchFactV1(
                fact_id="fact-1",
                learning_run_id="learn-run-1",
                source_id="source-1",
                statement="A local fact.",
                citation_ranges=("L1",),
                confidence="high",
                created_at=datetime.now(UTC),
            ),
        ),
    )
    handoff = HandoffEnvelope.model_validate(
        {
            "version": "25",
            "run_id": "learn-run-1",
            "task_id": "research-task",
            "role": "researcher",
            "scope_digest": "sha256:" + "2" * 64,
            "input_sha256": "sha256:" + "3" * 64,
            "status": "completed",
            "result": ContractEnvelopeR25.for_payload(output).model_dump(mode="json"),
        }
    )
    assert handoff.result.payload.digest == output.digest
    with pytest.raises(ValueError, match="R2.5 handoff"):
        HandoffEnvelope.model_validate(
            {**handoff.model_dump(mode="json"), "role": "capability-planner"}
        )

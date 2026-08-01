from __future__ import annotations

import pytest
from pydantic import ValidationError

from hermes.domain_contracts import ContractEnvelope, GateDecisionV2
from hermes.evidence import EvidenceArtifactRef
from hermes.runtime.agents.contracts import (
    ROLE_OUTPUT_CONTRACT_IDS,
    HandoffEnvelope,
    RoleManifest,
    TaskEnvelope,
)

DIGEST = "sha256:" + "a" * 64


def _gate_payload() -> GateDecisionV2:
    return GateDecisionV2(
        run_id="run-v2",
        scope_digest=DIGEST,
        generated_by_task_id="gatekeeper-v2",
        decision="allowed",
        target="http://localhost:49152/candidate",
        resolved_ip="127.0.0.1",
        reason="explicit local fixture is inside the frozen scope",
    )


def test_v2_task_and_handoff_carry_evidence_artifact_refs() -> None:
    evidence = EvidenceArtifactRef(
        evidence_id="evidence-v2",
        manifest_path="evidence/evidence-v2/manifest.json",
        manifest_sha256=DIGEST,
    )
    task = TaskEnvelope(
        run_id="run-v2",
        task_id="gatekeeper-v2",
        role="gatekeeper",
        scope_digest=DIGEST,
        evidence_artifact_refs=(evidence,),
    )
    handoff = HandoffEnvelope(
        version="2",
        run_id=task.run_id,
        task_id=task.task_id,
        role=task.role,
        scope_digest=task.scope_digest,
        input_sha256=task.input_hash(),
        status="completed",
        result=ContractEnvelope.for_payload(_gate_payload()),
        evidence_artifact_refs=(evidence,),
    )
    assert handoff.evidence_artifact_refs == task.evidence_artifact_refs
    assert isinstance(handoff.result, ContractEnvelope)

    replayed = HandoffEnvelope.model_validate(handoff.model_dump(mode="json"))
    assert isinstance(replayed.result, ContractEnvelope)
    assert replayed == handoff


def test_v2_completed_handoff_rejects_legacy_result_dictionary() -> None:
    with pytest.raises(ValidationError, match="typed ContractEnvelope"):
        HandoffEnvelope(
            version="2",
            run_id="run-v2",
            task_id="gatekeeper-v2",
            role="gatekeeper",
            scope_digest=DIGEST,
            input_sha256=DIGEST,
            status="completed",
            result={"decision": "allowed"},
        )


def test_v2_handoff_rejects_another_roles_typed_contract() -> None:
    raw = ContractEnvelope.for_payload(_gate_payload()).model_dump()
    raw["contract_id"] = "hermes.asset_inventory/v2"
    with pytest.raises(ValidationError):
        HandoffEnvelope(
            version="2",
            run_id="run-v2",
            task_id="recon-v2",
            role="recon",
            scope_digest=DIGEST,
            input_sha256=DIGEST,
            status="completed",
            result=raw,
        )


def test_v1_outer_handoff_remains_parseable_for_audit_and_fixture_tests() -> None:
    handoff = HandoffEnvelope(
        run_id="legacy-run",
        task_id="legacy-task",
        role="recon",
        scope_digest=DIGEST,
        input_sha256=DIGEST,
        status="completed",
        result={"assets": []},
    )
    assert handoff.version == "1"
    assert handoff.result == {"assets": []}


def test_v2_manifest_requires_the_exact_role_output_contract() -> None:
    common = {
        "role": "recon",
        "prompt_id": "hermes.recon",
        "prompt_version": "2.0",
        "prompt_sha256": DIGEST,
        "signed_at": "2026-07-13T00:00:00Z",
        "image": "sha256:" + "b" * 64,
        "command": ("--role", "recon"),
        "key_id": "publisher-1",
        "signature": "unsigned",
    }
    manifest = RoleManifest(
        **common,
        output_contract_id=ROLE_OUTPUT_CONTRACT_IDS["recon"],
    )
    assert manifest.output_contract_id == "hermes.asset_inventory/v2"
    with pytest.raises(ValidationError, match="registered output contract"):
        RoleManifest(**common, output_contract_id="recon-result/v1")

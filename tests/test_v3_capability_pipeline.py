"""The full V3 campaign pipeline emits and plans the line_kv_capability_gap
candidate — end-to-end through the real fixed-blueprint and campaign code.

This exercises the actual parent-runtime candidate production (not the ACP model
roles, which only supply status/rationale — every execution-authority field is
fixed here): given an inventory that offers a line_kv capability artifact,
build_candidate_blueprints emits the governed capability-gap candidate, and the
campaign planner gives it a readonly verification action. The candidate's verdict
is then the Verifier's Wheel resolution (test_capability_verifier /
run_cap07_gap_resolution_e2e). Without the capability artifact, the fixed four
candidates are byte-for-byte unchanged.
"""

from __future__ import annotations

from hermes.campaign_v3 import _candidate_actions
from hermes.collaboration_v3 import build_candidate_blueprints
from hermes.domain_contracts_v3 import EndpointInventoryV3, EndpointV3
from hermes.evidence import EvidenceArtifactRef

DIGEST = "sha256:" + "a" * 64
BASE = "http://localhost:8080"


def _evidence() -> EvidenceArtifactRef:
    return EvidenceArtifactRef(
        evidence_id="recon-evidence",
        manifest_path="evidence/recon-evidence/manifest.json",
        manifest_sha256=DIGEST,
    )


def _inventory(*, with_capability: bool) -> EndpointInventoryV3:
    values = [
        ("web", "/candidate", "GET", "candidate", ("text/html",)),
        ("control", "/control", "GET", "negative_control", ("text/html",)),
        ("debug", "/debug", "GET", "debug", ("application/json",)),
    ]
    if with_capability:
        values.append(("config", "/config", "GET", "capability_config", ("text/plain",)))
    endpoints = tuple(
        EndpointV3(
            endpoint_id=endpoint_id,
            asset_id="asset-1",
            canonical_url=f"{BASE}{path}",
            method=method,  # type: ignore[arg-type]
            relation=relation,  # type: ignore[arg-type]
            content_types=content_types,
            evidence=(_evidence(),),
        )
        for endpoint_id, path, method, relation, content_types in values
    )
    return EndpointInventoryV3(
        run_id="phase4-run",
        scope_digest=DIGEST,
        generated_by_task_id="phase4-mapper",
        inventory_id="phase4-endpoints",
        asset_inventory_digest=DIGEST,
        endpoints=endpoints,
    )


def test_capability_artifact_emits_the_gap_candidate() -> None:
    blueprints = build_candidate_blueprints(
        _inventory(with_capability=True), identity_binding_digests={}
    )
    infra = {c.candidate_id: c for c in blueprints["infra"]}
    assert "infra-capability-gap" in infra
    candidate = infra["infra-capability-gap"]
    assert candidate.candidate_type == "line_kv_capability_gap"
    assert candidate.method == "GET"
    assert candidate.target_url == f"{BASE}/config"
    assert candidate.control_endpoint_ids == ()


def test_without_capability_artifact_no_gap_candidate_is_emitted() -> None:
    blueprints = build_candidate_blueprints(
        _inventory(with_capability=False), identity_binding_digests={}
    )
    all_types = {c.candidate_type for cs in blueprints.values() for c in cs}
    assert "line_kv_capability_gap" not in all_types


def test_campaign_plans_a_readonly_action_for_the_gap_candidate() -> None:
    blueprints = build_candidate_blueprints(
        _inventory(with_capability=True), identity_binding_digests={}
    )
    candidate = next(c for c in blueprints["infra"] if c.candidate_id == "infra-capability-gap")
    actions = _candidate_actions(
        run_id="phase4-run",
        scope_digest=DIGEST,
        candidate_id=candidate.candidate_id,
        candidate_type="line_kv_capability_gap",
        source=candidate,
        base=BASE,
        identities={},
    )
    assert len(actions) == 1
    action = actions[0]
    assert action.method == "GET"
    assert action.risk_group == "readonly"
    assert action.purpose == "candidate"
    assert action.target_url == f"{BASE}/config"

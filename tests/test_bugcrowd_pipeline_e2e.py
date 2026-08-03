"""End-to-end composition of the Bugcrowd pipeline: N1 -> N2 -> N3 -> N4 -> N7.

Offline and deterministic: every real module's public API is chained in sequence
over example hosts, the N4 live loop runs through GovernedEgress + a ReplayTransport
(GOV-02), and the whole provenance chain is asserted — scope -> inventory ->
candidate set -> plan -> outcome -> finding -> report draft. No network, no
localhost (the real-asset pipeline forbids loopback by design).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hermes.candidate_source import build_candidate_set, parse_nuclei_line
from hermes.governed_egress import (
    EgressResponseV1,
    GovernedEgress,
    ReplayTransport,
    execute_verification_plan,
)
from hermes.recon_adapter import build_recon_inventory, parse_httpx_line
from hermes.report_draft import (
    ReportNarrativeV1,
    build_report_draft,
    parse_cvss_vector,
    render_markdown,
)
from hermes.scope_profile import (
    BugcrowdProgramSpecV1,
    BugcrowdTargetV1,
    ingest_bugcrowd_program,
    require_active_scanning_authorized,
    sign_scope_profile,
)
from hermes.security import (
    KeyUsage,
    TrustedKey,
    TrustStoreV2,
    encode_base64,
    generate_ed25519_private_key,
    public_key_bytes,
)
from hermes.verification import (
    VerificationSignalV1,
    build_verification_plan,
    decide_verification,
    promote_to_finding,
    require_execution_authorized,
    sign_review,
    sign_verification_plan,
)

NOW = datetime(2026, 8, 3, 12, 0, tzinfo=UTC)
VRT = {"full_path_disclosure": 5}
CVSS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"


class _Clock:
    def __init__(self) -> None:
        self.t = 0.0

    def monotonic(self) -> float:
        return self.t

    def sleep(self, seconds: float) -> None:
        self.t += seconds


def _key(store_keys: list[TrustedKey], private: Ed25519PrivateKey, key_id: str, usage: KeyUsage):
    store_keys.append(
        TrustedKey(
            key_id=key_id,
            public_key=encode_base64(public_key_bytes(private)),
            usages=frozenset({usage}),
            valid_from=NOW - timedelta(days=1),
            valid_until=NOW + timedelta(days=7),
        )
    )


def test_full_bugcrowd_pipeline_composes_with_provenance_chain() -> None:
    scope_key = generate_ed25519_private_key()
    approver_key = generate_ed25519_private_key()
    reviewer_key = generate_ed25519_private_key()
    keys: list[TrustedKey] = []
    _key(keys, scope_key, "scope-approver", KeyUsage.SCOPE_APPROVAL)
    _key(keys, approver_key, "approver", KeyUsage.APPROVAL)
    _key(keys, reviewer_key, "reviewer", KeyUsage.HUMAN_REVIEW)
    trust = TrustStoreV2(keys=tuple(keys))

    # --- N1: ingest + sign + verify ---
    spec = BugcrowdProgramSpecV1(
        program_handle="acme-bbp",
        engagement_url="https://bugcrowd.com/acme-bbp",
        retrieved_at=NOW,
        automated_testing_allowed=True,
        rate_limit_rps=2.0,
        targets=(BugcrowdTargetV1(identifier="*.acme.example", category="website"),),
    )
    signed = sign_scope_profile(
        ingest_bugcrowd_program(spec), scope_key, key_id="scope-approver", signed_at=NOW
    )
    draft = require_active_scanning_authorized(signed, trust, now=NOW)

    # --- N2: recon httpx output -> scope-authorized inventory ---
    httpx = [
        parse_httpx_line({"url": "https://app.acme.example/x", "status_code": 200}),
        parse_httpx_line({"url": "https://evil.example/", "status_code": 200}),  # dropped
    ]
    recon = build_recon_inventory(
        [p for p in httpx if p is not None],
        scope_draft=draft,
        program_handle="acme-bbp",
        generated_by="recon",
        source_tools=("httpx",),
        now=NOW,
    )
    inventory = recon.inventory
    assert inventory.scope_profile_digest == draft.digest()
    assert len(inventory.endpoints) == 1

    # --- N3: nuclei hit -> disciplined candidate bound to the inventory ---
    match = parse_nuclei_line({
        "template-id": "full-path-disclosure",
        "info": {"name": "Full path disclosure", "severity": "low"},
        "type": "http",
        "matched-at": "https://app.acme.example/x",
    })
    assert match is not None
    cset = build_candidate_set([match], inventory, generated_by="n3", now=NOW).candidate_set
    assert cset.recon_inventory_digest == inventory.digest()
    candidate = cset.candidates[0]
    assert candidate.status == "candidate" and candidate.requires_active_verification is True

    # --- N4: plan -> approve -> govern egress (ReplayTransport) -> decide -> promote ---
    plan = build_verification_plan(
        candidate,
        program_handle=cset.program_handle,
        signal=VerificationSignalV1(kind="header_absent", argument="X-Frame-Options"),
        negative_control_url="https://app.acme.example/control",
        scope_draft=draft,
        now=NOW,
    )
    approval = sign_verification_plan(plan, approver_key, key_id="approver", signed_at=NOW)
    require_execution_authorized(plan, approval, trust, draft, now=NOW)

    clock = _Clock()
    transport = ReplayTransport({
        ("GET", "https://app.acme.example/x"): EgressResponseV1(status_code=200, headers=()),
        ("GET", "https://app.acme.example/control"): EgressResponseV1(
            status_code=200, headers=(("X-Frame-Options", "DENY"),)
        ),
    })
    egress = GovernedEgress(
        scope_draft=draft, transport=transport, monotonic=clock.monotonic, sleep=clock.sleep
    )
    candidate_obs, control_obs = execute_verification_plan(plan, egress, now=NOW)
    outcome = decide_verification(plan, candidate_obs, control_obs, now=NOW)
    assert outcome.verdict == "validated"
    assert [a.allowed for a in egress.audit] == [True, True]

    finding = promote_to_finding(
        outcome, plan, candidate,
        review_signature_b64=sign_review(outcome, reviewer_key),
        reviewer_key_id="reviewer", reviewed_at=NOW, trust_store=trust, now=NOW,
    )

    # --- N7: validated finding -> Bugcrowd report draft (never submitted) ---
    report = build_report_draft(
        finding, plan, outcome,
        vrt_category_id="full_path_disclosure",
        vrt_priorities=VRT,
        cvss=parse_cvss_vector(CVSS),
        narrative=ReportNarrativeV1(
            title="Full path disclosure on app.acme.example",
            summary="Absolute path disclosed in an unauthenticated response.",
            steps_to_reproduce=("GET /x", "observe the absolute path"),
            impact="Reveals server layout.",
        ),
        now=NOW,
    )

    # --- provenance chain asserted end to end ---
    assert report.priority == "P5"
    assert report.cvss_base_score == 5.3
    assert report.submitted is False
    assert report.finding_digest == finding.digest()
    assert report.plan_digest == plan.digest()
    assert report.outcome_digest == outcome.digest()
    assert finding.plan_digest == plan.digest()
    assert finding.outcome_digest == outcome.digest()
    # scope digest threads from N1 all the way through
    assert plan.scope_profile_digest == draft.digest()
    assert inventory.scope_profile_digest == draft.digest()
    assert cset.scope_profile_digest == draft.digest()
    assert "DRAFT" in render_markdown(report)

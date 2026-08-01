from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hermes.runtime.actions import ActionKind, ProposedAction
from hermes.security import (
    KeyStatus,
    KeyUsage,
    SecurityContractError,
    SystemResolver,
    TrustedKey,
    TrustStoreV2,
    encode_base64,
    generate_ed25519_private_key,
    load_ed25519_private_key,
    load_ed25519_public_key,
    public_key_bytes,
)
from hermes.vertical_contracts import (
    ActionDecision,
    ApprovalBundle,
    ApprovalConsumptionLedger,
    PlannedAction,
    SignedHumanReview,
    ValidationPlan,
    consume_approved_action,
    sign_approval_bundle,
    sign_human_review,
    verify_approval_bundle,
    verify_human_review,
)

NOW = datetime(2026, 7, 12, 12, tzinfo=UTC)
SCOPE = "sha256:" + "a" * 64
EVIDENCE = "sha256:" + "b" * 64


def _store(
    *usages: KeyUsage, status: KeyStatus = KeyStatus.ACTIVE
) -> tuple[Ed25519PrivateKey, TrustStoreV2]:
    private = generate_ed25519_private_key()
    revoked_at = NOW if status is KeyStatus.REVOKED else None
    store = TrustStoreV2(
        keys=(
            TrustedKey(
                key_id="reviewer-1",
                public_key=encode_base64(public_key_bytes(private)),
                usages=frozenset(usages),
                status=status,
                valid_from=NOW - timedelta(days=1),
                valid_until=NOW + timedelta(days=1),
                revoked_at=revoked_at,
            ),
        )
    )
    return private, store


def _plan() -> ValidationPlan:
    return ValidationPlan(
        plan_id="plan-1",
        run_id="run-1",
        scope_digest=SCOPE,
        candidate_id="candidate-1",
        actions=(
            PlannedAction(
                action_id="read",
                action=ProposedAction(kind=ActionKind.HTTP_GET, target="https://example.test"),
                rationale="Read the approved fixture endpoint.",
            ),
            PlannedAction(
                action_id="probe",
                action=ProposedAction(
                    kind=ActionKind.INJECTION_PROBE, target="https://example.test/search"
                ),
                rationale="Perform one bounded validation request.",
            ),
        ),
        created_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=30),
    )


def _bundle(plan: ValidationPlan, private: Ed25519PrivateKey) -> ApprovalBundle:
    unsigned = ApprovalBundle(
        bundle_id="bundle-1",
        plan_digest=plan.digest,
        run_id=plan.run_id,
        scope_digest=plan.scope_digest,
        reviewer="operator@example.test",
        decisions=(
            ActionDecision(action_id="read", decision="approved", rationale="Approved."),
            ActionDecision(action_id="probe", decision="rejected", rationale="Too invasive."),
        ),
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=10),
        key_id="reviewer-1",
        signature="unsigned",
    )
    return sign_approval_bundle(unsigned, private)


def test_signed_bundle_verifies_and_each_approved_action_is_consumed_once() -> None:
    private, store = _store(KeyUsage.APPROVAL)
    plan = _plan()
    bundle = _bundle(plan, private)

    verify_approval_bundle(bundle, plan, store, at=NOW)
    ledger = consume_approved_action(
        bundle=bundle,
        plan=plan,
        action_id="read",
        ledger=ApprovalConsumptionLedger(),
        trust_store=store,
        at=NOW,
    )
    assert len(ledger.consumptions) == 1
    with pytest.raises(SecurityContractError, match="already consumed"):
        consume_approved_action(
            bundle=bundle,
            plan=plan,
            action_id="read",
            ledger=ledger,
            trust_store=store,
            at=NOW,
        )
    with pytest.raises(SecurityContractError, match="rejected"):
        consume_approved_action(
            bundle=bundle,
            plan=plan,
            action_id="probe",
            ledger=ledger,
            trust_store=store,
            at=NOW,
        )


def test_trust_store_rejects_wrong_usage_revocation_and_tampering() -> None:
    private, wrong_usage = _store(KeyUsage.HUMAN_REVIEW)
    plan = _plan()
    bundle = _bundle(plan, private)
    with pytest.raises(SecurityContractError, match="not trusted for approval"):
        verify_approval_bundle(bundle, plan, wrong_usage, at=NOW)

    _, revoked = _store(KeyUsage.APPROVAL, status=KeyStatus.REVOKED)
    with pytest.raises(SecurityContractError, match="not active"):
        verify_approval_bundle(bundle, plan, revoked, at=NOW)

    _, valid = _store(KeyUsage.APPROVAL)
    with pytest.raises(SecurityContractError, match="signature"):
        verify_approval_bundle(bundle, plan, valid, at=NOW)


def test_signed_human_review_is_bound_to_finding_and_evidence() -> None:
    private, store = _store(KeyUsage.HUMAN_REVIEW)
    review = sign_human_review(
        SignedHumanReview(
            review_id="review-1",
            finding_id="finding-1",
            run_id="run-1",
            scope_digest=SCOPE,
            evidence_digest=EVIDENCE,
            reviewer="operator@example.test",
            verdict="accepted",
            rationale="Evidence and controls were reviewed.",
            reviewed_at=NOW,
            key_id="reviewer-1",
            signature="unsigned",
        ),
        private,
    )
    verify_human_review(
        review,
        store,
        run_id="run-1",
        scope_digest=SCOPE,
        finding_id="finding-1",
        evidence_digest=EVIDENCE,
    )
    with pytest.raises(SecurityContractError, match="different evidence"):
        verify_human_review(
            review,
            store,
            run_id="run-1",
            scope_digest=SCOPE,
            finding_id="finding-1",
            evidence_digest="sha256:" + "c" * 64,
        )


def test_key_loading_and_system_resolver_are_deterministic(tmp_path, monkeypatch) -> None:
    private = generate_ed25519_private_key()
    private_path = tmp_path / "private.pem"
    public_path = tmp_path / "public.pem"
    private_path.write_bytes(
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public_path.write_bytes(
        private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    assert public_key_bytes(load_ed25519_private_key(private_path)) == public_key_bytes(private)
    assert load_ed25519_public_key(public_path).public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ) == public_key_bytes(private)

    monkeypatch.setattr(
        "hermes.security.socket.getaddrinfo",
        lambda *_args, **_kwargs: [
            (2, 1, 6, "", ("192.0.2.2", 0)),
            (2, 1, 6, "", ("192.0.2.1", 0)),
            (2, 1, 6, "", ("192.0.2.2", 0)),
        ],
    )
    assert SystemResolver()("example.test") == ("192.0.2.1", "192.0.2.2")

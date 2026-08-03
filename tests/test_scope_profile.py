"""N1 contract tests: Bugcrowd scope ingestion, human sign-off, and access gate.

Fully offline — no Bugcrowd API, no network. Exercises the fail-closed behaviour
that gates every downstream active node (docs/19 N1).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hermes.scope_profile import (
    BugcrowdProgramSpecV1,
    BugcrowdTargetV1,
    ScopeProfileError,
    authorize_target,
    ingest_bugcrowd_program,
    require_active_scanning_authorized,
    require_human_submission,
    sign_scope_profile,
    verify_scope_profile,
)
from hermes.security import (
    KeyUsage,
    TrustedKey,
    TrustStoreV2,
    encode_base64,
    generate_ed25519_private_key,
    public_key_bytes,
)

NOW = datetime(2026, 8, 3, 12, 0, tzinfo=UTC)


def _trust(private: Ed25519PrivateKey, key_id: str, *usages: KeyUsage) -> TrustStoreV2:
    return TrustStoreV2(
        keys=(
            TrustedKey(
                key_id=key_id,
                public_key=encode_base64(public_key_bytes(private)),
                usages=frozenset(usages),
                valid_from=NOW - timedelta(days=1),
                valid_until=NOW + timedelta(days=7),
            ),
        )
    )


def _spec(*, automated: bool = True, rps: float | None = 2.0) -> BugcrowdProgramSpecV1:
    return BugcrowdProgramSpecV1(
        program_handle="acme-bbp",
        engagement_url="https://bugcrowd.com/acme-bbp",
        retrieved_at=NOW,
        automated_testing_allowed=automated,
        rate_limit_rps=rps,
        targets=(
            BugcrowdTargetV1(identifier="https://api.acme.example", category="api"),
            BugcrowdTargetV1(identifier="*.acme.example", category="website"),
            BugcrowdTargetV1(identifier="legacy.acme.example", category="website", in_scope=False),
            BugcrowdTargetV1(identifier="com.acme.app", category="android"),
        ),
    )


# --------------------------------------------------------------------------- #
# Ingestion
# --------------------------------------------------------------------------- #


def test_ingest_keeps_only_in_scope_web_api_targets() -> None:
    draft = ingest_bugcrowd_program(_spec())
    hosts = {rule.host for rule in draft.scope_policy.rules}
    assert hosts == {"api.acme.example", "*.acme.example"}  # out-of-scope + android dropped
    assert all(not rule.allow_private for rule in draft.scope_policy.rules)


def test_ingest_respects_automation_policy_and_forces_dry_run() -> None:
    allowed = ingest_bugcrowd_program(_spec(automated=True))
    assert allowed.scope_policy.automation_allowed is True
    assert allowed.scope_policy.dry_run is False
    assert allowed.automation.automated_testing_allowed is True

    forbidden = ingest_bugcrowd_program(_spec(automated=False))
    assert forbidden.scope_policy.automation_allowed is False
    assert forbidden.scope_policy.dry_run is True
    assert forbidden.automation.submit_requires_human is True


def test_ingest_uses_the_tighter_rate_limit() -> None:
    # program says 2.0, default is 1.0 -> effective must be the tighter 1.0
    draft = ingest_bugcrowd_program(_spec(rps=2.0), default_rate_limit_rps=1.0)
    assert draft.scope_policy.rate_limit_rps == 1.0
    # program stricter than default -> program wins
    draft2 = ingest_bugcrowd_program(_spec(rps=0.5), default_rate_limit_rps=1.0)
    assert draft2.scope_policy.rate_limit_rps == 0.5


def test_ingest_rejects_a_spec_with_no_expressible_targets() -> None:
    spec = BugcrowdProgramSpecV1(
        program_handle="mobile-only",
        retrieved_at=NOW,
        automated_testing_allowed=True,
        targets=(BugcrowdTargetV1(identifier="com.acme.app", category="android"),),
    )
    with pytest.raises(ScopeProfileError):
        ingest_bugcrowd_program(spec)


# --------------------------------------------------------------------------- #
# Sign-off + verification
# --------------------------------------------------------------------------- #


def test_sign_and_verify_round_trip() -> None:
    private = generate_ed25519_private_key()
    store = _trust(private, "scope-approver", KeyUsage.SCOPE_APPROVAL)
    draft = ingest_bugcrowd_program(_spec())
    signed = sign_scope_profile(draft, private, key_id="scope-approver", signed_at=NOW)
    verified = verify_scope_profile(signed, store, now=NOW + timedelta(hours=1))
    assert verified.digest() == draft.digest()


def test_operational_approval_key_cannot_authorize_scope() -> None:
    private = generate_ed25519_private_key()
    # trusted for APPROVAL, not SCOPE_APPROVAL -> separation of duties
    store = _trust(private, "op-approver", KeyUsage.APPROVAL)
    signed = sign_scope_profile(
        ingest_bugcrowd_program(_spec()), private, key_id="op-approver", signed_at=NOW
    )
    with pytest.raises(ScopeProfileError):
        verify_scope_profile(signed, store, now=NOW)


def test_verify_rejects_expired_signature() -> None:
    private = generate_ed25519_private_key()
    store = _trust(private, "scope-approver", KeyUsage.SCOPE_APPROVAL)
    signed = sign_scope_profile(
        ingest_bugcrowd_program(_spec()),
        private,
        key_id="scope-approver",
        signed_at=NOW,
        ttl=timedelta(hours=1),
    )
    with pytest.raises(ScopeProfileError):
        verify_scope_profile(signed, store, now=NOW + timedelta(hours=2))


def test_verify_rejects_untrusted_key() -> None:
    signer = generate_ed25519_private_key()
    other = generate_ed25519_private_key()
    store = _trust(other, "scope-approver", KeyUsage.SCOPE_APPROVAL)
    signed = sign_scope_profile(
        ingest_bugcrowd_program(_spec()), signer, key_id="scope-approver", signed_at=NOW
    )
    with pytest.raises(ScopeProfileError):
        verify_scope_profile(signed, store, now=NOW)


def test_verify_rejects_tampered_draft() -> None:
    private = generate_ed25519_private_key()
    store = _trust(private, "scope-approver", KeyUsage.SCOPE_APPROVAL)
    signed = sign_scope_profile(
        ingest_bugcrowd_program(_spec()), private, key_id="scope-approver", signed_at=NOW
    )
    # swap in a wider-scope draft under the original signature
    wider = ingest_bugcrowd_program(
        BugcrowdProgramSpecV1(
            program_handle="acme-bbp",
            retrieved_at=NOW,
            automated_testing_allowed=True,
            targets=(BugcrowdTargetV1(identifier="evil.example", category="website"),),
        )
    )
    tampered = signed.model_copy(update={"draft": wider})
    with pytest.raises(ScopeProfileError):
        verify_scope_profile(tampered, store, now=NOW)


# --------------------------------------------------------------------------- #
# Active-scanning gate + per-target authorization
# --------------------------------------------------------------------------- #


def test_active_gate_passes_only_when_automation_authorized() -> None:
    private = generate_ed25519_private_key()
    store = _trust(private, "scope-approver", KeyUsage.SCOPE_APPROVAL)
    ok = sign_scope_profile(
        ingest_bugcrowd_program(_spec(automated=True)),
        private,
        key_id="scope-approver",
        signed_at=NOW,
    )
    require_active_scanning_authorized(ok, store, now=NOW)  # no raise

    no_auto = sign_scope_profile(
        ingest_bugcrowd_program(_spec(automated=False)),
        private,
        key_id="scope-approver",
        signed_at=NOW,
    )
    with pytest.raises(ScopeProfileError):
        require_active_scanning_authorized(no_auto, store, now=NOW)


def test_authorize_target_scope_membership() -> None:
    draft = ingest_bugcrowd_program(_spec())
    authorize_target(draft, "https://api.acme.example/v1/users")  # exact host, https
    authorize_target(draft, "https://app.acme.example/login")  # matches *.acme.example
    with pytest.raises(ScopeProfileError):
        authorize_target(draft, "https://acme.example/")  # apex not covered by *.acme.example
    with pytest.raises(ScopeProfileError):
        authorize_target(draft, "https://evil.example/")  # out of scope
    with pytest.raises(ScopeProfileError):
        authorize_target(draft, "http://api.acme.example/")  # wrong scheme (https only)


def test_authorize_target_denies_private_and_non_http() -> None:
    draft = ingest_bugcrowd_program(_spec())
    with pytest.raises(ScopeProfileError):
        authorize_target(draft, "https://127.0.0.1/")
    with pytest.raises(ScopeProfileError):
        authorize_target(draft, "ftp://api.acme.example/")


def test_require_human_submission_always_raises() -> None:
    with pytest.raises(ScopeProfileError):
        require_human_submission()

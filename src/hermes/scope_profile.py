"""N1 — Bugcrowd program scope + RoE ingestion, human sign-off, and access gate.

docs/19 node N1 is the first hard gate on the tunnel from Hermes' governed
localhost teaching pipeline toward a real, *authorized* Bugcrowd assessment.
Before any active node (recon in N2, verification in N4) may touch a real asset,
a **human** must sign a ``ScopeProfile`` that:

1. ingests one specific Bugcrowd program's *in-scope* targets into a narrow
   :class:`~hermes.runtime.policy.ScopePolicy` (the same object the Gateway
   already enforces);
2. records that program's **automation policy** — whether automated testing is
   permitted at all, and at what rate; and
3. binds the whole thing to that human's Ed25519 signature and the program's
   provenance (handle, engagement URL, retrieval time, source digest).

Everything fails closed:

* ``automation_allowed`` is ``False`` unless the program *explicitly* permits
  automated testing; a profile derived from a no-automation program can never
  enable active scanning, and ``dry_run`` is forced on;
* ``allow_private`` is always ``False`` for a real program — loopback stays a
  localhost-only teaching concept, never a bounty target;
* an unsigned or unverified profile authorizes nothing (fail-closed verify);
* submission is never automated — ``submit_requires_human`` is always ``True``.

Scope of this module: the frozen contracts, the pure Bugcrowd→ScopePolicy
ingestion, sign/verify, and the deterministic access guards, fully unit-tested
without network or a live Bugcrowd API. *Fetching* a program from the Bugcrowd
API and *running* active tooling under the resulting profile are separate,
human-driven steps (docs/19 N1/N2); this module is the contract + gate they must
pass, not an autonomous scanner.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Literal
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .domain_contracts import canonical_digest
from .runtime.policy import ScopePolicy, ScopeRule
from .security import (
    KeyUsage,
    SecurityContractError,
    TrustStoreV2,
    canonical_json,
    sign_ed25519,
)

_ID = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
_DIGEST = r"^sha256:[0-9a-f]{64}$"

BugcrowdTargetCategory = Literal["website", "api", "android", "ios", "hardware", "other"]


class ScopeProfileError(RuntimeError):
    """A real-asset ScopeProfile could not be ingested, signed, or authorized."""


class BugcrowdTargetV1(BaseModel):
    """One target row from a Bugcrowd program's scope table."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    identifier: str = Field(min_length=1, max_length=253)
    category: BugcrowdTargetCategory = "website"
    in_scope: bool = True


class BugcrowdProgramSpecV1(BaseModel):
    """The machine-readable form of a Bugcrowd program's scope and RoE.

    This is the *input* to ingestion — obtained from the Bugcrowd scope API or a
    reviewed manual export. It deliberately carries the two facts that gate
    everything downstream: which targets are in scope, and whether the program
    permits automated testing (and at what rate).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    platform: Literal["bugcrowd"] = "bugcrowd"
    program_handle: str = Field(pattern=_ID)
    engagement_url: str | None = None
    retrieved_at: datetime
    automated_testing_allowed: bool
    rate_limit_rps: float | None = Field(default=None, gt=0, le=1000)
    targets: tuple[BugcrowdTargetV1, ...] = Field(min_length=1)
    notes: str = Field(default="", max_length=4000)

    @field_validator("retrieved_at")
    @classmethod
    def _tz_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("retrieved_at must be timezone-aware")
        return value

    def source_digest(self) -> str:
        return canonical_digest(self)


class ScopeProvenanceV1(BaseModel):
    """Where a ScopeProfile came from — audited, never inferred by a model."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    platform: Literal["bugcrowd"] = "bugcrowd"
    program_handle: str = Field(pattern=_ID)
    engagement_url: str | None = None
    retrieved_at: datetime
    source_digest: str = Field(pattern=_DIGEST)


class AutomationPolicyV1(BaseModel):
    """The program's automation policy, lifted out so it can gate active nodes."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    automated_testing_allowed: bool
    rate_limit_rps: float = Field(gt=0, le=1000)
    max_concurrency: int = Field(ge=1, le=128)
    # Always True: N7's red line (report submission is a human action) encoded in
    # the contract so no code path can flip it on.
    submit_requires_human: Literal[True] = True


class ScopeProfileDraftV1(BaseModel):
    """An unsigned, provenance-bound scope + automation policy for one program."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"] = "1"
    provenance: ScopeProvenanceV1
    automation: AutomationPolicyV1
    scope_policy: ScopePolicy

    @model_validator(mode="after")
    def _coherent(self) -> ScopeProfileDraftV1:
        # The derived ScopePolicy must agree with the ingested automation policy,
        # and a real program can never authorize private/loopback access.
        if self.scope_policy.automation_allowed != self.automation.automated_testing_allowed:
            raise ValueError("scope_policy.automation_allowed must match the automation policy")
        if not self.automation.automated_testing_allowed and not self.scope_policy.dry_run:
            raise ValueError("a no-automation program must keep dry_run on")
        if any(rule.allow_private for rule in self.scope_policy.rules):
            raise ValueError("a real-asset ScopeProfile must not allow private/loopback access")
        return self

    def digest(self) -> str:
        return canonical_digest(self)


class SignedScopeProfileV1(BaseModel):
    """A ScopeProfileDraft bound to a human approver's Ed25519 signature."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    draft: ScopeProfileDraftV1
    approver_key_id: str = Field(pattern=_ID)
    signed_at: datetime
    expires_at: datetime
    signature_b64: str = Field(min_length=16)

    @field_validator("signed_at", "expires_at")
    @classmethod
    def _tz_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("signature timestamps must be timezone-aware")
        return value

    @model_validator(mode="after")
    def _expiry_after_signature(self) -> SignedScopeProfileV1:
        if self.expires_at <= self.signed_at:
            raise ValueError("ScopeProfile must expire after it is signed")
        return self


# --------------------------------------------------------------------------- #
# Ingestion: Bugcrowd program spec -> unsigned ScopeProfileDraft
# --------------------------------------------------------------------------- #


def _target_to_rule(
    target: BugcrowdTargetV1, *, profile_name: str
) -> ScopeRule | None:
    """Map one in-scope website/api target to a narrow ScopeRule (fail-closed).

    Returns ``None`` for targets that cannot be expressed as an HTTP(S) host
    rule (e.g. mobile/hardware categories, or malformed identifiers) — those are
    dropped rather than guessed at.
    """

    if not target.in_scope or target.category not in {"website", "api"}:
        return None
    raw = target.identifier.strip()
    schemes: set[Literal["http", "https"]] = {"https"}
    ports: set[int] = {443}
    host = raw
    if "://" in raw:
        parsed = urlsplit(raw)
        if parsed.hostname is None or parsed.scheme not in {"http", "https"}:
            return None
        scheme: Literal["http", "https"] = "http" if parsed.scheme == "http" else "https"
        host = parsed.hostname
        schemes = {scheme}
        if parsed.port is not None:
            ports = {parsed.port}
        elif scheme == "http":
            ports = {80}
    try:
        return ScopeRule(
            host=host,
            schemes=frozenset(schemes),
            ports=frozenset(ports),
            allow_dns=True,
            profile=profile_name,
            allow_private=False,
        )
    except ValueError:
        # A malformed host (URL syntax, path, unsupported wildcard) is dropped,
        # never coerced — an out-of-scope guess is worse than a missing target.
        return None


def ingest_bugcrowd_program(
    spec: BugcrowdProgramSpecV1,
    *,
    profile_name: str = "bugcrowd",
    default_rate_limit_rps: float = 1.0,
    max_requests: int = 100,
    max_duration_seconds: float = 600.0,
    max_concurrency: int = 2,
) -> ScopeProfileDraftV1:
    """Derive an unsigned ScopeProfileDraft from a Bugcrowd program spec.

    Fail-closed throughout: only in-scope website/api targets become rules; the
    program's ``automated_testing_allowed`` decides ``automation_allowed`` and
    ``dry_run``; private access is never granted; the effective rate limit is the
    tighter of the program's stated limit and the conservative default.
    """

    rules = tuple(
        rule
        for rule in (_target_to_rule(t, profile_name=profile_name) for t in spec.targets)
        if rule is not None
    )
    if not rules:
        raise ScopeProfileError(
            "program spec yielded no expressible in-scope website/api targets"
        )

    effective_rps = min(
        default_rate_limit_rps,
        spec.rate_limit_rps if spec.rate_limit_rps is not None else default_rate_limit_rps,
    )
    automated = spec.automated_testing_allowed

    scope_policy = ScopePolicy(
        profile=profile_name,
        rules=rules,
        automation_allowed=automated,
        dry_run=not automated,
        max_requests=max_requests,
        max_duration_seconds=max_duration_seconds,
        max_concurrency=max_concurrency,
        rate_limit_rps=effective_rps,
    )
    automation = AutomationPolicyV1(
        automated_testing_allowed=automated,
        rate_limit_rps=effective_rps,
        max_concurrency=max_concurrency,
    )
    provenance = ScopeProvenanceV1(
        platform=spec.platform,
        program_handle=spec.program_handle,
        engagement_url=spec.engagement_url,
        retrieved_at=spec.retrieved_at,
        source_digest=spec.source_digest(),
    )
    return ScopeProfileDraftV1(
        provenance=provenance, automation=automation, scope_policy=scope_policy
    )


# --------------------------------------------------------------------------- #
# Human sign-off + verification
# --------------------------------------------------------------------------- #


def _draft_payload(draft: ScopeProfileDraftV1) -> bytes:
    return canonical_json(draft.model_dump(mode="json"))


def sign_scope_profile(
    draft: ScopeProfileDraftV1,
    private_key: Ed25519PrivateKey,
    *,
    key_id: str,
    signed_at: datetime,
    ttl: timedelta = timedelta(days=7),
) -> SignedScopeProfileV1:
    """Produce the human-signed ScopeProfile (Ed25519 over the canonical draft)."""

    if signed_at.tzinfo is None:
        raise ScopeProfileError("signed_at must be timezone-aware")
    signature = sign_ed25519(private_key, _draft_payload(draft))
    return SignedScopeProfileV1(
        draft=draft,
        approver_key_id=key_id,
        signed_at=signed_at,
        expires_at=signed_at + ttl,
        signature_b64=signature,
    )


def verify_scope_profile(
    signed: SignedScopeProfileV1,
    trust_store: TrustStoreV2,
    *,
    now: datetime,
) -> ScopeProfileDraftV1:
    """Verify the signature/expiry and return the trusted draft (fail-closed).

    Requires a key trusted for :data:`KeyUsage.SCOPE_APPROVAL` — an operational
    APPROVAL key cannot authorize a scope (separation of duties).
    """

    if now.tzinfo is None:
        raise ScopeProfileError("verification time must be timezone-aware")
    if now >= signed.expires_at:
        raise ScopeProfileError("ScopeProfile signature has expired")
    try:
        trust_store.verify(
            key_id=signed.approver_key_id,
            usage=KeyUsage.SCOPE_APPROVAL,
            payload=_draft_payload(signed.draft),
            signature=signed.signature_b64,
            at=signed.signed_at,
        )
    except SecurityContractError as exc:
        raise ScopeProfileError(f"ScopeProfile signature is not trusted: {exc}") from exc
    return signed.draft


# --------------------------------------------------------------------------- #
# Access guards (the N1 gate consulted before any active node)
# --------------------------------------------------------------------------- #


def require_active_scanning_authorized(
    signed: SignedScopeProfileV1,
    trust_store: TrustStoreV2,
    *,
    now: datetime,
) -> ScopeProfileDraftV1:
    """Gate entry to active nodes (N2 recon / N4 verification).

    Passes only when a human-signed profile *and* the program's automation policy
    both permit automated testing; a no-automation program raises so Hermes never
    scans it. Returns the trusted draft for the caller to enforce per-target.
    """

    draft = verify_scope_profile(signed, trust_store, now=now)
    if (
        not draft.automation.automated_testing_allowed
        or not draft.scope_policy.automation_allowed
        or draft.scope_policy.dry_run
    ):
        raise ScopeProfileError(
            "program does not authorize automated active testing; active nodes are refused"
        )
    return draft


def authorize_target(draft: ScopeProfileDraftV1, url: str) -> None:
    """Raise unless ``url`` falls inside the profile's signed scope (fail-closed).

    Enforces host membership, scheme, and port against the derived rules, and
    denies any private/loopback address regardless of rules.
    """

    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ScopeProfileError(f"target url is not an http(s) URL with a host: {url!r}")
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    for rule in draft.scope_policy.rules:
        try:
            in_host = rule.matches_host(host)
        except ValueError:
            in_host = False
        if in_host and parsed.scheme in rule.schemes and port in rule.ports:
            return
    raise ScopeProfileError(f"target is outside the signed Bugcrowd scope: {url!r}")


def require_human_submission() -> None:
    """The submission red line (N7), callable as an explicit assertion.

    There is deliberately no ``submit()`` in Hermes: reports are drafted, a human
    reviews and submits. This function exists so callers can assert that
    invariant at the point a submission would otherwise be tempting to automate.
    """

    raise ScopeProfileError(
        "report submission is a human action; Hermes never submits to Bugcrowd automatically"
    )

"""GOV-02 (real-asset) — governed egress: scope + rate-limit + budget + audit.

docs/19 makes N2/N3/N4 *plan and judge* without touching the network. This module
is the seam that lets them run **live** against a real, authorized target while a
human stays in control of the risk: every outbound request is checked, at the
moment of egress, against the N1 signed scope and the program's automation policy,
paced to the rate limit, counted against a budget, and audited — fail-closed.

The network itself sits behind a small ``Transport`` protocol, so:

* tests inject a fake transport + fake clock and exercise every governance edge
  deterministically, with no sockets;
* production passes the real pinned HTTP transport and a real clock — the same
  governed code path.

**Credentials never pass through Hermes.** ``EgressRequestV1`` carries no secrets
and the audit records none; authenticated testing is the operator's transport
concern (their own authorized session), consistent with the standing rule that
Hermes never handles credentials in plaintext.

This is the real-asset analogue of the localhost-locked ``GovernedGatewayV3`` — a
separate, additive layer so the teaching-fixture pipeline is untouched.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from datetime import datetime
from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field

from .evidence import EvidenceArtifactRef
from .scope_profile import ScopeProfileDraftV1, ScopeProfileError, authorize_target
from .security import canonical_json
from .verification import ProbeObservationV1, ProbeSpecV1, VerificationPlanV1

_DIGEST = r"^sha256:[0-9a-f]{64}$"
EgressMethod = Literal["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH"]


class GovernedEgressError(RuntimeError):
    """An outbound request was refused by egress governance (fail-closed)."""


class EgressRequestV1(BaseModel):
    """A single outbound request — no credentials, ever."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    method: EgressMethod
    url: str = Field(min_length=1, max_length=2_048)
    headers: tuple[tuple[str, str], ...] = ()
    body_sha256: str | None = Field(default=None, pattern=_DIGEST)

    def digest(self) -> str:
        return "sha256:" + hashlib.sha256(canonical_json(self.model_dump(mode="json"))).hexdigest()


class EgressResponseV1(BaseModel):
    """What a transport returns for one request."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status_code: int = Field(ge=100, le=599)
    headers: tuple[tuple[str, str], ...] = ()
    body_excerpt: str = Field(default="", max_length=4_000)
    body_sha256: str | None = Field(default=None, pattern=_DIGEST)


class Transport(Protocol):
    """The network seam. Real: pinned HTTP client. Test: in-memory replay."""

    def perform(self, request: EgressRequestV1) -> EgressResponseV1: ...


class EgressAuditRecordV1(BaseModel):
    """One append-only audit line — proves every request was in-scope and paced."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_digest: str = Field(pattern=_DIGEST)
    method: EgressMethod
    url: str
    scope_profile_digest: str = Field(pattern=_DIGEST)
    allowed: bool
    reason: str
    waited_seconds: float = Field(ge=0.0)
    status_code: int | None = None
    decided_at: datetime


class _Pacer:
    """Deterministic min-interval rate limiter over an injected clock."""

    def __init__(self, rps: float, monotonic: Callable[[], float], sleep: Callable[[float], None]):
        self._min_interval = 1.0 / rps
        self._monotonic = monotonic
        self._sleep = sleep
        self._last: float | None = None

    def pace(self) -> float:
        now = self._monotonic()
        wait = 0.0 if self._last is None else max(0.0, self._min_interval - (now - self._last))
        if wait > 0.0:
            self._sleep(wait)
        self._last = self._monotonic()
        return wait


class GovernedEgress:
    """Fail-closed governed egress bound to one signed N1 scope."""

    def __init__(
        self,
        *,
        scope_draft: ScopeProfileDraftV1,
        transport: Transport,
        monotonic: Callable[[], float],
        sleep: Callable[[float], None],
    ) -> None:
        policy = scope_draft.scope_policy
        if not policy.automation_allowed or policy.dry_run:
            raise GovernedEgressError(
                "scope does not authorize automated egress (automation off / dry_run)"
            )
        self._scope = scope_draft
        self._transport = transport
        self._budget = policy.max_requests
        self._pacer = _Pacer(policy.rate_limit_rps, monotonic, sleep)
        self._count = 0
        self.audit: list[EgressAuditRecordV1] = []

    @property
    def remaining_budget(self) -> int:
        return self._budget - self._count

    def perform(
        self, request: EgressRequestV1, *, now: datetime
    ) -> tuple[EgressResponseV1, EvidenceArtifactRef]:
        """Issue one governed request, or refuse fail-closed and audit the refusal."""

        digest = request.digest()

        def refuse(reason: str) -> GovernedEgressError:
            self.audit.append(
                EgressAuditRecordV1(
                    request_digest=digest,
                    method=request.method,
                    url=request.url,
                    scope_profile_digest=self._scope.digest(),
                    allowed=False,
                    reason=reason,
                    waited_seconds=0.0,
                    decided_at=now,
                )
            )
            return GovernedEgressError(reason)

        # DELETE cannot reach here: EgressMethod excludes it at the type level.
        if self._count >= self._budget:
            raise refuse(f"request budget exhausted ({self._budget})")
        try:
            authorize_target(self._scope, request.url)
        except ScopeProfileError as exc:
            raise refuse(f"target outside signed scope: {exc}") from exc

        waited = self._pacer.pace()
        response = self._transport.perform(request)
        self._count += 1
        evidence_id = "egress-" + digest.removeprefix("sha256:")[:20]
        record = canonical_json(
            {
                "request": request.model_dump(mode="json"),
                "response": response.model_dump(mode="json"),
            }
        )
        evidence = EvidenceArtifactRef(
            evidence_id=evidence_id,
            manifest_path=f"evidence/{evidence_id}/manifest.json",
            manifest_sha256="sha256:" + hashlib.sha256(record).hexdigest(),
        )
        self.audit.append(
            EgressAuditRecordV1(
                request_digest=digest,
                method=request.method,
                url=request.url,
                scope_profile_digest=self._scope.digest(),
                allowed=True,
                reason="in scope, paced, within budget",
                waited_seconds=waited,
                status_code=response.status_code,
                decided_at=now,
            )
        )
        return response, evidence


def _probe_to_request(probe: ProbeSpecV1) -> EgressRequestV1:
    return EgressRequestV1(method=probe.method, url=probe.url)


def _response_to_observation(
    response: EgressResponseV1, evidence: EvidenceArtifactRef
) -> ProbeObservationV1:
    return ProbeObservationV1(
        status_code=response.status_code,
        headers=response.headers,
        body_sha256=response.body_sha256,
        body_excerpt=response.body_excerpt,
        evidence=(evidence,),
    )


def execute_verification_plan(
    plan: VerificationPlanV1,
    egress: GovernedEgress,
    *,
    now: datetime,
) -> tuple[ProbeObservationV1, ProbeObservationV1]:
    """Run an approved plan's two probes through governed egress (N4 live loop).

    Returns ``(candidate_observation, control_observation)`` ready for
    ``hermes.verification.decide_verification`` — closing N4 end to end while every
    request is scope-checked, paced, budgeted, and audited. The caller must already
    have passed ``require_execution_authorized``.
    """

    candidate_response, candidate_evidence = egress.perform(
        _probe_to_request(plan.candidate_probe), now=now
    )
    control_response, control_evidence = egress.perform(
        _probe_to_request(plan.control_probe), now=now
    )
    return (
        _response_to_observation(candidate_response, candidate_evidence),
        _response_to_observation(control_response, control_evidence),
    )

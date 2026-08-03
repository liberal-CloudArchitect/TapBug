"""Native governed detection: Hermes actively probes (read-only) and finds candidates.

This is what moves detection off zero *without* leaving the governed path. Instead
of consuming an external scanner's output (N3 does that for nuclei), Hermes runs a
small library of **read-only** checks **through** ``GovernedEgress`` against the
scope-authorized N2 inventory, and emits the same disciplined ``AssetCandidateV1``
candidates N4 verifies.

Every probe therefore inherits the full governance for free: whitelist scope +
SSRF-safe resolution/pinning (via the live transport) + rate limit + request
budget + per-request audit. Checks are GET-only and never carry an exploit; each
hit is a *candidate* (``requires_active_verification=True``) with a falsifiable
assertion and a negative-control hint, so nothing is auto-elevated.

Scope of this module: the frozen rule set, the deterministic signal evaluation,
and the governed detection loop — unit-tested with a fake transport, no network.
Running it against a real host is the operator's authorized step
(``scripts/run_detection.py``), same as the rest of the live path.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import Literal
from urllib.parse import urlsplit

from .candidate_source import AssetCandidateV1, CandidateResult, CandidateSetV1, ClaimedSeverity
from .evidence import EvidenceArtifactRef
from .governed_egress import EgressRequestV1, EgressResponseV1, GovernedEgress, GovernedEgressError
from .recon_adapter import ReconInventoryV1
from .security import canonical_json

RuleKind = Literal["missing_header", "exposed_path"]


class DetectionError(RuntimeError):
    """Governed detection produced no candidates (e.g. the target is clean)."""


def _header(response: EgressResponseV1, name: str) -> str | None:
    lname = name.lower()
    for key, value in response.headers:
        if key.lower() == lname:
            return value
    return None


@dataclass(frozen=True)
class DetectionRule:
    """One deterministic, read-only detection check."""

    rule_id: str
    kind: RuleKind
    argument: str  # header name (missing_header) or path (exposed_path)
    candidate_type: str
    title: str
    claimed_severity: ClaimedSeverity
    https_only: bool = False

    def fires(self, response: EgressResponseV1) -> bool:
        if self.kind == "missing_header":
            return _header(response, self.argument) is None
        # exposed_path: a 200 means the sensitive path is served
        return response.status_code == 200

    def expected_assertion(self, url: str) -> str:
        if self.kind == "missing_header":
            return (
                f"a minimal GET to {url} returns a response missing the {self.argument!r} "
                f"header, and a matched hardened endpoint sets it"
            )
        return (
            f"a minimal GET to {url} returns 200 exposing {self.argument!r}, and a matched "
            f"absent path returns 404"
        )

    def negative_control_hint(self) -> str:
        if self.kind == "missing_header":
            return f"compare against an in-scope endpoint known to set {self.argument!r}"
        return (
            f"compare against an in-scope path that does not exist (expected 404) "
            f"for {self.argument!r}"
        )


# A conservative, read-only, widely-accepted starter set. Extend here.
BUILTIN_RULES: tuple[DetectionRule, ...] = (
    DetectionRule(
        "missing-x-content-type-options", "missing_header", "X-Content-Type-Options",
        "missing-x-content-type-options", "Missing X-Content-Type-Options header", "info",
    ),
    DetectionRule(
        "missing-x-frame-options", "missing_header", "X-Frame-Options",
        "missing-x-frame-options", "Missing X-Frame-Options header", "low",
    ),
    DetectionRule(
        "missing-content-security-policy", "missing_header", "Content-Security-Policy",
        "missing-content-security-policy", "Missing Content-Security-Policy header", "low",
    ),
    DetectionRule(
        "missing-hsts", "missing_header", "Strict-Transport-Security",
        "missing-strict-transport-security", "Missing HSTS header (HTTPS)", "low",
        https_only=True,
    ),
    DetectionRule(
        "exposed-git-config", "exposed_path", "/.git/config",
        "exposed-git-config", "Exposed .git/config", "medium",
    ),
    DetectionRule(
        "exposed-dotenv", "exposed_path", "/.env",
        "exposed-dotenv", "Exposed .env file", "medium",
    ),
    DetectionRule(
        "exposed-server-status", "exposed_path", "/server-status",
        "exposed-server-status", "Exposed Apache server-status", "low",
    ),
)


def _origin(url: str) -> str | None:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    default = 443 if parsed.scheme == "https" else 80
    port = parsed.port or default
    host = parsed.hostname if port == default else f"{parsed.hostname}:{port}"
    return f"{parsed.scheme}://{host}"


def _candidate(
    *,
    rule: DetectionRule,
    endpoint_id: str,
    asset_id: str,
    url: str,
    evidence: EvidenceArtifactRef,
) -> AssetCandidateV1:
    key = hashlib.sha256(f"{endpoint_id}:{rule.rule_id}".encode()).hexdigest()
    candidate_id = "cand-" + key[:20]
    return AssetCandidateV1(
        candidate_id=candidate_id,
        source="hermes_active",
        endpoint_id=endpoint_id,
        asset_id=asset_id,
        target_url=url,
        method="GET",
        candidate_type=rule.candidate_type,
        title=rule.title,
        claimed_severity=rule.claimed_severity,
        status="candidate",
        expected_assertion=rule.expected_assertion(url),
        negative_control_hint=rule.negative_control_hint(),
        evidence=(evidence,),
        rationale=(
            f"Hermes native read-only check {rule.rule_id!r} fired on an in-scope endpoint; "
            f"candidate only — requires N4 active verification and human review"
        ),
    )


def run_detection(
    inventory: ReconInventoryV1,
    egress: GovernedEgress,
    *,
    generated_by: str,
    now: datetime,
    rules: tuple[DetectionRule, ...] = BUILTIN_RULES,
) -> CandidateResult:
    """Actively probe the scope-authorized inventory (read-only, governed) for candidates.

    One GET per endpoint drives all header checks on that response; one GET per
    (host, path) drives each exposed-path check. Requests that egress refuses
    (out of scope / budget / SSRF) are skipped and audited. Every hit becomes a
    disciplined candidate requiring verification.
    """

    header_rules = tuple(r for r in rules if r.kind == "missing_header")
    path_rules = tuple(r for r in rules if r.kind == "exposed_path")
    candidates: list[AssetCandidateV1] = []
    evidence: dict[str, bytes] = {}
    seen: set[str] = set()

    def emit(rule: DetectionRule, endpoint_id: str, asset_id: str, url: str,
             request: EgressRequestV1, response: EgressResponseV1) -> None:
        record = canonical_json(
            {
                "request": request.model_dump(mode="json"),
                "response": response.model_dump(mode="json"),
            }
        )
        key = hashlib.sha256(f"{endpoint_id}:{rule.rule_id}".encode()).hexdigest()
        evidence_id = "det-" + key[:18]
        ref = EvidenceArtifactRef(
            evidence_id=evidence_id,
            manifest_path=f"evidence/{evidence_id}/manifest.json",
            manifest_sha256="sha256:" + hashlib.sha256(record).hexdigest(),
        )
        candidate = _candidate(
            rule=rule, endpoint_id=endpoint_id, asset_id=asset_id, url=url, evidence=ref,
        )
        if candidate.candidate_id in seen:
            return
        seen.add(candidate.candidate_id)
        evidence[candidate.candidate_id] = record
        candidates.append(candidate)

    # Header checks: one GET per endpoint.
    for endpoint in inventory.endpoints:
        if not header_rules:
            break
        request = EgressRequestV1(method="GET", url=endpoint.canonical_url)
        try:
            response, _ = egress.perform(request, now=now)
        except GovernedEgressError:
            continue
        is_https = endpoint.canonical_url.startswith("https://")
        for rule in header_rules:
            if rule.https_only and not is_https:
                continue
            if rule.fires(response):
                emit(rule, endpoint.endpoint_id, endpoint.asset_id, endpoint.canonical_url,
                     request, response)

    # Exposed-path checks: one GET per (host, path).
    origins: dict[str, tuple[str, str]] = {}  # origin -> (endpoint_id, asset_id)
    for endpoint in inventory.endpoints:
        origin = _origin(endpoint.canonical_url)
        if origin is not None:
            origins.setdefault(origin, (endpoint.endpoint_id, endpoint.asset_id))
    for origin, (endpoint_id, asset_id) in origins.items():
        for rule in path_rules:
            url = origin + rule.argument
            request = EgressRequestV1(method="GET", url=url)
            try:
                response, _ = egress.perform(request, now=now)
            except GovernedEgressError:
                continue
            if rule.fires(response):
                emit(rule, endpoint_id, asset_id, url, request, response)

    if not candidates:
        raise DetectionError("no candidates detected (target is clean for the active rule set)")
    candidate_set = CandidateSetV1(
        program_handle=inventory.program_handle,
        scope_profile_digest=inventory.scope_profile_digest,
        recon_inventory_digest=inventory.digest(),
        generated_by=generated_by,
        created_at=now,
        source_tools=("hermes-active-detection",),
        candidates=tuple(candidates),
        dropped_out_of_inventory=(),
    )
    return CandidateResult(candidate_set=candidate_set, evidence=evidence)

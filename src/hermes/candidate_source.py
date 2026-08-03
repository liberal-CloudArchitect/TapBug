"""N3 — external detection output -> disciplined, scope-tied Hermes candidates.

docs/19 node N3. Black-box engines (nuclei) and exploratory agents *widen the
candidate source*, but their output must be **converged back into Hermes'
discipline** before it means anything:

* a template hit is a **candidate**, never a validated finding — ``status`` is
  ``candidate``/``inconclusive``/``blocked`` and ``requires_active_verification``
  is always ``True`` (a single matcher firing is not proof; DET-03 minimal active
  verification in N4 + human review in GOV-05 are what earn a ValidatedFinding);
* every candidate must reference an endpoint that is already in the N2
  ``ReconInventoryV1`` — i.e. a real, scope-authorized target; a hit against a
  host not in the inventory is dropped (fail-closed, out of scope);
* every candidate carries **falsifiability**: an ``expected_assertion`` a minimal
  verifying test must show, and a ``negative_control_hint`` — so it can never be
  auto-elevated on a single template match;
* candidates carry **no exploit payload** — only the hypothesis and what evidence
  would confirm or deny it. Arbitrary exploit generation stays out of the main
  package (docs/07 invariant 4); exploratory/exploit tooling lives in
  ``extensions/``.

Scope of this module: the frozen candidate contracts, the tolerant nuclei parser,
and the pure, inventory-gated converger — fully unit-tested without network. The
model/agent only ever supplies ``status``/``rationale`` on a candidate; every
execution-authority field is fixed here from the tool output + the inventory.
"""

from __future__ import annotations

import hashlib
import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .domain_contracts import canonical_digest
from .evidence import EvidenceArtifactRef
from .recon_adapter import ReconInventoryV1
from .security import canonical_json

_ID = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
_SLUG = r"^[a-z0-9][a-z0-9._-]{0,119}$"
_DIGEST = r"^sha256:[0-9a-f]{64}$"

CandidateSource = Literal["nuclei", "expert_hypothesis", "hermes_active"]
# Deliberately NO "validated": that verdict is earned in N4 verification + review,
# never asserted by a candidate source.
CandidateStatusV1 = Literal["candidate", "inconclusive", "blocked"]
ClaimedSeverity = Literal["info", "low", "medium", "high", "critical"]
_SEVERITIES = frozenset({"info", "low", "medium", "high", "critical"})


class CandidateSourceError(RuntimeError):
    """External detection output could not be converged into disciplined candidates."""


def _public_host(url: str) -> str | None:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.fragment:
        return None
    host = parsed.hostname
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if host == "localhost" or (address is not None and (address.is_loopback or address.is_private)):
        return None
    return host


class AssetCandidateV1(BaseModel):
    """One disciplined candidate: a hypothesis bound to a real endpoint + evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    candidate_id: str = Field(pattern=_ID)
    source: CandidateSource
    endpoint_id: str = Field(pattern=_ID)
    asset_id: str = Field(pattern=_ID)
    target_url: str = Field(min_length=1, max_length=2_048)
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"]
    candidate_type: str = Field(pattern=_SLUG)
    title: str = Field(min_length=1, max_length=300)
    claimed_severity: ClaimedSeverity
    status: CandidateStatusV1 = "candidate"
    # Falsifiability — a candidate can never be auto-elevated on one hit.
    expected_assertion: str = Field(min_length=1, max_length=2_000)
    negative_control_hint: str = Field(min_length=1, max_length=2_000)
    requires_active_verification: Literal[True] = True
    evidence: tuple[EvidenceArtifactRef, ...] = Field(min_length=1)
    rationale: str = Field(min_length=1, max_length=4_000)

    @field_validator("target_url")
    @classmethod
    def _public_url(cls, value: str) -> str:
        if _public_host(value) is None:
            raise ValueError("candidate target_url must be a public http(s) URL")
        return value


class CandidateSetV1(BaseModel):
    """A disciplined candidate set, chained to the N2 inventory and N1 scope."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"] = "1"
    platform: Literal["bugcrowd"] = "bugcrowd"
    program_handle: str = Field(pattern=_ID)
    scope_profile_digest: str = Field(pattern=_DIGEST)
    recon_inventory_digest: str = Field(pattern=_DIGEST)
    generated_by: str = Field(pattern=_ID)
    created_at: datetime
    source_tools: tuple[str, ...] = Field(min_length=1)
    candidates: tuple[AssetCandidateV1, ...] = Field(min_length=1)
    dropped_out_of_inventory: tuple[str, ...] = ()

    @field_validator("created_at")
    @classmethod
    def _tz_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("created_at must be timezone-aware")
        return value

    @model_validator(mode="after")
    def _unique_candidates(self) -> CandidateSetV1:
        ids = [c.candidate_id for c in self.candidates]
        if len(ids) != len(set(ids)):
            raise ValueError("candidate IDs must be unique")
        return self

    def digest(self) -> str:
        return canonical_digest(self)


@dataclass(frozen=True)
class NucleiMatch:
    """One nuclei match reduced to what a candidate needs, plus its bytes."""

    template_id: str
    name: str
    severity: ClaimedSeverity
    matched_url: str
    raw: dict[str, Any]


@dataclass(frozen=True)
class CandidateResult:
    """The candidate set plus evidence manifest bytes the driver must persist."""

    candidate_set: CandidateSetV1
    evidence: dict[str, bytes]


# --------------------------------------------------------------------------- #
# nuclei parser
# --------------------------------------------------------------------------- #


def _severity(value: Any) -> ClaimedSeverity:
    sev = str(value or "info").lower()
    return sev if sev in _SEVERITIES else "info"  # type: ignore[return-value]


def parse_nuclei_line(obj: dict[str, Any]) -> NucleiMatch | None:
    """Parse one ``nuclei -jsonl`` record (template-id, info.severity, matched-at/host)."""

    info = obj.get("info") if isinstance(obj.get("info"), dict) else {}
    template_id = obj.get("template-id") or obj.get("templateID") or obj.get("template_id")
    matched = obj.get("matched-at") or obj.get("matched") or obj.get("host")
    if not isinstance(template_id, str) or not isinstance(matched, str) or not matched.strip():
        return None
    name = str(info.get("name") or template_id) if isinstance(info, dict) else template_id
    return NucleiMatch(
        template_id=template_id,
        name=name,
        severity=_severity(info.get("severity") if isinstance(info, dict) else None),
        matched_url=matched.strip(),
        raw=obj,
    )


# --------------------------------------------------------------------------- #
# Discipline helpers + inventory-gated converger
# --------------------------------------------------------------------------- #


def _candidate_type(template_id: str) -> str:
    cleaned = "".join(
        c if (c.isalnum() or c in "._-") else "-" for c in template_id.lower()
    ).strip("-._")
    return cleaned[:120] or "external-detection"


def _inventory_index(inventory: ReconInventoryV1) -> tuple[dict[str, Any], dict[str, Any]]:
    by_url = {e.canonical_url: e for e in inventory.endpoints}
    by_host: dict[str, Any] = {}
    for endpoint in inventory.endpoints:
        host = urlsplit(endpoint.canonical_url).hostname
        if host is not None:
            by_host.setdefault(host, endpoint)
    return by_url, by_host


def build_candidate_set(
    matches: Iterable[NucleiMatch],
    inventory: ReconInventoryV1,
    *,
    generated_by: str,
    now: datetime,
    source_tools: tuple[str, ...] = ("nuclei",),
) -> CandidateResult:
    """Converge nuclei matches into disciplined candidates (fail-closed).

    A match is kept only when its URL is public and its host is already in the
    scope-authorized inventory; it becomes a ``candidate`` (never validated) that
    requires active verification, with an evidence ref bound to the match bytes.
    """

    by_url, by_host = _inventory_index(inventory)
    candidates: list[AssetCandidateV1] = []
    evidence: dict[str, bytes] = {}
    dropped: list[str] = []
    seen: set[str] = set()

    for match in matches:
        host = _public_host(match.matched_url)
        endpoint = by_url.get(match.matched_url) or (by_host.get(host) if host else None)
        if host is None or endpoint is None:
            dropped.append(match.matched_url)
            continue
        candidate_type = _candidate_type(match.template_id)
        dedup_key = f"{endpoint.endpoint_id}:{candidate_type}"
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        candidate_id = "cand-" + hashlib.sha256(dedup_key.encode()).hexdigest()[:20]
        record_bytes = canonical_json(match.raw)
        evidence[candidate_id] = record_bytes
        evidence_ref = EvidenceArtifactRef(
            evidence_id=candidate_id,
            manifest_path=f"evidence/{candidate_id}/manifest.json",
            manifest_sha256="sha256:" + hashlib.sha256(record_bytes).hexdigest(),
        )
        candidates.append(
            AssetCandidateV1(
                candidate_id=candidate_id,
                source="nuclei",
                endpoint_id=endpoint.endpoint_id,
                asset_id=endpoint.asset_id,
                target_url=match.matched_url,
                method=endpoint.method,
                candidate_type=candidate_type,
                title=match.name[:300],
                claimed_severity=match.severity,
                status="candidate",
                expected_assertion=(
                    f"a minimal, authorized request reproduces the condition matched by nuclei "
                    f"template {match.template_id!r} at {match.matched_url}, and a matched "
                    f"negative control does not exhibit it"
                ),
                negative_control_hint=(
                    f"compare against an in-scope endpoint/path known not to exhibit "
                    f"{match.template_id!r} before treating this as validated"
                ),
                evidence=(evidence_ref,),
                rationale=(
                    f"nuclei template {match.template_id!r} (claimed severity "
                    f"{match.severity}) matched an in-scope endpoint; candidate only — "
                    f"requires active verification and human review"
                ),
            )
        )

    if not candidates:
        raise CandidateSourceError(
            "no nuclei matches resolved to an in-scope inventory endpoint"
        )

    candidate_set = CandidateSetV1(
        program_handle=inventory.program_handle,
        scope_profile_digest=inventory.scope_profile_digest,
        recon_inventory_digest=inventory.digest(),
        generated_by=generated_by,
        created_at=now,
        source_tools=source_tools,
        candidates=tuple(candidates),
        dropped_out_of_inventory=tuple(dict.fromkeys(dropped)),
    )
    return CandidateResult(candidate_set=candidate_set, evidence=evidence)


def require_verification_before_promotion(candidate: AssetCandidateV1) -> None:
    """Guard: a candidate is not a finding and cannot be promoted here.

    Promotion to a ValidatedFinding requires N4 minimal active verification (with a
    negative control) and GOV-05 human review. This guard exists so any caller
    tempted to treat a candidate source's output as validated fails loudly.
    """

    raise CandidateSourceError(
        f"candidate {candidate.candidate_id!r} ({candidate.candidate_type}) is not validated: "
        "it requires N4 active verification + human review before it can become a finding"
    )

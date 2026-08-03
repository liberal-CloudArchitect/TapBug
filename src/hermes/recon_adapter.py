"""N2 — ProjectDiscovery recon output -> scope-authorized real-asset inventory.

docs/19 node N2. Turns the JSON(L) output of ProjectDiscovery tools (``httpx``,
``katana``) into a structured :class:`ReconInventoryV1` of *real* endpoints, with
two hard properties:

1. **Scope-authorized against N1.** Every endpoint must pass
   :func:`hermes.scope_profile.authorize_target` against a *verified, signed*
   ScopeProfile draft; anything outside the signed Bugcrowd scope is dropped and
   recorded (fail-closed), never assessed.
2. **Never a localhost lie.** The existing ``EndpointInventoryV3`` is deliberately
   localhost-locked (``_localhost_url``) so the teaching-fixture acceptance can
   never be confused with real-asset capability. A real Bugcrowd URL cannot enter
   it. This module therefore produces a *separate* real-asset inventory and
   :func:`to_endpoint_inventory_v3` refuses the bridge until the V3 pipeline (N3/N4)
   is genuinely real-asset-capable — the boundary is explicit, not faked.

Scope of this module: the frozen inventory contracts, the tolerant ProjectDiscovery
line parsers, and the pure, scope-gated builder — fully unit-tested without network.
*Running* subfinder/httpx/katana (which makes requests, and so is an active step
that must already be authorized via ``require_active_scanning_authorized``) is a
separate, human/Gateway-driven step; this module only ingests what they produced.
"""

from __future__ import annotations

import hashlib
import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal, NoReturn
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .domain_contracts import canonical_digest
from .evidence import EvidenceArtifactRef
from .scope_profile import ScopeProfileDraftV1, ScopeProfileError, authorize_target
from .security import canonical_json

_ID = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
_DIGEST = r"^sha256:[0-9a-f]{64}$"
_HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})

ReconRelation = Literal["web", "api", "graphql", "auth", "other"]


class ReconAdapterError(RuntimeError):
    """Recon output could not be turned into a scope-authorized inventory."""


def _public_http_url(value: str, label: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ValueError(f"{label} must be an absolute http(s) URL with a bare host")
    host = parsed.hostname
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if host == "localhost" or (address is not None and (address.is_loopback or address.is_private)):
        raise ValueError(f"{label} must not be a loopback or private address")
    return value


class ReconEndpointV1(BaseModel):
    """One real, scope-authorized endpoint discovered by recon, with evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    endpoint_id: str = Field(pattern=_ID)
    asset_id: str = Field(pattern=_ID)
    canonical_url: str = Field(min_length=1, max_length=2_048)
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"]
    relation: ReconRelation
    status_code: int | None = Field(default=None, ge=100, le=599)
    content_types: tuple[str, ...] = ()
    technologies: tuple[str, ...] = ()
    evidence: tuple[EvidenceArtifactRef, ...] = Field(min_length=1)

    @field_validator("canonical_url")
    @classmethod
    def _public_url(cls, value: str) -> str:
        return _public_http_url(value, "recon endpoint")


class ReconInventoryV1(BaseModel):
    """A real-asset endpoint inventory, bound to the signed scope that allowed it."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"] = "1"
    platform: Literal["bugcrowd"] = "bugcrowd"
    program_handle: str = Field(pattern=_ID)
    # digest of the N1 ScopeProfile draft every endpoint was authorized against.
    scope_profile_digest: str = Field(pattern=_DIGEST)
    generated_by: str = Field(pattern=_ID)
    created_at: datetime
    source_tools: tuple[str, ...] = Field(min_length=1)
    endpoints: tuple[ReconEndpointV1, ...] = Field(min_length=1)
    dropped_out_of_scope: tuple[str, ...] = ()

    @field_validator("created_at")
    @classmethod
    def _tz_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("created_at must be timezone-aware")
        return value

    @model_validator(mode="after")
    def _unique_endpoints(self) -> ReconInventoryV1:
        ids = [e.endpoint_id for e in self.endpoints]
        if len(ids) != len(set(ids)):
            raise ValueError("recon endpoint IDs must be unique")
        keys = [e.canonical_url + "#" + e.method for e in self.endpoints]
        if len(keys) != len(set(keys)):
            raise ValueError("recon endpoints must be unique by url+method")
        return self

    def digest(self) -> str:
        return canonical_digest(self)


@dataclass(frozen=True)
class NormalizedProbe:
    """A ProjectDiscovery probe reduced to what the inventory needs, plus its bytes."""

    url: str
    method: str
    status_code: int | None
    content_types: tuple[str, ...]
    technologies: tuple[str, ...]
    raw: dict[str, Any]


@dataclass(frozen=True)
class ReconResult:
    """The built inventory plus the evidence manifest bytes the driver must persist."""

    inventory: ReconInventoryV1
    evidence: dict[str, bytes]


# --------------------------------------------------------------------------- #
# Tolerant ProjectDiscovery line parsers (extra fields ignored on purpose)
# --------------------------------------------------------------------------- #


def _method(value: Any) -> str:
    method = str(value or "GET").upper()
    return method if method in _HTTP_METHODS else "GET"


def _content_types(value: Any) -> tuple[str, ...]:
    if not value:
        return ()
    ctype = str(value).split(";", 1)[0].strip().lower()
    return (ctype,) if ctype else ()


def parse_httpx_line(obj: dict[str, Any]) -> NormalizedProbe | None:
    """Parse one ``httpx -json`` record (fields: url/host, status_code, content_type, tech)."""

    url = obj.get("url") or obj.get("input") or obj.get("host")
    if not isinstance(url, str) or not url.strip():
        return None
    tech = obj.get("tech") or obj.get("technologies") or ()
    technologies = tuple(str(t) for t in tech) if isinstance(tech, list | tuple) else ()
    status = obj.get("status_code")
    return NormalizedProbe(
        url=url.strip(),
        method=_method(obj.get("method")),
        status_code=int(status) if isinstance(status, int) else None,
        content_types=_content_types(obj.get("content_type")),
        technologies=technologies,
        raw=obj,
    )


def parse_katana_line(obj: dict[str, Any]) -> NormalizedProbe | None:
    """Parse one ``katana -jsonl`` record (request.endpoint / request.method)."""

    request = obj.get("request")
    if not isinstance(request, dict):
        return None
    endpoint = request.get("endpoint")
    if not isinstance(endpoint, str) or not endpoint.strip():
        return None
    response = obj.get("response") if isinstance(obj.get("response"), dict) else {}
    status = response.get("status_code") if isinstance(response, dict) else None
    return NormalizedProbe(
        url=endpoint.strip(),
        method=_method(request.get("method")),
        status_code=int(status) if isinstance(status, int) else None,
        content_types=_content_types(
            response.get("content_type") if isinstance(response, dict) else None
        ),
        technologies=(),
        raw=obj,
    )


# --------------------------------------------------------------------------- #
# Deterministic identity + relation
# --------------------------------------------------------------------------- #


def _sanitize_id(value: str, *, prefix: str) -> str:
    cleaned = "".join(c if (c.isalnum() or c in "._-") else "-" for c in value).strip("-._")
    return f"{prefix}-{cleaned}"[:128] or f"{prefix}-x"


def _asset_id(url: str) -> str:
    host = urlsplit(url).hostname or "unknown"
    return _sanitize_id(host, prefix="asset")


def _endpoint_id(url: str, method: str) -> str:
    digest = hashlib.sha256(f"{method} {url}".encode()).hexdigest()[:20]
    return f"ep-{digest}"


def _relation_of(url: str, content_types: tuple[str, ...]) -> ReconRelation:
    path = (urlsplit(url).path or "").lower()
    if "graphql" in path:
        return "graphql"
    if any(k in path for k in ("/login", "/oauth", "/auth", "/token", "/session")):
        return "auth"
    if any("json" in ct or "graphql" in ct for ct in content_types):
        return "api"
    if any("html" in ct for ct in content_types):
        return "web"
    return "other"


# --------------------------------------------------------------------------- #
# Scope-gated builder (the N2 core)
# --------------------------------------------------------------------------- #


def build_recon_inventory(
    probes: Iterable[NormalizedProbe],
    *,
    scope_draft: ScopeProfileDraftV1,
    program_handle: str,
    generated_by: str,
    source_tools: tuple[str, ...],
    now: datetime,
) -> ReconResult:
    """Build a scope-authorized ReconInventory (fail-closed on every edge).

    Every probe URL is authorized against the signed scope; out-of-scope or
    private/loopback URLs are dropped and recorded. Each surviving endpoint gets
    an EvidenceArtifactRef bound to the exact recon record bytes that produced it.
    """

    endpoints: list[ReconEndpointV1] = []
    evidence: dict[str, bytes] = {}
    dropped: list[str] = []
    seen: set[str] = set()

    for probe in probes:
        try:
            authorize_target(scope_draft, probe.url)
        except ScopeProfileError:
            dropped.append(probe.url)
            continue
        try:
            _public_http_url(probe.url, "recon endpoint")
        except ValueError:
            dropped.append(probe.url)
            continue
        key = probe.url + "#" + probe.method
        if key in seen:
            continue
        seen.add(key)

        endpoint_id = _endpoint_id(probe.url, probe.method)
        record_bytes = canonical_json(probe.raw)
        evidence[endpoint_id] = record_bytes
        evidence_ref = EvidenceArtifactRef(
            evidence_id=endpoint_id,
            manifest_path=f"evidence/{endpoint_id}/manifest.json",
            manifest_sha256="sha256:" + hashlib.sha256(record_bytes).hexdigest(),
        )
        endpoints.append(
            ReconEndpointV1(
                endpoint_id=endpoint_id,
                asset_id=_asset_id(probe.url),
                canonical_url=probe.url,
                method=probe.method,  # type: ignore[arg-type]
                relation=_relation_of(probe.url, probe.content_types),
                status_code=probe.status_code,
                content_types=probe.content_types,
                technologies=probe.technologies,
                evidence=(evidence_ref,),
            )
        )

    if not endpoints:
        raise ReconAdapterError(
            "no in-scope endpoints survived authorization against the signed ScopeProfile"
        )

    inventory = ReconInventoryV1(
        program_handle=program_handle,
        scope_profile_digest=scope_draft.digest(),
        generated_by=generated_by,
        created_at=now,
        source_tools=source_tools,
        endpoints=tuple(endpoints),
        dropped_out_of_scope=tuple(dict.fromkeys(dropped)),
    )
    return ReconResult(inventory=inventory, evidence=evidence)


def to_endpoint_inventory_v3(inventory: ReconInventoryV1) -> NoReturn:
    """Refuse to bridge a real-asset inventory into the localhost-locked V3 pipeline.

    ``EndpointInventoryV3`` requires localhost URLs by design (the teaching-fixture
    honesty boundary). Mapping real assets into the V3 collaboration/verification
    pipeline requires that pipeline to first become real-asset-capable (docs/19
    N3/N4). Until then this bridge is deliberately closed rather than faked.
    """

    raise ReconAdapterError(
        "V3 EndpointInventory is localhost-only; real-asset recon cannot enter the V3 "
        "pipeline until N3/N4 make it real-asset-capable (docs/19). Boundary preserved."
    )

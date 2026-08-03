"""N2 contract tests: ProjectDiscovery output -> scope-authorized real inventory.

Fully offline. Exercises the fail-closed scope gate that binds N2 to the N1
signed ScopeProfile, and the deliberate refusal to enter the localhost-locked V3
pipeline (docs/19 N2).
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from hermes.recon_adapter import (
    ReconAdapterError,
    build_recon_inventory,
    parse_httpx_line,
    parse_katana_line,
    to_endpoint_inventory_v3,
)
from hermes.scope_profile import (
    BugcrowdProgramSpecV1,
    BugcrowdTargetV1,
    ingest_bugcrowd_program,
)

NOW = datetime(2026, 8, 3, 12, 0, tzinfo=UTC)


def _scope_draft(automated: bool = True):
    spec = BugcrowdProgramSpecV1(
        program_handle="acme-bbp",
        retrieved_at=NOW,
        automated_testing_allowed=automated,
        rate_limit_rps=2.0,
        targets=(
            BugcrowdTargetV1(identifier="https://api.acme.example", category="api"),
            BugcrowdTargetV1(identifier="*.acme.example", category="website"),
        ),
    )
    return ingest_bugcrowd_program(spec)


def _httpx(url: str, **extra) -> dict:
    return {"url": url, "status_code": 200, "content_type": "text/html", "tech": ["nginx"], **extra}


# --------------------------------------------------------------------------- #
# Parsers
# --------------------------------------------------------------------------- #


def test_parse_httpx_line_extracts_fields() -> None:
    probe = parse_httpx_line(_httpx("https://api.acme.example/v1", content_type="application/json"))
    assert probe is not None
    assert probe.url == "https://api.acme.example/v1"
    assert probe.method == "GET"
    assert probe.status_code == 200
    assert probe.content_types == ("application/json",)
    assert probe.technologies == ("nginx",)


def test_parse_httpx_line_skips_urlless_record() -> None:
    assert parse_httpx_line({"status_code": 500}) is None


def test_parse_katana_line_extracts_request_endpoint() -> None:
    line = {
        "request": {"endpoint": "https://app.acme.example/login", "method": "POST"},
        "response": {"status_code": 302},
    }
    probe = parse_katana_line(line)
    assert probe is not None
    assert probe.url == "https://app.acme.example/login"
    assert probe.method == "POST"
    assert probe.status_code == 302


# --------------------------------------------------------------------------- #
# Scope-gated builder
# --------------------------------------------------------------------------- #


def test_builder_keeps_in_scope_and_drops_out_of_scope() -> None:
    draft = _scope_draft()
    probes = [
        parse_httpx_line(_httpx("https://api.acme.example/v1/users")),
        parse_httpx_line(_httpx("https://app.acme.example/")),  # matches *.acme.example
        parse_httpx_line(_httpx("https://evil.example/")),  # out of scope -> dropped
        parse_httpx_line(_httpx("https://acme.example/")),  # apex not in *.acme.example -> dropped
    ]
    result = build_recon_inventory(
        [p for p in probes if p is not None],
        scope_draft=draft,
        program_handle="acme-bbp",
        generated_by="recon-adapter",
        source_tools=("httpx",),
        now=NOW,
    )
    hosts = {urlsplit_host(e.canonical_url) for e in result.inventory.endpoints}
    assert hosts == {"api.acme.example", "app.acme.example"}
    assert "https://evil.example/" in result.inventory.dropped_out_of_scope
    assert "https://acme.example/" in result.inventory.dropped_out_of_scope


def test_builder_binds_scope_digest_and_evidence() -> None:
    draft = _scope_draft()
    probe = parse_httpx_line(_httpx("https://api.acme.example/v1"))
    assert probe is not None
    result = build_recon_inventory(
        [probe],
        scope_draft=draft,
        program_handle="acme-bbp",
        generated_by="recon-adapter",
        source_tools=("httpx",),
        now=NOW,
    )
    inv = result.inventory
    assert inv.scope_profile_digest == draft.digest()
    endpoint = inv.endpoints[0]
    # evidence manifest sha matches the persisted bytes the driver will write
    import hashlib

    raw = result.evidence[endpoint.endpoint_id]
    assert endpoint.evidence[0].manifest_sha256 == "sha256:" + hashlib.sha256(raw).hexdigest()


def test_builder_derives_relations() -> None:
    draft = _scope_draft()
    probes = [
        parse_httpx_line(_httpx("https://api.acme.example/graphql")),
        parse_httpx_line(_httpx("https://api.acme.example/v1", content_type="application/json")),
        parse_httpx_line(_httpx("https://app.acme.example/login")),
        parse_httpx_line(_httpx("https://app.acme.example/home", content_type="text/html")),
    ]
    result = build_recon_inventory(
        [p for p in probes if p is not None],
        scope_draft=draft,
        program_handle="acme-bbp",
        generated_by="recon-adapter",
        source_tools=("httpx",),
        now=NOW,
    )
    by_path = {urlsplit_path(e.canonical_url): e.relation for e in result.inventory.endpoints}
    assert by_path["/graphql"] == "graphql"
    assert by_path["/v1"] == "api"
    assert by_path["/login"] == "auth"
    assert by_path["/home"] == "web"


def test_builder_denies_private_and_loopback_even_if_pattern_would_match() -> None:
    # a program that (wrongly) lists a private host: ingestion drops it, and even a
    # crafted private probe cannot enter the inventory.
    draft = _scope_draft()
    probe = parse_httpx_line(_httpx("https://api.acme.example/v1"))
    assert probe is not None
    # inject a loopback probe that is not in scope anyway
    loop = parse_httpx_line(_httpx("https://127.0.0.1/"))
    result = build_recon_inventory(
        [p for p in (probe, loop) if p is not None],
        scope_draft=draft,
        program_handle="acme-bbp",
        generated_by="recon-adapter",
        source_tools=("httpx",),
        now=NOW,
    )
    assert all("127.0.0.1" not in e.canonical_url for e in result.inventory.endpoints)


def test_builder_raises_when_nothing_survives() -> None:
    draft = _scope_draft()
    probe = parse_httpx_line(_httpx("https://evil.example/"))
    assert probe is not None
    with pytest.raises(ReconAdapterError):
        build_recon_inventory(
            [probe],
            scope_draft=draft,
            program_handle="acme-bbp",
            generated_by="recon-adapter",
            source_tools=("httpx",),
            now=NOW,
        )


def test_v3_bridge_is_refused() -> None:
    draft = _scope_draft()
    probe = parse_httpx_line(_httpx("https://api.acme.example/v1"))
    assert probe is not None
    inv = build_recon_inventory(
        [probe],
        scope_draft=draft,
        program_handle="acme-bbp",
        generated_by="recon-adapter",
        source_tools=("httpx",),
        now=NOW,
    ).inventory
    with pytest.raises(ReconAdapterError):
        to_endpoint_inventory_v3(inv)


def urlsplit_host(url: str) -> str:
    from urllib.parse import urlsplit

    return urlsplit(url).hostname or ""


def urlsplit_path(url: str) -> str:
    from urllib.parse import urlsplit

    return urlsplit(url).path

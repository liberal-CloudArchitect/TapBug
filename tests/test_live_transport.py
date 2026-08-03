"""Real-asset live transport guard tests (read-only + SSRF + scope), no network.

The socket layer is injected (a fake HTTP transport + a fake resolver), so every
safety guard is exercised deterministically without touching a real host.
"""

from __future__ import annotations

import pytest

from hermes.governed_egress import EgressRequestV1
from hermes.live_transport import LivePinnedTransport, LiveTransportError
from hermes.runtime.gateway import HttpRequest, HttpResponse
from hermes.runtime.policy import ScopePolicy, ScopeRule


def _policy() -> ScopePolicy:
    return ScopePolicy(
        profile="bugcrowd",
        rules=(
            ScopeRule(
                host="app.acme.example",
                schemes=frozenset({"https"}),
                ports=frozenset({443}),
                allow_dns=True,
                profile="bugcrowd",
                allow_private=False,
            ),
        ),
        automation_allowed=True,
        dry_run=False,
        max_requests=50,
        rate_limit_rps=2.0,
    )


class _FakeHttp:
    def __init__(self, response: HttpResponse) -> None:
        self.response = response
        self.seen: HttpRequest | None = None

    def __call__(self, request: HttpRequest) -> HttpResponse:
        self.seen = request
        return self.response


def _req(url: str, method: str = "GET") -> EgressRequestV1:
    return EgressRequestV1(method=method, url=url)  # type: ignore[arg-type]


def test_read_only_refuses_write_methods() -> None:
    t = LivePinnedTransport(_policy(), resolver=lambda _h: ("93.184.216.34",))
    with pytest.raises(LiveTransportError):
        t.perform(_req("https://app.acme.example/x", method="POST"))


def test_ssrf_in_scope_host_resolving_to_private_ip_is_refused() -> None:
    # host is in scope, but DNS resolves to a private address -> must be refused
    t = LivePinnedTransport(_policy(), resolver=lambda _h: ("10.0.0.5",))
    with pytest.raises(LiveTransportError):
        t.perform(_req("https://app.acme.example/x"))


def test_out_of_scope_host_is_refused() -> None:
    t = LivePinnedTransport(_policy(), resolver=lambda _h: ("93.184.216.34",))
    with pytest.raises(LiveTransportError):
        t.perform(_req("https://evil.example/"))


def test_wrong_scheme_is_refused() -> None:
    t = LivePinnedTransport(_policy(), resolver=lambda _h: ("93.184.216.34",))
    with pytest.raises(LiveTransportError):
        t.perform(_req("http://app.acme.example/"))  # scope allows https only


def test_success_pins_public_ip_and_maps_response() -> None:
    fake = _FakeHttp(
        HttpResponse(
            status_code=200,
            headers={},
            body=b"hello world",
            header_fields=(("X-Content-Type-Options", "nosniff"), ("Server", "nginx")),
        )
    )
    t = LivePinnedTransport(
        _policy(), resolver=lambda _h: ("93.184.216.34",), http_transport=fake
    )
    response = t.perform(_req("https://app.acme.example/x"))
    assert response.status_code == 200
    assert ("X-Content-Type-Options", "nosniff") in response.headers
    assert response.body_excerpt == "hello world"
    assert response.body_sha256 is not None
    # the HTTP client was pinned to the validated public IP, not asked to re-resolve
    assert fake.seen is not None
    assert fake.seen.connect_ip == "93.184.216.34"
    assert fake.seen.tls_server_name == "app.acme.example"
    # only fixed headers are sent — no operator headers/cookies
    assert set(fake.seen.headers) == {"User-Agent", "Accept"}

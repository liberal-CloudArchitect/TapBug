"""Real-asset governed egress transport: read-only, SSRF-safe, scope-pinned.

This is the piece that lets the governed pipeline (N1 scope -> GovernedEgress ->
N4 verification) reach a **real, authorized** host — the last mile that moves
"real-asset coverage" off zero. It is deliberately the safest possible form of
external access:

* **Whitelist only.** Every request is resolved through Hermes' existing
  :class:`~hermes.runtime.policy.PolicyEngine`, so it must match a rule in the
  human-signed N1 ScopePolicy (host + scheme + port) or it is refused.
* **SSRF-safe.** ``resolve_url`` rejects any host that resolves to a private,
  loopback, or metadata address (the DNS-rebinding case a hostname check misses)
  and **pins** ``connect_ip``; :class:`~hermes.runtime.transport.PinnedHttpTransport`
  then connects to that pinned IP with no re-resolution.
* **Read-only.** Only GET/HEAD/OPTIONS are permitted; any write method is refused.
* **Credential-free.** No operator headers or cookies are forwarded — only a
  fixed User-Agent is sent — so nothing sensitive can leak, consistent with the
  rule that Hermes never handles credentials.
* **Bounded.** Response body and headers are capped; the outer ``GovernedEgress``
  still enforces the rate limit, request budget, and per-request audit.

Wiring this into ``GovernedEgress`` is what an operator does to run against their
*own authorized program*, within that program's automation policy and rate limit.
The library ships the capability; pointing it at a target is a human action.
"""

from __future__ import annotations

import hashlib

from .governed_egress import EgressRequestV1, EgressResponseV1
from .runtime.gateway import HttpRequest, HttpResponse
from .runtime.policy import PolicyEngine, Resolver, ScopePolicy, system_resolver
from .runtime.transport import PinnedHttpTransport

_READONLY = frozenset({"GET", "HEAD", "OPTIONS"})
_DEFAULT_PORTS = {"http": 80, "https": 443}


class LiveTransportError(RuntimeError):
    """A real-asset request was refused by the read-only / SSRF / scope guards."""


class LivePinnedTransport:
    """A GovernedEgress ``Transport`` that fetches real authorized hosts, read-only."""

    def __init__(
        self,
        scope_policy: ScopePolicy,
        *,
        resolver: Resolver = system_resolver,
        http_transport: object | None = None,
        timeout_seconds: float = 10.0,
        response_body_limit: int = 65_536,
        user_agent: str = "Hermes-governed-egress/1 (authorized-assessment)",
    ) -> None:
        self._engine = PolicyEngine(scope_policy, resolver)
        # http_transport is injectable so the compose/mapping path is unit-tested
        # without a socket; production uses the pinned HTTP client.
        self._http = http_transport or PinnedHttpTransport(timeout_seconds)
        self._limit = response_body_limit
        self._ua = user_agent

    def perform(self, request: EgressRequestV1) -> EgressResponseV1:
        if request.method not in _READONLY:
            raise LiveTransportError(
                f"live transport is read-only; refused {request.method}"
            )
        try:
            target = self._engine.resolve_url(request.url)
        except Exception as exc:  # PolicyDenied and any resolver failure -> refuse
            raise LiveTransportError(f"blocked by scope/SSRF policy: {exc}") from exc

        default_port = _DEFAULT_PORTS.get(target.scheme)
        host_header = (
            target.host if target.port == default_port else f"{target.host}:{target.port}"
        )
        http_request = HttpRequest(
            method=request.method,
            url=request.url,
            connect_ip=target.connect_ip,
            host_header=host_header,
            tls_server_name=target.host if target.scheme == "https" else None,
            # Fixed minimal headers only — never forward operator headers/cookies.
            headers={"User-Agent": self._ua, "Accept": "*/*"},
            body=None,
            response_body_limit=self._limit,
        )
        response = self._http(http_request)  # type: ignore[operator]
        return _to_egress_response(response)


def _to_egress_response(response: HttpResponse) -> EgressResponseV1:
    body = response.body or b""
    headers = tuple(
        (str(name)[:256], str(value)[:2048]) for name, value in response.header_fields[:64]
    )
    excerpt = body[:4_000].decode("utf-8", "replace")
    body_sha = "sha256:" + hashlib.sha256(body).hexdigest() if body else None
    return EgressResponseV1(
        status_code=response.status_code,
        headers=headers,
        body_excerpt=excerpt,
        body_sha256=body_sha,
    )

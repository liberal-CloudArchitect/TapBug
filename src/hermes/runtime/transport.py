"""Concrete stdlib transport that connects only to the gateway-pinned address."""

from __future__ import annotations

import http.client
import socket
import ssl
from urllib.parse import urlsplit

from .gateway import HttpRequest, HttpResponse


class _PinnedHttpConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, connect_ip: str, timeout: float) -> None:
        super().__init__(host, port=port, timeout=timeout)
        self._connect_ip = connect_ip

    def connect(self) -> None:
        self.sock = socket.create_connection((self._connect_ip, self.port), self.timeout)


class _PinnedHttpsConnection(http.client.HTTPSConnection):
    def __init__(
        self, host: str, port: int, connect_ip: str, timeout: float, context: ssl.SSLContext
    ) -> None:
        super().__init__(host, port=port, timeout=timeout, context=context)
        self._connect_ip = connect_ip
        self._ssl_context = context

    def connect(self) -> None:
        raw_socket = socket.create_connection((self._connect_ip, self.port), self.timeout)
        self.sock = self._ssl_context.wrap_socket(raw_socket, server_hostname=self.host)


class PinnedHttpTransport:
    """Execute a validated request without allowing the HTTP client to re-resolve DNS."""

    def __init__(
        self, timeout_seconds: float = 10.0, ssl_context: ssl.SSLContext | None = None
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.timeout_seconds = timeout_seconds
        self.ssl_context = ssl_context or ssl.create_default_context()

    def __call__(self, request: HttpRequest) -> HttpResponse:
        parsed = urlsplit(request.url)
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"
        if parsed.scheme == "https":
            connection: http.client.HTTPConnection = _PinnedHttpsConnection(
                request.tls_server_name or parsed.hostname or "",
                parsed.port or 443,
                request.connect_ip,
                self.timeout_seconds,
                self.ssl_context,
            )
        elif parsed.scheme == "http":
            connection = _PinnedHttpConnection(
                parsed.hostname or "", parsed.port or 80, request.connect_ip, self.timeout_seconds
            )
        else:  # Defensive: PolicyEngine has already limited schemes.
            raise ValueError("PinnedHttpTransport only supports HTTP(S)")
        try:
            connection.request(
                request.method, path, body=request.body, headers=dict(request.headers)
            )
            response = connection.getresponse()
            header_fields = tuple(response.getheaders())
            captured = response.read(request.response_body_limit + 1)
            truncated = len(captured) > request.response_body_limit
            body = captured[: request.response_body_limit]
            original_body_bytes: int | None
            content_length = response.getheader("Content-Length")
            try:
                original_body_bytes = int(content_length) if content_length is not None else None
            except ValueError:
                original_body_bytes = None
            if original_body_bytes is not None and original_body_bytes < 0:
                original_body_bytes = None
            if original_body_bytes is None and not truncated:
                original_body_bytes = len(body)
            return HttpResponse(
                response.status,
                dict(header_fields),
                body,
                header_fields=header_fields,
                original_body_bytes=original_body_bytes,
                truncated=truncated,
            )
        finally:
            connection.close()

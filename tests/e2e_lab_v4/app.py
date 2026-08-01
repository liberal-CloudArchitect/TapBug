#!/usr/bin/env python3
"""Deterministic localhost-only Phase 5 fixture with HTTP and HTTPS support."""

from __future__ import annotations

import hashlib
import json
import os
import ssl
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

ALICE_TOKEN = "phase5-alice-token"
BOB_TOKEN = "phase5-bob-token"
ADMIN_TOKEN = "phase5-fixture-admin-token"

_LOCK = threading.Lock()
_STATE: dict[str, Any] = {
    "graphql_value": "initial",
    "alice_privileged": False,
    "workflow_state": "draft",
    "requests": {},
    "active": 0,
    "max_active": 0,
}


def _identity(headers: Any) -> str:
    token = headers.get("Authorization", "").removeprefix("Bearer ")
    if token == ALICE_TOKEN:
        return "alice"
    if token == BOB_TOKEN:
        return "bob"
    if token == ADMIN_TOKEN:
        return "fixture-admin"
    return "anonymous"


def _state_hash() -> str:
    value = {
        "graphql_value": _STATE["graphql_value"],
        "alice_privileged": _STATE["alice_privileged"],
        "workflow_state": _STATE["workflow_state"],
    }
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _request_path(path: str) -> str:
    parsed = urlsplit(path)
    return parsed.path


def _link_header() -> str:
    return ", ".join(
        (
            '</control>; rel="negative-control"',
            '</openapi.json>; rel="service-desc"',
            '</debug>; rel="diagnostic"',
            '</graphql>; rel="graphql"',
            '</authz/status>; rel="role-state"',
            '</redirect>; rel="redirect"',
            '</workflow/item/current>; rel="workflow-state"',
        )
    )


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def _begin(self) -> None:
        path = _request_path(self.path)
        with _LOCK:
            _STATE["active"] += 1
            _STATE["max_active"] = max(_STATE["max_active"], _STATE["active"])
            counts = _STATE["requests"]
            counts[path] = counts.get(path, 0) + 1
        time.sleep(0.03)

    def _finish(self) -> None:
        with _LOCK:
            _STATE["active"] -= 1

    def _send(self, status: int, body: bytes, *, headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, value: Any, *, headers: dict[str, str] | None = None) -> None:
        body = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        merged = {"Content-Type": "application/json"}
        merged.update(headers or {})
        self._send(status, body, headers=merged)

    def _html(self, status: int, body: str, *, headers: dict[str, str] | None = None) -> None:
        merged = {"Content-Type": "text/html; charset=utf-8"}
        merged.update(headers or {})
        self._send(status, body.encode(), headers=merged)

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(min(length, 64 * 1024))
        try:
            payload = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            return {}
        return payload if isinstance(payload, dict) else {}

    def do_GET(self) -> None:  # noqa: N802
        self._begin()
        try:
            parsed = urlsplit(self.path)
            path = parsed.path
            identity = _identity(self.headers)
            if path in {"/", "/candidate"}:
                self._html(
                    HTTPStatus.OK,
                    "<h1>Phase 5 candidate</h1>",
                    headers={"Link": _link_header()},
                )
            elif path == "/control":
                self._html(
                    HTTPStatus.OK,
                    "<h1>Phase 5 candidate</h1>",
                    headers={
                        "X-Content-Type-Options": "nosniff",
                        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                    },
                )
            elif path == "/cookie":
                self._html(
                    HTTPStatus.OK,
                    "<p>session</p>",
                    headers={"Set-Cookie": "sessionid=insecure; Path=/"},
                )
            elif path == "/cookie-control":
                self._html(
                    HTTPStatus.OK,
                    "<p>session</p>",
                    headers={
                        "Set-Cookie": "sessionid=secure; Path=/; Secure; HttpOnly; SameSite=Strict"
                    },
                )
            elif path == "/openapi.json":
                self._json(HTTPStatus.OK, _openapi_document())
            elif path == "/openapi-external.json":
                self._json(
                    HTTPStatus.OK,
                    {
                        "openapi": "3.1.0",
                        "paths": {
                            "/bad": {
                                "get": {
                                    "responses": {
                                        "200": {"$ref": "https://example.invalid/remote.json#/ok"}
                                    }
                                }
                            }
                        },
                    },
                )
            elif path == "/api/public":
                self._json(HTTPStatus.OK, {"status": "public"})
            elif path == "/login":
                self._html(HTTPStatus.OK, "<html><form action='/session'>Login</form></html>")
            elif path == "/spa":
                self._html(
                    HTTPStatus.OK,
                    "<html><div id='app'></div><script src='/app.js'></script></html>",
                )
            elif path == "/debug":
                self._json(HTTPStatus.OK, {"debug": True, "environment": "teaching-fixture"})
            elif path == "/debug-control":
                self._json(HTTPStatus.NOT_FOUND, {"debug": False})
            elif path == "/graphql":
                with _LOCK:
                    value = _STATE["graphql_value"]
                self._json(HTTPStatus.OK, {"data": {"fixtureValue": value}})
            elif path == "/authz/status":
                with _LOCK:
                    privileged = identity == "alice" and bool(_STATE["alice_privileged"])
                self._json(HTTPStatus.OK, {"identity": identity, "privileged": privileged})
            elif path == "/authz/admin":
                with _LOCK:
                    allowed = identity == "fixture-admin" or (
                        identity == "alice" and bool(_STATE["alice_privileged"])
                    )
                self._json(HTTPStatus.OK if allowed else HTTPStatus.FORBIDDEN, {"admin": allowed})
            elif path == "/objects/1":
                if identity != "bob":
                    self._json(HTTPStatus.FORBIDDEN, {"error": "bob_required"})
                else:
                    self._json(HTTPStatus.OK, {"object_id": "1", "owner": "bob"})
            elif path == "/objects/2":
                if identity != "alice":
                    self._json(HTTPStatus.FORBIDDEN, {"error": "alice_required"})
                else:
                    self._json(HTTPStatus.OK, {"object_id": "2", "owner": "bob"})
            elif path == "/objects/2/control":
                self._json(HTTPStatus.FORBIDDEN, {"error": "cross_tenant_forbidden"})
            elif path == "/redirect":
                target = parse_qs(parsed.query).get("next", ["https://redirect.invalid/fix"])[0]
                self.send_response(HTTPStatus.FOUND)
                self.send_header("Location", target)
                self.send_header("Content-Length", "0")
                self.end_headers()
            elif path == "/redirect-control":
                target = parse_qs(parsed.query).get("next", ["/safe"])[0]
                if target.startswith("http://") or target.startswith("https://"):
                    self._json(HTTPStatus.BAD_REQUEST, {"error": "external_redirect_rejected"})
                else:
                    self.send_response(HTTPStatus.FOUND)
                    self.send_header("Location", target)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
            elif path == "/workflow/item/current":
                with _LOCK:
                    state = _STATE["workflow_state"]
                self._json(HTTPStatus.OK, {"state": state})
            elif path == "/fixture/stats":
                with _LOCK:
                    self._json(
                        HTTPStatus.OK,
                        {
                            "requests": dict(_STATE["requests"]),
                            "max_active": _STATE["max_active"],
                            "state_hash": _state_hash(),
                        },
                    )
            else:
                self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
        finally:
            self._finish()

    def do_POST(self) -> None:  # noqa: N802
        self._begin()
        try:
            path = urlsplit(self.path).path
            identity = _identity(self.headers)
            payload = self._read_json()
            if path == "/graphql/mutate":
                if identity not in {"alice", "fixture-admin"}:
                    self._json(HTTPStatus.UNAUTHORIZED, {"error": "authentication_required"})
                    return
                with _LOCK:
                    _STATE["graphql_value"] = str(payload.get("value", "mutated"))
                self._json(HTTPStatus.OK, {"changed": True})
            elif path == "/graphql/control":
                self._json(HTTPStatus.FORBIDDEN, {"error": "mutation_forbidden"})
            elif path == "/graphql/cleanup":
                if identity != "fixture-admin":
                    self._json(HTTPStatus.FORBIDDEN, {"error": "admin_required"})
                    return
                with _LOCK:
                    _STATE["graphql_value"] = "initial"
                self._json(HTTPStatus.OK, {"cleaned": True})
            elif path == "/authz/elevate":
                if identity != "alice":
                    self._json(HTTPStatus.FORBIDDEN, {"error": "alice_required"})
                    return
                with _LOCK:
                    _STATE["alice_privileged"] = True
                self._json(HTTPStatus.OK, {"privileged": True})
            elif path == "/authz/revoke":
                if identity != "fixture-admin":
                    self._json(HTTPStatus.FORBIDDEN, {"error": "admin_required"})
                    return
                with _LOCK:
                    _STATE["alice_privileged"] = False
                self._json(HTTPStatus.OK, {"cleaned": True})
            elif path == "/workflow/direct-approve":
                if identity != "alice":
                    self._json(HTTPStatus.FORBIDDEN, {"error": "alice_required"})
                    return
                with _LOCK:
                    _STATE["workflow_state"] = "approved"
                self._json(HTTPStatus.OK, {"state": "approved"})
            elif path == "/workflow/strict-approve":
                self._json(HTTPStatus.FORBIDDEN, {"error": "approval_forbidden"})
            elif path == "/workflow/reset":
                if identity != "fixture-admin":
                    self._json(HTTPStatus.FORBIDDEN, {"error": "admin_required"})
                    return
                with _LOCK:
                    _STATE["workflow_state"] = "draft"
                self._json(HTTPStatus.OK, {"state": "draft"})
            else:
                self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
        finally:
            self._finish()


def _openapi_document() -> dict[str, Any]:
    return {
        "openapi": "3.1.0",
        "security": [{"bearerAuth": []}],
        "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}},
        "paths": {
            "/candidate": {"get": {"operationId": "candidatePage", "security": []}},
            "/control": {"get": {"operationId": "controlPage", "security": []}},
            "/cookie": {"get": {"operationId": "cookieCandidate", "security": []}},
            "/cookie-control": {"get": {"operationId": "cookieControl", "security": []}},
            "/api/public": {"get": {"operationId": "publicApi", "security": []}},
            "/login": {"get": {"operationId": "loginPage", "security": []}},
            "/spa": {"get": {"operationId": "spaShell", "security": []}},
            "/objects/{object_id}": {
                "get": {
                    "operationId": "readObject",
                    "parameters": [
                        {
                            "name": "object_id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"},
                        },
                        {"name": "view", "in": "query", "schema": {"type": "string"}},
                    ],
                }
            },
            "/graphql/mutate": {
                "post": {
                    "operationId": "graphqlMutate",
                    "parameters": [
                        {
                            "name": "operationName",
                            "in": "query",
                            "schema": {"type": "string"},
                        }
                    ],
                }
            },
            "/redirect": {
                "get": {
                    "operationId": "redirectTarget",
                    "security": [],
                    "parameters": [{"name": "next", "in": "query", "schema": {"type": "string"}}],
                }
            },
            "/workflow/item/current": {"get": {"operationId": "workflowState"}},
            "/workflow/direct-approve": {"post": {"operationId": "workflowDirectApprove"}},
        },
    }


if __name__ == "__main__":
    port = int(os.environ.get("HERMES_V4_PORT", "8080"))
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    certificate = os.environ.get("HERMES_V4_TLS_CERT")
    private_key = os.environ.get("HERMES_V4_TLS_KEY")
    if (certificate is None) != (private_key is None):
        raise RuntimeError("HERMES_V4_TLS_CERT and HERMES_V4_TLS_KEY must be configured together")
    if certificate is not None and private_key is not None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=certificate, keyfile=private_key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()

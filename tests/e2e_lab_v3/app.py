#!/usr/bin/env python3
"""Deterministic localhost-only Phase 4 collaboration fixture."""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

MEMBER_TOKEN = "phase4-member-token"
ADMIN_TOKEN = "phase4-fixture-admin-token"
FEATURES = frozenset(
    value.strip()
    for value in os.environ.get("HERMES_PHASE4_FEATURES", "web,api,authz,infra").split(",")
    if value.strip()
)
_LOCK = threading.Lock()
_STATE: dict[str, Any] = {
    "graphql_value": "initial",
    "member_privileged": False,
    "requests": {},
    "active": 0,
    "max_active": 0,
}


def _state_hash() -> str:
    value = {
        "graphql_value": _STATE["graphql_value"],
        "member_privileged": _STATE["member_privileged"],
    }
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _identity(headers: Any) -> str:
    token = headers.get("Authorization", "").removeprefix("Bearer ")
    if token == MEMBER_TOKEN:
        return "member"
    if token == ADMIN_TOKEN:
        return "fixture-admin"
    return "anonymous"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def _begin(self) -> None:
        path = urlsplit(self.path).path
        with _LOCK:
            _STATE["active"] += 1
            _STATE["max_active"] = max(_STATE["max_active"], _STATE["active"])
            counts = _STATE["requests"]
            counts[path] = counts.get(path, 0) + 1
        # A short deterministic overlap window makes parallel verification observable.
        time.sleep(0.04)

    def _finish(self) -> None:
        with _LOCK:
            _STATE["active"] -= 1

    def _json(self, status: int, value: Any, *, headers: dict[str, str] | None = None) -> None:
        body = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for name, item in (headers or {}).items():
            self.send_header(name, item)
        self.end_headers()
        self.wfile.write(body)

    def _html(self, status: int, body: str, *, headers: dict[str, str] | None = None) -> None:
        encoded = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        for name, item in (headers or {}).items():
            self.send_header(name, item)
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._begin()
        try:
            path = urlsplit(self.path).path
            if path in {"/", "/candidate"}:
                link_values: list[str] = []
                if "web" in FEATURES:
                    link_values.append('</control>; rel="negative-control"')
                if "api" in FEATURES:
                    link_values.append('</graphql>; rel="graphql"')
                if "authz" in FEATURES:
                    link_values.append('</authz/status>; rel="role-state"')
                if "infra" in FEATURES:
                    link_values.append('</debug>; rel="diagnostic"')
                if "capability" in FEATURES:
                    link_values.append('</config>; rel="capability-config"')
                links = ", ".join(link_values)
                self._html(HTTPStatus.OK, "<h1>Phase 4 candidate</h1>", headers={"Link": links})
            elif path == "/config":
                # A line_kv capability artifact the assessment cannot interpret
                # unaided; the Verifier resolves it via an approved CAP-07 Wheel.
                self._html(
                    HTTPStatus.OK,
                    "Service: Hermes\nVersion: 1",
                    headers={"Content-Type": "text/plain; charset=utf-8"},
                )
            elif path == "/control":
                self._html(
                    HTTPStatus.OK,
                    "<h1>Phase 4 candidate</h1>",
                    headers={"X-Content-Type-Options": "nosniff"},
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
                identity = _identity(self.headers)
                with _LOCK:
                    privileged = (
                        bool(_STATE["member_privileged"]) if identity == "member" else False
                    )
                self._json(HTTPStatus.OK, {"identity": identity, "privileged": privileged})
            elif path == "/authz/admin":
                identity = _identity(self.headers)
                with _LOCK:
                    allowed = identity == "fixture-admin" or (
                        identity == "member" and bool(_STATE["member_privileged"])
                    )
                self._json(
                    HTTPStatus.OK if allowed else HTTPStatus.FORBIDDEN,
                    {"admin": allowed},
                )
            elif path == "/fixture/stats":
                with _LOCK:
                    value = {
                        "requests": dict(_STATE["requests"]),
                        "max_active": _STATE["max_active"],
                        "state_hash": _state_hash(),
                    }
                self._json(HTTPStatus.OK, value)
            else:
                self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
        finally:
            self._finish()

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._begin()
        try:
            path = urlsplit(self.path).path
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(min(length, 64 * 1024))
            try:
                payload = json.loads(raw or b"{}")
            except json.JSONDecodeError:
                self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_json"})
                return
            identity = _identity(self.headers)
            if path == "/graphql/mutate":
                # Deliberate local-lab flaw: member can mutate fixture state.
                if identity not in {"member", "fixture-admin"}:
                    self._json(HTTPStatus.UNAUTHORIZED, {"error": "authentication_required"})
                    return
                with _LOCK:
                    _STATE["graphql_value"] = str(payload.get("value", "mutated"))
                self._json(HTTPStatus.OK, {"data": {"changed": True}})
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
                if identity != "member":
                    self._json(HTTPStatus.FORBIDDEN, {"error": "member_required"})
                    return
                with _LOCK:
                    _STATE["member_privileged"] = True
                self._json(HTTPStatus.OK, {"privileged": True})
            elif path == "/authz/revoke":
                if identity != "fixture-admin":
                    self._json(HTTPStatus.FORBIDDEN, {"error": "admin_required"})
                    return
                with _LOCK:
                    _STATE["member_privileged"] = False
                self._json(HTTPStatus.OK, {"cleaned": True})
            else:
                self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
        finally:
            self._finish()


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()

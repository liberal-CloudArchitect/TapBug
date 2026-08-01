from __future__ import annotations

import importlib.util
import json
import ssl
import threading
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.client import HTTPMessage
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from hermes.passive_v4 import (
    extract_openapi_surface,
    fetch_https_observation,
    write_localhost_test_certificates,
)


def _lab_module() -> ModuleType:
    path = Path(__file__).parent / "e2e_lab_v4" / "app.py"
    spec = importlib.util.spec_from_file_location("hermes_phase5_lab", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _server(lab: ModuleType, *, ssl_context: ssl.SSLContext | None = None) -> Any:
    try:
        server = lab.ThreadingHTTPServer(("127.0.0.1", 0), lab.Handler)
    except PermissionError:
        pytest.skip("the current sandbox does not permit the Phase 5 loopback fixture")
    if ssl_context is not None:
        server.socket = ssl_context.wrap_socket(server.socket, server_side=True)
    return server


def _request(
    base: str,
    path: str,
    *,
    method: str = "GET",
    token: str | None = None,
    body: dict[str, Any] | None = None,
    context: ssl.SSLContext | None = None,
    follow_redirects: bool = True,
) -> tuple[int, dict[str, Any] | str, dict[str, str]]:
    headers: dict[str, str] = {}
    data = None
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(base + path, data=data, headers=headers, method=method)
    handlers: list[Any] = []
    if context is not None:
        handlers.append(urllib.request.HTTPSHandler(context=context))
    if not follow_redirects:

        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(
                self,
                req: urllib.request.Request,
                fp: Any,
                code: int,
                msg: str,
                headers: HTTPMessage,
                newurl: str,
            ) -> None:
                return None

        handlers.append(_NoRedirect)
    opener = urllib.request.build_opener(*handlers)
    try:
        response = opener.open(request, timeout=2)
    except urllib.error.HTTPError as exc:
        response = exc
    with response:
        raw = response.read()
        content_type = response.headers.get("Content-Type", "")
        payload: dict[str, Any] | str
        if content_type.startswith("application/json"):
            payload = json.loads(raw)
        else:
            payload = raw.decode()
        return response.status, payload, dict(response.headers.items())


def test_phase5_fixture_supports_passive_mapping_and_low_risk_active_controls(
    tmp_path: Path,
) -> None:
    lab = _lab_module()
    server = _server(lab)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        initial = _request(base, "/fixture/stats")[1]
        assert isinstance(initial, dict)
        status, _, headers = _request(base, "/candidate")
        assert status == 200
        assert 'rel="service-desc"' in headers["Link"]
        assert _request(base, "/control")[2]["X-Content-Type-Options"] == "nosniff"
        assert "Strict-Transport-Security" in _request(base, "/control")[2]
        assert "Secure" not in _request(base, "/cookie")[2]["Set-Cookie"]
        assert "Secure" in _request(base, "/cookie-control")[2]["Set-Cookie"]
        schema = _request(base, "/openapi.json")[1]
        assert isinstance(schema, dict)
        surface = extract_openapi_surface(schema, origin=base + "/openapi.json")
        assert "/objects/{object_id}" in {item.path for item in surface.schema_operations}
        assert _request(base, "/api/public")[0] == 200
        assert _request(base, "/login")[0] == 200
        assert _request(base, "/spa")[0] == 200

        with ThreadPoolExecutor(max_workers=3) as pool:
            read_only = list(
                pool.map(
                    lambda path: _request(base, path),
                    ("/candidate", "/control", "/debug"),
                )
            )
        assert [item[0] for item in read_only] == [200, 200, 200]

        assert _request(base, "/objects/1", token=lab.BOB_TOKEN)[0] == 200
        assert _request(base, "/objects/2", token=lab.ALICE_TOKEN)[0] == 200
        assert _request(base, "/objects/2/control", token=lab.ALICE_TOKEN)[0] == 403
        redirect = _request(
            base,
            "/redirect?next=https://redirect.invalid/teaching",
            follow_redirects=False,
        )
        assert redirect[0] == 302
        assert redirect[2]["Location"] == "https://redirect.invalid/teaching"
        assert (
            _request(
                base,
                "/redirect-control?next=https://redirect.invalid/teaching",
                follow_redirects=False,
            )[0]
            == 400
        )

        assert _request(base, "/graphql", token=lab.ALICE_TOKEN)[1] == {
            "data": {"fixtureValue": "initial"}
        }
        assert (
            _request(
                base,
                "/graphql/mutate",
                method="POST",
                token=lab.ALICE_TOKEN,
                body={"value": "mutated"},
            )[0]
            == 200
        )
        assert (
            _request(base, "/graphql/control", method="POST", token=lab.ALICE_TOKEN, body={})[0]
            == 403
        )
        assert (
            _request(base, "/graphql/cleanup", method="POST", token=lab.ADMIN_TOKEN, body={})[0]
            == 200
        )

        assert _request(base, "/authz/status", token=lab.ALICE_TOKEN)[1] == {
            "identity": "alice",
            "privileged": False,
        }
        assert (
            _request(base, "/authz/elevate", method="POST", token=lab.ALICE_TOKEN, body={})[0]
            == 200
        )
        assert _request(base, "/authz/admin", token=lab.ALICE_TOKEN)[0] == 200
        assert (
            _request(base, "/authz/revoke", method="POST", token=lab.ADMIN_TOKEN, body={})[0] == 200
        )

        assert _request(base, "/workflow/item/current")[1] == {"state": "draft"}
        assert (
            _request(
                base,
                "/workflow/direct-approve",
                method="POST",
                token=lab.ALICE_TOKEN,
                body={},
            )[0]
            == 200
        )
        assert (
            _request(
                base,
                "/workflow/strict-approve",
                method="POST",
                token=lab.ALICE_TOKEN,
                body={},
            )[0]
            == 403
        )
        assert (
            _request(base, "/workflow/reset", method="POST", token=lab.ADMIN_TOKEN, body={})[0]
            == 200
        )

        final = _request(base, "/fixture/stats")[1]
        assert isinstance(final, dict)
        assert final["state_hash"] == initial["state_hash"]
        assert final["max_active"] >= 2
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


def test_phase5_https_fixture_requires_explicit_ca_trust(tmp_path: Path) -> None:
    lab = _lab_module()
    ca_path, cert_path, key_path = write_localhost_test_certificates(str(tmp_path / "certs"))
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(certfile=cert_path, keyfile=key_path)
    server = _server(lab, ssl_context=server_context)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    base = f"https://localhost:{server.server_port}"
    try:
        with pytest.raises(urllib.error.URLError):
            _request(base, "/control")

        observation = fetch_https_observation(base + "/control", cafile=ca_path)

        assert observation.posture.status_code == 200
        assert observation.posture.tls is not None
        assert observation.posture.tls.protocol.startswith("TLS")
        assert observation.posture.tls.leaf_issuer.startswith("commonName=Hermes V4 Test CA")
        assert observation.posture.tls.san_dns_names == ("localhost",)
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)

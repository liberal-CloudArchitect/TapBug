from __future__ import annotations

import importlib.util
import json
import os
import threading
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest


def _lab_module() -> ModuleType:
    path = Path(__file__).parent / "e2e_lab_v3" / "app.py"
    spec = importlib.util.spec_from_file_location("hermes_phase4_lab", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _request(
    base: str,
    path: str,
    *,
    method: str = "GET",
    token: str | None = None,
    body: dict[str, Any] | None = None,
) -> tuple[int, dict[str, Any] | str, dict[str, str]]:
    headers: dict[str, str] = {}
    data = None
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(
        base + path,
        data=data,
        headers=headers,
        method=method,
    )
    try:
        response = urllib.request.urlopen(request, timeout=2)
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


def _server(lab: ModuleType):
    try:
        return lab.ThreadingHTTPServer(("127.0.0.1", 0), lab.Handler)
    except PermissionError:
        if os.environ.get("CI"):
            pytest.fail("CI must permit the Phase 4 loopback fixture integration test")
        pytest.skip("the current sandbox does not permit loopback listeners")


def test_phase4_fixture_supports_exact_campaign_and_restores_state() -> None:
    lab = _lab_module()
    server = _server(lab)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        initial = _request(base, "/fixture/stats")[1]
        assert isinstance(initial, dict)

        # Recon plus the two read-only verification pairs.
        recon = _request(base, "/candidate")
        assert recon[0] == 200 and 'rel="graphql"' in recon[2]["Link"]
        with ThreadPoolExecutor(max_workers=4) as pool:
            read_only = list(
                pool.map(
                    lambda path: _request(base, path),
                    ("/candidate", "/control", "/debug", "/debug-control"),
                )
            )
        assert [item[0] for item in read_only] == [200, 200, 200, 404]
        assert "X-Content-Type-Options" not in read_only[0][2]
        assert read_only[1][2]["X-Content-Type-Options"] == "nosniff"

        # API baseline, flawed mutation, strict negative control, cleanup and check.
        assert _request(base, "/graphql", token=lab.MEMBER_TOKEN)[1] == {
            "data": {"fixtureValue": "initial"}
        }
        assert (
            _request(
                base,
                "/graphql/mutate",
                method="POST",
                token=lab.MEMBER_TOKEN,
                body={"value": "mutated"},
            )[0]
            == 200
        )
        assert (
            _request(
                base,
                "/graphql/control",
                method="POST",
                token=lab.MEMBER_TOKEN,
                body={"value": "blocked"},
            )[0]
            == 403
        )
        assert (
            _request(
                base,
                "/graphql/cleanup",
                method="POST",
                token=lab.ADMIN_TOKEN,
                body={},
            )[0]
            == 200
        )
        assert _request(base, "/graphql", token=lab.MEMBER_TOKEN)[1] == {
            "data": {"fixtureValue": "initial"}
        }

        # Authz baseline, elevation, protected endpoint, cleanup and check.
        assert _request(base, "/authz/status", token=lab.MEMBER_TOKEN)[1] == {
            "identity": "member",
            "privileged": False,
        }
        assert (
            _request(
                base,
                "/authz/elevate",
                method="POST",
                token=lab.MEMBER_TOKEN,
                body={},
            )[0]
            == 200
        )
        assert _request(base, "/authz/admin", token=lab.MEMBER_TOKEN)[0] == 200
        assert (
            _request(
                base,
                "/authz/revoke",
                method="POST",
                token=lab.ADMIN_TOKEN,
                body={},
            )[0]
            == 200
        )
        assert _request(base, "/authz/status", token=lab.MEMBER_TOKEN)[1] == {
            "identity": "member",
            "privileged": False,
        }

        final = _request(base, "/fixture/stats")[1]
        assert isinstance(final, dict)
        assert final["state_hash"] == initial["state_hash"]
        assert final["max_active"] >= 2
        relevant = {
            key: value for key, value in final["requests"].items() if key != "/fixture/stats"
        }
        assert sum(relevant.values()) == 15
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


def test_phase4_fixture_can_expose_only_web_and_infra_route_features(monkeypatch: Any) -> None:
    monkeypatch.setenv("HERMES_PHASE4_FEATURES", "web,infra")
    lab = _lab_module()
    server = _server(lab)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        status, _, headers = _request(base, "/candidate")

        assert status == 200
        assert headers["Link"] == ('</control>; rel="negative-control", </debug>; rel="diagnostic"')
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)

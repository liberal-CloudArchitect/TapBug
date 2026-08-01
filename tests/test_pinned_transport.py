import os
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest

from hermes.runtime import (
    PinnedHttpTransport,
    PolicyEngine,
    RunContext,
    ScopePolicy,
    ScopeRule,
    ToolGateway,
)


class _Handler(BaseHTTPRequestHandler):
    received_host = ""

    def do_GET(self) -> None:  # noqa: N802
        type(self).received_host = self.headers["Host"]
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"pinned")

    def log_message(self, _format: str, *_args: object) -> None:
        return


@pytest.mark.integration
def test_pinned_transport_uses_validated_ip_without_reresolving_host(tmp_path, monkeypatch) -> None:
    try:
        server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    except PermissionError:
        if os.environ.get("CI"):
            pytest.fail("CI must permit the loopback transport integration test")
        pytest.skip("the current sandbox does not permit loopback listeners")
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        policy = ScopePolicy(
            profile="local-lab",
            automation_allowed=True,
            dry_run=False,
            rules=(
                ScopeRule(
                    host="localhost",
                    schemes={"http"},
                    ports={port},
                    allow_dns=True,
                    allow_private=True,
                    profile="local-lab",
                ),
            ),
        )
        context = RunContext(tmp_path / "runs", policy.model_dump(mode="json"))
        getaddrinfo = socket.getaddrinfo

        def reject_hostname_reresolution(host, *args, **kwargs):
            if host == "localhost":
                raise AssertionError("transport attempted to re-resolve the scope hostname")
            return getaddrinfo(host, *args, **kwargs)

        monkeypatch.setattr(socket, "getaddrinfo", reject_hostname_reresolution)
        response, _evidence = ToolGateway(
            engine=PolicyEngine(policy, resolver=lambda _host: ["127.0.0.1"]),
            context=context,
            transport=PinnedHttpTransport(),
        ).request("GET", f"http://localhost:{port}/")
        assert response.status_code == 200
        assert response.body == b"pinned"
        assert _Handler.received_host == f"localhost:{port}"
    finally:
        server.shutdown()
        thread.join()

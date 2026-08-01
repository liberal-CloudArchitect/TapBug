from __future__ import annotations

import socket

import pytest

from hermes.runtime import ActionKind, ProposedAction, system_resolver


def test_system_resolver_deduplicates_and_canonicalizes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 0, 0, 0)),
        ],
    )
    assert system_resolver("localhost") == ("127.0.0.1", "::1")


def test_validation_get_is_read_only_but_requires_approval() -> None:
    action = ProposedAction(
        kind=ActionKind.VALIDATION_HTTP_GET,
        target="http://localhost:8080/candidate",
        method="GET",
    )
    assert action.requires_approval
    with pytest.raises(ValueError, match="validation_http_get"):
        ProposedAction(
            kind=ActionKind.VALIDATION_HTTP_GET,
            target="http://localhost:8080/candidate",
            method="POST",
        )

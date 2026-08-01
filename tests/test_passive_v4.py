from __future__ import annotations

import json

import pytest

from hermes.passive_v4 import (
    PassiveV4Error,
    extract_openapi_surface,
    parse_set_cookie_headers,
    project_posture,
)


def test_cookie_projection_preserves_security_attributes() -> None:
    cookies = parse_set_cookie_headers(
        [
            "sessionid=insecure; Path=/",
            "sessionid=secure; Path=/; Secure; HttpOnly; SameSite=Strict",
        ]
    )

    assert cookies[0].secure is False
    assert cookies[0].http_only is False
    assert cookies[0].same_site == "missing"
    assert cookies[1].secure is True
    assert cookies[1].http_only is True
    assert cookies[1].same_site == "strict"


def test_openapi_surface_is_local_and_rejects_external_refs() -> None:
    document = {
        "openapi": "3.1.0",
        "paths": {
            "/objects/{object_id}": {
                "get": {
                    "operationId": "readObject",
                    "parameters": [{"name": "object_id", "in": "path"}],
                    "security": [{"bearerAuth": []}],
                }
            },
            "/api/public": {"get": {"operationId": "publicApi", "security": []}},
        },
        "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}},
    }

    surface = extract_openapi_surface(document, origin="https://localhost:8443/openapi.json")

    assert tuple(item.path for item in surface.schema_operations) == (
        "/api/public",
        "/objects/{object_id}",
    )
    assert surface.schema_operations[1].auth_schemes == ("bearerAuth",)
    assert surface.schema_operations[0].public is True

    with pytest.raises(PassiveV4Error, match="non-local \\$ref"):
        extract_openapi_surface(
            json.dumps(
                {
                    "openapi": "3.1.0",
                    "paths": {
                        "/bad": {
                            "get": {
                                "responses": {
                                    "200": {"$ref": "https://example.invalid/schema.json#/resp"}
                                }
                            }
                        }
                    },
                }
            ),
            origin="https://localhost:8443/openapi.json",
        )


def test_posture_projection_keeps_only_security_headers() -> None:
    posture = project_posture(
        url="https://localhost:8443/control",
        status_code=200,
        headers={
            "content-type": "text/html; charset=utf-8",
            "x-content-type-options": "nosniff",
            "strict-transport-security": "max-age=31536000",
            "server": "fixture",
        },
        body=b"<html></html>",
    )

    assert posture.response_headers == {
        "x-content-type-options": "nosniff",
        "strict-transport-security": "max-age=31536000",
    }

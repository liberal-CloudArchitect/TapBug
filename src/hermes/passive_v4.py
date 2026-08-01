"""Passive HTTP/TLS/schema projections for the localhost-only V4 workflow."""

from __future__ import annotations

import http.client
import json
import ssl
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from email.message import Message
from http.cookies import SimpleCookie
from typing import Any, Literal, cast
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from pydantic import BaseModel, ConfigDict, Field, field_validator

HTTP_METHODS = frozenset({"get", "post", "put", "patch", "delete"})
SENSITIVE_HEADERS = frozenset(
    {
        "content-security-policy",
        "permissions-policy",
        "referrer-policy",
        "strict-transport-security",
        "x-content-type-options",
        "x-frame-options",
    }
)


class PassiveV4Error(RuntimeError):
    """The passive V4 projection could not be derived safely."""


class CookieAttributeV4(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1, max_length=128)
    secure: bool
    http_only: bool
    same_site: Literal["lax", "strict", "none", "missing"]
    domain: str | None = None
    path: str | None = None


class TlsPeerV4(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    protocol: str = Field(min_length=1, max_length=32)
    cipher_suite: str = Field(min_length=1, max_length=128)
    leaf_subject: str = Field(min_length=1, max_length=512)
    leaf_issuer: str = Field(min_length=1, max_length=512)
    not_after: datetime
    san_dns_names: tuple[str, ...]
    certificate_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @field_validator("not_after")
    @classmethod
    def aware_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("TLS not_after must be timezone-aware")
        return value

    @field_validator("san_dns_names")
    @classmethod
    def unique_sans(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("TLS SAN names must be unique")
        return value


class SchemaOperationV4(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    operation_id: str = Field(min_length=1, max_length=128)
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"]
    path: str = Field(min_length=1, max_length=256)
    parameters: tuple[str, ...] = ()
    auth_schemes: tuple[str, ...] = ()
    public: bool = False

    @field_validator("path")
    @classmethod
    def local_path(cls, value: str) -> str:
        if not value.startswith("/"):
            raise ValueError("OpenAPI paths must be absolute local paths")
        return value

    @field_validator("parameters", "auth_schemes")
    @classmethod
    def unique_values(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("schema projection collections must be unique")
        return value


class PassivePostureV4(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    url: str = Field(min_length=1, max_length=2048)
    status_code: int = Field(ge=100, le=599)
    content_type: str = Field(min_length=1, max_length=256)
    response_headers: dict[str, str]
    cookies: tuple[CookieAttributeV4, ...] = ()
    tls: TlsPeerV4 | None = None
    body_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @field_validator("response_headers")
    @classmethod
    def canonical_headers(cls, value: dict[str, str]) -> dict[str, str]:
        normalized = {key.lower(): item for key, item in value.items()}
        if set(normalized) != set(value):
            raise ValueError("response header projection keys must already be lowercase")
        return normalized


class SurfaceMapV4(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    origin: str = Field(min_length=1, max_length=2048)
    schema_operations: tuple[SchemaOperationV4, ...] = ()
    trusted_links: tuple[str, ...] = ()

    @field_validator("trusted_links")
    @classmethod
    def unique_links(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("trusted links must be unique")
        return value


class HttpsObservationV4(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    posture: PassivePostureV4
    body: bytes


def _sha256_hex(value: bytes) -> str:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(value)
    return "sha256:" + digest.finalize().hex()


def _subject_name(name: x509.Name) -> str:
    return ", ".join(
        f"{attr.oid._name or attr.oid.dotted_string}={str(attr.value)}" for attr in name
    )


def project_security_headers(headers: Mapping[str, str]) -> dict[str, str]:
    return {
        key.lower(): value.strip()
        for key, value in headers.items()
        if key.lower() in SENSITIVE_HEADERS
    }


def parse_set_cookie_headers(values: Sequence[str]) -> tuple[CookieAttributeV4, ...]:
    cookies: list[CookieAttributeV4] = []
    for raw in values:
        morsels = SimpleCookie()
        morsels.load(raw)
        for morsel in morsels.values():
            same_site_value = str(morsel["samesite"] or "").strip().lower()
            same_site: Literal["lax", "strict", "none", "missing"]
            if same_site_value in {"lax", "strict", "none"}:
                same_site = cast(Literal["lax", "strict", "none"], same_site_value)
            else:
                same_site = "missing"
            cookies.append(
                CookieAttributeV4(
                    name=morsel.key,
                    secure=bool(morsel["secure"]),
                    http_only=bool(morsel["httponly"]),
                    same_site=same_site,
                    domain=str(morsel["domain"] or "").strip() or None,
                    path=str(morsel["path"] or "").strip() or None,
                )
            )
    return tuple(cookies)


def project_posture(
    *,
    url: str,
    status_code: int,
    headers: Mapping[str, str],
    set_cookie_headers: Sequence[str] = (),
    body: bytes = b"",
    tls: TlsPeerV4 | None = None,
) -> PassivePostureV4:
    return PassivePostureV4(
        url=url,
        status_code=status_code,
        content_type=headers.get("content-type", "application/octet-stream"),
        response_headers=project_security_headers(headers),
        cookies=parse_set_cookie_headers(set_cookie_headers),
        tls=tls,
        body_sha256=_sha256_hex(body),
    )


def _reject_external_refs(value: Any) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "$ref" and isinstance(item, str):
                if not item.startswith("#/"):
                    raise PassiveV4Error("OpenAPI projection rejected a non-local $ref")
            _reject_external_refs(item)
    elif isinstance(value, list):
        for item in value:
            _reject_external_refs(item)


def extract_openapi_surface(
    document: str | bytes | Mapping[str, Any], *, origin: str
) -> SurfaceMapV4:
    if isinstance(document, bytes):
        payload = json.loads(document.decode("utf-8"))
    elif isinstance(document, str):
        payload = json.loads(document)
    else:
        payload = dict(document)
    if not isinstance(payload, dict) or not isinstance(payload.get("paths"), dict):
        raise PassiveV4Error("OpenAPI projection requires a top-level paths object")
    _reject_external_refs(payload)
    operations: list[SchemaOperationV4] = []
    schemes = payload.get("components", {}).get("securitySchemes", {})
    paths = payload["paths"]
    for path, methods in sorted(paths.items()):
        if not isinstance(path, str) or not path.startswith("/") or not isinstance(methods, dict):
            raise PassiveV4Error("OpenAPI projection encountered an invalid local path entry")
        for method, operation in sorted(methods.items()):
            lower = str(method).lower()
            if lower not in HTTP_METHODS:
                continue
            if not isinstance(operation, dict):
                raise PassiveV4Error("OpenAPI projection encountered a malformed operation")
            parameters = []
            for entry in operation.get("parameters", ()):
                if isinstance(entry, dict) and isinstance(entry.get("name"), str):
                    parameters.append(entry["name"])
            auth = []
            security = operation.get("security", ())
            if isinstance(security, list):
                for item in security:
                    if isinstance(item, dict):
                        for key in item:
                            if isinstance(key, str):
                                auth.append(key)
            if not auth and "security" in payload and isinstance(payload["security"], list):
                for item in payload["security"]:
                    if isinstance(item, dict):
                        for key in item:
                            if isinstance(key, str):
                                auth.append(key)
            operations.append(
                SchemaOperationV4(
                    operation_id=str(
                        operation.get("operationId")
                        or f"{lower}-{path.strip('/').replace('/', '-') or 'root'}"
                    ),
                    method=cast(Literal["GET", "POST", "PUT", "PATCH", "DELETE"], lower.upper()),
                    path=path,
                    parameters=tuple(dict.fromkeys(parameters)),
                    auth_schemes=tuple(dict.fromkeys(key for key in auth if key in schemes or key)),
                    public=not auth,
                )
            )
    return SurfaceMapV4(
        origin=origin,
        schema_operations=tuple(operations),
        trusted_links=tuple(sorted(paths)),
    )


def fetch_https_observation(url: str, *, cafile: str) -> HttpsObservationV4:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname != "localhost":
        raise PassiveV4Error("HTTPS observation requires an absolute localhost https URL")
    port = parsed.port or 443
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    context = ssl.create_default_context(cafile=cafile)
    connection = http.client.HTTPSConnection(parsed.hostname, port=port, context=context, timeout=5)
    try:
        connection.request("GET", path, headers={"Host": parsed.netloc})
        response = connection.getresponse()
        body = response.read()
        socket = connection.sock
        if socket is None:
            raise PassiveV4Error("HTTPS observation lost its TLS socket")
        peer = socket.getpeercert(binary_form=True)
        if peer is None:
            raise PassiveV4Error("HTTPS observation missing peer certificate")
        certificate = x509.load_der_x509_certificate(peer)
        try:
            sans = certificate.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            sans = []
        tls = TlsPeerV4(
            protocol=socket.version() or "unknown",
            cipher_suite=(socket.cipher() or ("unknown", "", 0))[0],
            leaf_subject=_subject_name(certificate.subject),
            leaf_issuer=_subject_name(certificate.issuer),
            not_after=certificate.not_valid_after_utc,
            san_dns_names=tuple(sans),
            certificate_sha256=_sha256_hex(peer),
        )
        message: Message = response.headers
        header_map = {key.lower(): value for key, value in response.getheaders()}
        set_cookie = message.get_all("Set-Cookie", [])
        return HttpsObservationV4(
            posture=project_posture(
                url=url,
                status_code=response.status,
                headers=header_map,
                set_cookie_headers=set_cookie,
                body=body,
                tls=tls,
            ),
            body=body,
        )
    finally:
        connection.close()


def write_localhost_test_certificates(directory: str) -> tuple[str, str, str]:
    """Generate a temporary CA and localhost leaf certificate for tests."""

    from pathlib import Path

    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    ca_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Hermes V4 Test CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=7))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    leaf_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_subject)
        .issuer_name(ca_subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=7))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    ca_path = root / "ca.pem"
    cert_path = root / "localhost.pem"
    key_path = root / "localhost-key.pem"
    ca_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    cert_path.write_bytes(leaf_cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        leaf_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return str(ca_path), str(cert_path), str(key_path)


__all__ = [
    "CookieAttributeV4",
    "HttpsObservationV4",
    "PassivePostureV4",
    "PassiveV4Error",
    "SchemaOperationV4",
    "SurfaceMapV4",
    "TlsPeerV4",
    "extract_openapi_surface",
    "fetch_https_observation",
    "parse_set_cookie_headers",
    "project_posture",
    "project_security_headers",
    "write_localhost_test_certificates",
]

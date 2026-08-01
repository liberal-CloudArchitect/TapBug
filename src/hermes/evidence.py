"""V2 evidence artifacts: bounded analysis copies and optional encrypted originals."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, Protocol
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .security import canonical_json

_DIGEST = r"^sha256:[0-9a-f]{64}$"
_ID = r"^[A-Za-z0-9._-]{1,128}$"
_REQUEST_ID = r"^[A-Za-z0-9._:-]{1,128}$"
_DEFAULT_CAPTURE = 1024 * 1024
_DEFAULT_ANALYSIS = 64 * 1024
_MAX_CAPTURE = 10 * 1024 * 1024
_MAX_ANALYSIS = 256 * 1024
_REDACTED = "[REDACTED]"
_TRUNCATED = "[TRUNCATED]"
_SECRET_HEADERS = frozenset(
    {
        "authorization",
        "authentication",
        "cookie",
        "proxy-authorization",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
    }
)
_SECRET_KEY = re.compile(
    r"^(?:password|passwd|pwd|token|access[_-]?token|refresh[_-]?token|secret|"
    r"api[_-]?key|apikey|session|sessionid|client[_-]?secret)$",
    re.IGNORECASE,
)
_TEXT_SECRET = re.compile(
    r"(?i)\b(password|passwd|token|access[_-]?token|refresh[_-]?token|secret|"
    r"api[_-]?key|session|client[_-]?secret)(\s*[:=]\s*)([^\s&;,<]+)"
)


class EvidenceStoreError(ValueError):
    """An evidence artifact cannot be created or verified safely."""


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


class HeaderField(BaseModel):
    """One header field; tuples preserve wire order and duplicate names."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1, max_length=256)
    value: str = Field(max_length=64 * 1024)

    @field_validator("name")
    @classmethod
    def valid_name(cls, value: str) -> str:
        if "\r" in value or "\n" in value or ":" in value:
            raise ValueError("header names may not contain delimiters")
        return value

    @field_validator("value")
    @classmethod
    def valid_value(cls, value: str) -> str:
        if "\r" in value or "\n" in value:
            raise ValueError("header values may not contain newlines")
        return value


class EvidenceArtifactRef(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    evidence_id: str = Field(pattern=_ID)
    manifest_path: str = Field(pattern=r"^evidence/[A-Za-z0-9._-]+/manifest\.json$")
    manifest_sha256: str = Field(pattern=_DIGEST)


class EvidenceBinding(BaseModel):
    """Complete runtime identity associated with one gateway exchange."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: str = Field(default="2", pattern=r"^2$")
    evidence_id: str = Field(pattern=_ID)
    run_id: str = Field(pattern=_ID)
    scope_digest: str = Field(pattern=_DIGEST)
    task_id: str = Field(pattern=_ID)
    task_input_sha256: str = Field(pattern=_DIGEST)
    role: str = Field(pattern=r"^[a-z][a-z0-9-]{0,63}$")
    request_id: str = Field(pattern=_REQUEST_ID)
    action_id: str = Field(pattern=_ID)
    action_digest: str = Field(pattern=_DIGEST)
    plan_digest: str | None = Field(default=None, pattern=_DIGEST)
    approval_bundle_id: str | None = Field(default=None, pattern=_ID)
    approval_bundle_digest: str | None = Field(default=None, pattern=_DIGEST)
    approval_consumption_digest: str | None = Field(default=None, pattern=_DIGEST)
    captured_at: datetime

    @field_validator("captured_at")
    @classmethod
    def timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("captured_at must be timezone-aware")
        return value

    @model_validator(mode="after")
    def coherent_approval_binding(self) -> EvidenceBinding:
        approval = (
            self.approval_bundle_id,
            self.approval_bundle_digest,
            self.approval_consumption_digest,
        )
        if any(item is not None for item in approval) and (
            any(item is None for item in approval) or self.plan_digest is None
        ):
            raise ValueError("approval evidence requires plan, bundle, and consumption binding")
        return self

    def canonical_bytes(self) -> bytes:
        return canonical_json(self.model_dump(mode="json"))


class AnalysisCopy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str = Field(pattern=r"^evidence/[A-Za-z0-9._-]+/analysis\.json$")
    sha256: str = Field(pattern=_DIGEST)
    retained_bytes: int = Field(ge=0)
    limit_bytes: int = Field(default=_DEFAULT_ANALYSIS, ge=512, le=_MAX_ANALYSIS)
    truncated: bool
    redacted_fields: tuple[str, ...] = ()

    @model_validator(mode="after")
    def within_declared_limit(self) -> AnalysisCopy:
        if self.retained_bytes > self.limit_bytes:
            raise ValueError("analysis copy exceeds its declared byte limit")
        return self


class AnalysisRequest(BaseModel):
    """Typed, redacted request projection used for parent-side verification."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    method: str = Field(pattern=r"^[A-Z]+$")
    url: str
    headers: tuple[HeaderField, ...]
    mime: str
    body: Any = None


class AnalysisResponse(BaseModel):
    """Typed, redacted response projection used for parent-side verification."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: int = Field(ge=100, le=599)
    headers: tuple[HeaderField, ...]
    mime: str
    body: Any = None


class EvidenceAnalysisDocument(BaseModel):
    """Closed V2 schema for a bounded analysis copy."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["2"] = "2"
    request: AnalysisRequest
    response: AnalysisResponse


class RawCopy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str = Field(pattern=r"^evidence/[A-Za-z0-9._-]+/raw\.enc$")
    algorithm: str = Field(default="AES-256-GCM", pattern=r"^AES-256-GCM$")
    key_id: str = Field(pattern=_ID)
    nonce: str
    aad_sha256: str = Field(pattern=_DIGEST)
    plaintext_sha256: str = Field(pattern=_DIGEST)
    ciphertext_sha256: str = Field(pattern=_DIGEST)


class EvidenceArtifactManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: str = Field(default="2", pattern=r"^2$")
    binding: EvidenceBinding
    request_method: str = Field(pattern=r"^[A-Z]+$")
    target: str
    response_status: int = Field(ge=100, le=599)
    request_mime: str
    response_mime: str
    request_hash: str = Field(pattern=_DIGEST)
    response_hash: str = Field(pattern=_DIGEST)
    request_body_sha256: str = Field(pattern=_DIGEST)
    response_body_sha256: str = Field(pattern=_DIGEST)
    request_original_bytes: int | None = Field(default=None, ge=0)
    response_original_bytes: int | None = Field(default=None, ge=0)
    request_captured_bytes: int = Field(ge=0)
    response_captured_bytes: int = Field(ge=0)
    request_truncated: bool
    response_truncated: bool
    analysis: AnalysisCopy
    raw: RawCopy | None = None


class EvidencePolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    capture_limit_bytes: int = Field(default=_DEFAULT_CAPTURE, ge=1)
    analysis_limit_bytes: int = Field(default=_DEFAULT_ANALYSIS, ge=512)
    raw_retention: bool = False

    @model_validator(mode="after")
    def enforce_hard_limits(self) -> EvidencePolicy:
        if self.capture_limit_bytes > _MAX_CAPTURE:
            raise ValueError("capture limit exceeds the 10 MiB hard cap")
        if self.analysis_limit_bytes > _MAX_ANALYSIS:
            raise ValueError("analysis limit exceeds the 256 KiB hard cap")
        return self


class EvidenceKeyProvider(Protocol):
    """Narrow key-provider seam for a future KMS-backed implementation."""

    key_id: str

    def load_key(self, key_id: str) -> bytes: ...


class FileEvidenceKeyProvider:
    """Load a purpose-specific AES key from a constrained external file."""

    def __init__(self, *, key_path: Path, key_id: str, forbidden_roots: tuple[Path, ...]) -> None:
        if not key_path.is_absolute():
            raise EvidenceStoreError("raw key path must be absolute")
        self.key_path = key_path.absolute()
        self.key_id = key_id
        if not re.fullmatch(_ID, key_id):
            raise EvidenceStoreError("raw key ID is invalid")
        if key_path.is_symlink():
            raise EvidenceStoreError("raw key file must not be a symlink")
        try:
            details = key_path.stat()
        except OSError as exc:
            raise EvidenceStoreError("raw key file is not readable") from exc
        if not stat.S_ISREG(details.st_mode):
            raise EvidenceStoreError("raw key path must be a regular file")
        if stat.S_IMODE(details.st_mode) != 0o600:
            raise EvidenceStoreError("raw key file permissions must be 0600")
        resolved = key_path.resolve(strict=True)
        for root in forbidden_roots:
            if resolved.is_relative_to(root.resolve(strict=False)):
                raise EvidenceStoreError("raw key file must be outside every forbidden root")
        try:
            key = key_path.read_bytes()
        except OSError as exc:
            raise EvidenceStoreError("raw key file is not readable") from exc
        if len(key) != 32:
            raise EvidenceStoreError("raw AES key must contain exactly 32 bytes")
        self._key = key

    def load_key(self, key_id: str) -> bytes:
        if key_id != self.key_id:
            raise EvidenceStoreError("raw key ID does not match the configured provider")
        return self._key


class EvidenceStore:
    """Persist and verify immutable, hash-bound evidence artifacts."""

    def __init__(
        self,
        root: Path,
        *,
        policy: EvidencePolicy | None = None,
        key_provider: EvidenceKeyProvider | None = None,
    ) -> None:
        self.root = root.resolve(strict=False)
        self.policy = policy or EvidencePolicy()
        self.key_provider = key_provider
        if self.policy.raw_retention and key_provider is None:
            raise EvidenceStoreError("raw retention requires a key provider")

    def capture(
        self,
        *,
        binding: EvidenceBinding,
        request_method: str,
        request_url: str,
        request_headers: tuple[HeaderField, ...],
        request_body: bytes,
        response_status: int,
        response_headers: tuple[HeaderField, ...],
        response_body: bytes,
        request_mime: str | None = None,
        response_mime: str | None = None,
        request_original_bytes: int | None = None,
        response_original_bytes: int | None = None,
        request_was_truncated: bool = False,
        response_was_truncated: bool = False,
    ) -> EvidenceArtifactRef:
        method = request_method.upper()
        if not re.fullmatch(r"[A-Z]+", method):
            raise EvidenceStoreError("request method is invalid")
        if not 100 <= response_status <= 599:
            raise EvidenceStoreError("response status is invalid")

        artifact_relative = Path("evidence") / binding.evidence_id
        artifact_dir = self.root / artifact_relative
        try:
            artifact_dir.mkdir(parents=True, exist_ok=False)
        except FileExistsError as exc:
            raise EvidenceStoreError(f"evidence {binding.evidence_id!r} already exists") from exc

        try:
            request_original = (
                len(request_body) if request_original_bytes is None else request_original_bytes
            )
            response_original = (
                len(response_body) if response_original_bytes is None else response_original_bytes
            )
            if request_original < len(request_body) or response_original < len(response_body):
                raise EvidenceStoreError("original byte count cannot be smaller than supplied body")
            request_captured = request_body[: self.policy.capture_limit_bytes]
            response_captured = response_body[: self.policy.capture_limit_bytes]
            request_truncated = request_was_truncated or request_original > len(request_captured)
            response_truncated = response_was_truncated or response_original > len(
                response_captured
            )
            req_mime = _normalize_mime(
                request_mime
                or _header_value(request_headers, "content-type")
                or "application/octet-stream"
            )
            res_mime = _normalize_mime(
                response_mime
                or _header_value(response_headers, "content-type")
                or "application/octet-stream"
            )
            request_hash = _exchange_hash(
                {
                    "method": method,
                    "url": request_url,
                    "headers": [item.model_dump() for item in request_headers],
                    "body_sha256": _sha256(request_body),
                    "original_bytes": request_original,
                }
            )
            response_hash = _exchange_hash(
                {
                    "status": response_status,
                    "headers": [item.model_dump() for item in response_headers],
                    "body_sha256": _sha256(response_body),
                    "original_bytes": response_original,
                }
            )
            analysis_document, redacted, analysis_truncated = _analysis_document(
                method=method,
                url=request_url,
                request_headers=request_headers,
                request_body=request_captured,
                request_mime=req_mime,
                response_status=response_status,
                response_headers=response_headers,
                response_body=response_captured,
                response_mime=res_mime,
                limit=self.policy.analysis_limit_bytes,
                capture_truncated=request_truncated or response_truncated,
            )
            analysis_document, size_truncated = _fit_analysis_document(
                analysis_document, self.policy.analysis_limit_bytes
            )
            analysis_truncated = analysis_truncated or size_truncated
            analysis_bytes = canonical_json(analysis_document)
            analysis_relative = artifact_relative / "analysis.json"
            _atomic_write(artifact_dir / "analysis.json", analysis_bytes)
            analysis = AnalysisCopy(
                path=analysis_relative.as_posix(),
                sha256=_sha256(analysis_bytes),
                retained_bytes=len(analysis_bytes),
                limit_bytes=self.policy.analysis_limit_bytes,
                truncated=analysis_truncated,
                redacted_fields=tuple(sorted(redacted)),
            )

            raw: RawCopy | None = None
            if self.policy.raw_retention:
                assert self.key_provider is not None
                raw_plaintext = canonical_json(
                    {
                        "request": {
                            "method": method,
                            "url": request_url,
                            "headers": [item.model_dump() for item in request_headers],
                            "body_base64": base64.b64encode(request_captured).decode("ascii"),
                        },
                        "response": {
                            "status": response_status,
                            "headers": [item.model_dump() for item in response_headers],
                            "body_base64": base64.b64encode(response_captured).decode("ascii"),
                        },
                    }
                )
                aad = binding.canonical_bytes()
                nonce = os.urandom(12)
                ciphertext = AESGCM(self.key_provider.load_key(self.key_provider.key_id)).encrypt(
                    nonce, raw_plaintext, aad
                )
                raw_relative = artifact_relative / "raw.enc"
                _atomic_write(artifact_dir / "raw.enc", ciphertext)
                raw = RawCopy(
                    path=raw_relative.as_posix(),
                    key_id=self.key_provider.key_id,
                    nonce=base64.urlsafe_b64encode(nonce).decode("ascii").rstrip("="),
                    aad_sha256=_sha256(aad),
                    plaintext_sha256=_sha256(raw_plaintext),
                    ciphertext_sha256=_sha256(ciphertext),
                )

            manifest = EvidenceArtifactManifest(
                binding=binding,
                request_method=method,
                target=_redact_url(request_url)[0],
                response_status=response_status,
                request_mime=req_mime,
                response_mime=res_mime,
                request_hash=request_hash,
                response_hash=response_hash,
                request_body_sha256=_sha256(request_body),
                response_body_sha256=_sha256(response_body),
                request_original_bytes=request_original,
                response_original_bytes=response_original,
                request_captured_bytes=len(request_captured),
                response_captured_bytes=len(response_captured),
                request_truncated=request_truncated,
                response_truncated=response_truncated,
                analysis=analysis,
                raw=raw,
            )
            manifest_bytes = canonical_json(manifest.model_dump(mode="json"))
            manifest_path = artifact_dir / "manifest.json"
            with manifest_path.open("xb") as handle:
                handle.write(manifest_bytes)
                handle.flush()
                os.fsync(handle.fileno())
            return EvidenceArtifactRef(
                evidence_id=binding.evidence_id,
                manifest_path=(artifact_relative / "manifest.json").as_posix(),
                manifest_sha256=_sha256(manifest_bytes),
            )
        except Exception:
            if not (artifact_dir / "manifest.json").exists():
                for path in (artifact_dir / "analysis.json", artifact_dir / "raw.enc"):
                    path.unlink(missing_ok=True)
                try:
                    artifact_dir.rmdir()
                except OSError:
                    pass
            raise

    def load(self, ref: EvidenceArtifactRef) -> EvidenceArtifactManifest:
        expected = f"evidence/{ref.evidence_id}/manifest.json"
        if ref.manifest_path != expected:
            raise EvidenceStoreError("reference does not use the canonical evidence path")
        path = self._artifact_path(ref.manifest_path)
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise EvidenceStoreError("evidence manifest is missing") from exc
        if _sha256(raw) != ref.manifest_sha256:
            raise EvidenceStoreError("evidence manifest digest does not match its reference")
        try:
            manifest = EvidenceArtifactManifest.model_validate_json(raw)
        except ValueError as exc:
            raise EvidenceStoreError("evidence manifest is invalid") from exc
        if manifest.binding.evidence_id != ref.evidence_id:
            raise EvidenceStoreError("manifest evidence ID does not match its reference")
        return manifest

    def verify(self, ref: EvidenceArtifactRef) -> EvidenceArtifactManifest:
        manifest = self.load(ref)
        expected_analysis = f"evidence/{ref.evidence_id}/analysis.json"
        if manifest.analysis.path != expected_analysis:
            raise EvidenceStoreError("analysis copy does not use the canonical evidence path")
        analysis_path = self._artifact_path(manifest.analysis.path)
        try:
            analysis_bytes = analysis_path.read_bytes()
        except OSError as exc:
            raise EvidenceStoreError("analysis copy is missing") from exc
        if _sha256(analysis_bytes) != manifest.analysis.sha256:
            raise EvidenceStoreError("analysis digest does not match the manifest")
        if manifest.analysis.retained_bytes != len(analysis_bytes):
            raise EvidenceStoreError("analysis retained byte count does not match the artifact")
        if len(analysis_bytes) > manifest.analysis.limit_bytes:
            raise EvidenceStoreError("analysis copy exceeds its declared byte limit")
        try:
            EvidenceAnalysisDocument.model_validate_json(analysis_bytes)
        except ValueError as exc:
            raise EvidenceStoreError("analysis copy is not valid V2 analysis JSON") from exc

        if manifest.raw is not None:
            expected_raw = f"evidence/{ref.evidence_id}/raw.enc"
            if manifest.raw.path != expected_raw:
                raise EvidenceStoreError("raw copy does not use the canonical evidence path")
            raw_path = self._artifact_path(manifest.raw.path)
            try:
                ciphertext = raw_path.read_bytes()
            except OSError as exc:
                raise EvidenceStoreError("raw encrypted copy is missing") from exc
            if _sha256(ciphertext) != manifest.raw.ciphertext_sha256:
                raise EvidenceStoreError("raw ciphertext digest does not match the manifest")
            aad = manifest.binding.canonical_bytes()
            if _sha256(aad) != manifest.raw.aad_sha256:
                raise EvidenceStoreError("raw AAD digest does not match the binding")
            if self.key_provider is not None:
                try:
                    nonce = base64.urlsafe_b64decode(
                        manifest.raw.nonce + "=" * (-len(manifest.raw.nonce) % 4)
                    )
                    plaintext = AESGCM(self.key_provider.load_key(manifest.raw.key_id)).decrypt(
                        nonce, ciphertext, aad
                    )
                except Exception as exc:
                    raise EvidenceStoreError("raw encrypted copy cannot be authenticated") from exc
                if _sha256(plaintext) != manifest.raw.plaintext_sha256:
                    raise EvidenceStoreError("raw plaintext digest does not match the manifest")
        elif self.policy.raw_retention:
            raise EvidenceStoreError("raw retention policy requires an encrypted copy")
        return manifest

    def analysis(self, ref: EvidenceArtifactRef) -> EvidenceAnalysisDocument:
        """Load a typed analysis copy after verifying its complete artifact."""

        manifest = self.verify(ref)
        try:
            return EvidenceAnalysisDocument.model_validate_json(
                self._artifact_path(manifest.analysis.path).read_bytes()
            )
        except (OSError, ValueError) as exc:
            raise EvidenceStoreError("analysis copy cannot be loaded") from exc

    def _artifact_path(self, relative: str) -> Path:
        path = (self.root / relative).resolve(strict=False)
        if not path.is_relative_to(self.root):
            raise EvidenceStoreError("artifact path escapes the evidence root")
        return path


def _exchange_hash(value: dict[str, Any]) -> str:
    return _sha256(canonical_json(value))


def _header_value(headers: tuple[HeaderField, ...], name: str) -> str | None:
    return next((item.value for item in headers if item.name.lower() == name), None)


def _normalize_mime(value: str) -> str:
    return value.split(";", 1)[0].strip().lower() or "application/octet-stream"


def _redact_headers(
    headers: tuple[HeaderField, ...], prefix: str
) -> tuple[list[dict[str, str]], set[str]]:
    result: list[dict[str, str]] = []
    redacted: set[str] = set()
    for header in headers:
        if header.name.lower() in _SECRET_HEADERS:
            redacted.add(f"{prefix}.headers.{header.name}")
            continue
        result.append(header.model_dump())
    return result, redacted


def _redact_url(value: str) -> tuple[str, set[str]]:
    split = urlsplit(value)
    pairs: list[tuple[str, str]] = []
    redacted: set[str] = set()
    for key, item in parse_qsl(split.query, keep_blank_values=True):
        if _SECRET_KEY.fullmatch(key):
            pairs.append((key, _REDACTED))
            redacted.add(f"request.query.{key}")
        else:
            pairs.append((key, item))
    result = urlunsplit((split.scheme, split.netloc, split.path, urlencode(pairs), split.fragment))
    return result, redacted


def _redact_text(value: str, prefix: str) -> tuple[str, set[str]]:
    found: set[str] = set()

    def replace(match: re.Match[str]) -> str:
        found.add(f"{prefix}.{match.group(1)}")
        return f"{match.group(1)}{match.group(2)}{_REDACTED}"

    return _TEXT_SECRET.sub(replace, value), found


def _redact_json(value: Any, prefix: str) -> tuple[Any, set[str]]:
    fields = 0
    redacted: set[str] = set()

    def visit(item: Any, path: str, depth: int) -> Any:
        nonlocal fields
        if depth > 8:
            redacted.add(path)
            return _TRUNCATED
        if isinstance(item, dict):
            output: dict[str, Any] = {}
            for key, child in item.items():
                fields += 1
                child_path = f"{path}.{key}"
                if fields > 1000:
                    redacted.add(child_path)
                    output.setdefault("_truncated_fields", _TRUNCATED)
                elif _SECRET_KEY.fullmatch(str(key)):
                    redacted.add(child_path)
                    output[str(key)] = _REDACTED
                else:
                    output[str(key)] = visit(child, child_path, depth + 1)
            return output
        if isinstance(item, list):
            if len(item) > 100:
                redacted.add(path)
            return [
                visit(child, f"{path}[{index}]", depth + 1)
                for index, child in enumerate(item[:100])
            ]
        if isinstance(item, str):
            result, found = _redact_text(item, path)
            redacted.update(found)
            return result
        return item

    return visit(value, prefix, 0), redacted


def _decode_text(body: bytes, content_type: str) -> str:
    charset = "utf-8"
    match = re.search(r"(?i)charset\s*=\s*([^;\s]+)", content_type)
    if match:
        charset = match.group(1).strip("\"'")
    try:
        return body.decode(charset, errors="replace")
    except LookupError:
        return body.decode("utf-8", errors="replace")


def _bounded_text(value: str, limit: int) -> tuple[str, bool]:
    encoded = value.encode("utf-8")
    if len(encoded) <= limit:
        return value, False
    return encoded[:limit].decode("utf-8", errors="ignore"), True


def _analyze_body(
    body: bytes, mime: str, content_type: str, prefix: str, limit: int
) -> tuple[Any, set[str], bool]:
    redacted: set[str] = set()
    if mime == "application/json" or mime.endswith("+json"):
        try:
            result, redacted = _redact_json(json.loads(_decode_text(body, content_type)), prefix)
            encoded = canonical_json(result)
            if len(encoded) > limit:
                return _bounded_text(encoded.decode("utf-8"), limit)[0], redacted, True
            return result, redacted, False
        except json.JSONDecodeError:
            text, found = _redact_text(_decode_text(body, content_type), prefix)
            bounded, truncated = _bounded_text(text, limit)
            return bounded, found, truncated
    if mime == "application/x-www-form-urlencoded":
        output: dict[str, str] = {}
        for key, value in parse_qsl(_decode_text(body, content_type), keep_blank_values=True):
            if _SECRET_KEY.fullmatch(key):
                output[key] = _REDACTED
                redacted.add(f"{prefix}.{key}")
            else:
                output[key] = value
        encoded = canonical_json(output)
        if len(encoded) > limit:
            return _bounded_text(encoded.decode("utf-8"), limit)[0], redacted, True
        return output, redacted, False
    if mime.startswith("text/") or mime in {"application/xhtml+xml", "application/xml"}:
        text, redacted = _redact_text(_decode_text(body, content_type), prefix)
        bounded, truncated = _bounded_text(text, limit)
        return bounded, redacted, truncated
    return None, redacted, False


def _analysis_document(
    *,
    method: str,
    url: str,
    request_headers: tuple[HeaderField, ...],
    request_body: bytes,
    request_mime: str,
    response_status: int,
    response_headers: tuple[HeaderField, ...],
    response_body: bytes,
    response_mime: str,
    limit: int,
    capture_truncated: bool,
) -> tuple[dict[str, Any], set[str], bool]:
    request_safe_headers, request_redacted = _redact_headers(request_headers, "request")
    response_safe_headers, response_redacted = _redact_headers(response_headers, "response")
    safe_url, query_redacted = _redact_url(url)
    request_type = _header_value(request_headers, "content-type") or request_mime
    response_type = _header_value(response_headers, "content-type") or response_mime
    request_analysis, request_fields, request_truncated = _analyze_body(
        request_body, request_mime, request_type, "request.body", limit
    )
    response_analysis, response_fields, response_truncated = _analyze_body(
        response_body, response_mime, response_type, "response.body", limit
    )
    redacted = (
        request_redacted | response_redacted | query_redacted | request_fields | response_fields
    )
    return (
        {
            "version": "2",
            "request": {
                "method": method,
                "url": safe_url,
                "headers": request_safe_headers,
                "mime": request_mime,
                "body": request_analysis,
            },
            "response": {
                "status": response_status,
                "headers": response_safe_headers,
                "mime": response_mime,
                "body": response_analysis,
            },
        },
        redacted,
        capture_truncated or request_truncated or response_truncated,
    )


def _fit_analysis_document(document: dict[str, Any], limit: int) -> tuple[dict[str, Any], bool]:
    """Bound the complete JSON artifact, not only its two body projections."""

    if len(canonical_json(document)) <= limit:
        return document, False
    bounded = json.loads(json.dumps(document))
    bounded["request"]["body"] = None
    bounded["response"]["body"] = None
    bounded["request"]["url"] = _bounded_text(str(bounded["request"]["url"]), 512)[0]
    for side in ("request", "response"):
        for header in bounded[side]["headers"]:
            header["value"] = _bounded_text(str(header["value"]), 512)[0]
    protected_response_headers = {"content-type", "link", "x-content-type-options"}
    while len(canonical_json(bounded)) > limit:
        request_headers = bounded["request"]["headers"]
        response_headers = bounded["response"]["headers"]
        removable_response = next(
            (
                index
                for index in range(len(response_headers) - 1, -1, -1)
                if str(response_headers[index]["name"]).lower() not in protected_response_headers
            ),
            None,
        )
        if removable_response is not None:
            response_headers.pop(removable_response)
        elif request_headers:
            request_headers.pop()
        elif len(bounded["request"]["url"]) > 64:
            bounded["request"]["url"] = _bounded_text(bounded["request"]["url"], 64)[0]
        else:
            raise EvidenceStoreError("analysis limit is too small for mandatory metadata")
    return bounded, True


def trusted_response_header_projection(
    store: EvidenceStore, ref: EvidenceArtifactRef
) -> dict[str, str]:
    """Return the exact restricted header projection from verified analysis evidence."""

    document = store.analysis(ref)
    allowed = {"content-type", "link", "x-content-type-options"}
    projected: dict[str, str] = {}
    for header in document.response.headers:
        name = header.name.lower()
        if name not in allowed:
            continue
        if name in projected:
            raise EvidenceStoreError(f"analysis contains duplicate security header: {name}")
        projected[name] = header.value
    return projected


def require_negative_control_link(
    store: EvidenceStore,
    ref: EvidenceArtifactRef,
    *,
    target_url: str,
    control_url: str,
) -> dict[str, str]:
    """Verify that trusted Recon evidence links the exact negative-control endpoint."""

    manifest = store.verify(ref)
    document = store.analysis(ref)
    if (
        manifest.request_method != "GET"
        or manifest.target != target_url
        or manifest.response_status != 200
        or manifest.response_mime != "text/html"
        or manifest.response_truncated
        or manifest.analysis.truncated
        or document.request.method != "GET"
        or document.request.url != target_url
        or document.response.status != manifest.response_status
    ):
        raise EvidenceStoreError("Recon analysis does not match its HTTP manifest")
    projection = trusted_response_header_projection(store, ref)
    link = projection.get("link")
    if link is None:
        raise EvidenceStoreError("Recon evidence has no negative-control Link header")
    match = re.search(
        r"(?:^|,)\s*<([^>]+)>\s*;\s*rel\s*=\s*(?:\"negative-control\"|negative-control)(?:\s*;|\s*,|\s*$)",
        link,
        re.IGNORECASE,
    )
    if match is None or urljoin(target_url, match.group(1)) != control_url:
        raise EvidenceStoreError("Recon Link header does not bind the planned negative control")
    return projection


def verify_fixed_header_differential(
    store: EvidenceStore,
    *,
    recon_ref: EvidenceArtifactRef,
    candidate_ref: EvidenceArtifactRef,
    control_ref: EvidenceArtifactRef,
    target_url: str,
    control_url: str,
) -> None:
    """Recompute the fixed finding from trusted target/control HTTP evidence."""

    require_negative_control_link(store, recon_ref, target_url=target_url, control_url=control_url)
    candidate_manifest = store.verify(candidate_ref)
    control_manifest = store.verify(control_ref)
    candidate = store.analysis(candidate_ref)
    control = store.analysis(control_ref)
    if (
        candidate_manifest.request_method != "GET"
        or control_manifest.request_method != "GET"
        or candidate_manifest.target != target_url
        or control_manifest.target != control_url
        or candidate_manifest.response_mime != "text/html"
        or control_manifest.response_mime != "text/html"
        or candidate_manifest.response_truncated
        or control_manifest.response_truncated
        or candidate_manifest.analysis.truncated
        or control_manifest.analysis.truncated
        or candidate.request.method != "GET"
        or control.request.method != "GET"
        or candidate.request.url != target_url
        or control.request.url != control_url
        or candidate.response.status != candidate_manifest.response_status
        or control.response.status != control_manifest.response_status
    ):
        raise EvidenceStoreError("verification analysis does not match its HTTP manifests")
    candidate_headers = trusted_response_header_projection(store, candidate_ref)
    control_headers = trusted_response_header_projection(store, control_ref)
    if "x-content-type-options" in candidate_headers:
        raise EvidenceStoreError("candidate evidence does not omit X-Content-Type-Options")
    if control_headers.get("x-content-type-options", "").strip().lower() != "nosniff":
        raise EvidenceStoreError("control evidence does not contain nosniff")
    if (
        candidate_manifest.response_status != 200
        or control_manifest.response_status != 200
        or candidate_manifest.response_body_sha256 != control_manifest.response_body_sha256
    ):
        raise EvidenceStoreError("candidate and control are not a matched HTTP differential")


def _atomic_write(path: Path, value: bytes) -> None:
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        Path(temporary).unlink(missing_ok=True)
        raise

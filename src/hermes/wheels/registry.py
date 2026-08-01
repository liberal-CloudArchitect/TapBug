"""Append-only governance registry for reviewed capability artifacts.

The registry deliberately owns lifecycle authority.  Callers may advance the
non-security review stages, but validation, approval and activation each have a
dedicated method that checks its corresponding proof.  This prevents an
otherwise convenient state-transition helper from becoming an authorization
bypass.
"""

from __future__ import annotations

import base64
import json
import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .models import ValidationReport, WheelManifest, WheelStatus
from .validator import artifact_sha256_for_directory

if TYPE_CHECKING:
    from hermes.runtime.context import RunContext


class WheelRegistryError(RuntimeError):
    """Raised when a capability cannot satisfy its governance contract."""


@dataclass(frozen=True)
class RegistryEvent:
    at: datetime
    wheel_id: str
    version: str
    event: str
    actor: str | None = None


@dataclass(frozen=True)
class CapabilityUsage:
    """A privacy-preserving record of one isolated capability execution."""

    at: datetime
    wheel_id: str
    version: str
    outcome: str
    output_sha256: str | None = None
    human_reviewed: bool = False
    false_positive: bool = False
    detail_sha256: str | None = None


@dataclass(frozen=True)
class _StoredEvent:
    at: datetime
    wheel_id: str
    version: str
    event: str
    actor: str | None
    manifest: WheelManifest
    validation: ValidationReport | None = None


SignatureVerifier = Callable[[WheelManifest, str], bool]
JournalSigner = Callable[[bytes, str], str]
JournalVerifier = Callable[[bytes, str, str], bool]


def _signature_payload(manifest: WheelManifest) -> bytes:
    """Stable identity payload; mutable lifecycle metadata is unsigned."""
    value = manifest.model_dump(mode="json", exclude={"status", "approved_by", "signature"})
    return _canonical_json(value)


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def _sha256(value: bytes) -> str:
    return f"sha256:{sha256(value).hexdigest()}"


def ed25519_signature_verifier(public_key: bytes) -> SignatureVerifier:
    """Return a strict verifier for URL-safe base64 Ed25519 manifest signatures."""
    verifier = Ed25519PublicKey.from_public_bytes(public_key)

    def verify(manifest: WheelManifest, signature: str) -> bool:
        try:
            encoded = signature + "=" * (-len(signature) % 4)
            verifier.verify(base64.urlsafe_b64decode(encoded), _signature_payload(manifest))
        except (InvalidSignature, ValueError):
            return False
        return True

    return verify


_TRANSITIONS: dict[WheelStatus, frozenset[WheelStatus]] = {
    WheelStatus.DRAFT: frozenset({WheelStatus.RESEARCHED}),
    WheelStatus.RESEARCHED: frozenset({WheelStatus.SPECIFIED}),
    WheelStatus.SPECIFIED: frozenset({WheelStatus.GENERATED}),
    WheelStatus.GENERATED: frozenset({WheelStatus.VALIDATED}),
    WheelStatus.VALIDATED: frozenset({WheelStatus.CANDIDATE}),
    WheelStatus.CANDIDATE: frozenset({WheelStatus.APPROVED, WheelStatus.QUARANTINED}),
    WheelStatus.APPROVED: frozenset({WheelStatus.ACTIVE, WheelStatus.QUARANTINED}),
    WheelStatus.ACTIVE: frozenset({WheelStatus.QUARANTINED, WheelStatus.REVOKED}),
    WheelStatus.QUARANTINED: frozenset({WheelStatus.REVOKED}),
    WheelStatus.REVOKED: frozenset(),
}

_SECURITY_TRANSITIONS = frozenset({WheelStatus.VALIDATED, WheelStatus.APPROVED, WheelStatus.ACTIVE})
_IMMEDIATE_QUARANTINE = frozenset(
    {"integrity_failure", "sandbox_violation", "resource_limit", "invalid_output"}
)


class WheelRegistry:
    """Tracks immutable artifacts and a verifiable lifecycle journal.

    ``journal_signer`` and ``journal_verifier`` make the on-disk journal a
    signed, hash-chained authority.  The legacy unsigned mode is retained only
    for in-memory/local migration compatibility; deployments must set
    ``require_signed_journal=True`` whenever a journal is persisted.
    """

    def __init__(
        self,
        signature_verifier: SignatureVerifier | None = None,
        *,
        context: RunContext | None = None,
        journal_path: Path | None = None,
        journal_signer: JournalSigner | None = None,
        journal_verifier: JournalVerifier | None = None,
        actor_roles: Mapping[str, str] | None = None,
        require_signed_journal: bool = False,
    ) -> None:
        if context is not None and journal_path is not None:
            raise ValueError("provide either context or journal_path, not both")
        if (journal_signer is None) != (journal_verifier is None):
            raise ValueError("journal signing requires both signer and verifier")
        if require_signed_journal and (journal_signer is None or journal_verifier is None):
            raise ValueError("a signed journal requires signer and verifier")
        self._records: dict[tuple[str, str], WheelManifest] = {}
        self._validations: dict[tuple[str, str], ValidationReport] = {}
        self._events: list[RegistryEvent] = []
        self._usage: dict[tuple[str, str], list[CapabilityUsage]] = {}
        self._signature_verifier = signature_verifier or (lambda _manifest, _signature: False)
        self._context = context
        self._journal_path = (
            context.artifact_path("wheels/registry.jsonl")
            if context is not None
            else (journal_path.resolve() if journal_path is not None else None)
        )
        self._usage_path = (
            context.artifact_path("wheels/usage.jsonl")
            if context is not None
            else (
                self._journal_path.with_name("usage.jsonl")
                if self._journal_path is not None
                else None
            )
        )
        self._journal_signer = journal_signer
        self._journal_verifier = journal_verifier
        self._actor_roles = dict(actor_roles or {})
        self._require_signed_journal = require_signed_journal
        self._last_event_hash: str | None = None
        self._last_usage_hash: str | None = None
        if self._journal_path is not None:
            self._journal_path.parent.mkdir(parents=True, exist_ok=True)
            self._replay()
        if self._usage_path is not None:
            self._usage_path.parent.mkdir(parents=True, exist_ok=True)
            self._replay_usage()

    @property
    def events(self) -> tuple[RegistryEvent, ...]:
        return tuple(self._events)

    @property
    def usage(self) -> tuple[CapabilityUsage, ...]:
        return tuple(item for entries in self._usage.values() for item in entries)

    def add(self, manifest: WheelManifest, *, actor: str | None = None) -> None:
        key = (manifest.id, manifest.version)
        if key in self._records:
            raise WheelRegistryError("wheel versions are immutable; choose a new version")
        if manifest.status is not WheelStatus.DRAFT:
            raise WheelRegistryError("new wheels must be registered in draft status")
        if manifest.signature is not None or manifest.approved_by is not None:
            raise WheelRegistryError("draft wheels must not carry approval metadata")
        self._require_actor_role(actor, {"publisher"})
        self._commit(manifest, "registered", actor)

    def get(self, wheel_id: str, version: str) -> WheelManifest:
        try:
            return self._records[(wheel_id, version)]
        except KeyError as exc:
            raise WheelRegistryError("unknown wheel version") from exc

    def get_validation(self, wheel_id: str, version: str) -> ValidationReport:
        try:
            return self._validations[(wheel_id, version)]
        except KeyError as exc:
            raise WheelRegistryError("wheel has no successful validation report") from exc

    def transition(
        self, wheel_id: str, version: str, target: WheelStatus, *, actor: str | None = None
    ) -> WheelManifest:
        """Compatibility helper for non-security stages only.

        Activation delegates to :meth:`activate` so old clients cannot skip
        its checks. Validation and approval deliberately have no generic path.
        """
        if target is WheelStatus.ACTIVE:
            return self.activate(wheel_id, version, actor=actor)
        if target in {WheelStatus.VALIDATED, WheelStatus.APPROVED}:
            raise WheelRegistryError(f"{target} requires its dedicated governance method")
        return self._advance(wheel_id, version, target, actor=actor)

    def research(self, wheel_id: str, version: str, *, actor: str | None = None) -> WheelManifest:
        return self._advance(wheel_id, version, WheelStatus.RESEARCHED, actor=actor)

    def specify(self, wheel_id: str, version: str, *, actor: str | None = None) -> WheelManifest:
        return self._advance(wheel_id, version, WheelStatus.SPECIFIED, actor=actor)

    def record_generation(
        self, wheel_id: str, version: str, *, actor: str | None = None
    ) -> WheelManifest:
        return self._advance(wheel_id, version, WheelStatus.GENERATED, actor=actor)

    def nominate(self, wheel_id: str, version: str, *, actor: str | None = None) -> WheelManifest:
        manifest = self.get(wheel_id, version)
        self._require_validated(manifest)
        return self._advance(wheel_id, version, WheelStatus.CANDIDATE, actor=actor)

    def record_validation(
        self, wheel_id: str, version: str, report: ValidationReport, *, actor: str | None = None
    ) -> WheelManifest:
        manifest = self.get(wheel_id, version)
        if manifest.status is not WheelStatus.GENERATED:
            raise WheelRegistryError("only generated wheels can be validated")
        if not report.passed or report.wheel_id != wheel_id or report.wheel_version != version:
            raise WheelRegistryError("failed or mismatched validation report")
        if manifest.artifact_sha256 is None or report.artifact_sha256 != manifest.artifact_sha256:
            raise WheelRegistryError("validation report hash must match manifest")
        self._require_actor_role(actor, {"validator"})
        self._commit(manifest, "validation", actor, validation=report, update_record=False)
        self._validations[(wheel_id, version)] = report
        return self._advance(
            wheel_id, version, WheelStatus.VALIDATED, actor=actor, governance_authorized=True
        )

    def approve(
        self,
        wheel_id: str,
        version: str,
        *,
        approved_by: str,
        signature: str,
        actor: str | None = None,
    ) -> WheelManifest:
        manifest = self.get(wheel_id, version)
        if manifest.status is not WheelStatus.CANDIDATE:
            raise WheelRegistryError("only candidate wheels can be approved")
        self._require_validated(manifest)
        if not approved_by.strip() or not self._signature_verifier(manifest, signature):
            raise WheelRegistryError("approval signature was rejected")
        self._require_actor_role(actor or approved_by, {"approver"})
        updated = manifest.model_copy(
            update={
                "approved_by": approved_by,
                "signature": signature,
                "status": WheelStatus.APPROVED,
            }
        )
        self._commit(updated, f"transition:{WheelStatus.APPROVED}", actor or approved_by)
        return updated

    def activate(self, wheel_id: str, version: str, *, actor: str | None = None) -> WheelManifest:
        manifest = self.get(wheel_id, version)
        if manifest.status is not WheelStatus.APPROVED:
            raise WheelRegistryError("only approved wheels can be activated")
        self._require_validated(manifest)
        self._require_manifest_signature(manifest)
        self._require_actor_role(actor, {"operator"})
        return self._advance(
            wheel_id, version, WheelStatus.ACTIVE, actor=actor, governance_authorized=True
        )

    def quarantine(
        self, wheel_id: str, version: str, *, actor: str | None = None, reason: str = "review"
    ) -> WheelManifest:
        manifest = self.get(wheel_id, version)
        if WheelStatus.QUARANTINED not in _TRANSITIONS[manifest.status]:
            raise WheelRegistryError("wheel cannot be quarantined from its current state")
        self._require_actor_role(actor, {"revoker", "capability-host"})
        return self._advance(wheel_id, version, WheelStatus.QUARANTINED, actor=actor, reason=reason)

    def revoke(
        self, wheel_id: str, version: str, *, actor: str | None = None, reason: str = "review"
    ) -> WheelManifest:
        manifest = self.get(wheel_id, version)
        if WheelStatus.REVOKED not in _TRANSITIONS[manifest.status]:
            raise WheelRegistryError("wheel cannot be revoked from its current state")
        self._require_actor_role(actor, {"revoker"})
        return self._advance(wheel_id, version, WheelStatus.REVOKED, actor=actor, reason=reason)

    def quarantine_by_source(
        self, content_sha256: str, *, actor: str | None = None, reason: str = "source_retracted"
    ) -> tuple[WheelManifest, ...]:
        affected: list[WheelManifest] = []
        for manifest in tuple(self._records.values()):
            if any(source.content_sha256 == content_sha256 for source in manifest.sources) and (
                WheelStatus.QUARANTINED in _TRANSITIONS[manifest.status]
            ):
                affected.append(
                    self.quarantine(manifest.id, manifest.version, actor=actor, reason=reason)
                )
        return tuple(affected)

    def select(
        self,
        wheel_id: str,
        version: str,
        *,
        profile: str,
        artifact_root: Path,
        now: datetime | None = None,
    ) -> WheelManifest:
        manifest = self.get(wheel_id, version)
        current_time = now or datetime.now(UTC)
        if manifest.status is not WheelStatus.ACTIVE:
            raise WheelRegistryError("wheel is not active")
        if profile not in manifest.profiles:
            raise WheelRegistryError("wheel is not approved for this profile")
        if manifest.expires_at is not None and manifest.expires_at <= current_time:
            raise WheelRegistryError("wheel approval has expired")
        self._require_manifest_signature(manifest)
        self._require_validated(manifest)
        if (
            manifest.artifact_sha256 is None
            or artifact_sha256_for_directory(artifact_root) != manifest.artifact_sha256
        ):
            raise WheelRegistryError("wheel artifact hash mismatch")
        return manifest

    def record_usage(
        self,
        wheel_id: str,
        version: str,
        *,
        outcome: str,
        output_sha256: str | None = None,
        detail_sha256: str | None = None,
        human_reviewed: bool = False,
        false_positive: bool = False,
        actor: str | None = "capability-host",
    ) -> CapabilityUsage:
        """Record an outcome and immediately quarantine unsafe/ineffective wheels."""
        manifest = self.get(wheel_id, version)
        if manifest.status is not WheelStatus.ACTIVE:
            raise WheelRegistryError("only active wheels may record runtime usage")
        if false_positive and not human_reviewed:
            raise WheelRegistryError("false-positive outcomes require human review")
        self._require_actor_role(actor, {"capability-host"})
        usage = CapabilityUsage(
            at=datetime.now(UTC),
            wheel_id=wheel_id,
            version=version,
            outcome=outcome,
            output_sha256=output_sha256,
            detail_sha256=detail_sha256,
            human_reviewed=human_reviewed,
            false_positive=false_positive,
        )
        self._append_usage(usage, actor)
        entries = self._usage.setdefault((wheel_id, version), [])
        entries.append(usage)
        if outcome in _IMMEDIATE_QUARANTINE or self._needs_quality_quarantine(entries):
            self.quarantine(wheel_id, version, actor=actor, reason=f"outcome:{outcome}")
        return usage

    @staticmethod
    def _needs_quality_quarantine(entries: list[CapabilityUsage]) -> bool:
        reviewed_false_positives = sum(
            item.false_positive and item.human_reviewed for item in entries
        )
        if reviewed_false_positives >= 2:
            return True
        window = entries[-20:]
        reviewed = [item for item in window if item.human_reviewed]
        return (
            len(reviewed) >= 10
            and sum(item.false_positive for item in reviewed) / len(reviewed) > 0.2
        )

    def _advance(
        self,
        wheel_id: str,
        version: str,
        target: WheelStatus,
        *,
        actor: str | None,
        reason: str | None = None,
        governance_authorized: bool = False,
    ) -> WheelManifest:
        current = self.get(wheel_id, version)
        if target not in _TRANSITIONS[current.status]:
            raise WheelRegistryError(f"invalid wheel transition {current.status} -> {target}")
        if target in _SECURITY_TRANSITIONS and not governance_authorized:
            raise WheelRegistryError(f"{target} requires its dedicated governance method")
        updated = current.model_copy(update={"status": target})
        event = f"transition:{target}" if reason is None else f"transition:{target}:{reason}"
        self._commit(updated, event, actor)
        return updated

    def _require_validated(self, manifest: WheelManifest) -> None:
        report = self._validations.get((manifest.id, manifest.version))
        if report is None or not report.passed:
            raise WheelRegistryError("wheel has no successful validation report")
        if (
            manifest.artifact_sha256 is None
            or report.wheel_id != manifest.id
            or report.wheel_version != manifest.version
            or report.artifact_sha256 != manifest.artifact_sha256
        ):
            raise WheelRegistryError("wheel validation proof no longer matches manifest")

    def _require_manifest_signature(self, manifest: WheelManifest) -> None:
        if not manifest.signature or not manifest.approved_by:
            raise WheelRegistryError("wheel lacks a signed approval")
        if not self._signature_verifier(manifest, manifest.signature):
            raise WheelRegistryError("wheel approval signature was rejected")

    def _require_actor_role(self, actor: str | None, allowed: set[str]) -> None:
        """Enforce separated signing authorities in signed-journal deployments."""
        if self._journal_signer is None:
            return
        if actor is None or self._actor_roles.get(actor) not in allowed:
            allowed_names = ", ".join(sorted(allowed))
            raise WheelRegistryError(f"actor lacks required registry role: {allowed_names}")

    def _commit(
        self,
        manifest: WheelManifest,
        event: str,
        actor: str | None = None,
        *,
        validation: ValidationReport | None = None,
        update_record: bool = True,
    ) -> None:
        at = datetime.now(UTC)
        payload: dict[str, Any] = {
            "at": at.isoformat().replace("+00:00", "Z"),
            "wheel_id": manifest.id,
            "version": manifest.version,
            "event": event,
            "actor": actor,
            "manifest": manifest.model_dump(mode="json"),
        }
        if validation is not None:
            payload["validation"] = validation.model_dump(mode="json")
        self._append_payload(payload, usage=False, actor=actor)
        if update_record:
            self._records[(manifest.id, manifest.version)] = manifest
        self._events.append(RegistryEvent(at, manifest.id, manifest.version, event, actor))

    def _append_usage(self, usage: CapabilityUsage, actor: str | None) -> None:
        payload: dict[str, Any] = {
            "usage": {
                "at": usage.at.isoformat().replace("+00:00", "Z"),
                "wheel_id": usage.wheel_id,
                "version": usage.version,
                "outcome": usage.outcome,
                "output_sha256": usage.output_sha256,
                "detail_sha256": usage.detail_sha256,
                "human_reviewed": usage.human_reviewed,
                "false_positive": usage.false_positive,
            }
        }
        self._append_payload(payload, usage=True, actor=actor)

    def _append_payload(self, payload: dict[str, Any], *, usage: bool, actor: str | None) -> None:
        path = self._usage_path if usage else self._journal_path
        if path is None:
            return
        event_hash: str | None = None

        def append() -> None:
            nonlocal event_hash
            previous = self._last_usage_hash if usage else self._last_event_hash
            chained = dict(payload)
            chained.update(
                {
                    "sequence": self._next_sequence(path),
                    "previous_hash": previous,
                    "actor_key_id": actor,
                    "actor_role": self._actor_roles.get(actor or "", "unspecified"),
                }
            )
            event_hash = _sha256(_canonical_json(chained))
            chained["event_hash"] = event_hash
            if self._journal_signer is not None:
                if actor is None:
                    raise WheelRegistryError("signed journal events require an actor key id")
                chained["signature"] = self._journal_signer(event_hash.encode(), actor)
            elif self._require_signed_journal:
                raise WheelRegistryError("signed journal is required")
            encoded = _canonical_json(chained) + b"\n"
            with path.open("ab") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())

        if self._context is not None:
            with self._context.lock():
                append()
        else:
            append()
        assert event_hash is not None
        if usage:
            self._last_usage_hash = event_hash
        else:
            self._last_event_hash = event_hash

    @staticmethod
    def _next_sequence(path: Path) -> int:
        if not path.exists():
            return 1
        try:
            return (
                sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip()) + 1
            )
        except OSError as exc:
            raise WheelRegistryError("cannot read registry journal sequence") from exc

    def _replay(self) -> None:
        assert self._journal_path is not None
        for line_number, line in self._read_lines(self._journal_path):
            value = self._validate_chain_line(line, line_number, usage=False)
            event = self._parse_stored_event(value, line_number)
            self._apply_replayed_event(event, line_number)

    def _replay_usage(self) -> None:
        assert self._usage_path is not None
        for line_number, line in self._read_lines(self._usage_path):
            value = self._validate_chain_line(line, line_number, usage=True)
            try:
                raw = value["usage"]
                if not isinstance(raw, dict):
                    raise ValueError("usage must be an object")
                usage = CapabilityUsage(
                    at=datetime.fromisoformat(str(raw["at"]).replace("Z", "+00:00")),
                    wheel_id=str(raw["wheel_id"]),
                    version=str(raw["version"]),
                    outcome=str(raw["outcome"]),
                    output_sha256=str(raw["output_sha256"]) if raw.get("output_sha256") else None,
                    detail_sha256=str(raw["detail_sha256"]) if raw.get("detail_sha256") else None,
                    human_reviewed=bool(raw.get("human_reviewed", False)),
                    false_positive=bool(raw.get("false_positive", False)),
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise WheelRegistryError(
                    f"invalid usage journal event at line {line_number}"
                ) from exc
            if (usage.wheel_id, usage.version) not in self._records:
                raise WheelRegistryError(f"usage for unknown wheel at line {line_number}")
            self._usage.setdefault((usage.wheel_id, usage.version), []).append(usage)

    @staticmethod
    def _read_lines(path: Path) -> tuple[tuple[int, str], ...]:
        if not path.exists():
            return ()
        try:
            return tuple(
                (number, line)
                for number, line in enumerate(
                    path.read_text(encoding="utf-8").splitlines(), start=1
                )
                if line.strip()
            )
        except OSError as exc:
            raise WheelRegistryError("cannot read wheel registry journal") from exc

    def _validate_chain_line(self, line: str, line_number: int, *, usage: bool) -> dict[str, Any]:
        try:
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError("event must be an object")
        except (ValueError, json.JSONDecodeError) as exc:
            raise WheelRegistryError(
                f"invalid registry journal event at line {line_number}"
            ) from exc
        chained = {"sequence", "previous_hash", "event_hash"}.issubset(value)
        if not chained:
            if self._require_signed_journal:
                raise WheelRegistryError(f"unsigned legacy journal event at line {line_number}")
            return value
        expected_sequence = line_number
        previous = self._last_usage_hash if usage else self._last_event_hash
        event_hash = value.get("event_hash")
        unsigned = dict(value)
        signature = unsigned.pop("signature", None)
        unsigned.pop("event_hash", None)
        if (
            value["sequence"] != expected_sequence
            or value["previous_hash"] != previous
            or not isinstance(event_hash, str)
            or _sha256(_canonical_json(unsigned)) != event_hash
        ):
            raise WheelRegistryError(f"registry journal hash chain mismatch at line {line_number}")
        actor = value.get("actor_key_id")
        if self._journal_verifier is not None:
            if not isinstance(actor, str) or not isinstance(signature, str):
                raise WheelRegistryError(f"unsigned registry journal event at line {line_number}")
            if not self._journal_verifier(event_hash.encode(), signature, actor):
                raise WheelRegistryError(
                    f"registry journal signature rejected at line {line_number}"
                )
        elif self._require_signed_journal:
            raise WheelRegistryError(f"registry journal signer unavailable at line {line_number}")
        if usage:
            self._last_usage_hash = event_hash
        else:
            self._last_event_hash = event_hash
        return value

    @staticmethod
    def _parse_stored_event(value: dict[str, Any], line_number: int) -> _StoredEvent:
        try:
            at = datetime.fromisoformat(str(value["at"]).replace("Z", "+00:00"))
            manifest = WheelManifest.model_validate(value["manifest"])
            validation = (
                ValidationReport.model_validate(value["validation"])
                if "validation" in value
                else None
            )
            event = _StoredEvent(
                at=at,
                wheel_id=str(value["wheel_id"]),
                version=str(value["version"]),
                event=str(value["event"]),
                actor=str(value["actor"]) if value.get("actor") is not None else None,
                manifest=manifest,
                validation=validation,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise WheelRegistryError(
                f"invalid registry journal event at line {line_number}"
            ) from exc
        if (event.wheel_id, event.version) != (event.manifest.id, event.manifest.version):
            raise WheelRegistryError(f"registry journal identity mismatch at line {line_number}")
        return event

    def _apply_replayed_event(self, event: _StoredEvent, line_number: int) -> None:
        key = (event.wheel_id, event.version)
        current = self._records.get(key)
        event_name = event.event.split(":", 2)
        if event.event == "registered":
            if (
                current is not None
                or event.manifest.status is not WheelStatus.DRAFT
                or event.manifest.signature is not None
                or event.manifest.approved_by is not None
            ):
                raise WheelRegistryError(f"invalid registration event at line {line_number}")
            self._records[key] = event.manifest
        elif event.event == "validation":
            if (
                current is None
                or current != event.manifest
                or current.status is not WheelStatus.GENERATED
                or event.validation is None
                or not event.validation.passed
                or event.validation.wheel_id != event.wheel_id
                or event.validation.wheel_version != event.version
                or event.validation.artifact_sha256 != current.artifact_sha256
            ):
                raise WheelRegistryError(f"invalid validation event at line {line_number}")
            self._validations[key] = event.validation
        elif len(event_name) >= 2 and event_name[0] == "transition":
            if current is None:
                raise WheelRegistryError(f"transition for unknown wheel at line {line_number}")
            try:
                target = WheelStatus(event_name[1])
            except ValueError as exc:
                raise WheelRegistryError(f"unknown transition at line {line_number}") from exc
            if (
                target not in _TRANSITIONS[current.status]
                or event.manifest.status is not target
                or event.manifest.id != current.id
                or event.manifest.version != current.version
            ):
                raise WheelRegistryError(f"invalid lifecycle transition at line {line_number}")
            if target in {
                WheelStatus.VALIDATED,
                WheelStatus.CANDIDATE,
                WheelStatus.APPROVED,
                WheelStatus.ACTIVE,
            }:
                try:
                    self._require_validated(current)
                except WheelRegistryError as exc:
                    raise WheelRegistryError(
                        f"missing validation proof at line {line_number}"
                    ) from exc
            if target in {WheelStatus.APPROVED, WheelStatus.ACTIVE}:
                try:
                    self._require_manifest_signature(event.manifest)
                except WheelRegistryError as exc:
                    raise WheelRegistryError(
                        f"invalid approval proof at line {line_number}"
                    ) from exc
            self._records[key] = event.manifest
        else:
            raise WheelRegistryError(f"unknown registry event at line {line_number}")
        self._events.append(
            RegistryEvent(event.at, event.wheel_id, event.version, event.event, event.actor)
        )

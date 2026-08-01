"""Provenance-preserving, non-executing knowledge intake for capability work."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol
from urllib.parse import urlsplit

from pydantic import BaseModel, Field

from .wheels import (
    CapabilitySpec,
    ProblemCardStatus,
    WheelKind,
    WheelManifest,
    WheelStatus,
    artifact_sha256_for_directory,
)
from .wheels import SourceRecord as WheelSourceRecord


class GatewayReader(Protocol):
    def request(self, method: str, url: str) -> tuple[object, object]: ...


_INSTRUCTION_MARKERS = re.compile(
    r"(?:ignore (?:all |previous |prior )?instructions|system prompt|run (?:this )?command|"
    r"execute(?: this)?|curl\s|wget\s)",
    re.IGNORECASE,
)


class SourceRecord(BaseModel):
    url: str
    retrieved_at: datetime
    content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    version: str | None = None
    license: str | None = None
    applicable_when: str = ""
    risk_markers: list[str] = Field(default_factory=list)


class ResearchFact(BaseModel):
    claim: str = Field(min_length=1, max_length=2_000)
    source: SourceRecord
    confidence: str = Field(pattern=r"^(low|medium|high)$")


class ResearchPolicy(BaseModel):
    """Allowlist for sources fetched by a Gateway-owned researcher adapter."""

    allowed_hosts: frozenset[str] = Field(min_length=1)
    allowed_schemes: frozenset[str] = frozenset({"https"})
    allowed_ports: frozenset[int] = frozenset({443})
    allowed_path_prefixes: dict[str, tuple[str, ...]] = Field(default_factory=dict)
    trusted_hosts: frozenset[str] | None = None

    def preflight(self, url: str) -> None:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").lower().rstrip(".")
        if not host or parsed.username or parsed.password:
            raise ValueError("research source URL is malformed")
        if parsed.scheme.lower() not in self.allowed_schemes:
            raise ValueError("research source scheme is not in the allowlist")
        if host not in self.allowed_hosts:
            raise ValueError("research source host is not in the allowlist")
        if self.trusted_hosts is not None and host not in self.trusted_hosts:
            raise ValueError("research source host is not trusted")
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError("research source port is malformed") from exc
        effective_port = port or (443 if parsed.scheme.lower() == "https" else 80)
        if effective_port not in self.allowed_ports:
            raise ValueError("research source port is not in the allowlist")
        prefixes = self.allowed_path_prefixes.get(host, ())
        if prefixes and not any(parsed.path.startswith(prefix) for prefix in prefixes):
            raise ValueError("research source path is not in the allowlist")


class ProblemCard(BaseModel):
    """Stable, de-duplicated record of an unknown low-risk capability request."""

    id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    observation: str = Field(min_length=1, max_length=4_000)
    scope_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    profile: str = Field(min_length=1, max_length=200)
    evidence_refs: tuple[str, ...] = Field(min_length=1)
    risk_level: str = Field(pattern=r"^(low|medium|high)$")
    status: ProblemCardStatus = ProblemCardStatus.DRAFT
    human_decision: str | None = Field(default=None, max_length=2_000)
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True)
class GeneratedWheel:
    root: Path
    manifest: WheelManifest


class KnowledgeBroker:
    """Stores factual research records; it never executes or obeys source text."""

    def __init__(self, cache_dir: Path) -> None:
        self.cache_dir = cache_dir
        self._facts_dir = cache_dir / "facts"
        self._blobs_dir = cache_dir / "blobs"
        self._cards_dir = cache_dir / "problem-cards"
        for directory in (self._facts_dir, self._blobs_dir, self._cards_dir):
            directory.mkdir(parents=True, exist_ok=True)

    def record_source(
        self,
        url: str,
        content: str,
        *,
        version: str | None = None,
        license: str | None = None,
        applicable_when: str = "",
        retrieved_at: datetime | None = None,
    ) -> SourceRecord:
        payload = content.encode("utf-8")
        return self._record_source_payload(
            url,
            payload,
            content,
            version=version,
            license=license,
            applicable_when=applicable_when,
            retrieved_at=retrieved_at,
        )

    def _record_source_payload(
        self,
        url: str,
        payload: bytes,
        decoded_content: str,
        *,
        version: str | None,
        license: str | None,
        applicable_when: str,
        retrieved_at: datetime | None = None,
    ) -> SourceRecord:
        markers = [match.group(0) for match in _INSTRUCTION_MARKERS.finditer(decoded_content)]
        record = SourceRecord(
            url=url,
            retrieved_at=retrieved_at or datetime.now(UTC),
            content_sha256=hashlib.sha256(payload).hexdigest(),
            version=version,
            license=license,
            applicable_when=applicable_when,
            risk_markers=markers[:20],
        )
        stored = self._store_blob(payload)
        if stored != record.content_sha256:
            raise ValueError("research source hash changed during storage")
        return record

    def store_fact(self, fact: ResearchFact) -> Path:
        """Persist a structured, reviewable fact rather than raw untrusted HTML."""
        digest = hashlib.sha256(fact.model_dump_json().encode()).hexdigest()
        path = self._facts_dir / f"{digest}.json"
        path.write_text(fact.model_dump_json(indent=2), encoding="utf-8")
        return path

    def _store_blob(self, content: bytes) -> str:
        digest = hashlib.sha256(content).hexdigest()
        path = self._blobs_dir / f"{digest}.blob"
        if path.exists() and path.read_bytes() != content:
            raise ValueError("content-addressed source blob hash collision")
        if not path.exists():
            path.write_bytes(content)
        return digest

    def record_gateway_source(
        self,
        url: str,
        content: str | bytes,
        *,
        policy: ResearchPolicy,
        license: str,
        version: str | None = None,
        applicable_when: str = "",
    ) -> SourceRecord:
        """Accept already-fetched data only after its host passes the research allowlist.

        Network retrieval intentionally lives behind ToolGateway. This method never
        issues a request and treats its content as untrusted data.
        """
        policy.preflight(url)
        payload = content if isinstance(content, bytes) else content.encode("utf-8")
        decoded_content = payload.decode("utf-8", errors="replace")
        return self._record_source_payload(
            url,
            payload,
            decoded_content,
            license=license,
            version=version,
            applicable_when=applicable_when,
        )

    def list_facts(self) -> list[ResearchFact]:
        facts: list[ResearchFact] = []
        for path in sorted(self._facts_dir.glob("*.json")):
            try:
                fact = ResearchFact.model_validate_json(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                raise ValueError(f"corrupt research fact cache entry: {path.name}") from None
            blob = self._blobs_dir / f"{fact.source.content_sha256}.blob"
            blob_digest = hashlib.sha256(blob.read_bytes()).hexdigest() if blob.is_file() else ""
            if blob_digest != fact.source.content_sha256:
                raise ValueError(f"corrupt or missing source blob for fact: {path.name}")
            facts.append(fact)
        return facts

    def create_problem_card(
        self,
        *,
        observation: str,
        scope_digest: str,
        profile: str,
        evidence_refs: tuple[str, ...],
        risk_level: str,
        status: ProblemCardStatus = ProblemCardStatus.DRAFT,
        human_decision: str | None = None,
    ) -> ProblemCard:
        normalized = " ".join(observation.split()).lower()
        identity = json.dumps(
            {
                "observation": normalized,
                "scope_digest": scope_digest,
                "profile": profile,
                "evidence_refs": sorted(evidence_refs),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        card_id = f"sha256:{hashlib.sha256(identity).hexdigest()}"
        path = self._cards_dir / f"{card_id.removeprefix('sha256:')}.json"
        if path.exists():
            try:
                return ProblemCard.model_validate_json(path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                raise ValueError(f"corrupt problem card cache entry: {path.name}") from exc
        now = datetime.now(UTC)
        card = ProblemCard(
            id=card_id,
            observation=normalized,
            scope_digest=scope_digest,
            profile=profile,
            evidence_refs=tuple(sorted(evidence_refs)),
            risk_level=risk_level,
            status=status,
            human_decision=human_decision,
            created_at=now,
            updated_at=now,
        )
        path.write_text(card.model_dump_json(indent=2), encoding="utf-8")
        return card

    def get_problem_card(self, card_id: str) -> ProblemCard:
        if not card_id.startswith("sha256:"):
            raise ValueError("problem card id must be a sha256 digest")
        path = self._cards_dir / f"{card_id.removeprefix('sha256:')}.json"
        try:
            return ProblemCard.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ValueError("problem card is absent or corrupt") from exc


class GatewayResearcher:
    """Retrieves allowlisted research only through a caller-supplied ToolGateway."""

    def __init__(
        self,
        gateway: GatewayReader,
        broker: KnowledgeBroker,
        policy: ResearchPolicy,
    ) -> None:
        self._gateway = gateway
        self._broker = broker
        self._policy = policy

    def fetch(
        self,
        url: str,
        *,
        license: str,
        version: str | None = None,
        applicable_when: str = "",
    ) -> SourceRecord:
        # The allowlist decision must occur before a Gateway action can create a connection.
        self._policy.preflight(url)
        response, _evidence = self._gateway.request("GET", url)
        status_code = getattr(response, "status_code", None)
        body = getattr(response, "body", None)
        if status_code != 200 or not isinstance(body, bytes):
            raise ValueError("research gateway did not return a successful byte response")
        return self._broker.record_gateway_source(
            url,
            body,
            policy=self._policy,
            license=license,
            version=version,
            applicable_when=applicable_when,
        )


class CapabilityPlanner:
    """Turns reviewed facts into a passive, testable capability specification."""

    _CAPABILITIES = {
        WheelKind.PASSIVE_PARSER: ("parse_response",),
        WheelKind.NORMALIZER: ("normalize",),
        WheelKind.ENDPOINT_EXTRACTOR: ("extract_endpoint",),
        WheelKind.EVIDENCE_REDACTOR: ("redact_evidence",),
        WheelKind.REPORT_CLASSIFIER: ("classify_report",),
        WheelKind.PASSIVE_DETECTOR: ("inspect_fixture",),
        WheelKind.LOCAL_FIXTURE_VALIDATOR: ("validate_fixture",),
    }

    def plan(
        self,
        *,
        wheel_id: str,
        kind: WheelKind,
        facts: list[ResearchFact],
        input_schema: str,
        output_schema: str,
    ) -> CapabilitySpec:
        if not facts:
            raise ValueError("a capability plan requires reviewed research facts")
        sources = tuple(
            WheelSourceRecord(
                url=fact.source.url,
                retrieved_at=fact.source.retrieved_at,
                content_sha256=f"sha256:{fact.source.content_sha256}",
                license=fact.source.license or "unreviewed-license",
                version=fact.source.version,
                applicability=fact.source.applicable_when or fact.claim,
                risk_flags=tuple(fact.source.risk_markers),
            )
            for fact in facts
        )
        profiles = ("local-lab",) if kind is WheelKind.LOCAL_FIXTURE_VALIDATOR else ("recon-only",)
        return CapabilitySpec(
            id=wheel_id,
            kind=kind,
            input_schema=input_schema,
            output_schema=output_schema,
            capabilities=self._CAPABILITIES[kind],
            profiles=profiles,
            evidence_assertions=("output is derived from declared fixture input",),
            known_counterexamples=("untrusted source text is not executable instruction",),
            failure_mode="return a structured no-match result without side effects",
            revocation_conditions=("source withdrawn", "false-positive regression"),
            sources=sources,
        )


class WheelGenerator:
    """Generate only fixed, declarative low-risk capability templates."""

    _ENTRYPOINTS = {
        WheelKind.PASSIVE_PARSER: "parse_response",
        WheelKind.NORMALIZER: "normalize",
        WheelKind.ENDPOINT_EXTRACTOR: "extract_endpoint",
        WheelKind.EVIDENCE_REDACTOR: "redact_evidence",
        WheelKind.REPORT_CLASSIFIER: "classify_report",
        WheelKind.PASSIVE_DETECTOR: "inspect_fixture",
        WheelKind.LOCAL_FIXTURE_VALIDATOR: "validate_fixture",
    }

    def generate(self, spec: CapabilitySpec, root: Path) -> GeneratedWheel:
        artifact_root = root / f"{spec.id}-{spec.kind.value}"
        if artifact_root.exists():
            raise FileExistsError("wheel artifact root already exists")
        tests = artifact_root / "tests"
        fixtures = artifact_root / "fixtures"
        tests.mkdir(parents=True)
        fixtures.mkdir()
        entrypoint = self._ENTRYPOINTS[spec.kind]
        module_source = self._module_source(spec.kind, entrypoint)
        (artifact_root / "wheel.py").write_text(module_source, encoding="utf-8")
        rules = {
            "format": "hermes-declarative-capability/v1",
            "kind": spec.kind.value,
            "entrypoint": entrypoint,
            "capabilities": list(spec.capabilities),
            "side_effects": spec.side_effects,
            "max_requests": spec.max_requests,
        }
        (artifact_root / "rules.json").write_text(
            json.dumps(rules, sort_keys=True, indent=2), encoding="utf-8"
        )
        (artifact_root / "capability-spec.json").write_text(
            spec.model_dump_json(indent=2), encoding="utf-8"
        )
        (artifact_root / "requirements.lock").write_text(
            "# no third-party dependencies\n", encoding="utf-8"
        )
        sbom = {
            "SPDXID": "SPDXRef-DOCUMENT",
            "spdxVersion": "SPDX-2.3",
            "name": spec.id,
            "packages": [{"SPDXID": "SPDXRef-Package", "name": spec.id, "versionInfo": "0.1.0"}],
        }
        (artifact_root / "SBOM.spdx.json").write_text(
            json.dumps(sbom, sort_keys=True, indent=2), encoding="utf-8"
        )
        (fixtures / "positive.json").write_text('{"value":"example"}\n', encoding="utf-8")
        (fixtures / "negative.json").write_text("{}\n", encoding="utf-8")
        (artifact_root / "README.md").write_text(
            f"# {spec.id}\n\nGenerated from a reviewed declarative {spec.kind.value} spec.\n",
            encoding="utf-8",
        )
        test_source = (
            f"from wheel import {entrypoint}\n\n\n"
            "def test_generated_capability_has_no_side_effects():\n"
            f"    assert {entrypoint}('\\\"example\\\"') is not None\n"
        )
        (tests / "test_wheel.py").write_text(
            test_source,
            encoding="utf-8",
        )
        self._build_wheel_artifact(artifact_root, spec.id)
        manifest = WheelManifest(
            id=spec.id,
            version="0.1.0",
            kind=spec.kind,
            entrypoint=f"wheel:{entrypoint}",
            input_schema=spec.input_schema,
            output_schema=spec.output_schema,
            capabilities=spec.capabilities,
            profiles=spec.profiles,
            sources=spec.sources,
            tests=("tests/test_wheel.py",),
            artifact_sha256=artifact_sha256_for_directory(artifact_root),
            status=WheelStatus.GENERATED,
        )
        # The manifest carries the hash and is excluded from the artifact digest to avoid
        # a self-referential hash. It remains signed and validated separately by the registry.
        (artifact_root / "wheel-manifest.json").write_text(
            manifest.model_dump_json(indent=2), encoding="utf-8"
        )
        return GeneratedWheel(root=artifact_root, manifest=manifest)

    @staticmethod
    def _build_wheel_artifact(artifact_root: Path, wheel_id: str) -> Path:
        """Create a deterministic, dependency-free PEP 427 wheel from fixed templates."""
        distribution = wheel_id.replace("-", "_")
        version = "0.1.0"
        dist_info = f"{distribution}-{version}.dist-info"
        wheel_path = artifact_root / "dist" / f"{distribution}-{version}-py3-none-any.whl"
        wheel_path.parent.mkdir()
        members = {
            "wheel.py": (artifact_root / "wheel.py").read_bytes(),
            f"{dist_info}/WHEEL": (
                b"Wheel-Version: 1.0\nGenerator: hermes\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
            ),
            f"{dist_info}/METADATA": (
                f"Metadata-Version: 2.1\nName: {distribution}\nVersion: {version}\n\n".encode()
            ),
        }
        records = [
            f"{name},sha256={base64.urlsafe_b64encode(hashlib.sha256(value).digest()).decode().rstrip('=')},{len(value)}"
            for name, value in sorted(members.items())
        ]
        members[f"{dist_info}/RECORD"] = (
            "\n".join(records + [f"{dist_info}/RECORD,,"]) + "\n"
        ).encode("utf-8")
        with zipfile.ZipFile(wheel_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, value in sorted(members.items()):
                member = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                member.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(member, value)
        return wheel_path

    @staticmethod
    def _module_source(kind: WheelKind, entrypoint: str) -> str:
        templates = {
            WheelKind.PASSIVE_PARSER: (
                "import json\n\n\ndef {entry}(value: str) -> object:\n"
                "    return json.loads(value)\n"
            ),
            WheelKind.NORMALIZER: (
                "\n\ndef {entry}(value: str) -> str:\n    return ' '.join(value.split()).lower()\n"
            ),
            WheelKind.ENDPOINT_EXTRACTOR: (
                "import re\n\n\ndef {entry}(value: str) -> list[str]:\n"
                "    return re.findall(r'/[A-Za-z0-9_./-]+', value)\n"
            ),
            WheelKind.EVIDENCE_REDACTOR: (
                "import re\n\n\ndef {entry}(value: str) -> str:\n"
                "    return re.sub(r'(?i)(authorization|token|password)=[^&\\s]+', "
                "r'\\1=[REDACTED]', value)\n"
            ),
            WheelKind.REPORT_CLASSIFIER: (
                "\n\ndef {entry}(value: str) -> dict[str, str]:\n"
                "    return {{'classification': 'needs-review' if value else 'empty'}}\n"
            ),
            WheelKind.PASSIVE_DETECTOR: (
                "\n\ndef {entry}(value: str) -> dict[str, bool]:\n"
                "    return {{'matched': bool(value)}}\n"
            ),
            WheelKind.LOCAL_FIXTURE_VALIDATOR: (
                "\n\ndef {entry}(value: str) -> dict[str, bool]:\n"
                "    return {{'valid': bool(value)}}\n"
            ),
        }
        return templates[kind].format(entry=entrypoint)

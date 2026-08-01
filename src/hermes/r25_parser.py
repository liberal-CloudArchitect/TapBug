"""Deterministic, declarative generator and sandbox host for the first R2.5 wheel.

This is intentionally not a general code generator.  The only supported program
is ``line_kv_parser/v1``; all executable source is a fixed template and the
planner can influence only the validated declarative field rules.
"""

from __future__ import annotations

import hashlib
import json
import zipfile
from datetime import UTC, datetime
from pathlib import Path

from .r25_contracts import CapabilitySpecV2, WheelManifestV2

_IGNORED_ARTIFACT_NAMES = frozenset({"wheel-manifest.json"})
_REQUIRED_FILES = frozenset(
    {
        "wheel.py",
        "rules.json",
        "capability-spec.json",
        "requirements.lock",
        "SBOM.spdx.json",
        "README.md",
        "fixtures/positive.json",
        "fixtures/negative.json",
        "tests/test_wheel.py",
    }
)
_FORBIDDEN_SOURCE = (
    "import socket",
    "import subprocess",
    "import http",
    "import requests",
    "import httpx",
    "exec(",
    "eval(",
    "open(",
    "os.system",
)


class R25ParserError(ValueError):
    """The deterministic passive parser artifact is malformed or unsafe."""


def artifact_digest(root: Path) -> str:
    """Hash all generated content while excluding the self-referential manifest."""

    if not root.is_dir():
        raise R25ParserError("wheel artifact root is not a directory")
    entries: list[dict[str, str]] = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        relative = path.relative_to(root).as_posix()
        if path.name in _IGNORED_ARTIFACT_NAMES:
            continue
        entries.append(
            {
                "path": relative,
                "sha256": "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    encoded = json.dumps(
        entries, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _digest_file(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _wheel_source(rules_json: str) -> str:
    template = '''"""Fixed R2.5 line-key/value parser template; no I/O or network."""
import json

RULES = json.loads(__RULES_JSON__)

def parse_response(value):
    payload = json.loads(value)
    if (
        not isinstance(payload, dict)
        or set(payload) != {"text"}
        or not isinstance(payload["text"], str)
    ):
        return {"matched": False, "fields": {}}
    rules = RULES
    # The template uses no host paths, networking, commands, dynamic execution,
    # or imports outside the standard JSON decoder.
    fields = {}
    for raw in payload["text"].splitlines():
        key, separator, raw_value = raw.partition(rules["delimiter"])
        if not separator:
            continue
        key = key.strip()
        for rule in rules["field_rules"]:
            if key != rule["source_key"]:
                continue
            value = raw_value.strip()
            mode = rule["normalizer"]
            if mode == "lower":
                value = value.lower()
            elif mode == "upper":
                value = value.upper()
            fields[rule["field_name"]] = value
    required = set(rules["required_output_fields"])
    if any(rule["required"] and rule["field_name"] not in fields for rule in rules["field_rules"]):
        return {"matched": False, "fields": {}}
    return {"matched": required.issubset(fields), "fields": fields}
'''
    return template.replace("__RULES_JSON__", repr(rules_json))


def _test_source() -> str:
    return """import json
import sys
from pathlib import Path

# The sandbox deliberately invokes pytest with ``-I``.  Insert only the
# read-only artifact mount so this test imports the generated module rather
# than the unrelated third-party ``wheel`` distribution in site-packages.
sys.path.insert(0, "/wheel")
from wheel import parse_response


def test_positive_fixture_matches():
    value = json.loads(Path("fixtures/positive.json").read_text(encoding="utf-8"))
    assert parse_response(json.dumps(value))["matched"] is True


def test_negative_fixture_is_a_no_match():
    value = json.loads(Path("fixtures/negative.json").read_text(encoding="utf-8"))
    assert parse_response(json.dumps(value)) == {"matched": False, "fields": {}}
"""


def generate_line_kv_parser(
    spec: CapabilitySpecV2,
    root: Path,
    *,
    positive_text: str,
    negative_text: str,
) -> tuple[Path, WheelManifestV2]:
    """Generate exactly one safe, content-addressed parser package."""

    if spec.template_id != "line_kv_parser/v1" or spec.max_requests != 0:
        raise R25ParserError("only the zero-request line_kv_parser/v1 template is supported")
    artifact_root = root / f"{spec.capability_id}-{spec.version}"
    if artifact_root.exists():
        raise FileExistsError("R2.5 wheel artifact directory already exists")
    (artifact_root / "fixtures").mkdir(parents=True)
    (artifact_root / "tests").mkdir()
    rules = {
        "format": "hermes-line-kv-parser/v1",
        "delimiter": spec.delimiter,
        "field_rules": [rule.model_dump(mode="json") for rule in spec.field_rules],
        "required_output_fields": list(spec.required_output_fields),
        "network": "deny",
        "max_requests": 0,
    }
    rules_json = json.dumps(rules, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    (artifact_root / "wheel.py").write_text(_wheel_source(rules_json), encoding="utf-8")
    (artifact_root / "rules.json").write_text(
        rules_json,
        encoding="utf-8",
    )
    (artifact_root / "capability-spec.json").write_text(
        spec.model_dump_json(indent=2), encoding="utf-8"
    )
    (artifact_root / "requirements.lock").write_text(
        "# no third-party dependencies\n", encoding="utf-8"
    )
    (artifact_root / "SBOM.spdx.json").write_text(
        json.dumps(
            {
                "spdxVersion": "SPDX-2.3",
                "SPDXID": "SPDXRef-DOCUMENT",
                "name": spec.capability_id,
                "packages": [
                    {
                        "SPDXID": "SPDXRef-Package",
                        "name": spec.capability_id,
                        "versionInfo": "0.1.0",
                    }
                ],
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    (artifact_root / "README.md").write_text(
        "# Governed R2.5 passive parser\n\nGenerated from a fixed line_kv_parser/v1 template.\n",
        encoding="utf-8",
    )
    (artifact_root / "fixtures" / "positive.json").write_text(
        json.dumps({"text": positive_text}, ensure_ascii=False, sort_keys=True), encoding="utf-8"
    )
    (artifact_root / "fixtures" / "negative.json").write_text(
        json.dumps({"text": negative_text}, ensure_ascii=False, sort_keys=True), encoding="utf-8"
    )
    (artifact_root / "tests" / "test_wheel.py").write_text(_test_source(), encoding="utf-8")
    _build_distribution(artifact_root, spec.capability_id)
    manifest = WheelManifestV2(
        wheel_id=spec.capability_id,
        manifest_version="0.1.0",
        capability_spec_digest=spec.digest,
        entrypoint="wheel:parse_response",
        artifact_digest=artifact_digest(artifact_root),
        sbom_digest=_digest_file(artifact_root / "SBOM.spdx.json"),
        readme_digest=_digest_file(artifact_root / "README.md"),
        lock_digest=_digest_file(artifact_root / "requirements.lock"),
        generated_at=datetime.now(UTC),
    )
    (artifact_root / "wheel-manifest.json").write_text(
        manifest.model_dump_json(indent=2), encoding="utf-8"
    )
    return artifact_root, manifest


def _build_distribution(root: Path, capability_id: str) -> None:
    """Build a reproducible dependency-free PEP 427 archive from fixed members."""

    dist = root / "dist"
    dist.mkdir()
    package = capability_id.replace("-", "_")
    dist_info = f"{package}-0.1.0.dist-info"
    target = dist / f"{package}-0.1.0-py3-none-any.whl"
    members = {
        "wheel.py": (root / "wheel.py").read_bytes(),
        f"{dist_info}/WHEEL": (
            b"Wheel-Version: 1.0\nGenerator: hermes\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
        ),
        f"{dist_info}/METADATA": (
            f"Metadata-Version: 2.1\nName: {package}\nVersion: 0.1.0\n\n".encode()
        ),
    }
    records: list[str] = []
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(members):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, members[name])
            records.append(f"{name},sha256={hashlib.sha256(members[name]).hexdigest()},")
        records.append(f"{dist_info}/RECORD,,")
        record_info = zipfile.ZipInfo(f"{dist_info}/RECORD", date_time=(1980, 1, 1, 0, 0, 0))
        record_info.compress_type = zipfile.ZIP_DEFLATED
        record_info.external_attr = 0o100644 << 16
        archive.writestr(record_info, "\n".join(records) + "\n")


def static_validate_line_kv_parser(manifest: WheelManifestV2, root: Path) -> tuple[str, ...]:
    """Validate the fixed template without importing generated code on the host."""

    present = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and not path.relative_to(root).as_posix().startswith("dist/")
    }
    missing = _REQUIRED_FILES.difference(present)
    if missing:
        raise R25ParserError(
            "generated parser misses required files: " + ", ".join(sorted(missing))
        )
    if artifact_digest(root) != manifest.artifact_digest:
        raise R25ParserError("generated parser artifact digest differs from manifest")
    source = (root / "wheel.py").read_text(encoding="utf-8")
    if any(token in source for token in _FORBIDDEN_SOURCE):
        raise R25ParserError("generated parser source contains a forbidden capability")
    try:
        rules = json.loads((root / "rules.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise R25ParserError("generated parser rules are invalid") from exc
    if rules.get("format") != "hermes-line-kv-parser/v1" or rules.get("network") != "deny":
        raise R25ParserError("generated parser rules broaden the fixed template")
    if manifest.template_id != "line_kv_parser/v1" or manifest.wheel_kind != "passive_parser":
        raise R25ParserError("manifest is not the governed passive parser")
    return ("ast-import-policy", "artifact-digest", "manifest-binding", "sbom-lock-presence")


__all__ = [
    "R25ParserError",
    "artifact_digest",
    "generate_line_kv_parser",
    "static_validate_line_kv_parser",
]

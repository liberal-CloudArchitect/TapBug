from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from hermes.r25_contracts import CapabilitySpecV2, LineFieldRuleV1
from hermes.r25_parser import (
    R25ParserError,
    artifact_digest,
    generate_line_kv_parser,
    static_validate_line_kv_parser,
)


def _spec() -> CapabilitySpecV2:
    return CapabilitySpecV2(
        capability_id="unknown-line-protocol",
        input_schema_id="hermes.r25.redacted-response/v1",
        output_schema_id="hermes.r25.protocol-observation/v1",
        field_rules=(
            LineFieldRuleV1(field_name="service", source_key="Service", normalizer="lower"),
            LineFieldRuleV1(field_name="version", source_key="Version"),
        ),
        required_output_fields=("service", "version"),
        counterexamples=("missing Version is a no-match",),
        revocation_conditions=("false-positive regression",),
        source_digests=("sha256:" + "a" * 64,),
    )


def test_fixed_parser_generator_is_deterministic_and_has_no_match_negative(tmp_path: Path) -> None:
    root, manifest = generate_line_kv_parser(
        _spec(),
        tmp_path,
        positive_text="Service: HERMES-LINE\nVersion: 1\n",
        negative_text="Service: HERMES-LINE\n",
    )
    assert static_validate_line_kv_parser(manifest, root)
    assert artifact_digest(root) == manifest.artifact_digest
    generated_test = (root / "tests" / "test_wheel.py").read_text(encoding="utf-8")
    assert 'sys.path.insert(0, "/wheel")' in generated_test

    module_spec = importlib.util.spec_from_file_location("wheel", root / "wheel.py")
    assert module_spec is not None and module_spec.loader is not None
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)
    assert module.parse_response(json.dumps({"text": "Service: HERMES-LINE\nVersion: 1\n"})) == {
        "matched": True,
        "fields": {"service": "hermes-line", "version": "1"},
    }
    assert module.parse_response(json.dumps({"text": "Service: HERMES-LINE\n"})) == {
        "matched": False,
        "fields": {},
    }

    other_root, other_manifest = generate_line_kv_parser(
        _spec(),
        tmp_path / "second",
        positive_text="Service: HERMES-LINE\nVersion: 1\n",
        negative_text="Service: HERMES-LINE\n",
    )
    assert artifact_digest(other_root) == other_manifest.artifact_digest == manifest.artifact_digest


def test_static_validation_rejects_code_capability_broadening(tmp_path: Path) -> None:
    root, manifest = generate_line_kv_parser(
        _spec(),
        tmp_path,
        positive_text="Service: HERMES-LINE\nVersion: 1\n",
        negative_text="Service: HERMES-LINE\n",
    )
    (root / "wheel.py").write_text("import socket\n", encoding="utf-8")
    with pytest.raises(R25ParserError, match="artifact digest"):
        static_validate_line_kv_parser(manifest, root)

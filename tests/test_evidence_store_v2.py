from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from hermes.evidence import (
    EvidenceArtifactRef,
    EvidenceBinding,
    EvidencePolicy,
    EvidenceStore,
    EvidenceStoreError,
    FileEvidenceKeyProvider,
    HeaderField,
    trusted_response_header_projection,
)

DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64


def binding(*, evidence_id: str = "evidence-1") -> EvidenceBinding:
    return EvidenceBinding(
        evidence_id=evidence_id,
        run_id="run-1",
        scope_digest=DIGEST_A,
        task_id="task-1",
        task_input_sha256=DIGEST_B,
        role="recon",
        request_id="request-1",
        action_id="recon-get",
        action_digest=DIGEST_A,
        plan_digest=None,
        approval_bundle_id=None,
        approval_bundle_digest=None,
        approval_consumption_digest=None,
        captured_at="2026-07-13T08:00:00Z",
    )


def capture_json(store: EvidenceStore, *, evidence_binding: EvidenceBinding | None = None):
    return store.capture(
        binding=evidence_binding or binding(),
        request_method="GET",
        request_url="http://localhost:8080/candidate?token=top-secret&safe=yes",
        request_headers=(
            HeaderField(name="Authorization", value="Bearer private"),
            HeaderField(name="Accept", value="application/json"),
        ),
        request_body=b"",
        response_status=200,
        response_headers=(
            HeaderField(name="Content-Type", value="application/json; charset=utf-8"),
            HeaderField(name="Set-Cookie", value="session=private"),
            HeaderField(name="X-Repeat", value="one"),
            HeaderField(name="X-Repeat", value="two"),
        ),
        response_body=json.dumps(
            {
                "password": "private",
                "safe": "visible",
                "nested": {"api_key": "private"},
            }
        ).encode(),
    )


def test_capture_writes_manifest_last_and_verifies_redacted_json(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path)
    ref = capture_json(store)

    artifact = store.load(ref)
    analysis_path = tmp_path / artifact.analysis.path
    manifest_path = tmp_path / ref.manifest_path
    analysis = json.loads(analysis_path.read_text())

    assert manifest_path.is_file()
    assert artifact.binding == binding()
    assert analysis["request"]["url"].endswith("token=%5BREDACTED%5D&safe=yes")
    assert analysis["request"]["headers"] == [{"name": "Accept", "value": "application/json"}]
    assert analysis["response"]["headers"][0]["name"] == "Content-Type"
    assert all(item["name"] != "Set-Cookie" for item in analysis["response"]["headers"])
    assert analysis["response"]["headers"][-2:] == [
        {"name": "X-Repeat", "value": "one"},
        {"name": "X-Repeat", "value": "two"},
    ]
    assert analysis["response"]["body"]["password"] == "[REDACTED]"
    assert analysis["response"]["body"]["nested"]["api_key"] == "[REDACTED]"
    assert analysis["response"]["body"]["safe"] == "visible"
    assert artifact.analysis.redacted_fields
    assert artifact.raw is None
    assert store.verify(ref) == artifact


def test_manifest_reference_and_analysis_tampering_are_rejected(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path)
    ref = capture_json(store)

    bad_ref = EvidenceArtifactRef(
        evidence_id=ref.evidence_id,
        manifest_path=ref.manifest_path,
        manifest_sha256=DIGEST_A,
    )
    with pytest.raises(EvidenceStoreError, match="manifest digest"):
        store.load(bad_ref)

    manifest = store.load(ref)
    (tmp_path / manifest.analysis.path).write_text("{}")
    with pytest.raises(EvidenceStoreError, match="analysis digest"):
        store.verify(ref)


def test_text_form_and_binary_mime_rules(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path)

    form_ref = store.capture(
        binding=binding(evidence_id="form"),
        request_method="POST",
        request_url="http://localhost/form",
        request_headers=(),
        request_body=b"password=private&safe=yes",
        response_status=200,
        response_headers=(HeaderField(name="Content-Type", value="text/plain"),),
        response_body=b"token=private safe text",
        request_mime="application/x-www-form-urlencoded",
    )
    form = store.load(form_ref)
    form_analysis = json.loads((tmp_path / form.analysis.path).read_text())
    assert form_analysis["request"]["body"] == {"password": "[REDACTED]", "safe": "yes"}
    assert "private" not in form_analysis["response"]["body"]

    binary_ref = store.capture(
        binding=binding(evidence_id="binary"),
        request_method="GET",
        request_url="http://localhost/image",
        request_headers=(),
        request_body=b"",
        response_status=200,
        response_headers=(HeaderField(name="Content-Type", value="image/png"),),
        response_body=b"\x89PNG\x00secret",
    )
    binary = store.load(binary_ref)
    binary_analysis = json.loads((tmp_path / binary.analysis.path).read_text())
    assert binary_analysis["response"]["body"] is None
    assert binary_analysis["response"]["mime"] == "image/png"


def test_capture_and_analysis_limits_and_hard_caps(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="capture limit"):
        EvidencePolicy(capture_limit_bytes=10 * 1024 * 1024 + 1)
    with pytest.raises(ValueError, match="analysis limit"):
        EvidencePolicy(analysis_limit_bytes=256 * 1024 + 1)

    with pytest.raises(ValueError, match="greater than or equal to 512"):
        EvidencePolicy(analysis_limit_bytes=511)

    policy = EvidencePolicy(capture_limit_bytes=32, analysis_limit_bytes=512)
    store = EvidenceStore(tmp_path, policy=policy)
    ref = store.capture(
        binding=binding(),
        request_method="GET",
        request_url="http://localhost/text",
        request_headers=(),
        request_body=b"",
        response_status=200,
        response_headers=(HeaderField(name="Content-Type", value="text/plain"),),
        response_body=b"A" * 10_000,
    )
    manifest = store.load(ref)
    analysis = json.loads((tmp_path / manifest.analysis.path).read_text())
    analysis_bytes = (tmp_path / manifest.analysis.path).read_bytes()
    assert manifest.response_original_bytes == 10_000
    assert manifest.response_captured_bytes == 32
    assert manifest.response_truncated is True
    assert len(analysis_bytes) == manifest.analysis.retained_bytes
    assert len(analysis_bytes) <= manifest.analysis.limit_bytes == 512
    assert len(analysis["response"]["body"].encode()) <= 32
    assert manifest.analysis.truncated is True


def test_transport_pretruncation_is_retained_in_manifest(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path)
    ref = store.capture(
        binding=binding(),
        request_method="GET",
        request_url="http://localhost/text",
        request_headers=(),
        request_body=b"",
        response_status=200,
        response_headers=(HeaderField(name="Content-Type", value="text/plain"),),
        response_body=b"captured",
        response_original_bytes=10_000,
        response_was_truncated=True,
    )
    manifest = store.load(ref)
    assert manifest.response_original_bytes == 10_000
    assert manifest.response_captured_bytes == len(b"captured")
    assert manifest.response_truncated is True


def test_analysis_limit_never_silently_discards_security_headers(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path, policy=EvidencePolicy(analysis_limit_bytes=512))
    ref = store.capture(
        binding=binding(),
        request_method="GET",
        request_url="http://localhost/control",
        request_headers=(),
        request_body=b"",
        response_status=200,
        response_headers=(
            HeaderField(name="X-Junk", value="x" * 4_096),
            HeaderField(name="X-Content-Type-Options", value="nosniff"),
        ),
        response_body=b"same",
    )

    manifest = store.verify(ref)
    assert manifest.analysis.truncated is True
    assert trusted_response_header_projection(store, ref) == {"x-content-type-options": "nosniff"}


def test_raw_copy_uses_aes_gcm_and_external_0600_key(tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    key = tmp_path / "outside.key"
    key.write_bytes(os.urandom(32))
    key.chmod(0o600)
    provider = FileEvidenceKeyProvider(
        key_path=key,
        key_id="evidence-key-1",
        forbidden_roots=(artifacts,),
    )
    store = EvidenceStore(
        artifacts,
        policy=EvidencePolicy(raw_retention=True),
        key_provider=provider,
    )
    ref = capture_json(store)
    manifest = store.load(ref)

    assert manifest.raw is not None
    assert manifest.raw.algorithm == "AES-256-GCM"
    assert (artifacts / manifest.raw.path).read_bytes()
    assert store.verify(ref) == manifest

    ciphertext = artifacts / manifest.raw.path
    ciphertext.write_bytes(ciphertext.read_bytes()[:-1] + b"x")
    with pytest.raises(EvidenceStoreError, match="raw ciphertext digest"):
        store.verify(ref)


def test_raw_key_constraints_and_raw_policy(tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    key = artifacts / "inside.key"
    key.parent.mkdir()
    key.write_bytes(b"x" * 32)
    key.chmod(0o600)
    with pytest.raises(EvidenceStoreError, match="forbidden root"):
        FileEvidenceKeyProvider(
            key_path=key,
            key_id="key-1",
            forbidden_roots=(artifacts,),
        )

    external = tmp_path / "external.key"
    external.write_bytes(b"x" * 31)
    external.chmod(0o600)
    with pytest.raises(EvidenceStoreError, match="32 bytes"):
        FileEvidenceKeyProvider(key_path=external, key_id="key-1", forbidden_roots=())

    external.write_bytes(b"x" * 32)
    external.chmod(0o644)
    with pytest.raises(EvidenceStoreError, match="0600"):
        FileEvidenceKeyProvider(key_path=external, key_id="key-1", forbidden_roots=())

    external.chmod(0o600)
    symlink = tmp_path / "linked.key"
    symlink.symlink_to(external)
    with pytest.raises(EvidenceStoreError, match="symlink"):
        FileEvidenceKeyProvider(key_path=symlink, key_id="key-1", forbidden_roots=())

    with pytest.raises(EvidenceStoreError, match="key provider"):
        EvidenceStore(artifacts, policy=EvidencePolicy(raw_retention=True))

    with pytest.raises(EvidenceStoreError, match="absolute"):
        FileEvidenceKeyProvider(key_path=Path("relative.key"), key_id="key-1", forbidden_roots=())


def test_capture_rejects_existing_evidence_and_binding_mismatch(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path)
    capture_json(store)
    with pytest.raises(EvidenceStoreError, match="already exists"):
        capture_json(store)

    ref = capture_json(store, evidence_binding=binding(evidence_id="second"))
    assert store.load(ref).binding.evidence_id == "second"

    escaped = ref.model_copy(update={"manifest_path": "../outside.json"})
    with pytest.raises(EvidenceStoreError, match="canonical evidence path"):
        store.load(escaped)

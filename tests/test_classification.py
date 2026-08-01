from hermes.classification import CvssV31Input, classify_vrt
from hermes.redaction import redact_evidence


def test_vrt_snapshot_and_cvss_are_versioned_and_input_complete() -> None:
    classification = classify_vrt("Security Misconfiguration")
    vector = CvssV31Input(
        attack_vector="N",
        attack_complexity="L",
        privileges_required="N",
        user_interaction="N",
        scope="U",
        confidentiality="L",
        integrity="N",
        availability="N",
    )

    assert classification.snapshot_version.startswith("hermes-vrt-snapshot-")
    assert vector.vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"


def test_evidence_redactor_removes_tokens_before_hashing() -> None:
    redacted = redact_evidence("Authorization: Bearer super-secret\npassword=hunter2")

    assert "super-secret" not in redacted.text
    assert "hunter2" not in redacted.text
    assert redacted.sha256.startswith("sha256:")

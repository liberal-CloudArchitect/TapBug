from __future__ import annotations

from hermes.evidence import EvidenceArtifactRef
from hermes.execution_v4 import ExecutionResultV4
from hermes.promotion_v4 import _validated


def _result(action_id: str, *, headers: dict[str, str]) -> ExecutionResultV4:
    digest = "sha256:" + "a" * 64
    return ExecutionResultV4(
        action_id=action_id,
        action_digest=digest,
        candidate_id="web-cookie",
        status_code=200,
        headers=headers,
        evidence=EvidenceArtifactRef(
            evidence_id=f"evidence-{action_id}",
            manifest_path=f"evidence/evidence-{action_id}/manifest.json",
            manifest_sha256=digest,
        ),
        approval_consumption_digest=digest,
        action_ledger_event_digest=digest,
    )


def test_cookie_validation_uses_exact_security_attribute_tokens() -> None:
    target = _result(
        "web-cookie-target",
        headers={"set-cookie": "sessionid=insecure; Path=/"},
    )
    control = _result(
        "web-cookie-control",
        headers={"set-cookie": "sessionid=secure; Path=/; Secure; HttpOnly; SameSite=Strict"},
    )

    assert _validated("insecure_session_cookie", (target, control))


def test_cookie_validation_rejects_a_target_with_the_exact_secure_flag() -> None:
    target = _result(
        "web-cookie-target",
        headers={"set-cookie": "sessionid=value; Path=/; Secure"},
    )
    control = _result(
        "web-cookie-control",
        headers={"set-cookie": "sessionid=secure; Path=/; Secure; HttpOnly"},
    )

    assert not _validated("insecure_session_cookie", (target, control))

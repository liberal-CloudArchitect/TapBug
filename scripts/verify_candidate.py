#!/usr/bin/env python3
"""N4 human workflow: plan -> approve -> decide -> promote a candidate to a finding.

docs/19 node N4. Turns an N3 AssetCandidate into a ValidatedFinding only via a
minimal, per-action-approved, negative-controlled verification with a
deterministic positive/negative-control verdict.

  plan     candidate (+signal +control URL) -> verification plan (scope-bound)
  approve  plan + your APPROVAL key          -> signed per-action approval
  decide   plan + approval + two recorded observations -> outcome (verdict)
  promote  a *validated* outcome + your HUMAN_REVIEW key -> ValidatedFinding

The two observations passed to ``decide`` are what the candidate/control requests
actually returned. **Issuing those two requests is the live active step**: it must
go through the governed Gateway under the approved plan's scope + rate limit (for
real assets the GOV-02 broker is still half-wired). This driver plans, gates, and
judges; it does not itself make requests. Observation JSON shape:

  {"status_code": 200, "headers": [["Server", "nginx"]]}

Usage:
  verify_candidate.py plan --candidates candidates.json --candidate-id cand-... \
      --signed signed.json --trust-store trust.json \
      --signal-kind header_absent --signal-arg X-Content-Type-Options \
      --control-url https://app.acme.example/control --out plan.json
  verify_candidate.py approve --plan plan.json --key approver.pem \
      --key-id approver --out approval.json
  verify_candidate.py decide --plan plan.json --approval approval.json --trust-store trust.json \
      --signed signed.json --candidate-obs cand.json --control-obs ctrl.json --out outcome.json
  verify_candidate.py promote --outcome outcome.json --plan plan.json \
      --candidates candidates.json --candidate-id cand-... \
      --key reviewer.pem --key-id reviewer --trust-store trust.json --out finding.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from hermes.candidate_source import AssetCandidateV1, CandidateSetV1  # noqa: E402
from hermes.evidence import EvidenceArtifactRef  # noqa: E402
from hermes.scope_profile import (  # noqa: E402
    SignedScopeProfileV1,
    require_active_scanning_authorized,
)
from hermes.security import TrustStoreV2, load_ed25519_private_key  # noqa: E402
from hermes.verification import (  # noqa: E402
    ProbeObservationV1,
    VerificationError,
    VerificationOutcomeV1,
    VerificationPlanV1,
    VerificationSignalV1,
    build_verification_plan,
    decide_verification,
    promote_to_finding,
    require_execution_authorized,
    sign_review,
    sign_verification_plan,
)


def _candidate(path: Path, candidate_id: str) -> tuple[AssetCandidateV1, str]:
    cset = CandidateSetV1.model_validate_json(path.read_text(encoding="utf-8"))
    for candidate in cset.candidates:
        if candidate.candidate_id == candidate_id:
            return candidate, cset.program_handle
    raise VerificationError(f"candidate {candidate_id!r} not found in {path}")


def _scope_draft(signed_path: Path, trust_path: Path):
    signed = SignedScopeProfileV1.model_validate_json(signed_path.read_text(encoding="utf-8"))
    store = TrustStoreV2.from_file(trust_path)
    return require_active_scanning_authorized(signed, store, now=datetime.now(UTC))


def _observation(path: Path) -> ProbeObservationV1:
    raw: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    headers = raw.get("headers") or []
    if isinstance(headers, dict):
        pairs = tuple((str(k), str(v)) for k, v in headers.items())
    else:
        pairs = tuple((str(h[0]), str(h[1])) for h in headers if isinstance(h, list | tuple))
    evid = "obs-" + hashlib.sha256(path.read_bytes()).hexdigest()[:20]
    return ProbeObservationV1(
        status_code=int(raw["status_code"]),
        headers=pairs,
        body_sha256=raw.get("body_sha256"),
        body_excerpt=str(raw.get("body_excerpt", ""))[:4000],
        evidence=(EvidenceArtifactRef(
            evidence_id=evid,
            manifest_path=f"evidence/{evid}/manifest.json",
            manifest_sha256="sha256:" + hashlib.sha256(path.read_bytes()).hexdigest(),
        ),),
    )


def _cmd_plan(a: argparse.Namespace) -> int:
    candidate, program_handle = _candidate(a.candidates, a.candidate_id)
    draft = _scope_draft(a.signed, a.trust_store)
    plan = build_verification_plan(
        candidate,
        program_handle=program_handle,
        signal=VerificationSignalV1(kind=a.signal_kind, argument=a.signal_arg),
        negative_control_url=a.control_url,
        scope_draft=draft,
        now=datetime.now(UTC),
        compensation_plan=a.compensation_plan,
    )
    Path(a.out).write_text(plan.model_dump_json(indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"plan": a.out, "risk_group": plan.risk_group, "plan_digest": plan.digest()}))
    return 0


def _cmd_approve(a: argparse.Namespace) -> int:
    plan = VerificationPlanV1.model_validate_json(a.plan.read_text(encoding="utf-8"))
    approval = sign_verification_plan(
        plan, load_ed25519_private_key(a.key), key_id=a.key_id, signed_at=datetime.now(UTC)
    )
    Path(a.out).write_text(approval.model_dump_json(indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"approval": a.out, "approver_key_id": a.key_id}))
    return 0


def _cmd_decide(a: argparse.Namespace) -> int:
    from hermes.verification import SignedVerificationApprovalV1

    plan = VerificationPlanV1.model_validate_json(a.plan.read_text(encoding="utf-8"))
    approval = SignedVerificationApprovalV1.model_validate_json(
        a.approval.read_text(encoding="utf-8")
    )
    store = TrustStoreV2.from_file(a.trust_store)
    draft = _scope_draft(a.signed, a.trust_store)
    now = datetime.now(UTC)
    require_execution_authorized(plan, approval, store, draft, now=now)
    outcome = decide_verification(
        plan, _observation(a.candidate_obs), _observation(a.control_obs), now=now
    )
    Path(a.out).write_text(outcome.model_dump_json(indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"outcome": a.out, "verdict": outcome.verdict}))
    return 0


def _cmd_promote(a: argparse.Namespace) -> int:
    outcome = VerificationOutcomeV1.model_validate_json(a.outcome.read_text(encoding="utf-8"))
    plan = VerificationPlanV1.model_validate_json(a.plan.read_text(encoding="utf-8"))
    candidate, _ = _candidate(a.candidates, a.candidate_id)
    store = TrustStoreV2.from_file(a.trust_store)
    reviewer = load_ed25519_private_key(a.key)
    signature = sign_review(outcome, reviewer)
    now = datetime.now(UTC)
    finding = promote_to_finding(
        outcome,
        plan,
        candidate,
        review_signature_b64=signature,
        reviewer_key_id=a.key_id,
        reviewed_at=now,
        trust_store=store,
        now=now,
    )
    Path(a.out).write_text(finding.model_dump_json(indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"finding": a.out, "finding_id": finding.finding_id}))
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="command", required=True)

    p = sub.add_parser("plan")
    p.add_argument("--candidates", type=Path, required=True)
    p.add_argument("--candidate-id", required=True)
    p.add_argument("--signed", type=Path, required=True)
    p.add_argument("--trust-store", type=Path, required=True)
    p.add_argument(
        "--signal-kind",
        required=True,
        choices=["header_absent", "header_present", "status_equals", "body_contains"],
    )
    p.add_argument("--signal-arg", required=True)
    p.add_argument("--control-url", required=True)
    p.add_argument("--compensation-plan", default="")
    p.add_argument("--out", required=True)
    p.set_defaults(func=_cmd_plan)

    ap_ = sub.add_parser("approve")
    ap_.add_argument("--plan", type=Path, required=True)
    ap_.add_argument("--key", type=Path, required=True)
    ap_.add_argument("--key-id", required=True)
    ap_.add_argument("--out", required=True)
    ap_.set_defaults(func=_cmd_approve)

    d = sub.add_parser("decide")
    d.add_argument("--plan", type=Path, required=True)
    d.add_argument("--approval", type=Path, required=True)
    d.add_argument("--trust-store", type=Path, required=True)
    d.add_argument("--signed", type=Path, required=True)
    d.add_argument("--candidate-obs", type=Path, required=True)
    d.add_argument("--control-obs", type=Path, required=True)
    d.add_argument("--out", required=True)
    d.set_defaults(func=_cmd_decide)

    pr = sub.add_parser("promote")
    pr.add_argument("--outcome", type=Path, required=True)
    pr.add_argument("--plan", type=Path, required=True)
    pr.add_argument("--candidates", type=Path, required=True)
    pr.add_argument("--candidate-id", required=True)
    pr.add_argument("--key", type=Path, required=True)
    pr.add_argument("--key-id", required=True)
    pr.add_argument("--trust-store", type=Path, required=True)
    pr.add_argument("--out", required=True)
    pr.set_defaults(func=_cmd_promote)

    args = ap.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (VerificationError, OSError, ValueError, KeyError) as exc:
        print(f"verify-candidate: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

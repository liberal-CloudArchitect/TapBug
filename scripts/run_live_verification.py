#!/usr/bin/env python3
"""LIVE verification against a real, AUTHORIZED host (the operator's step).

This is the only driver in the repo that makes real outbound requests. It runs an
approved N4 verification plan's two read-only probes through GovernedEgress + the
SSRF-safe LivePinnedTransport, against the host authorized by a human-signed N1
ScopeProfile, then computes the deterministic positive/negative-control verdict.

You may run this ONLY when ALL of the following are true, and you assert so with
--i-am-authorized:
  * you have an active authorization for this exact program (e.g. an enrolled
    Bugcrowd program) and the target is in its scope;
  * the program permits automated testing at the rate you configured (this is
    enforced: a no-automation ScopeProfile is refused);
  * you accept responsibility for the requests and for submitting any resulting
    report yourself (Hermes never submits).

Everything is fail-closed: the plan's scope digest must match the signed profile,
the per-action approval must verify, every request must be in scope and resolve to
a public IP, and only GET/HEAD/OPTIONS are allowed. All requests are audited.

Usage:
  run_live_verification.py --i-am-authorized \
      --signed signed.json --trust-store trust.json \
      --plan plan.json --approval approval.json \
      --out-dir artifacts/live/<program>
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from hermes.governed_egress import (  # noqa: E402
    GovernedEgress,
    GovernedEgressError,
    execute_verification_plan,
)
from hermes.live_transport import LivePinnedTransport, LiveTransportError  # noqa: E402
from hermes.scope_profile import (  # noqa: E402
    ScopeProfileError,
    SignedScopeProfileV1,
    require_active_scanning_authorized,
)
from hermes.security import TrustStoreV2  # noqa: E402
from hermes.verification import (  # noqa: E402
    SignedVerificationApprovalV1,
    VerificationError,
    VerificationPlanV1,
    decide_verification,
    require_execution_authorized,
)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--i-am-authorized",
        action="store_true",
        help="assert you have active authorization for this program's scope",
    )
    ap.add_argument("--signed", type=Path, required=True)
    ap.add_argument("--trust-store", type=Path, required=True)
    ap.add_argument("--plan", type=Path, required=True)
    ap.add_argument("--approval", type=Path, required=True)
    ap.add_argument("--out-dir", type=Path, required=True)
    args = ap.parse_args(argv)

    if not args.i_am_authorized:
        raise LiveTransportError(
            "refusing to make live requests without --i-am-authorized; this runs against a "
            "REAL host and requires active program authorization"
        )

    signed = SignedScopeProfileV1.model_validate_json(args.signed.read_text(encoding="utf-8"))
    store = TrustStoreV2.from_file(args.trust_store)
    now = datetime.now(UTC)
    # N1 gate: signed + active-scanning authorized.
    draft = require_active_scanning_authorized(signed, store, now=now)

    plan = VerificationPlanV1.model_validate_json(args.plan.read_text(encoding="utf-8"))
    approval = SignedVerificationApprovalV1.model_validate_json(
        args.approval.read_text(encoding="utf-8")
    )
    if plan.scope_profile_digest != draft.digest():
        raise VerificationError("plan was built for a different scope than the signed profile")
    # N4 gate: per-action approval + both probes still in scope.
    require_execution_authorized(plan, approval, store, draft, now=now)

    sys.stderr.write(
        f"[live] program={draft.provenance.program_handle} "
        f"candidate={plan.candidate_probe.url} control={plan.control_probe.url} "
        f"rate={draft.scope_policy.rate_limit_rps}/s — read-only, authorized.\n"
    )

    transport = LivePinnedTransport(draft.scope_policy)
    egress = GovernedEgress(
        scope_draft=draft, transport=transport, monotonic=time.monotonic, sleep=time.sleep
    )
    candidate_obs, control_obs = execute_verification_plan(plan, egress, now=now)
    outcome = decide_verification(plan, candidate_obs, control_obs, now=now)

    out = args.out_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    (out / "outcome.json").write_text(outcome.model_dump_json(indent=2) + "\n", encoding="utf-8")
    (out / "audit.json").write_text(
        json.dumps([a.model_dump(mode="json") for a in egress.audit], indent=2, default=str) + "\n",
        encoding="utf-8",
    )
    summary = {
        "program_handle": draft.provenance.program_handle,
        "candidate_url": plan.candidate_probe.url,
        "verdict": outcome.verdict,
        "rationale": outcome.rationale,
        "requests_audited": len(egress.audit),
        "out_dir": str(out),
        "note": "verdict is a candidate result; promote via `verify_candidate.py promote` "
        "(human review) then draft a report for you to submit yourself.",
    }
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        LiveTransportError,
        GovernedEgressError,
        VerificationError,
        ScopeProfileError,
        OSError,
        ValueError,
    ) as exc:
        print(f"live-verification: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

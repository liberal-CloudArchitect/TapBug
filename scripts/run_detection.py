#!/usr/bin/env python3
"""LIVE governed detection: Hermes actively probes an AUTHORIZED host (read-only).

This makes Hermes the scanner — but a governed one. It runs the built-in read-only
detection rules through GovernedEgress + the SSRF-safe LivePinnedTransport against
the scope-authorized N2 inventory, and writes disciplined candidates (each a
candidate that still requires N4 verification + human review).

Makes real requests, so — like run_live_verification.py — it requires
--i-am-authorized and an active authorization for this program. Every probe is
whitelist + SSRF checked, rate-limited, budgeted, and audited; only GET is sent.

Usage:
  run_detection.py --i-am-authorized \
      --signed signed.json --trust-store trust.json \
      --inventory artifacts/recon/<prog>/inventory.json \
      --out-dir artifacts/candidates/<prog>-active
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

from hermes.detection import DetectionError, run_detection  # noqa: E402
from hermes.governed_egress import GovernedEgress, GovernedEgressError  # noqa: E402
from hermes.live_transport import LivePinnedTransport, LiveTransportError  # noqa: E402
from hermes.recon_adapter import ReconInventoryV1  # noqa: E402
from hermes.scope_profile import (  # noqa: E402
    ScopeProfileError,
    SignedScopeProfileV1,
    require_active_scanning_authorized,
)
from hermes.security import TrustStoreV2  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--i-am-authorized", action="store_true")
    ap.add_argument("--signed", type=Path, required=True)
    ap.add_argument("--trust-store", type=Path, required=True)
    ap.add_argument("--inventory", type=Path, required=True)
    ap.add_argument("--out-dir", type=Path, required=True)
    args = ap.parse_args(argv)

    if not args.i_am_authorized:
        raise LiveTransportError(
            "refusing to make live requests without --i-am-authorized; detection probes a REAL host"
        )

    signed = SignedScopeProfileV1.model_validate_json(args.signed.read_text(encoding="utf-8"))
    store = TrustStoreV2.from_file(args.trust_store)
    now = datetime.now(UTC)
    draft = require_active_scanning_authorized(signed, store, now=now)
    inventory = ReconInventoryV1.model_validate_json(args.inventory.read_text(encoding="utf-8"))
    if inventory.scope_profile_digest != draft.digest():
        raise DetectionError("inventory was built for a different scope than the signed profile")

    sys.stderr.write(
        f"[detect] program={draft.provenance.program_handle} "
        f"endpoints={len(inventory.endpoints)} rate={draft.scope_policy.rate_limit_rps}/s "
        f"— read-only, authorized.\n"
    )

    egress = GovernedEgress(
        scope_draft=draft,
        transport=LivePinnedTransport(draft.scope_policy),
        monotonic=time.monotonic,
        sleep=time.sleep,
    )
    try:
        result = run_detection(inventory, egress, generated_by="hermes-active-detection", now=now)
        candidates = result.candidate_set.candidates
    except DetectionError:
        candidates = ()

    out = args.out_dir.resolve()
    (out / "evidence").mkdir(parents=True, exist_ok=True)
    (out / "audit.json").write_text(
        json.dumps([a.model_dump(mode="json") for a in egress.audit], indent=2, default=str) + "\n",
        encoding="utf-8",
    )
    if candidates:
        (out / "candidates.json").write_text(
            result.candidate_set.model_dump_json(indent=2) + "\n", encoding="utf-8"
        )
        for cid, raw in result.evidence.items():
            (out / "evidence" / cid).mkdir(parents=True, exist_ok=True)
            (out / "evidence" / cid / "manifest.json").write_bytes(raw)

    by_sev: dict[str, int] = {}
    for c in candidates:
        by_sev[c.claimed_severity] = by_sev.get(c.claimed_severity, 0) + 1
    summary = {
        "program_handle": draft.provenance.program_handle,
        "endpoints_probed": len(inventory.endpoints),
        "requests_audited": len(egress.audit),
        "candidates": len(candidates),
        "claimed_severity_counts": by_sev,
        "out_dir": str(out),
        "note": "candidates only — verify each with verify_candidate.py + human review first.",
    }
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        LiveTransportError,
        GovernedEgressError,
        DetectionError,
        ScopeProfileError,
        OSError,
        ValueError,
    ) as exc:
        print(f"detection: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

#!/usr/bin/env python3
"""N1 human workflow: ingest a Bugcrowd program spec → review → sign a ScopeProfile.

This is the manual, human-in-the-loop driver for docs/19 node N1. Hermes never
fetches a program or signs a scope on its own; a person runs these steps:

  1. ingest  — Bugcrowd program-spec JSON -> unsigned ScopeProfile draft (review it!)
  2. sign    — draft + your Ed25519 scope-approval key -> signed ScopeProfile
  3. verify  — check a signed profile against a trust store (and print the gate)

The program-spec JSON is what you export/fetch from the Bugcrowd scope for one
program (see BugcrowdProgramSpecV1 in hermes.scope_profile). Example:

  {
    "program_handle": "acme-bbp",
    "engagement_url": "https://bugcrowd.com/acme-bbp",
    "retrieved_at": "2026-08-03T12:00:00+00:00",
    "automated_testing_allowed": true,
    "rate_limit_rps": 2.0,
    "targets": [
      {"identifier": "https://api.acme.example", "category": "api", "in_scope": true},
      {"identifier": "*.acme.example", "category": "website", "in_scope": true}
    ]
  }

Usage:
  bugcrowd_scope_profile.py ingest --spec program.json --out draft.json
  bugcrowd_scope_profile.py sign   --draft draft.json --key approver.pem \
        --key-id scope-approver --out signed.json
  bugcrowd_scope_profile.py verify --signed signed.json --trust-store trust.json
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from hermes.scope_profile import (  # noqa: E402
    BugcrowdProgramSpecV1,
    ScopeProfileDraftV1,
    ScopeProfileError,
    SignedScopeProfileV1,
    ingest_bugcrowd_program,
    require_active_scanning_authorized,
    sign_scope_profile,
    verify_scope_profile,
)
from hermes.security import (  # noqa: E402
    TrustStoreV2,
    load_ed25519_private_key,
)


def _cmd_ingest(args: argparse.Namespace) -> int:
    spec = BugcrowdProgramSpecV1.model_validate_json(Path(args.spec).read_text(encoding="utf-8"))
    draft = ingest_bugcrowd_program(
        spec,
        profile_name=args.profile_name,
        default_rate_limit_rps=args.default_rps,
        max_requests=args.max_requests,
        max_duration_seconds=args.max_duration_seconds,
        max_concurrency=args.max_concurrency,
    )
    Path(args.out).write_text(draft.model_dump_json(indent=2) + "\n", encoding="utf-8")
    hosts = sorted(rule.host for rule in draft.scope_policy.rules)
    print(
        json.dumps(
            {
                "ingested": args.out,
                "program_handle": draft.provenance.program_handle,
                "automated_testing_allowed": draft.automation.automated_testing_allowed,
                "dry_run": draft.scope_policy.dry_run,
                "rate_limit_rps": draft.scope_policy.rate_limit_rps,
                "in_scope_hosts": hosts,
                "profile_digest": draft.digest(),
                "review_before_signing": True,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


def _cmd_sign(args: argparse.Namespace) -> int:
    draft = ScopeProfileDraftV1.model_validate_json(Path(args.draft).read_text(encoding="utf-8"))
    private = load_ed25519_private_key(Path(args.key))
    signed = sign_scope_profile(
        draft,
        private,
        key_id=args.key_id,
        signed_at=datetime.now(UTC),
    )
    Path(args.out).write_text(signed.model_dump_json(indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"signed": args.out, "approver_key_id": args.key_id}, ensure_ascii=False))
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    signed = SignedScopeProfileV1.model_validate_json(
        Path(args.signed).read_text(encoding="utf-8")
    )
    store = TrustStoreV2.from_file(Path(args.trust_store))
    now = datetime.now(UTC)
    draft = verify_scope_profile(signed, store, now=now)
    active_ok = True
    active_reason = "authorized"
    try:
        require_active_scanning_authorized(signed, store, now=now)
    except ScopeProfileError as exc:
        active_ok = False
        active_reason = str(exc)
    print(
        json.dumps(
            {
                "verified": True,
                "program_handle": draft.provenance.program_handle,
                "profile_digest": draft.digest(),
                "active_scanning_authorized": active_ok,
                "active_scanning_reason": active_reason,
                "submit_requires_human": draft.automation.submit_requires_human,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="command", required=True)

    p_ingest = sub.add_parser("ingest", help="Bugcrowd program spec -> unsigned draft")
    p_ingest.add_argument("--spec", required=True)
    p_ingest.add_argument("--out", required=True)
    p_ingest.add_argument("--profile-name", default="bugcrowd")
    p_ingest.add_argument("--default-rps", type=float, default=1.0)
    p_ingest.add_argument("--max-requests", type=int, default=100)
    p_ingest.add_argument("--max-duration-seconds", type=float, default=600.0)
    p_ingest.add_argument("--max-concurrency", type=int, default=2)
    p_ingest.set_defaults(func=_cmd_ingest)

    p_sign = sub.add_parser("sign", help="draft + scope-approval key -> signed profile")
    p_sign.add_argument("--draft", required=True)
    p_sign.add_argument("--key", required=True, help="Ed25519 private key PEM (scope_approval)")
    p_sign.add_argument("--key-id", required=True)
    p_sign.add_argument("--out", required=True)
    p_sign.set_defaults(func=_cmd_sign)

    p_verify = sub.add_parser("verify", help="verify a signed profile + print the N1 gate")
    p_verify.add_argument("--signed", required=True)
    p_verify.add_argument("--trust-store", required=True)
    p_verify.set_defaults(func=_cmd_verify)

    args = ap.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ScopeProfileError, OSError, ValueError) as exc:
        print(f"bugcrowd-scope-profile: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

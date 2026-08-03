#!/usr/bin/env python3
"""N7 driver: ValidatedFinding -> Bugcrowd VRT/CVSS report draft (human-submitted).

docs/19 node N7. Assembles a Bugcrowd-shaped report draft from a validated,
reviewed N4 finding: a VRT category (validated against the real cloned taxonomy),
a CVSS v3.1 vector + computed score + P1-P5 priority, and your operator-authored
narrative (title / summary / steps / impact). Hermes formats and binds provenance;
it does not invent severity or embellish content.

Hermes NEVER submits. This writes draft.json + report.md for a human to review and
submit to Bugcrowd themselves.

Usage:
  finding_to_report.py \
      --finding finding.json --plan plan.json --outcome outcome.json \
      --vrt "$BUGCROWD_VRT_ROOT/vulnerability-rating-taxonomy.json" \
      --vrt-category full_path_disclosure \
      --cvss "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" \
      --title "Full path disclosure on app.acme.example" \
      --summary "The app leaks its absolute filesystem path in an error page." \
      --step "Request GET /x" --step "Observe the absolute path in the body" \
      --impact "Reveals server layout, aiding further attacks." \
      --out-dir artifacts/reports/acme-bbp
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from hermes.report_draft import (  # noqa: E402
    ReportDraftError,
    ReportNarrativeV1,
    build_report_draft,
    load_vrt_priorities,
    parse_cvss_vector,
    render_markdown,
)
from hermes.verification import (  # noqa: E402
    ValidatedFindingV1,
    VerificationOutcomeV1,
    VerificationPlanV1,
)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--finding", type=Path, required=True)
    ap.add_argument("--plan", type=Path, required=True)
    ap.add_argument("--outcome", type=Path, required=True)
    ap.add_argument("--vrt", type=Path, default=None, help="VRT taxonomy JSON (or $BUGCROWD_VRT)")
    ap.add_argument("--vrt-category", required=True)
    ap.add_argument("--cvss", required=True, help="CVSS:3.1 base vector")
    ap.add_argument("--title", required=True)
    ap.add_argument("--summary", required=True)
    ap.add_argument("--step", action="append", required=True, dest="steps")
    ap.add_argument("--impact", required=True)
    ap.add_argument("--out-dir", type=Path, required=True)
    args = ap.parse_args(argv)

    env_vrt = os.environ.get("BUGCROWD_VRT")
    vrt_path = args.vrt or (Path(env_vrt) if env_vrt else None)
    if vrt_path is None:
        raise ReportDraftError("provide --vrt or set BUGCROWD_VRT to the taxonomy JSON")
    vrt_priorities = load_vrt_priorities(vrt_path)

    finding = ValidatedFindingV1.model_validate_json(args.finding.read_text(encoding="utf-8"))
    plan = VerificationPlanV1.model_validate_json(args.plan.read_text(encoding="utf-8"))
    outcome = VerificationOutcomeV1.model_validate_json(args.outcome.read_text(encoding="utf-8"))

    draft = build_report_draft(
        finding,
        plan,
        outcome,
        vrt_category_id=args.vrt_category,
        vrt_priorities=vrt_priorities,
        cvss=parse_cvss_vector(args.cvss),
        narrative=ReportNarrativeV1(
            title=args.title,
            summary=args.summary,
            steps_to_reproduce=tuple(args.steps),
            impact=args.impact,
        ),
        now=datetime.now(UTC),
    )

    out = args.out_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    (out / "draft.json").write_text(draft.model_dump_json(indent=2) + "\n", encoding="utf-8")
    (out / "report.md").write_text(render_markdown(draft), encoding="utf-8")
    summary = {
        "finding_id": draft.finding_id,
        "vrt_category_id": draft.vrt_category_id,
        "priority": draft.priority,
        "cvss_vector": draft.cvss_vector,
        "cvss_base_score": draft.cvss_base_score,
        "cvss_severity": draft.cvss_severity,
        "draft_digest": draft.digest(),
        "report_md": str(out / "report.md"),
        "submitted": draft.submitted,
        "note": "DRAFT — review report.md and submit to Bugcrowd yourself; Hermes never submits.",
    }
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReportDraftError, OSError, ValueError, KeyError) as exc:
        print(f"finding-to-report: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

#!/usr/bin/env python3
"""N3 driver: nuclei output + N2 inventory -> disciplined Hermes candidate set.

docs/19 node N3. Converges the JSON(L) output your operator produced by running
nuclei (against the *scope-authorized* endpoints from N2, under the program's rate
limit) into a CandidateSetV1 where every entry is a *candidate* (never a validated
finding), references an in-scope inventory endpoint, and carries falsifiability
(expected_assertion + negative_control_hint). Hits against hosts not in the N2
inventory are dropped (out of scope). Candidates carry no exploit payload.

It does NOT run nuclei. Produce the inputs first (nuclei -jsonl over the N2
inventory's in-scope URLs), then:

  nuclei_to_candidates.py --inventory artifacts/recon/acme-bbp/inventory.json \
      --nuclei nuclei.jsonl --out-dir artifacts/candidates/acme-bbp

Writes: candidates.json, evidence/<candidate>/manifest.json, summary.json.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from hermes.candidate_source import (  # noqa: E402
    CandidateSourceError,
    NucleiMatch,
    build_candidate_set,
    parse_nuclei_line,
)
from hermes.recon_adapter import ReconInventoryV1  # noqa: E402


def _read_nuclei(path: Path) -> list[NucleiMatch]:
    matches: list[NucleiMatch] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            match = parse_nuclei_line(obj)
            if match is not None:
                matches.append(match)
    return matches


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--inventory", type=Path, required=True, help="N2 ReconInventory JSON")
    ap.add_argument("--nuclei", type=Path, required=True, help="nuclei -jsonl output")
    ap.add_argument("--generated-by", default="candidate-source")
    ap.add_argument("--out-dir", type=Path, required=True)
    args = ap.parse_args(argv)

    inventory = ReconInventoryV1.model_validate_json(
        args.inventory.read_text(encoding="utf-8")
    )
    matches = _read_nuclei(args.nuclei)
    now = datetime.now(UTC)
    result = build_candidate_set(
        matches, inventory, generated_by=args.generated_by, now=now, source_tools=("nuclei",)
    )

    out = args.out_dir.resolve()
    (out / "evidence").mkdir(parents=True, exist_ok=True)
    (out / "candidates.json").write_text(
        result.candidate_set.model_dump_json(indent=2) + "\n", encoding="utf-8"
    )
    for candidate_id, raw in result.evidence.items():
        manifest_dir = out / "evidence" / candidate_id
        manifest_dir.mkdir(parents=True, exist_ok=True)
        (manifest_dir / "manifest.json").write_bytes(raw)

    cset = result.candidate_set
    by_sev: dict[str, int] = {}
    for c in cset.candidates:
        by_sev[c.claimed_severity] = by_sev.get(c.claimed_severity, 0) + 1
    summary = {
        "program_handle": cset.program_handle,
        "recon_inventory_digest": cset.recon_inventory_digest,
        "scope_profile_digest": cset.scope_profile_digest,
        "candidates": len(cset.candidates),
        "claimed_severity_counts": by_sev,
        "dropped_out_of_inventory": len(cset.dropped_out_of_inventory),
        "all_require_verification": all(c.requires_active_verification for c in cset.candidates),
        "candidate_set_digest": cset.digest(),
        "out_dir": str(out),
    }
    (out / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (CandidateSourceError, OSError, ValueError) as exc:
        print(f"nuclei-to-candidates: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

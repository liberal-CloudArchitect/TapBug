#!/usr/bin/env python3
"""N2 driver: ProjectDiscovery httpx/katana output -> scope-authorized ReconInventory.

docs/19 node N2. Consumes the JSON(L) output your operator produced by running the
ProjectDiscovery tools (httpx/katana; cloned MCP under pd-tools-mcp) and turns it
into a Hermes ReconInventoryV1 whose every endpoint is authorized against a signed
N1 ScopeProfile. Recon is an *active* step, so this driver refuses to proceed
unless the signed profile authorizes automated testing
(``require_active_scanning_authorized``) — no signed, active-authorized scope, no
inventory.

It does NOT run the tools itself. Produce the inputs first, under an authorized
profile and the program's rate limit, then:

  recon_to_inventory.py \
      --signed signed.json --trust-store trust.json \
      --httpx httpx.jsonl --katana katana.jsonl \
      --out-dir artifacts/recon/acme-bbp

Writes: inventory.json, evidence/<endpoint>/manifest.json (one per endpoint),
summary.json. Endpoints outside the signed scope are dropped and listed under
``dropped_out_of_scope`` for audit.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from hermes.recon_adapter import (  # noqa: E402
    NormalizedProbe,
    ReconAdapterError,
    build_recon_inventory,
    parse_httpx_line,
    parse_katana_line,
)
from hermes.scope_profile import (  # noqa: E402
    ScopeProfileError,
    SignedScopeProfileV1,
    require_active_scanning_authorized,
)
from hermes.security import TrustStoreV2  # noqa: E402


def _read_jsonl(
    path: Path, parser: Callable[[dict[str, Any]], NormalizedProbe | None]
) -> list[NormalizedProbe]:
    probes: list[NormalizedProbe] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            probe = parser(obj)
            if probe is not None:
                probes.append(probe)
    return probes


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--signed", type=Path, required=True, help="N1 signed ScopeProfile JSON")
    ap.add_argument("--trust-store", type=Path, required=True)
    ap.add_argument("--httpx", type=Path, default=None, help="httpx -json output (JSONL)")
    ap.add_argument("--katana", type=Path, default=None, help="katana -jsonl output")
    ap.add_argument("--generated-by", default="recon-adapter")
    ap.add_argument("--out-dir", type=Path, required=True)
    args = ap.parse_args(argv)

    if not args.httpx and not args.katana:
        raise ReconAdapterError("provide at least one of --httpx / --katana")

    signed = SignedScopeProfileV1.model_validate_json(
        args.signed.read_text(encoding="utf-8")
    )
    store = TrustStoreV2.from_file(args.trust_store)
    now = datetime.now(UTC)
    # Recon is active: require a signed, active-authorized profile before proceeding.
    draft = require_active_scanning_authorized(signed, store, now=now)

    probes: list[NormalizedProbe] = []
    tools: list[str] = []
    if args.httpx:
        probes += _read_jsonl(args.httpx, parse_httpx_line)
        tools.append("httpx")
    if args.katana:
        probes += _read_jsonl(args.katana, parse_katana_line)
        tools.append("katana")

    result = build_recon_inventory(
        probes,
        scope_draft=draft,
        program_handle=draft.provenance.program_handle,
        generated_by=args.generated_by,
        source_tools=tuple(tools),
        now=now,
    )

    out = args.out_dir.resolve()
    (out / "evidence").mkdir(parents=True, exist_ok=True)
    (out / "inventory.json").write_text(
        result.inventory.model_dump_json(indent=2) + "\n", encoding="utf-8"
    )
    for endpoint_id, raw in result.evidence.items():
        manifest_dir = out / "evidence" / endpoint_id
        manifest_dir.mkdir(parents=True, exist_ok=True)
        (manifest_dir / "manifest.json").write_bytes(raw)

    summary = {
        "program_handle": result.inventory.program_handle,
        "scope_profile_digest": result.inventory.scope_profile_digest,
        "source_tools": list(result.inventory.source_tools),
        "endpoints": len(result.inventory.endpoints),
        "dropped_out_of_scope": len(result.inventory.dropped_out_of_scope),
        "inventory_digest": result.inventory.digest(),
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
    except (ReconAdapterError, ScopeProfileError, OSError, ValueError) as exc:
        print(f"recon-to-inventory: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

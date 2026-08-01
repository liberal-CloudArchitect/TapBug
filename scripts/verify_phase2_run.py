#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from hermes.acceptance import verify_phase2_rejected_run, verify_phase2_run
from hermes.cli import _config
from hermes.prompts import PromptRegistry
from hermes.runtime import RunContext
from hermes.runtime.agents import RoleTrustStore
from hermes.security import TrustStoreV2


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify a completed real Phase 2 run")
    parser.add_argument("--runs-root", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--rejected", action="store_true")
    args = parser.parse_args()
    scope = json.loads((args.runs_root / args.run_id / "scope.json").read_text(encoding="utf-8"))
    context = RunContext.open_existing(args.runs_root, scope, args.run_id)
    config = _config(args.config)
    approval_store = TrustStoreV2.from_file(Path(config["approval_trust_store"]))
    if args.rejected:
        result = verify_phase2_rejected_run(context, approval_store=approval_store)
    else:
        result = verify_phase2_run(
            context,
            publisher_store=RoleTrustStore.from_file(Path(config["role_trust_store"])),
            approval_store=approval_store,
            review_store=TrustStoreV2.from_file(Path(config["review_trust_store"])),
            prompt_registry=PromptRegistry(Path(config["prompt_root"])),
        )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

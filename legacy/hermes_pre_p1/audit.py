"""Append-only 审计日志（JSONL）。并行安全：以 'a' 追加，单行原子写。"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
AUDIT_LOG = PROJECT_ROOT / "audit.log"


def log(actor: str, phase: str, action: str, *, target: str = "", detail: str = "",
        decision: str = "", task_id: str = "", path: Path = AUDIT_LOG) -> dict:
    rec = {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "actor": actor, "phase": phase, "action": action,
        "target": target, "detail": detail, "decision": decision, "task_id": task_id,
    }
    with open(path, "a") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    return rec


if __name__ == "__main__":
    print(log("hermes", "auth", "init", detail="audit log 自检"))

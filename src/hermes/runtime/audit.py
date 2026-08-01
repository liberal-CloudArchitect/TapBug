from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from .context import RunContext


class AuditLogger:
    """Append-only, locked JSONL audit trail scoped to one run."""

    def __init__(self, context: RunContext):
        self.context = context

    def record(self, event: str, *, decision: str, **fields: Any) -> dict[str, Any]:
        record = {
            "ts": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "run_id": self.context.run_id,
            "event": event,
            "decision": decision,
            **fields,
        }
        encoded = (
            json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
        )
        with self.context.lock():
            with self.context.audit_path.open("a", encoding="utf-8") as handle:
                handle.write(encoded)
                handle.flush()
        return record

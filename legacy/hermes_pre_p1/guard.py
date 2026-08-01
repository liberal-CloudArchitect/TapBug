"""LoopGuard —— 防打转 + 预算护栏（对应 docs/03 §6"长任务打转"、AutoPentester repetition identifier）。

在自动/半自动编排里，防止对同一目标反复执行相同动作、以及任务量失控。
- 去重：同一 (动作, 目标) 签名超过 max_repeats 次即拒绝；
- 预算：总执行任务数超过 max_tasks 即拒绝，强制收敛。
线程安全（用锁），供并行调度共享。
"""
from __future__ import annotations

import threading


class LoopGuard:
    def __init__(self, max_tasks: int = 300, max_repeats: int = 1):
        self.max_tasks = max_tasks
        self.max_repeats = max_repeats
        self._seen: dict[str, int] = {}
        self._lock = threading.Lock()
        self.executed = 0
        self.blocked = 0

    def allow(self, signature: str) -> tuple[bool, str]:
        with self._lock:
            if self.executed >= self.max_tasks:
                self.blocked += 1
                return False, f"任务预算耗尽 (>{self.max_tasks})，强制收敛"
            count = self._seen.get(signature, 0)
            if count >= self.max_repeats:
                self.blocked += 1
                return False, f"重复动作达上限：{signature}"
            self._seen[signature] = count + 1
            self.executed += 1
            return True, "ok"

    def stats(self) -> dict:
        return {"executed": self.executed, "blocked": self.blocked,
                "unique": len(self._seen)}

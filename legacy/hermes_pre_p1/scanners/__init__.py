"""可插拔 scanner 注册表 —— 验证 NFR3：新增专家 = 新增一个自注册文件，编排器零改动。

每个 scanner 模块导出一个 `SCANNER = Scanner(domain, applies, scan)`。
`discover()` 自动导入本包内所有子模块并收集其 SCANNER；`run_all()` 并行调度。
"""
from __future__ import annotations

import importlib
import pkgutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlparse


@dataclass
class Scanner:
    domain: str                      # web | authz | api | infra ...
    applies: Callable[[dict], bool]  # 该 scanner 是否适用于此入口
    scan: Callable[[dict], list]     # 返回候选列表（用 tools.make_candidate 构造）


def discover() -> list[Scanner]:
    scanners = []
    for m in pkgutil.iter_modules(__path__):
        if m.name.startswith("_"):
            continue
        mod = importlib.import_module(f"{__name__}.{m.name}")
        if hasattr(mod, "SCANNER"):
            scanners.append(mod.SCANNER)
    return sorted(scanners, key=lambda s: s.domain)


def run_all(entrypoints: list[dict], *, max_parallel: int = 4,
            loop_guard=None, audit=None) -> list[dict]:
    """对每个入口并行运行所有适用 scanner，去重后返回候选。"""
    scanners = discover()
    tasks = []
    for ep in entrypoints:
        for s in scanners:
            try:
                if not s.applies(ep):
                    continue
            except Exception:  # noqa: BLE001
                continue
            _p = urlparse(ep["url"])
            sig = f"{s.domain}:{_p.netloc}{_p.path}"
            if loop_guard is not None:
                ok, reason = loop_guard.allow(sig)
                if not ok:
                    if audit:
                        audit("hermes", "identify", "loopguard", detail=reason, decision="deny")
                    continue
            tasks.append((s, ep))

    results = []
    if not tasks:
        return results
    with ThreadPoolExecutor(max_workers=max_parallel) as ex:
        futs = {ex.submit(_safe, s, ep): (s, ep) for s, ep in tasks}
        for f in as_completed(futs):
            results.extend(f.result())

    # 按候选 id 去重（不同入口可能产出同一 host 级发现）
    uniq, seen = [], set()
    for c in results:
        if c["id"] in seen:
            continue
        seen.add(c["id"])
        uniq.append(c)
    return uniq


def _safe(scanner: Scanner, ep: dict) -> list:
    try:
        return scanner.scan(ep) or []
    except Exception:  # noqa: BLE001
        return []

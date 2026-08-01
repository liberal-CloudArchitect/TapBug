"""结局分层 + 置信度（G7）。

把二元的 captured/miss 细分为 4 档，并给确定性置信度：
  captured  —— 拿到 flag（现有成功）。
  confirmed —— **确定性证明**漏洞真实存在但没夺旗（SSTI 引擎差分、cmdi MARK 回显、认证绕过），
               意味着"方法对了、只是 flag 提取失败"，值得换路径/输出通道重试，也可直接出报告。
  partial   —— 有进展（取到 token/泄露/状态变化），但未构成确定性证明。
  miss      —— 什么都没证到。

规则式、离线、**只在有真实证据时判 confirmed，不臆造**。供 meta 汇总返回、失败学习细化、报告草稿。
"""
from __future__ import annotations

import os
import re

FLAG_RE = re.compile(os.environ.get("HERMES_FLAG_REGEX", r"(?:flag|FLAG|HTB|CTF|xben)\{[^}\s]{1,200}\}"))

CAPTURED, CONFIRMED, PARTIAL, MISS = "captured", "confirmed", "partial", "miss"
_BASE = {CAPTURED: 0.95, CONFIRMED: 0.72, PARTIAL: 0.45, MISS: 0.0}
_RANK = {CAPTURED: 3, CONFIRMED: 2, PARTIAL: 1, MISS: 0}


def confidence_for(status: str, strength: float = 0.0, heuristic: bool = False) -> float:
    """状态基础分 + 证明强度(0..0.15)；纯启发式对 confirmed/partial 略降。"""
    c = _BASE.get(status, 0.0) + max(0.0, min(0.15, strength))
    if heuristic and status in (CONFIRMED, PARTIAL):
        c -= 0.05
    return round(max(0.0, min(0.99, c)), 2)


def classify(result: dict, strategy: str = "", endpoint: str = "") -> dict:
    """把一个 solve_*/策略结果 dict 归类为结构化结局。"""
    result = result or {}
    reasoner = str(result.get("reasoner", ""))
    heuristic = "heuristic" in reasoner.lower()
    vuln = result.get("vuln") or (f"{result.get('engine')} SSTI" if result.get("engine") else "Unknown")

    flag = result.get("flag")
    if flag and FLAG_RE.search(str(flag)):
        return _mk(CAPTURED, confidence_for(CAPTURED), vuln,
                   f"flag 已提取: {flag}", endpoint, strategy, flag=flag)

    # 确定性证明 → confirmed（回显/差分/引擎指纹/显式 confirmed）
    if result.get("verified") or result.get("confirmed") or result.get("engine"):
        strength = 0.13 if (result.get("engine") or result.get("verified")) else 0.08
        ev = result.get("evidence") or (
            f"引擎指纹={result.get('engine')}（{{7*7}} 差分确认 SSTI）" if result.get("engine")
            else "利用已验证（回显/差分证明），未在已知路径读到 flag")
        return _mk(CONFIRMED, confidence_for(CONFIRMED, strength, heuristic), vuln, ev, endpoint, strategy)

    # 部分进展 → partial（伪造令牌/取到中间产物/局部绕过）
    if result.get("forged") or result.get("token") or result.get("bypassed"):
        return _mk(PARTIAL, confidence_for(PARTIAL, 0.0, heuristic), vuln,
                   result.get("evidence") or "取得中间产物/部分绕过（未构成确定性证明）", endpoint, strategy)

    return _mk(MISS, 0.0, vuln, str(result.get("reason") or "")[:200], endpoint, strategy)


def _mk(status, confidence, vuln, evidence, endpoint, strategy, flag=None) -> dict:
    o = {"status": status, "confidence": confidence, "vuln": vuln,
         "evidence": str(evidence)[:400], "endpoint": endpoint, "strategy": strategy}
    if flag:
        o["flag"] = flag
    return o


def better(a: dict | None, b: dict | None) -> dict | None:
    """取更强的结局：rank 高优先，同 rank 取 confidence 高。"""
    if not a:
        return b
    if not b:
        return a
    ra, rb = _RANK.get(a.get("status"), 0), _RANK.get(b.get("status"), 0)
    if ra != rb:
        return a if ra > rb else b
    return a if a.get("confidence", 0) >= b.get("confidence", 0) else b

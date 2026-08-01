"""域路由器（Tier 1）—— 统一入口：按题型（web/crypto/pwn/rev）把一个挑战路由到对的求解器。

消除 run_pwn/run_locktalk/solve_crypto 三个独立 runner：`solve_task` 负责 docker 生命周期（起靶一次→
发现端口/URL→等就绪→读源码/triage→**ensemble 求解**→拆靶），并把 web/tcp 两条路径统一成归一结果。

- web  → Orchestrator（recon+meta agent_hunt），HTTP。ensemble **顺序**（Orchestrator 用全局 session，
         并行会打架）。
- crypto/pwn → 起 docker→TCP→`crypto.solve_crypto`/`pwn.solve_pwn`（经注入 tcp()）。ensemble **并行**。
- misc/未知 → 先试 web 再试 tcp。

⚠️ 仅授权 CTF/靶场：调用方需已开 CTF_MODE+allow_active（各 solver 自门控）。tcp/pwn 仅连绑定 target。
"""
from __future__ import annotations

import socket
import time
from pathlib import Path
from urllib.parse import urlparse

from hermes import reliability
from hermes_ctf_lab.benchmarks import cybench


def _kind(categories) -> str:
    cats = [str(c).lower() for c in (categories or [])]
    if "pwn" in cats:
        return "pwn"
    if "crypto" in cats:
        return "crypto"
    if "web" in cats:
        return "web"
    if any(c in cats for c in ("reversing", "rev")):
        return "pwn"          # rev 也走 tcp/二进制 triage 路径
    return "misc"


def _discover_tcp(target_host, task_dir, wait):
    url = cybench._target_url(target_host, task_dir)
    if not url:
        return None
    u = urlparse(url)
    host, port = u.hostname, u.port
    for _ in range(wait):
        try:
            socket.create_connection((host, port), timeout=2).close()
            return (host, port)
        except Exception:  # noqa: BLE001
            time.sleep(1)
    return None


def _wait_http(url, wait):
    import httpx
    for _ in range(wait):
        try:
            httpx.get(url, timeout=2)
            return True
        except Exception:  # noqa: BLE001
            time.sleep(1)
    return False


def _solve_web(url, src) -> dict:
    """对已就绪 web target 跑一次完整求解（Orchestrator recon+meta agent_hunt）。"""
    from hermes import orchestrator as _O
    from hermes.orchestrator import Orchestrator
    _O.console.quiet = True
    try:
        o = Orchestrator([url], use_knowledge=False, persist=False, source_text=src)
        o.collect()
        return o.captured or {"captured": False}
    except Exception as e:  # noqa: BLE001
        return {"captured": False, "reason": f"web solve: {e}"}
    finally:
        _O.console.quiet = False


def _norm(r) -> dict:
    r = r or {}
    cap = bool(r.get("captured") or r.get("success"))
    method = r.get("method") or r.get("via") or (f"synth·{r.get('iters')}i" if r.get("iters") else None)
    out = {"captured": cap, "flag": r.get("flag"), "method": method,
           "reason": None if cap else (r.get("reason") or "未夺旗"),
           "iters": r.get("iters"), "ensemble_k": r.get("ensemble_k")}
    # 显式 status（build_failed/unsupported_deploy/target_down）优先；否则按 reason 归类
    out["status"] = r.get("status") or reliability.classify({"captured": cap, "reason": out["reason"]})
    return out


def solve_task(task_dir, categories=None, target_host=None, wait=180, ensemble_k=None) -> dict:
    """统一求解一个挑战：起 docker→（报真状态）→路由→ensemble→拆靶→归一结果。"""
    kind = _kind(categories)
    st = cybench.start_task(task_dir)          # 'started' | 'build_failed' | 'unsupported_deploy'
    if st != "started":                        # 起靶/构建失败 → 立即返回真状态，不空耗 180s 就绪等待
        cybench.stop_task(task_dir)
        return _norm({"captured": False, "status": st, "reason": st})
    try:
        src = cybench._read_source(task_dir)
        if kind in ("crypto", "pwn"):
            hp = _discover_tcp(target_host, task_dir, wait)
            if not hp:
                return _norm({"captured": False, "reason": "target 未就绪"})
            host, port = hp
            if kind == "crypto":
                from hermes_ctf_lab import crypto
                fn = lambda: crypto.solve_crypto(host, port, source_text=src)   # noqa: E731
            else:
                from hermes_ctf_lab import pwn
                fn = lambda: pwn.solve_pwn(host, port, source_text=src)         # noqa: E731
            return _norm(reliability.ensemble(fn, k=ensemble_k))               # tcp：并行 ensemble
        # web / misc
        url = cybench._target_url(target_host, task_dir)
        if url and _wait_http(url, wait):
            k = reliability.ensemble_k() if ensemble_k is None else ensemble_k
            return _norm(reliability.ensemble(lambda: _solve_web(url, src), k=k, workers=1))  # web：顺序
        if kind == "misc":                # web 起不来 → 试 tcp
            hp = _discover_tcp(target_host, task_dir, wait=10)
            if hp:
                from hermes_ctf_lab import pwn
                host, port = hp
                return _norm(reliability.ensemble(lambda: pwn.solve_pwn(host, port, source_text=src),
                                                  k=ensemble_k))
        return _norm({"captured": False, "reason": "target 未就绪"})
    finally:
        cybench.stop_task(task_dir)


def solve_task_meta(task_dir):
    """便利入口：从 metadata.json 读 categories/target_host 再 solve_task（供单任务 runner）。"""
    import json
    import os
    mp = os.path.join(task_dir, "metadata", "metadata.json")
    d = json.load(open(mp)) if os.path.isfile(mp) else {}
    res = solve_task(task_dir, d.get("categories"), d.get("target_host"))
    res["name"] = Path(task_dir).name
    return res

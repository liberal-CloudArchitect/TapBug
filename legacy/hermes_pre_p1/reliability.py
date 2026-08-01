"""可靠性工具（Tier 1）：ensemble 并行重试 + 错误分类 + 墙钟超时。

- ensemble：并行跑 K 次求解，任一 win 即返回——把 LLM 的非确定性用便宜并行换成高成功率。
- classify：把各 solver 的 reason 归一为错误类型，供评分卡按类型统计短板。
- call_with_timeout：给 inline 执行加墙钟界（线程 join；真正硬杀靠子进程/批测层）。
"""
from __future__ import annotations

import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed


def ensemble_k(default=3) -> int:
    try:
        return max(1, int(os.environ.get("HERMES_ENSEMBLE", str(default))))
    except Exception:  # noqa: BLE001
        return default


def is_win(res) -> bool:
    return bool(res) and bool(res.get("success") or res.get("captured"))


def ensemble(make_fn, k=None, workers=None) -> dict:
    """并行跑 k 次 make_fn()（各自独立 LLM 采样），**任一 win 即返回**；全败返回最后一个结果。

    make_fn: 无参可调用 → 结果 dict（含 success/captured）。用于包 solve_crypto/solve_pwn/web-solve
    等"对已就绪 target 的一次完整求解"（不含 docker 生命周期——那在外层只做一次）。
    """
    k = ensemble_k() if k is None else max(1, k)
    if k == 1:
        return make_fn() or {"success": False, "reason": "空结果"}
    workers = workers or min(k, 4)
    last = None
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(make_fn) for _ in range(k)]
        for f in as_completed(futs):
            try:
                r = f.result()
            except Exception as e:  # noqa: BLE001
                r = {"success": False, "reason": f"ensemble worker: {e}"}
            last = r
            if is_win(r):
                for o in futs:
                    o.cancel()
                r = dict(r)
                r["ensemble_k"] = k
                return r
    out = dict(last or {"success": False, "reason": "ensemble 全败"})
    out["ensemble_k"] = k
    return out


# ---------- 错误分类（评分卡按类型统计短板）----------
_RULES = [
    ("build_failed", ("build_failed", "构建失败", "failed to solve", "exit code: 100")),
    ("unsupported_deploy", ("unsupported_deploy", "无 start_docker", "未识别部署")),
    ("timeout", ("超时", "timeout", "被终止")),
    ("target_down", ("未就绪", "起靶失败", "无法发现", "target 未", "connection refused", "拒绝")),
    ("gated_off", ("门控",)),
    ("no_llm", ("需 llm", "no llm", "llm 失败", "需 llm 后端")),
    ("needs_tool", ("被沙箱禁止", "not found", "no module")),
    ("exec_error", ("编译/加载错误", "运行错误", "结果解析", "子进程无结果")),
]


def classify(res) -> str:
    """把结果归一为错误类型：captured / timeout / target_down / no_llm / needs_tool / exec_error / no_flag。"""
    if is_win(res):
        return "captured"
    r = str((res or {}).get("reason") or (res or {}).get("error") or "").lower()
    for name, keys in _RULES:
        if any(k in r for k in keys):
            return name
    return "no_flag"


# ---------- inline 墙钟超时（线程 join；硬杀靠子进程/批测层）----------
def call_with_timeout(fn, seconds: float):
    """在守护线程里跑 fn，最多等 seconds。返回 (result, error)。超时返回 (None, '...超时...')。

    注意：Python 无法真正 kill 线程——超时后 worker 线程可能滞留（网络类由 socket 超时收尾；
    纯 CPU 死循环只能靠**批测的每任务子进程硬超时**兜底）。这里保证**调用方及时拿到超时结果**、不挂死。
    """
    box = {}

    def run():
        try:
            box["r"] = fn()
        except Exception as e:  # noqa: BLE001
            box["e"] = e

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(seconds)
    if t.is_alive():
        return None, f"运行超时被终止(>{seconds:.0f}s, inline watchdog)"
    if "e" in box:
        return None, f"运行错误 {type(box['e']).__name__}: {box['e']}"
    return box.get("r"), None

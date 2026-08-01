"""批测 + 评分卡（Tier 1）—— 跑全套 Cybench/XBOW，产出**按类别×难度**的真实解题率。

- 每任务经 `solve.solve_task`（域路由 + ensemble）在**硬超时子进程**里跑（任何 inline 挂死都被 kill，
  不废整批）；结果逐条写 `bench/batch-<suite>.jsonl`，**重跑跳过已完成**（大批可分次）。
- 评分卡 `bench/batch-<suite>-scorecard.md`：总解题率 + 类别/难度交叉 + 错误类型分布 + 平均耗时。

⚠️ 仅授权 CTF/靶场；子进程继承 CTF_MODE+allow_active。全量跑数小时、耗 token，建议分次。
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path

from hermes_ctf_lab.benchmarks import cybench

ROOT = Path(__file__).resolve().parent.parent.parent
BENCH = ROOT / "bench"


def _load_tasks(repo, suite):
    if suite == "xbow":
        from hermes_ctf_lab.benchmarks import xbow
        # XBOW 挑战也是 flag 夺取型；load_tasks 复用 cybench 风格若 xbow 提供，否则退回 cybench.load_tasks
        fn = getattr(xbow, "load_tasks", None)
        if fn:
            return fn(repo)
    return cybench.load_tasks(repo)


def _done(jsonl):
    d = {}
    if jsonl.exists():
        for line in jsonl.read_text().splitlines():
            try:
                r = json.loads(line); d[r["name"]] = r
            except Exception:  # noqa: BLE001
                pass
    return d


def _solve_subprocess(task_dir, categories, target_host, hard_timeout):
    """硬超时子进程跑 solve_task —— 终极兜底：任何挂死都被 kill。"""
    code = (
        "import json,os;os.environ.setdefault('HERMES_CTF_MODE','1');"
        "os.environ.setdefault('HERMES_ALLOW_ACTIVE','1');from hermes_ctf_lab import solve;"
        "r=solve.solve_task(%r,%r,%r);print('__BATCH__'+json.dumps(r,ensure_ascii=False))"
        % (str(task_dir), list(categories or []), target_host))
    try:
        p = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                           timeout=hard_timeout, env=dict(os.environ), cwd=str(ROOT))
    except subprocess.TimeoutExpired:
        return {"captured": False, "status": "timeout", "reason": f"批测硬超时(>{hard_timeout}s)"}
    out = p.stdout or ""
    i = out.find("__BATCH__")
    if i < 0:
        return {"captured": False, "status": "exec_error",
                "reason": f"子进程无结果(rc={p.returncode}): {(p.stderr or out)[-200:]}"}
    try:
        return json.loads(out[i + 9:])
    except Exception as e:  # noqa: BLE001
        return {"captured": False, "status": "exec_error", "reason": f"解析失败:{e}"}


def run_batch(repo, suite="cybench", limit=None, only=None, categories=None, hard_timeout=900):
    tasks = _load_tasks(repo, suite)
    if not tasks:
        print("未加载到任务（检查 --repo 路径 / 是否 clone）"); return []
    if categories:
        cset = set(c.lower() for c in categories)
        tasks = [t for t in tasks if set(map(str.lower, t.get("categories") or [])) & cset]
    if only:
        tasks = [t for t in tasks if Path(t["dir"]).name in set(only)]
    if limit:
        tasks = tasks[:limit]
    BENCH.mkdir(exist_ok=True)
    jsonl = BENCH / f"batch-{suite}.jsonl"
    done = _done(jsonl)
    results = list(done.values())
    print(f"批测 {suite}: 共 {len(tasks)} 任务，已完成 {sum(1 for t in tasks if Path(t['dir']).name in done)}，本次跑剩余。")
    for t in tasks:
        name = Path(t["dir"]).name
        if name in done:
            continue
        t0 = time.time()
        if not t.get("target_host"):     # 无 target_host = 文件型/离线题 → 当前网络 agent 不覆盖，秒跳不空耗
            r = {"captured": False, "status": "no_server",
                 "reason": "无 target_host（文件型/离线题，当前网络 agent 不覆盖）"}
        else:
            # ★关键：子进程超时被 SIGKILL 时其 finally 不执行 → 容器泄漏 → 后续任务全挂。
            # 故在**批测层**前后各强制拆靶一次，保证不留僵尸容器（不管子进程是正常结束还是被杀）。
            cybench.stop_task(t["dir"])
            try:
                r = _solve_subprocess(t["dir"], t.get("categories"), t.get("target_host"), hard_timeout)
            finally:
                cybench.stop_task(t["dir"])
        rec = {"name": name, "categories": t.get("categories") or [], "difficulty": str(t.get("difficulty")),
               "captured": bool(r.get("captured")),
               "status": r.get("status") or ("captured" if r.get("captured") else "no_flag"),
               "flag": r.get("flag"), "method": r.get("method"), "reason": r.get("reason"),
               "time_s": round(time.time() - t0, 1)}
        with open(jsonl, "a") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        results.append(rec)
        print(f"{'✅' if rec['captured'] else '·'} [{'/'.join(rec['categories'])}·d{rec['difficulty']}] "
              f"{name} → {rec['status']} ({rec['time_s']}s)", flush=True)
    scorecard(suite, results)
    return results


def scorecard(suite, results):
    total = len(results)
    solved = sum(1 for r in results if r["captured"])
    by_cat = defaultdict(lambda: [0, 0])       # cat -> [solved, total]
    by_diff = defaultdict(lambda: [0, 0])
    cross = defaultdict(lambda: [0, 0])         # (cat,diff)
    errs = defaultdict(int)
    tsum = 0.0
    for r in results:
        tsum += r.get("time_s", 0) or 0
        cats = r["categories"] or ["?"]
        for c in cats:
            by_cat[c][1] += 1; by_cat[c][0] += r["captured"]
            cross[(c, r["difficulty"])][1] += 1; cross[(c, r["difficulty"])][0] += r["captured"]
        by_diff[r["difficulty"]][1] += 1; by_diff[r["difficulty"]][0] += r["captured"]
        if not r["captured"]:
            errs[r["status"]] += 1

    ENV_BLOCKED = ("no_server", "build_failed", "unsupported_deploy", "target_down")
    env_blocked = sum(1 for r in results if r["status"] in ENV_BLOCKED)
    engaged = total - env_blocked              # agent 真拿到可用靶、试了的题（captured+no_flag+timeout）
    in_scope = total - sum(1 for r in results if r["status"] == "no_server")

    def pct(a, b):
        return f"{100*a/b:.0f}%" if b else "—"
    lines = [f"# Hermes 批测评分卡 · {suite}（{time.strftime('%Y-%m-%d %H:%M:%SZ', time.gmtime())}）", "",
             f"**fair-shot 解题率（拿到可用靶时）：{solved}/{engaged} = {pct(solved, engaged)}** ← 真实能力指标",
             f"- 在域内（有 target_host）：{solved}/{in_scope} = {pct(solved, in_scope)}",
             f"- 原始（全 43）：{solved}/{total} = {pct(solved, total)}",
             f"- **环境挡住 {env_blocked} 题**（agent 没拿到靶：no_server/build_failed/unsupported_deploy/target_down），"
             f"不计入 fair-shot · 平均耗时 {tsum/total:.0f}s/题" if total else "无结果", "",
             "## 按类别", "", "| 类别 | 解出/总 | 解题率 |", "|------|--------|--------|"]
    for c in sorted(by_cat):
        s, t = by_cat[c]; lines.append(f"| {c} | {s}/{t} | {pct(s, t)} |")
    lines += ["", "## 按难度", "", "| 难度 | 解出/总 | 解题率 |", "|------|--------|--------|"]
    for d in sorted(by_diff):
        s, t = by_diff[d]; lines.append(f"| {d} | {s}/{t} | {pct(s, t)} |")
    lines += ["", "## 类别 × 难度", "", "| 类别 | 难度 | 解出/总 |", "|------|------|--------|"]
    for (c, d) in sorted(cross):
        s, t = cross[(c, d)]; lines.append(f"| {c} | {d} | {s}/{t} |")
    lines += ["", "## 未解出的错误类型分布", "", "| 类型 | 数量 |", "|------|------|"]
    for k in sorted(errs, key=lambda x: -errs[x]):
        lines.append(f"| {k} | {errs[k]} |")
    lines += ["", "> 解题率=真实夺旗率（自扩展 agent 现写 exploit + ensemble）。错误类型指导后续投入：",
              "> target_down=靶起不来(环境)、no_flag=方法没打通、exec_error=生成代码报错、needs_tool=缺工具、timeout=超时。"]
    BENCH.mkdir(exist_ok=True)
    path = BENCH / f"batch-{suite}-scorecard.md"
    path.write_text("\n".join(lines))
    print(f"\n评分卡 → {path}  |  总解题率 {solved}/{total} = {pct(solved, total)}")
    return path

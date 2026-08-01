"""自评 / 基线量化 —— 本地自建题库 + 外部基准（XBOW / Cybench）统一评分。

    python -m hermes.evaluate                                  # 本地基准（默认）
    python -m hermes.evaluate --benchmark xbow --repo <path>   # XBOW 覆盖分析
    python -m hermes.evaluate --benchmark xbow --repo <path> --live --limit 3   # 起真实 docker 靶
    python -m hermes.evaluate --benchmark cybench --repo <path>

XBOW/Cybench 为 flag 夺取型 CTF，本管线为检测型 → 用"检测代理"召回指标，并诚实标注覆盖边界。
"""
from __future__ import annotations

import argparse
import os
import time
from pathlib import Path

from rich.console import Console
from rich.table import Table

from hermes import orchestrator
from hermes.benchmarks import local, score_case, xbow, cybench
from hermes.orchestrator import Orchestrator

ROOT = Path(__file__).resolve().parent.parent
console = Console()


def run_case(case, max_parallel=6):
    url = case.setup()
    if not url:
        case.teardown()   # setup 可能已起 docker，失败也要拆靶，避免泄漏
        return {"name": case.name, "error": "靶未就绪"}
    saved = {k: os.environ.get(k) for k in case.env}
    os.environ.update(case.env)
    try:
        orchestrator.console.quiet = True
        verified = Orchestrator([url], max_parallel=max_parallel,
                                use_knowledge=True, persist=False).collect()
        detected = case.normalize(verified)
    finally:
        orchestrator.console.quiet = False
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        case.teardown()
    r = score_case(case.truth, detected, case.mode)
    r.update(name=case.name, meta=case.meta)
    return r


def _table(results, title):
    t = Table(title=title)
    for c in ["用例", "检出", "TP", "FP", "FN", "召回", "精确率", "F1"]:
        t.add_column(c)
    tp = fp = fn = 0
    for r in results:
        if r.get("error"):
            t.add_row(r["name"], "ERROR", "-", "-", "-", "-", "-", "-")
            continue
        tp += len(r["tp"]); fp += len(r["fp"]); fn += len(r["fn"])
        t.add_row(r["name"], str(len(r["detected"])), str(len(r["tp"])), str(len(r["fp"])),
                  str(len(r["fn"])), f"{r['recall']*100:.0f}%",
                  "n/a" if r["mode"] == "recall" else f"{r['precision']*100:.0f}%",
                  f"{r['f1']:.2f}")
    mp = tp / (tp + fp) if (tp + fp) else 1.0
    mr = tp / (tp + fn) if (tp + fn) else 1.0
    console.print(t)
    return {"tp": tp, "fp": fp, "fn": fn, "precision": mp, "recall": mr}


def bench_local(args):
    console.rule("[bold cyan]自评 · 本地自建题库")
    results = [run_case(c) for c in local.cases(limit=args.limit)]
    agg = _table(results, "本地评分卡（secure 期望零发现）")
    _scorecard_local(results, agg)
    for r in results:
        if not r.get("error") and r["fn"]:
            console.print(f"  [yellow]{r['name']} 漏报: {sorted(r['fn'])}")
    console.print(f"综合 · 召回 {agg['recall']*100:.0f}% · 精确率 {agg['precision']*100:.0f}% · 评分卡→ bench/scorecard.md")


def bench_xbow(args):
    console.rule("[bold cyan]外部基准 · XBOW validation-benchmarks")
    if not args.repo or not Path(args.repo).exists():
        console.print("[red]需 --repo 指向 clone 的 validation-benchmarks 仓库")
        return
    cov = xbow.coverage(args.repo)
    ct = Table(title=f"XBOW 覆盖分析（共 {cov['total']} 挑战）")
    ct.add_column("标签"); ct.add_column("数量"); ct.add_column("检测器可覆盖")
    for tag, info in cov["by_tag"].items():
        ct.add_row(tag, str(info["count"]), "✅" if info["detectable"] else "—（需利用型 agent）")
    console.print(ct)
    console.print(f"[bold]可检测覆盖：{cov['detectable_challenges']}/{cov['total']} "
                  f"= {cov['coverage_pct']}%[/]（其余属检测管线覆盖边界外，诚实计入差距）")

    live_results = []
    if args.live:
        console.print(f"\n[cyan]起真实 docker 靶跑管线（limit={args.limit or 'all-detectable'}）…")
        os.environ["HERMES_ALLOW_ACTIVE"] = "1"    # 授权本地 docker 靶，允许主动工具/探针
        for c in xbow.cases(args.repo, limit=args.limit, names=args.only):
            console.print(f"  ▶ {c.name} tags={c.meta.get('tags')} 期望类={sorted(c.truth)}")
            live_results.append(run_case(c))
        _table(live_results, "XBOW 实测（检测代理·召回模式）")
        hits = sum(1 for r in live_results if not r.get("error") and r.get("hit"))
        done = [r for r in live_results if not r.get("error")]
        if done:
            console.print(f"[bold]检测代理命中率：{hits}/{len(done)} = {100*hits/len(done):.0f}%")
    _scorecard_xbow(cov, live_results)


def _run_flag_case(name, setup, teardown, known_flag, env=None):
    url = setup()
    if not url:
        teardown()
        return {"name": name, "error": "靶未就绪"}
    saved = {k: os.environ.get(k) for k in (env or {})}
    os.environ.update(env or {})
    os.environ["HERMES_CTF_MODE"] = "1"
    try:
        orchestrator.console.quiet = True
        o = Orchestrator([url], max_parallel=6, use_knowledge=False, persist=False)
        o.collect()
        cap = o.captured
    finally:
        orchestrator.console.quiet = False
        for k, v in saved.items():
            os.environ[k] = v if v is not None else os.environ.pop(k, "")
        os.environ.pop("HERMES_CTF_MODE", None)
        teardown()
    win = bool(cap.get("captured")) and (known_flag is None or cap.get("flag") == known_flag)
    return {"name": name, "captured": cap.get("captured"), "flag": cap.get("flag"),
            "via": cap.get("via"), "expected": known_flag, "win": win}


def bench_cybench(args):
    console.rule("[bold cyan]外部基准 · Cybench")
    cov = cybench.coverage(args.repo)
    console.print(cov)
    if args.fixture:
        console.print("\n[cyan]本地 flag 捕获 harness 验证（labs/flag_ctf_lab.py）…")
        import subprocess as sp
        import sys as _sys
        import httpx as _httpx
        import time as _t
        port, proc = 8995, None

        def setup():
            nonlocal proc
            proc = sp.Popen([_sys.executable, str(ROOT / "labs/flag_ctf_lab.py"), str(port)],
                            stdout=sp.DEVNULL, stderr=sp.DEVNULL)
            for _ in range(20):
                try:
                    _httpx.get(f"http://127.0.0.1:{port}/", timeout=1); return f"http://127.0.0.1:{port}"
                except Exception:  # noqa: BLE001
                    _t.sleep(0.3)
            return None

        def teardown():
            if proc:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except Exception:  # noqa: BLE001
                    proc.kill()

        r = _run_flag_case("flag_ctf_fixture", setup, teardown, "flag{hermes_ctf_pwned}",
                           env={"HERMES_ALLOW_ACTIVE": "1"})
        if r.get("error"):
            console.print(f"[red]{r['name']}: {r['error']}")
        else:
            mark = "✅ 夺旗成功" if r["win"] else "❌ 未夺旗"
            console.print(f"  {mark} · 捕获 flag={r['flag']} · 来源={r['via']} · 期望={r['expected']}")
        console.print("[dim]（真实 Cybench：以 --repo 指向 clone，web 任务经其 start_docker.sh 起靶后同法评估；"
                      "非 web 类属覆盖边界外。）")


def _scorecard_local(results, agg):
    out = ROOT / "bench"; out.mkdir(exist_ok=True)
    lines = [f"# Hermes 自评 · 本地题库（{time.strftime('%Y-%m-%d %H:%M:%SZ', time.gmtime())}）", "",
             f"- 召回 {agg['recall']*100:.0f}% · 精确率 {agg['precision']*100:.0f}%", "",
             "| 用例 | 检出 | TP | FP | FN | 召回 | 精确率 | F1 |",
             "|------|------|----|----|----|------|--------|----|"]
    for r in results:
        if r.get("error"):
            lines.append(f"| {r['name']} | ERROR |||||||")
            continue
        prec = "n/a" if r["mode"] == "recall" else f"{r['precision']*100:.0f}%"
        lines.append(f"| {r['name']} | {len(r['detected'])} | {len(r['tp'])} | {len(r['fp'])} | "
                     f"{len(r['fn'])} | {r['recall']*100:.0f}% | {prec} | {r['f1']:.2f} |")
    (out / "scorecard.md").write_text("\n".join(lines), encoding="utf-8")


def _scorecard_xbow(cov, live_results):
    out = ROOT / "bench"; out.mkdir(exist_ok=True)
    lines = [f"# Hermes 自评 · XBOW 外部基准（{time.strftime('%Y-%m-%d %H:%M:%SZ', time.gmtime())}）", "",
             f"- 共 {cov['total']} 挑战 · 检测器可覆盖 {cov['detectable_challenges']} "
             f"({cov['coverage_pct']}%)；其余需利用型 agent，属覆盖边界外。", "",
             "## 标签覆盖", "| 标签 | 数量 | 可覆盖 |", "|------|------|--------|"]
    for tag, info in cov["by_tag"].items():
        lines.append(f"| {tag} | {info['count']} | {'是' if info['detectable'] else '否'} |")
    if live_results:
        lines += ["", "## 实测（检测代理·召回）", "| 挑战 | 期望类 | 检出类 | 命中 |", "|------|--------|--------|------|"]
        for r in live_results:
            if r.get("error"):
                lines.append(f"| {r['name']} | | ERROR | |"); continue
            lines.append(f"| {r['name']} | {sorted(r['tp']|r['fn'])} | {sorted(r['detected'])} | "
                         f"{'✅' if r.get('hit') else '❌'} |")
    (out / "scorecard-xbow.md").write_text("\n".join(lines), encoding="utf-8")


def bench_batch(args):
    """Tier 1 批测：全套跑 solve_task（域路由+ensemble+硬超时），出真实解题率评分卡。可恢复。"""
    from hermes.benchmarks import batch
    if not args.repo:
        console.print("[red]--batch 需 --repo 指向 clone 的基准仓库路径。"); return
    batch.run_batch(args.repo, suite=args.batch, limit=args.limit, only=args.only,
                    categories=args.categories, hard_timeout=args.hard_timeout)


def main():
    ap = argparse.ArgumentParser(description="Hermes 自评 / 基线量化")
    ap.add_argument("--benchmark", choices=["local", "xbow", "cybench"], default="local")
    ap.add_argument("--batch", choices=["cybench", "xbow"], help="Tier1 全量批测（真实解题率评分卡，可恢复）")
    ap.add_argument("--repo", help="外部基准仓库路径")
    ap.add_argument("--live", action="store_true", help="XBOW：起真实 docker 靶")
    ap.add_argument("--limit", type=int, help="用例数量上限")
    ap.add_argument("--only", nargs="+", help="仅跑指定挑战名（如 XBEN-009-24）")
    ap.add_argument("--categories", nargs="+", help="批测仅跑指定类别（web crypto pwn ...）")
    ap.add_argument("--hard-timeout", type=int, default=900, dest="hard_timeout", help="批测每任务硬超时(秒)")
    ap.add_argument("--fixture", action="store_true", help="Cybench：跑本地 flag 捕获 harness 验证")
    args = ap.parse_args()
    if args.batch:
        bench_batch(args)
        return
    {"local": bench_local, "xbow": bench_xbow, "cybench": bench_cybench}[args.benchmark](args)


if __name__ == "__main__":
    main()

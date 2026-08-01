"""Cybench 适配器（github.com/andyzorigin/cybench）。

Cybench = 40 个专业 CTF，**flag 夺取型**，任务用 `metadata/metadata.json` 描述
（categories / target_host / difficulty / subtasks）。它**不提供** XBOW 那样的"漏洞标签"，
故对纯检测管线只能做**很弱**的评估：仅 web 类在域内，且没有可对齐的目标漏洞类。

本适配器：加载真实任务元数据、按类别统计、识别 web 子集与其 target_host；
诚实标注——真正评分需其 flag harness / 利用型 agent，非本检测管线所长。
"""
from __future__ import annotations

import glob
import json
from pathlib import Path

# Cybench 若用数值 category_id，做映射；字符串则直接用
CATEGORY_ID = {0: "crypto", 1: "forensics", 2: "misc", 3: "ppc",
               4: "pwn", 5: "reversing", 6: "web", 7: "blockchain"}
WEB = "web"


def _categories(meta: dict) -> list[str]:
    cats = meta.get("categories", meta.get("category", []))
    if isinstance(cats, (str, int)):
        cats = [cats]
    out = []
    for c in cats or []:
        if isinstance(c, int):
            out.append(CATEGORY_ID.get(c, str(c)))
        else:
            out.append(str(c).lower())
    return out


def load_tasks(repo: str) -> list[dict]:
    tasks = []
    for f in sorted(glob.glob(f"{repo}/**/metadata/metadata.json", recursive=True)):
        try:
            d = json.load(open(f))
        except Exception:  # noqa: BLE001
            continue
        tasks.append({"dir": str(Path(f).parent.parent),
                      "categories": _categories(d),
                      "target_host": d.get("target_host") or d.get("target"),
                      "difficulty": d.get("difficulty"),
                      "has_server": bool(d.get("target_host") or d.get("target"))})
    return tasks


def coverage(repo: str | None) -> dict:
    if not repo or not Path(repo).exists():
        return {"available": False,
                "note": "未提供 Cybench repo。克隆 github.com/andyzorigin/cybench 后以 --repo 指定。"
                        "注意：仓库含大量任务资产（数百 MB+，部分用 submodule/LFS）。"}
    tasks = load_tasks(repo)
    if not tasks:
        return {"available": True, "total": 0,
                "note": "未找到 metadata.json——工作树可能尚未 checkout 完成，或路径结构不同。"}
    by_cat = {}
    for t in tasks:
        for c in t["categories"]:
            by_cat[c] = by_cat.get(c, 0) + 1
    web = [t for t in tasks if WEB in t["categories"]]
    return {"available": True, "total": len(tasks), "by_category": dict(sorted(by_cat.items(), key=lambda x: -x[1])),
            "web_tasks": len(web),
            "web_with_server": sum(1 for t in web if t["has_server"]),
            "note": "仅 web 子集在检测管线域内；Cybench 无漏洞标签 + flag 夺取型 → "
                    "检测代理无可对齐目标类，真正评分需其 flag harness 或利用型 agent。crypto/pwn/rev/forensics 属覆盖边界外。"}


def cases(repo: str | None, limit=None):
    # 检测代理无标签可对齐；真正评估走 flag harness（见 flag_run）。
    return []


# ---------------- 真实 flag harness（start_docker.sh + target_host + agent 夺旗）----------------
import re as _re
import subprocess as _sp
import time as _time


def _find_compose(task_dir):
    """定位 compose 文件：root 或 env/ 子目录（hkcert 用 env/）。返回 (dir, file) 或 (None, None)。"""
    for sub in (".", "env"):
        d = Path(task_dir) / sub
        for name in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
            f = d / name
            if f.exists():
                return str(d), str(f)
    return None, None


def _find_start_script(task_dir):
    for s in ("start_docker.sh", "run.sh", "setup.sh"):
        p = Path(task_dir) / s
        if p.exists():
            return str(p)
    return None


def _compose_running(cfile, cdir) -> bool:
    try:
        r = _sp.run(["docker", "compose", "-f", cfile, "ps", "-q"], cwd=cdir,
                    capture_output=True, text=True, timeout=25)
        return bool((r.stdout or "").strip())
    except Exception:  # noqa: BLE001
        return False


def _target_url(target_host: str | None, task_dir: str | None = None):
    """稳健发现 http://127.0.0.1:<hostport>：遍历 compose 服务查该内部端口的宿主映射
    （解决 hkcert 服务名≠target_host、端口非 1:1），失败回退 target_host 端口。"""
    if not target_host:
        return None
    m = _re.match(r"([\w.-]+):(\d+)", str(target_host))
    iport = m.group(2) if m else None
    cdir, cfile = _find_compose(task_dir) if task_dir else (None, None)
    if cfile and iport:
        svcs = []
        try:
            svcs = _sp.run(["docker", "compose", "-f", cfile, "config", "--services"], cwd=cdir,
                           capture_output=True, text=True, timeout=20).stdout.split()
        except Exception:  # noqa: BLE001
            pass
        cands = ([m.group(1)] if m and m.group(1) not in svcs else []) + svcs
        for svc in cands:
            try:
                r = _sp.run(["docker", "compose", "-f", cfile, "port", svc, iport], cwd=cdir,
                            capture_output=True, text=True, timeout=20)
                mm = _re.search(r":(\d+)\s*$", (r.stdout or "").strip())
                if mm:
                    return f"http://127.0.0.1:{mm.group(1)}"
            except Exception:  # noqa: BLE001
                pass
    mm = _re.search(r":(\d+)", str(target_host))
    return f"http://127.0.0.1:{mm.group(1)}" if mm else None


def _ensure_shared_net():
    """Cybench 挑战 compose 依赖外部网络 shared_net（其 harness 预建）；确保存在。"""
    try:
        _sp.run(["docker", "network", "create", "shared_net"], capture_output=True, timeout=20)
    except Exception:  # noqa: BLE001
        pass


_BUILD_FAIL = ("failed to solve", "exit code: 100", "error [", "returned a non-zero code",
               "unable to locate package", "could not resolve", "temporary failure resolving",
               "no such file", "cannot connect to the docker daemon")


def start_task(task_dir: str, timeout=1200, retries=2) -> str:
    """起靶并**报真状态**：'started' | 'build_failed' | 'unsupported_deploy'。

    - 有 start_docker.sh/run.sh/setup.sh → bash 跑；否则 root/env docker-compose → `up -d --build`；都没有→unsupported。
    - 用 `docker compose ps -q` **确认容器真的起来了**（不再"脚本跑完就当成功"）；没起+构建失败特征→重试；仍失败→build_failed。
    """
    _ensure_shared_net()
    script = _find_start_script(task_dir)
    cdir, cfile = _find_compose(task_dir)
    if not script and not cfile:
        return "unsupported_deploy"
    for _ in range(max(1, retries + 1)):
        out = ""
        try:
            if script:
                r = _sp.run(["bash", script], cwd=task_dir, capture_output=True, text=True, timeout=timeout)
            else:
                r = _sp.run(["docker", "compose", "-f", cfile, "up", "-d", "--build"], cwd=cdir,
                            capture_output=True, text=True, timeout=timeout)
            out = (r.stdout or "") + (r.stderr or "")
        except Exception as e:  # noqa: BLE001
            out = str(e)
        cd2, cf2 = (cdir, cfile) if cfile else _find_compose(task_dir)
        if cf2 and _compose_running(cf2, cd2):
            return "started"
        if not cf2 and script:      # 纯脚本无 compose 可查 → 退回老行为（认为起了）
            return "started"
        if any(k in out.lower() for k in _BUILD_FAIL):
            continue                # 构建失败 → 重试
    return "build_failed"


def stop_task(task_dir: str):
    for script in ("stop_docker.sh", "teardown.sh"):
        p = Path(task_dir) / script
        if p.exists():
            try:
                _sp.run(["bash", str(p)], cwd=task_dir, capture_output=True, timeout=120)
            except Exception:  # noqa: BLE001
                pass
    cdir, cfile = _find_compose(task_dir)     # 兜底：compose down（含 env/ compose、无 stop 脚本）
    if cfile:
        try:
            _sp.run(["docker", "compose", "-f", cfile, "down", "-v"], cwd=cdir,
                    capture_output=True, timeout=120)
        except Exception:  # noqa: BLE001
            pass


_SRC_EXT = (".py", ".php", ".sh", ".html", ".js", ".rb", ".go", ".java", ".ts",
            ".c", ".cc", ".cpp", ".h", ".hpp",          # pwn/rev 源码（HTB 常给）
            # 配置类：HAProxy/nginx ACL、supervisord、docker-compose 等对 web 链路利用至关重要
            ".cfg", ".conf", ".ini", ".yml", ".yaml", ".toml", ".env", ".txt")


_CFG_EXT = (".cfg", ".conf", ".ini", ".yml", ".yaml", ".toml", ".env")


def _read_source(task_dir: str) -> str:
    # 配置类文件（HAProxy/nginx ACL 等）体量小但对链路利用关键，**排在前面**避免被提示截断丢弃
    prio, rest = [], []
    for p in Path(task_dir).rglob("*"):
        if p.is_file() and p.suffix.lower() in _SRC_EXT and p.stat().st_size < 200_000:
            try:
                chunk = f"# ==== {p.name} ====\n" + p.read_text(errors="ignore")
            except Exception:  # noqa: BLE001
                continue
            (prio if p.suffix.lower() in _CFG_EXT else rest).append(chunk)
    # pwn/rev：附上任务目录内 ELF 的静态 triage（file/checksec/nm/strings/objdump），供 agent 逆向
    try:
        from hermes_ctf_lab import bintriage
        tri = bintriage.triage_dir(task_dir)
        if tri:
            rest.append(tri)
    except Exception:  # noqa: BLE001
        pass
    return "\n".join(prio + rest)


def flag_run(task_dir: str, target_host: str = None, known_flag: str = None, wait=180) -> dict:
    """起一个 Cybench web 任务 → agent 驱动的 CTF 管线夺旗 → 拆靶。需 HERMES_CTF_MODE=1。

    wait：就绪轮询次数（每次 1s），默认 180s——留足 JVM/Spring Boot 等慢启动。
    """
    import httpx
    from hermes import orchestrator as _O
    from hermes.orchestrator import Orchestrator
    if start_task(task_dir) != "started":
        return {"name": Path(task_dir).name, "error": "起靶失败/构建失败"}
    url = _target_url(target_host, task_dir)     # 用实际宿主端口
    try:
        ok = False
        for _ in range(wait):
            try:
                httpx.get(url, timeout=2); ok = True; break
            except Exception:  # noqa: BLE001
                _time.sleep(1)
        if not (url and ok):
            return {"name": Path(task_dir).name, "error": f"target 未就绪 ({url})"}
        _O.console.quiet = True
        o = Orchestrator([url], use_knowledge=False, persist=False, source_text=_read_source(task_dir))
        o.collect()
        _O.console.quiet = False
        cap = o.captured
    finally:
        stop_task(task_dir)
    win = bool(cap.get("captured")) and (known_flag is None or cap.get("flag") == known_flag)
    return {"name": Path(task_dir).name, "captured": cap.get("captured"),
            "flag": cap.get("flag"), "method": cap.get("method"), "win": win}

"""本地自建靶场适配器 —— vulnerable / secure 两用例，完整 precision/recall。"""
from __future__ import annotations

import re
import subprocess
import sys
import time
from pathlib import Path

import httpx

from hermes_ctf_lab.benchmarks.base import BenchCase

ROOT = Path(__file__).resolve().parent.parent.parent
PY = sys.executable

TRUTH_VULN = {
    "missing-sec-headers", "verbose-server", "reflected-xss-q", "idor-id",
    "api-noauth-api-profile", "api-errleak",
    "exposed-.env", "exposed-.git-config", "exposed-backup.zip", "exposed-admin",
    "exposed-.env.bak",
}


def normalize_id(fid: str) -> str:
    toks = [t for t in fid.split("-")
            if ":" not in t and not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", t)]
    return "-".join(toks)


def _free_port(port):
    """启动前清掉占用该端口的残留进程，避免偶发假阳/端口时序问题。"""
    try:
        out = subprocess.run(["lsof", "-ti", f"tcp:{port}"], capture_output=True, text=True, timeout=5).stdout
        for pid in out.split():
            try:
                subprocess.run(["kill", "-9", pid], capture_output=True, timeout=5)
            except Exception:  # noqa: BLE001
                pass
    except Exception:  # noqa: BLE001
        pass


def _wait(port, tries=30):
    for _ in range(tries):
        try:
            if httpx.get(f"http://127.0.0.1:{port}/", timeout=1).status_code:
                return True
        except Exception:  # noqa: BLE001
            time.sleep(0.3)
    return False


EXPLOIT_DOMAINS = {"ssti", "cmdi", "lfi", "sqli"}
TRUTH_EXPLOIT = {"ssti-name", "cmdi-host", "lfi-file", "sqli-id"}


def _lab_case(name, app, port, truth, normalize=None, env=None):
    holder = {}

    def setup():
        _free_port(port)      # 清残留，避免偶发假阳
        holder["proc"] = subprocess.Popen(
            [PY, str(ROOT / app), str(port)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return f"http://127.0.0.1:{port}" if _wait(port) else None

    def teardown():
        p = holder.get("proc")
        if p:
            p.terminate()
            try:
                p.wait(timeout=5)
            except Exception:  # noqa: BLE001
                p.kill()

    def default_normalize(verified):
        # nuclei 结果排除在本地 id-粒度 ground truth 之外（本地基准只评 Python 检测器）
        return {normalize_id(v["id"]) for v in verified if not v["id"].startswith("nuclei-")}

    return BenchCase(name=name, truth=truth, setup=setup, teardown=teardown,
                     normalize=normalize or default_normalize, mode="full", env=env or {})


TRUTH_INTERACTIVE = {"cmdi-host", "ssti-tmpl", "default-creds"}
INTERACTIVE_DOMAINS = EXPLOIT_DOMAINS | {"default"}


def _exploit_normalize(verified):
    # 只评利用型探针检出（ssti/cmdi/lfi/sqli），不因也发现的 XSS/缺失头而失真
    return {normalize_id(v["id"]) for v in verified
            if v["id"].split("-")[0] in EXPLOIT_DOMAINS}


def _interactive_normalize(verified):
    return {normalize_id(v["id"]) for v in verified
            if v["id"].split("-")[0] in INTERACTIVE_DOMAINS}


def cases(limit=None):
    cs = [
        _lab_case("vulnerable", "labs/vulnerable_app.py", 8991, set(TRUTH_VULN)),
        _lab_case("secure", "labs/secure_app.py", 8992, set()),
        _lab_case("exploit", "labs/exploit_lab.py", 8993, set(TRUTH_EXPLOIT),
                  normalize=_exploit_normalize, env={"HERMES_ALLOW_ACTIVE": "1"}),
        # 交互式：漏洞在默认口令登录+深层 POST 表单之后（需登录/深爬/表单驱动才可达）
        _lab_case("interactive", "labs/interactive_lab.py", 8994, set(TRUTH_INTERACTIVE),
                  normalize=_interactive_normalize, env={"HERMES_ALLOW_ACTIVE": "1"}),
    ]
    return cs[:limit] if limit else cs

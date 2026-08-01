"""命令注入探针（利用型·PoC 级）—— 良性 echo <标记> 证明注入，绝不投递危险命令。

主动探针：受 scope + dry_run 门控。GET/POST 均可注入（带会话）。仅用 echo 回显良性标记，不执行破坏性命令。
"""
from __future__ import annotations

from urllib.parse import urlparse

from hermes import cli, tools
from hermes.scanners import Scanner
from hermes.scope import Scope

MARK = "hmci9z1q"
PROBES = [f";echo {MARK}", f"|echo {MARK}", f"$(echo {MARK})", f"`echo {MARK}`",
          f"&& echo {MARK}", f"; echo {MARK}"]


def _host(url):
    return urlparse(url).netloc or url


def scan(ep: dict) -> list:
    if not cli.allow_active(Scope.load()):
        return []
    cands = []
    for p in tools.probe_params(ep):
        try:
            base, _ = tools.inject(ep, p, "hmbase")
        except Exception:  # noqa: BLE001
            continue
        if MARK in base.text:
            continue
        for probe in PROBES:
            try:
                r, req = tools.inject(ep, p, probe)
            except Exception:  # noqa: BLE001
                continue
            # 去掉被原样回显的 payload 后，标记仍在 → echo 确被执行（兼容"回显+执行"同时发生）
            if MARK in r.text.replace(probe, ""):
                c = tools.make_candidate(
                    f"cmdi-{p}-{_host(ep['url'])}", f"{req['method']} {req['url']}",
                    f"参数 {p} 操作系统命令注入：注入的 echo 标记被执行回显",
                    "Command Injection", "high", "server_side_injection.command_injection",
                    check={"kind": "reproduce", "request": req, "needle": MARK},
                    impact="可执行服务器命令（此处仅 echo 良性标记做 PoC，未投递危险命令）",
                    steps=[f"{req['method']} {req['url']}", f"响应含标记 {MARK}，证明 echo 被 shell 执行"])
                c["_exploit"] = {"ep": ep, "param": p, "kind": "cmdi"}  # CTF flag 捕获用
                cands.append(c)
                break
    return cands


SCANNER = Scanner(domain="cmdi", applies=lambda ep: bool(tools.probe_params(ep)), scan=scan)

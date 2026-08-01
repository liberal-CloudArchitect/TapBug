"""SSTI 探针（利用型·PoC 级）—— 良性算术标记 {{7*7}}->49 证明模板注入。

主动探针：受 scope + dry_run 门控（cli.allow_active）。GET 查询与 POST 表单均可注入（带会话/登录态）。
仅证明存在，不武器化、不 RCE 投递。
"""
from __future__ import annotations

from urllib.parse import urlparse

from hermes import cli, tools
from hermes.scanners import Scanner
from hermes.scope import Scope

PROBES = ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}"]
MARK = "49"


def _host(url):
    return urlparse(url).netloc or url


def scan(ep: dict) -> list:
    if not cli.allow_active(Scope.load()):
        return []
    cands = []
    for p in tools.probe_params(ep):
        try:
            base, _ = tools.inject(ep, p, "hms0")
        except Exception:  # noqa: BLE001
            continue
        if MARK in base.text:
            continue
        for probe in PROBES:
            try:
                r, req = tools.inject(ep, p, probe)
            except Exception:  # noqa: BLE001
                continue
            # 去掉被原样回显的 payload 后，49 仍在（且基线无 49）→ 表达式确被求值
            if MARK in r.text.replace(probe, ""):
                cands.append(tools.make_candidate(
                    f"ssti-{p}-{_host(ep['url'])}", f"{req['method']} {req['url']}",
                    f"参数 {p} 服务端模板注入（SSTI）：{probe} 求值为 {MARK}",
                    "SSTI", "high", "server_side_injection.server_side_template_injection",
                    check={"kind": "reproduce", "request": req, "needle": MARK},
                    impact="模板引擎执行注入表达式，通常可升级为 RCE（此处仅算术 PoC）",
                    steps=[f"{req['method']} {req['url']}", f"响应含 {MARK}，证明 {probe} 被服务端求值"]))
                break
    return cands


SCANNER = Scanner(domain="ssti", applies=lambda ep: bool(tools.probe_params(ep)), scan=scan)

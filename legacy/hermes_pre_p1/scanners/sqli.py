"""报错型 SQLi 探针（利用型·PoC 级）—— 单引号触发 SQL 报错证明可注入，不做数据抽取。

主动探针：受 scope + dry_run 门控。GET/POST 均可注入（带会话）。仅触发语法错误做存在性 PoC。
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from hermes import cli, tools
from hermes.scanners import Scanner
from hermes.scope import Scope

ERR = re.compile(r"(SQL syntax|SQLSTATE|mysql_fetch|ORA-\d+|unterminated quoted string|"
                 r"SQLite3::|PostgreSQL.*ERROR|syntax error near|Unclosed quotation mark|"
                 r"psycopg2|sqlalchemy\.exc|OperationalError)", re.I)


def _host(url):
    return urlparse(url).netloc or url


def scan(ep: dict) -> list:
    if not cli.allow_active(Scope.load()):
        return []
    cands = []
    for p in tools.injectable(ep):
        try:
            base, _ = tools.inject(ep, p, "1")
        except Exception:  # noqa: BLE001
            continue
        if ERR.search(base.text):
            continue
        try:
            r, req = tools.inject(ep, p, "1'")
        except Exception:  # noqa: BLE001
            continue
        m = ERR.search(r.text)
        if m:
            cands.append(tools.make_candidate(
                f"sqli-{p}-{_host(ep['url'])}", f"{req['method']} {req['url']}",
                f"参数 {p} 报错型 SQL 注入：单引号触发 SQL 语法错误",
                "SQL Injection", "high", "server_side_injection.sql_injection.error_based",
                check={"kind": "reproduce", "request": req, "needle": m.group(0)},
                impact="参数进入 SQL 查询，可注入（此处仅触发报错做存在性 PoC，未抽取数据）",
                steps=[f"{req['method']} {req['url']}", f"响应含 SQL 报错：{m.group(0)}"]))
    return cands


SCANNER = Scanner(domain="sqli", applies=lambda ep: bool(tools.injectable(ep)), scan=scan)

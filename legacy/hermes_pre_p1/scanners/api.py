"""API 专家 scanner —— 无鉴权访问、错误信息/SQL 泄露（只读）。"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from hermes import tools
from hermes.scanners import Scanner

ERROR_LEAK = re.compile(r"(SELECT\s+.*FROM|Traceback|stack trace|SQLSTATE|ORA-\d+)", re.I)


def _host(url):
    return urlparse(url).netloc or url


def scan(ep: dict) -> list:
    url, params = ep["url"], ep.get("params") or []
    cands = []
    sample = tools.with_param(url, params[0], "1") if params else url

    # 1) 无鉴权访问：不带 Authorization 即返回数据
    try:
        r = tools.get(sample)
    except Exception:  # noqa: BLE001
        return cands
    if r.status_code == 200 and ("application/json" in r.headers.get("content-type", "")
                                 or r.text.strip().startswith("{")):
        cands.append(tools.make_candidate(
            f"api-noauth-{_host(url)}-{urlparse(url).path.strip('/').replace('/','-')}", sample,
            "API 端点无需鉴权即可访问", "Broken Authentication", "medium",
            "broken_authentication_and_session_management.authentication_bypass",
            check={"kind": "status", "code": 200},
            impact="未认证访问 API 数据",
            steps=[f"GET {sample}（不带 Authorization 头）", "返回 200 + 数据"]))

    # 2) 错误信息 / SQL 泄露：畸形 id 触发
    if params:
        bad = tools.with_param(url, params[0], "abc'")
        try:
            rb = tools.get(bad)
        except Exception:  # noqa: BLE001
            rb = None
        if rb is not None and ERROR_LEAK.search(rb.text):
            m = ERROR_LEAK.search(rb.text)
            cands.append(tools.make_candidate(
                f"api-errleak-{_host(url)}", bad,
                "API 错误响应泄露内部信息（SQL/堆栈）", "Information Disclosure", "medium",
                "server_security_misconfiguration.information_disclosure.detailed_error_messages",
                check={"kind": "body", "needle": m.group(0)},
                impact="泄露后端查询/结构，辅助注入等进一步攻击",
                steps=[f"GET {bad}", "响应体包含内部 SQL/堆栈信息"]))
    return cands


SCANNER = Scanner(domain="api",
                  applies=lambda ep: ep.get("type") == "api",
                  scan=scan)

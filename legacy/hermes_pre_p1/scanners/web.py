"""Web 漏洞专家 scanner —— 反射型 XSS、缺失安全头、版本泄露（只读、最小影响）。"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from hermes import tools
from hermes.scanners import Scanner


def _host(url):
    return urlparse(url).netloc or url


def scan(ep: dict) -> list:
    url, params = ep["url"], ep.get("params") or []
    host = _host(url)
    cands = []

    probe = tools.http_probe(url.split("?")[0])
    if not probe.get("alive"):
        return cands

    missing = probe.get("missing_security_headers") or []
    if missing:
        cands.append(tools.make_candidate(
            f"missing-sec-headers-{host}", url.split("?")[0],
            f"缺失安全响应头: {', '.join(missing)}", "Security Misconfiguration",
            "high" if "content-security-policy" in missing else "medium",
            "server_security_misconfiguration.security_headers",
            check={"kind": "header_missing", "headers": missing},
            impact="点击劫持 / MIME 嗅探 / 缺乏 XSS 纵深防御",
            steps=[f"GET {url.split('?')[0]}", "检查响应头缺失"]))

    server = probe.get("server", "")
    if re.search(r"\d+\.\d+", server or ""):
        cands.append(tools.make_candidate(
            f"verbose-server-{host}", url.split("?")[0],
            f"Server 头泄露组件版本: {server}", "Information Disclosure", "low",
            "server_security_misconfiguration.information_disclosure",
            check={"kind": "header_present", "header": "server"},
            impact="泄露组件与版本，便于攻击者匹配已知 CVE",
            steps=[f"GET {url.split('?')[0]}", "读取 Server 头"]))

    for p in tools.injectable(ep):
        try:
            r, req = tools.inject(ep, p, tools.XSS_PROBE)
        except Exception:  # noqa: BLE001
            continue
        ctype = r.headers.get("content-type", "").lower()
        # 仅当响应以 HTML 渲染时，反射未转义才构成 XSS（避免 JSON 反射误报）
        if tools.XSS_PROBE in r.text and "html" in ctype:
            cands.append(tools.make_candidate(
                f"reflected-xss-{p}-{_host(url)}", f"{req['method']} {req['url']}",
                f"参数 {p} 反射未转义，反射型 XSS", "XSS", "high",
                "cross_site_scripting_xss.reflected.non_self",
                check={"kind": "reproduce", "request": req, "needle": tools.XSS_PROBE},
                impact="可在受害者浏览器执行任意脚本（会话窃取/钓鱼）",
                steps=[f"{req['method']} {req['url']}", "观察注入标记未转义，可插入 <script>"]))
    return cands


SCANNER = Scanner(domain="web",
                  applies=lambda ep: ep.get("type") in ("web", "api") or bool(ep.get("params")),
                  scan=scan)

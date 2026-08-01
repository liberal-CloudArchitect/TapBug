"""VRT 报告草稿生成 —— 把一条**已确认**的发现整理成对齐 Bugcrowd VRT 的报告草稿。

用途：合规工作流里，Hermes 出草稿，**你人工核实后再在 Bugcrowd 提交**。绝不自动提交。
可选 LLM 润色影响/修复段落（有 DeepSeek 等 key 时）；无 key 则用确定性模板。
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

# 漏洞类 → (Bugcrowd VRT 分类, 默认严重度, CWE, CVSS 向量参考)
VRT_MAP = {
    "Command Injection": ("server_side_injection.remote_code_execution", "P1", "CWE-78",
                          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "SSTI->RCE": ("server_side_injection.remote_code_execution", "P1", "CWE-1336",
                  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "SSTI": ("server_side_injection.server_side_template_injection", "P2", "CWE-1336", ""),
    "SQL Injection": ("server_side_injection.sql_injection", "P1", "CWE-89",
                      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "NoSQL Injection": ("server_side_injection.nosql_injection", "P1", "CWE-943", ""),
    "Insecure Deserialization": ("server_side_injection.remote_code_execution", "P1", "CWE-502", ""),
    "XXE": ("server_side_injection.xml_external_entity_injection", "P2", "CWE-611", ""),
    "SSRF": ("server_side_injection.server_side_request_forgery", "P2", "CWE-918", ""),
    "XPath Injection": ("server_side_injection.xpath_injection", "P3", "CWE-643", ""),
    "GraphQL": ("server_side_injection.graphql_injection", "P3", "CWE-200", ""),
    "XSS": ("cross_site_scripting_xss.reflected.non_self", "P3", "CWE-79", ""),
    "Broken Access Control": ("broken_access_control.idor", "P2", "CWE-639", ""),
    "Broken Authentication": ("broken_authentication_and_session_management.authentication_bypass", "P2", "CWE-287", ""),
    "JWT": ("broken_authentication_and_session_management.token_leakage.via_referer_header", "P2", "CWE-347", ""),
    "Mass Assignment": ("broken_access_control.mass_assignment", "P3", "CWE-915", ""),
    "Prototype Pollution": ("server_side_injection.prototype_pollution", "P3", "CWE-1321", ""),
    "Race Condition": ("broken_access_control.race_condition", "P3", "CWE-362", ""),
    "HTTP Method Tampering": ("broken_access_control.privilege_escalation", "P4", "CWE-650", ""),
    "Path Traversal": ("server_side_injection.file_inclusion.local", "P2", "CWE-22", ""),
    "Sensitive Data Exposure": ("sensitive_data_exposure.disclosure_of_secrets", "P2", "CWE-200", ""),
    "Information Disclosure": ("server_security_misconfiguration.information_disclosure", "P4", "CWE-200", ""),
    "Security Misconfiguration": ("server_security_misconfiguration.security_headers", "P4", "CWE-16", ""),
}
DEFAULT = ("other", "P4", "CWE-0", "")


def vrt_classify(vuln_class: str):
    return VRT_MAP.get(vuln_class, DEFAULT)


def _fix_advice(vclass: str) -> str:
    return {
        "Command Injection": "对用户输入做严格白名单校验；避免 shell 执行，用参数化 API（如 subprocess 列表参数、无 shell）。",
        "SSTI->RCE": "禁止把用户输入拼进模板源码；用沙箱/逻辑无关的模板，或对输入做上下文编码。",
        "SQL Injection": "全程参数化查询/预编译语句；最小权限数据库账号。",
        "NoSQL Injection": "对查询输入做类型/结构校验，禁止用户控制运算符（$ne/$gt 等）。",
        "Insecure Deserialization": "不反序列化不可信数据；用签名/白名单或改用 JSON 等安全格式。",
        "XXE": "禁用外部实体与 DTD（`resolve_entities=False`、`no_network=True`）。",
        "SSRF": "对出站 URL 做协议+目标白名单，禁 file:///内网/元数据；解析后再校验。",
        "XPath Injection": "参数化 XPath 或对输入转义；避免拼接查询。",
        "XSS": "对输出做上下文相关编码；启用 CSP 作纵深防御。",
        "Broken Access Control": "服务端对每个对象访问做授权校验（禁止仅凭 id 返回数据）。",
        "JWT": "用强密钥、拒绝 alg:none、校验签名与 claims。",
        "Mass Assignment": "字段白名单绑定，禁止用户设置 role/isAdmin 等特权字段。",
        "Sensitive Data Exposure": "移除暴露的敏感文件/路径，加访问控制并轮换泄露凭据。",
        "Security Misconfiguration": "补齐 CSP/X-Frame-Options/X-Content-Type-Options/HSTS/Referrer-Policy。",
    }.get(vclass, "按 OWASP 对应类别修复；最小权限、输入校验、输出编码。")


def _llm_polish(finding: dict, vrt) -> str | None:
    """有 LLM 时，润色"影响"段（专家口吻，基于证据不夸大）。无则返回 None。"""
    try:
        from hermes.exploit_agent import _llm_available, LLMReasoner
        if not _llm_available():
            return None
        r = LLMReasoner()
        prompt = (
            "你在写一份 bug bounty 漏洞报告的'影响'段落（3-5 句，专业、基于证据不夸大，中文）。\n"
            f"漏洞类型: {finding.get('vuln') or finding.get('class')}\n"
            f"VRT: {vrt[0]} 严重度 {vrt[1]}\n"
            f"位置: {finding.get('entrypoint') or finding.get('url')}\n"
            f"证据: {str(finding.get('poc') or finding.get('payload') or finding.get('evidence'))[:300]}\n"
            "只输出影响段落正文：")
        return r._complete(prompt).strip()
    except Exception:  # noqa: BLE001
        return None


def draft_report(finding: dict, *, target: str = "", llm: bool = True) -> str:
    """从一条已确认发现生成 VRT 报告草稿（markdown）。"""
    vclass = finding.get("vuln") or finding.get("class") or "Unknown"
    vrt_cat, severity, cwe, cvss = vrt_classify(vclass)
    url = finding.get("entrypoint") or finding.get("url") or target
    poc = finding.get("poc") or {}
    payload = finding.get("payload") or (poc.get("request") if isinstance(poc, dict) else "") or ""
    evidence = finding.get("evidence") or (poc.get("response_excerpt") if isinstance(poc, dict) else "") or ""
    steps = poc.get("steps") if isinstance(poc, dict) else None
    steps_md = "\n".join(f"{i+1}. {s}" for i, s in enumerate(steps)) if steps else \
        f"1. 向 `{url}` 发送以下请求/载荷\n2. 观察响应中的证据"
    impact = (_llm_polish(finding, (vrt_cat, severity, cwe, cvss)) if llm else None) \
        or finding.get("impact") or f"{vclass} 可被利用，危害见 VRT {vrt_cat}（{severity}）。"

    return f"""# [{severity}] {vclass} @ {url}

> ⚠️ **报告草稿——需你人工核实证据、按项目 RoE 最小化 PoC 后，再在 Bugcrowd 手动提交。**

- **VRT 分类**: `{vrt_cat}`
- **严重度**: {severity}
- **CWE**: {cwe}
- **CVSS v3.1**: {cvss or '（据实评估）'}
- **受影响资产/URL**: {url}
- **生成时间**: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}

## 摘要
{vclass} 漏洞存在于 `{url}`。

## 复现步骤
{steps_md}

## 载荷 / 请求
```
{payload or '(见复现步骤)'}
```

## 证据
```
{str(evidence)[:600] or '(核实后补最小、脱敏的证据)'}
```

## 影响
{impact}

## 修复建议
{_fix_advice(vclass)}

## 提交前人工核对
- [ ] 目标确在项目 in-scope，且 RoE 允许该测试
- [ ] 已用**最小 PoC** 复现，未做越权/破坏/外泄
- [ ] 证据已脱敏（无真实用户数据）
- [ ] 严重度/VRT 与实际影响相符（不夸大）
- [ ] 无重复（搜过该项目已知问题）
"""


if __name__ == "__main__":
    demo = {"vuln": "SQL Injection", "entrypoint": "https://example.com/item?id=1'",
            "payload": "GET /item?id=1'", "evidence": "SQL syntax error near ''",
            "poc": {"steps": ["访问 /item?id=1'", "响应含 SQL 报错"]}}
    print(draft_report(demo, llm=False))

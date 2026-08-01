"""真实安全 CLI 工具 passthrough —— subfinder（侦察）/ nuclei（扫描）。

设计：装了就用真实工具，没装则调用方优雅降级到纯 Python。所有触网仍受 scope 与 dry_run 约束。
输出统一归一化为 Excavator 的 asset / candidate schema，与 Python 检测无缝合流。
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from urllib.parse import urlparse

from hermes import tools

# nuclei 严重度 → (confidence, 我方漏洞类关键词)
NUCLEI_SEV = {"info": "low", "low": "low", "medium": "medium",
              "high": "high", "critical": "high"}


def have(tool: str) -> bool:
    return shutil.which(tool) is not None


def allow_active(scope) -> bool:
    """主动工具（nuclei 等）是否允许运行：非 dry_run，或显式 HERMES_ALLOW_ACTIVE=1（授权靶场）。"""
    if os.environ.get("HERMES_ALLOW_ACTIVE", "").lower() in ("1", "true", "yes"):
        return True
    return not getattr(scope, "dry_run", True)


# ---------- subfinder（子域枚举） ----------
def subfinder_enum(domain: str, timeout: int = 90) -> list[str]:
    if not have("subfinder"):
        return []
    try:
        p = subprocess.run(["subfinder", "-d", domain, "-silent"],
                           capture_output=True, text=True, timeout=timeout)
    except Exception:  # noqa: BLE001
        return []
    return sorted({ln.strip().lower() for ln in p.stdout.splitlines() if ln.strip()})


# ---------- nuclei（模板化漏洞扫描） ----------
def nuclei_scan(target: str, *, rate: int = 5, timeout: int = 240,
                extra_args: list[str] | None = None) -> list[dict]:
    """运行 nuclei，返回原始 JSONL 结果列表。"""
    if not have("nuclei"):
        return []
    cmd = ["nuclei", "-u", target, "-jsonl", "-silent", "-nc", "-rl", str(rate),
           "-timeout", "8", "-retries", "1"]
    if extra_args:
        cmd += extra_args
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except Exception:  # noqa: BLE001
        return []
    out = []
    for ln in p.stdout.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        try:
            out.append(json.loads(ln))
        except json.JSONDecodeError:
            continue
    return out


def _classify(info: dict, template_id: str) -> tuple[str, str]:
    """把 nuclei 结果映射到我方漏洞类 + VRT 猜测。"""
    tags = " ".join(info.get("tags", []) if isinstance(info.get("tags"), list) else [str(info.get("tags", ""))])
    blob = f"{template_id} {tags} {info.get('name','')}".lower()
    if "xss" in blob:
        return "XSS", "cross_site_scripting_xss"
    if any(k in blob for k in ("exposure", "disclosure", ".env", ".git", "backup", "secret", "credential")):
        return "Sensitive Data Exposure", "sensitive_data_exposure"
    if any(k in blob for k in ("misconfig", "header", "cors", "default-login")):
        return "Security Misconfiguration", "server_security_misconfiguration"
    if "sqli" in blob or "sql-injection" in blob:
        return "SQL Injection", "sql_injection"
    if "cve" in blob:
        return "Known CVE", template_id
    return "Information Disclosure", "server_security_misconfiguration.information_disclosure"


def nuclei_to_candidates(results: list[dict]) -> list[dict]:
    cands = []
    for r in results:
        info = r.get("info", {}) or {}
        tid = r.get("template-id", r.get("templateID", "nuclei"))
        sev = (info.get("severity") or "info").lower()
        conf = NUCLEI_SEV.get(sev, "low")
        vclass, vrt = _classify(info, tid)
        matched = r.get("matched-at") or r.get("matched_at") or r.get("host", "")
        host = urlparse(matched if "://" in matched else f"//{matched}").netloc or matched
        name = info.get("name", tid)
        extracted = r.get("extracted-results") or r.get("extracted_results") or []
        evidence = f"[nuclei:{tid}|{sev}] {name} @ {matched}" + (f" · extracted={extracted}" if extracted else "")
        cands.append(tools.make_candidate(
            f"nuclei-{tid}-{host}", matched or host, f"[nuclei] {name}", vclass, conf, vrt,
            check={"kind": "prevalidated", "evidence": evidence},
            impact=f"nuclei 模板 {tid} 命中（严重度 {sev}）",
            steps=[f"nuclei -u {matched} -t {tid}", "模板匹配确认"]))
    return cands

"""基础设施专家 scanner —— 敏感文件/路径暴露（只读探测，每 host 一次）。"""
from __future__ import annotations

from urllib.parse import urlparse

from hermes import knowledge, tools
from hermes.scanners import Scanner

# 小型敏感路径字典（只读 GET；非破坏）
SENSITIVE_PATHS = [
    "/.env", "/.git/config", "/.svn/entries", "/backup.zip", "/backup.sql",
    "/config.php.bak", "/admin", "/server-status", "/.aws/credentials",
]
# 高危关键词：命中即判 high（含知识库学到的新路径）
HIGH_KW = ("env", "credential", "backup", "htpasswd", ".git", ".aws", ".svn", ".sql", "config")


def scan(ep: dict) -> list:
    origin = urlparse(ep["url"])
    base = f"{origin.scheme}://{origin.netloc}"
    host = origin.netloc or base
    cands = []
    # 复利：默认字典 + 知识库中过往学到的路径（--no-knowledge 时为空）
    paths = list(dict.fromkeys(SENSITIVE_PATHS + knowledge.extra_paths()))
    for path in paths:
        target = base + path
        try:
            r = tools.get(target)
        except Exception:  # noqa: BLE001
            continue
        if r.status_code == 200 and len(r.text) > 0:
            high = any(kw in path.lower() for kw in HIGH_KW)
            cands.append(tools.make_candidate(
                f"exposed{path.replace('/', '-')}-{host}", target,
                f"敏感文件/路径暴露: {path}", "Sensitive Data Exposure",
                "high" if high else "medium",
                "sensitive_data_exposure.disclosure_of_secrets" if high
                else "server_security_misconfiguration.exposed_sensitive_path",
                check={"kind": "status", "code": 200},
                impact=("泄露凭据/源码/备份等敏感数据" if high else "暴露内部路径/面板"),
                steps=[f"GET {target}", "返回 200 且内容可读"]))
    return cands


# 只在根入口跑一次（避免每个入口重复探测 host 级路径）
SCANNER = Scanner(domain="infra",
                  applies=lambda ep: urlparse(ep["url"]).path in ("", "/"),
                  scan=scan)

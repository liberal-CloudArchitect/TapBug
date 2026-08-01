"""nuclei passthrough scanner —— 真实 CLI 集成，作为可插拔专家自动接入（NFR3）。

装了 nuclei 就作为一个专家参与识别阶段；没装则 applies 返回 False，自动跳过（优雅降级）。
nuclei 是主动扫描：受 scope + dry_run 约束——dry_run 下需 HERMES_ALLOW_ACTIVE=1（授权靶场）才运行。
"""
from __future__ import annotations

import os
from urllib.parse import urlparse

from hermes import cli
from hermes.scanners import Scanner
from hermes.scope import Scope

# 演练期用精选高信号模板 id（快且确定）；真实 engagement 可改用 HERMES_NUCLEI_TAGS 放开为标签范围。
TEMPLATE_IDS = "http-missing-security-headers,git-config,git-config-nginxoffbyslash,dotenv-file"


def scan(ep: dict) -> list:
    scope = Scope.load()
    if not cli.allow_active(scope):        # dry_run 且未显式允许主动工具 → 交给 HITL，先跳过
        return []
    o = urlparse(ep["url"])
    base = f"{o.scheme}://{o.netloc}"
    tags = os.environ.get("HERMES_NUCLEI_TAGS")
    extra = ["-tags", tags, "-ni"] if tags else ["-id", TEMPLATE_IDS, "-ni"]
    results = cli.nuclei_scan(base, rate=int(scope.rate_limit_rps or 5), extra_args=extra)
    return cli.nuclei_to_candidates(results)


SCANNER = Scanner(
    domain="nuclei",
    applies=lambda ep: (cli.have("nuclei") and not os.environ.get("HERMES_SKIP_NUCLEI")
                        and urlparse(ep["url"]).path in ("", "/")),
    scan=scan)

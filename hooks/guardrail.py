#!/usr/bin/env python3
"""Hermes 硬护栏 — Claude Code PreToolUse hook（确定性，不经过 LLM）。

职责（对应 docs/04 第 2 节修复的"用可被绕过的 LLM 防越权"矛盾）：
  1. scope 校验：命令若触碰 scope.yaml 之外的网络目标 -> deny
  2. 危险命令黑名单：系统破坏 / DoS / 反弹 shell / 持久化 -> deny
  3. 状态改变 / 利用类灰名单：POST/PUT/DELETE、爆破、利用框架 -> ask（触发 HITL）
  4. dry-run：开启时，任何主动触网命令 -> ask

输入：Claude Code 经 stdin 传入 PreToolUse 的 JSON（含 tool_name, tool_input）。
输出：stdout 打印决策 JSON；exit 0。deny/ask 由 permissionDecision 表达。

设计原则：宁可误报（fail-closed）也不放行越界。无法判定目标时，若命令明显触网 -> ask。
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import sys
from pathlib import Path

# scope.yaml 优先取项目根（本文件的上一级）
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCOPE_PATH = Path(os.environ.get("HERMES_SCOPE", PROJECT_ROOT / "scope.yaml"))

# ---- 危险命令：直接 deny（系统破坏 / DoS / 反弹shell / 持久化 / 外泄） ----
DENY_PATTERNS = [
    r"\brm\s+-rf\s+/(?!\S*(tmp|scratch))",  # rm -rf 根/系统目录
    r":\(\)\s*\{\s*:\|:&\s*\}\s*;",  # fork bomb
    r"\bmkfs\b",
    r"\bdd\s+if=.*of=/dev/",  # 磁盘擦除
    r">\s*/dev/sd[a-z]",
    r"\bshutdown\b",
    r"\breboot\b",
    r"bash\s+-i\s*>&?\s*/dev/tcp",  # 反弹 shell
    r"\bnc(at)?\b[^\n]*\s-e\b",  # nc -e 反弹
    r"/dev/tcp/\d",  # /dev/tcp 反弹
    r"authorized_keys",  # 远端持久化
    r"\bhping3\b[^\n]*--flood",
    r"\bslowloris\b",
    r"\bslowhttptest\b",
    r"\bab\b[^\n]*-n\s*[1-9]\d{4,}",  # apachebench 压测(DoS)
    r"--flood\b",
    r"-t0\b",  # 明显压测/最激进
]

# ---- 灰名单：ask（状态改变 / 利用 / 高噪声，触发 HITL） ----
ASK_PATTERNS = [
    r"\bsqlmap\b",
    r"\bhydra\b",
    r"\bmedusa\b",
    r"\bpatator\b",
    r"\bmsfconsole\b",
    r"\bmsfvenom\b",
    r"\bmetasploit\b",
    r"\bmasscan\b",
    r"-X\s*(POST|PUT|DELETE|PATCH)\b",  # 改变状态的 HTTP
    r"--method\s*(POST|PUT|DELETE|PATCH)\b",
    r"\bnuclei\b[^\n]*-rl\s*[2-9]\d{2,}",  # 高速率 nuclei
]

DECISION_ALLOW, DECISION_ASK, DECISION_DENY = "allow", "ask", "deny"


def emit(decision: str, reason: str) -> None:
    print(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": decision,
                    "permissionDecisionReason": reason,
                }
            }
        )
    )
    sys.exit(0)


def load_scope() -> dict:
    if not SCOPE_PATH.exists():
        return {}
    try:
        import yaml  # 项目 .venv 提供

        with open(SCOPE_PATH) as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


def resolve_scope(scope: dict) -> tuple[list[str], list[str], bool, bool]:
    """归一化 scope，兼容两种 schema：

    1. 旧的显式列表：`in_scope` / `out_of_scope` / `allow_localhost`；
    2. 当前 `scope.yaml` 的 `rules: [{host, ports, schemes, allow_private}]` —
       从 `rules[].host` 推导 in_scope，使护栏能真正读取本项目的 RoE 文件。

    返回 (in_scope, out_scope, allow_localhost, dry_run)。
    """
    in_scope = [str(h) for h in (scope.get("in_scope") or [])]
    out_scope = [str(h) for h in (scope.get("out_of_scope") or [])]

    rules = scope.get("rules")
    if not in_scope and isinstance(rules, list):
        for rule in rules:
            if isinstance(rule, dict) and rule.get("host"):
                in_scope.append(str(rule["host"]))

    allow_localhost = scope.get("allow_localhost")
    if allow_localhost is None:
        # 未显式声明时默认允许本地回环（local-lab 缺省姿态）。
        allow_localhost = True
    allow_localhost = bool(allow_localhost)

    dry_run = str(scope.get("dry_run", os.environ.get("HERMES_DRY_RUN", "on"))).lower() in (
        "on",
        "true",
        "1",
        "yes",
    )
    return in_scope, out_scope, allow_localhost, dry_run


HOST_RE = re.compile(
    r"https?://([^/\s:'\"]+)|(?<![\w.])((?:\d{1,3}\.){3}\d{1,3})"
    r"|(?<![\w./@-])([a-z0-9-]+(?:\.[a-z0-9-]+)+)",
    re.I,
)


def extract_targets(text: str) -> list[str]:
    """从命令字符串抽取候选网络目标（主机名/IP/URL 主机部分）。"""
    hits = set()
    for m in HOST_RE.finditer(text):
        host = m.group(1) or m.group(2) or m.group(3)
        if host:
            hits.add(host.lower().strip("."))
    # 过滤明显是文件名/开关的误命中
    return [
        h
        for h in hits
        if "." in h
        and not h.endswith(
            (".py", ".md", ".txt", ".json", ".yaml", ".yml", ".log", ".sh", ".html", ".js")
        )
    ]


def host_matches(host: str, patterns: list[str]) -> bool:
    for p in patterns:
        p = str(p).lower().strip()
        if not p:
            continue
        # CIDR
        try:
            if "/" in p and _ip_in_cidr(host, p):
                return True
        except ValueError:
            pass
        # 通配 *.example.com
        if p.startswith("*."):
            base = p[2:]
            if host == base or host.endswith("." + base):
                return True
        elif host == p or host.endswith("." + p):
            return True
    return False


def _ip_in_cidr(host: str, cidr: str) -> bool:
    try:
        return ipaddress.ip_address(host) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def is_localhost(host: str) -> bool:
    if host in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def main() -> None:
    raw = sys.stdin.read() or "{}"
    try:
        event = json.loads(raw)
    except json.JSONDecodeError:
        emit(DECISION_ASK, "无法解析 hook 输入，保守起见请人工确认。")

    tool = event.get("tool_name", "")
    tool_input = event.get("tool_input", {}) or {}
    # 只对可执行命令类工具做深检；其它只读工具放行
    if tool not in ("Bash", "BashOutput"):
        emit(DECISION_ALLOW, "非命令类工具，护栏放行。")

    command = str(tool_input.get("command", ""))
    low = command.lower()

    # 1) 危险命令 -> deny
    for pat in DENY_PATTERNS:
        if re.search(pat, command, re.I):
            emit(
                DECISION_DENY,
                f"命中危险命令黑名单（破坏/DoS/反弹shell/持久化）: /{pat}/。铁律#2 禁止。",
            )

    in_scope, out_scope, allow_localhost, dry_run = resolve_scope(load_scope())

    targets = extract_targets(command)

    # 2) scope 校验
    for host in targets:
        if is_localhost(host):
            if allow_localhost:
                continue
            emit(DECISION_DENY, f"目标 {host} 为本地回环，但 scope 未允许 localhost。")
        if host_matches(host, out_scope):
            emit(DECISION_DENY, f"目标 {host} 命中 out_of_scope，禁止触碰。铁律#1。")
        if not in_scope:
            emit(
                DECISION_ASK, f"scope.yaml 未定义 in_scope，无法确认 {host} 是否授权。请人工确认。"
            )
        if not host_matches(host, in_scope):
            emit(DECISION_DENY, f"目标 {host} 不在 in_scope 授权范围内。铁律#1：越界拒绝。")

    # 3) dry-run 下，任何触网命令 -> ask
    touches_net = bool(targets) or bool(
        re.search(r"\b(curl|wget|nmap|nuclei|httpx|subfinder|amass|ffuf|nikto)\b", low)
    )
    if dry_run and touches_net:
        emit(
            DECISION_ASK, "当前 dry-run 模式：主动触网命令需人工确认（或先关闭 dry-run）。铁律#5。"
        )

    # 4) 灰名单（状态改变 / 利用 / 高噪声）-> ask（HITL）
    for pat in ASK_PATTERNS:
        if re.search(pat, command, re.I):
            emit(DECISION_ASK, f"命中 HITL 灰名单（状态改变/利用/高噪声）: /{pat}/。需人工确认。")

    emit(DECISION_ALLOW, "scope 内、非危险命令，护栏放行。")


if __name__ == "__main__":
    main()

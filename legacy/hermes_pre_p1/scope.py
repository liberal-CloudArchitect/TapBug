"""Scope 加载与匹配 —— hook 与编排层共用的单一事实来源（解决 docs/04 G2.3）。"""
from __future__ import annotations

import hashlib
import ipaddress
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SCOPE = PROJECT_ROOT / "scope.yaml"


class Scope:
    def __init__(self, data: dict):
        self.data = data or {}
        self.in_scope = [str(x).lower() for x in (self.data.get("in_scope") or [])]
        self.out_of_scope = [str(x).lower() for x in (self.data.get("out_of_scope") or [])]
        self.allow_localhost = bool(self.data.get("allow_localhost", True))
        self.dry_run = str(self.data.get("dry_run", "on")).lower() in ("on", "true", "1", "yes")
        self.automation_allowed = bool(self.data.get("automation_allowed", True))
        self.rate_limit_rps = self.data.get("rate_limit_rps", 5)

    @classmethod
    def load(cls, path: Path | str = DEFAULT_SCOPE) -> "Scope":
        p = Path(path)
        data = yaml.safe_load(p.read_text()) if p.exists() else {}
        return cls(data or {})

    def digest(self) -> str:
        raw = yaml.safe_dump(self.data, sort_keys=True).encode()
        return "sha256:" + hashlib.sha256(raw).hexdigest()[:16]

    def is_localhost(self, host: str) -> bool:
        if host in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
            return True
        try:
            return ipaddress.ip_address(host).is_loopback
        except ValueError:
            return False

    @staticmethod
    def _match(host: str, patterns: list[str]) -> bool:
        host = host.lower().strip(".")
        for p in patterns:
            p = p.strip()
            if "/" in p:
                try:
                    if ipaddress.ip_address(host) in ipaddress.ip_network(p, strict=False):
                        return True
                    continue
                except ValueError:
                    pass
            if p.startswith("*."):
                base = p[2:]
                if host == base or host.endswith("." + base):
                    return True
            elif host == p or host.endswith("." + p):
                return True
        return False

    def allows(self, host: str) -> tuple[bool, str]:
        """返回 (是否允许, 原因)。fail-closed：不明确即拒绝。"""
        host = host.lower().strip(".")
        if self.is_localhost(host):
            return (self.allow_localhost,
                    "localhost 允许" if self.allow_localhost else "scope 未允许 localhost")
        if self._match(host, self.out_of_scope):
            return False, f"{host} 命中 out_of_scope"
        if not self.in_scope:
            return False, "in_scope 未定义，无法确认授权"
        if self._match(host, self.in_scope):
            return True, f"{host} ∈ in_scope"
        return False, f"{host} 不在 in_scope 授权范围内"


if __name__ == "__main__":
    import sys
    s = Scope.load()
    for h in sys.argv[1:]:
        print(h, "->", s.allows(h))
    print("digest:", s.digest(), "| dry_run:", s.dry_run)

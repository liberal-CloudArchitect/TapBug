from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .errors import PolicyDenied

Resolver = Callable[[str], Iterable[str]]


def system_resolver(host: str) -> tuple[str, ...]:
    """Resolve a hostname through the operating system without opening a connection."""
    try:
        addresses = {
            ipaddress.ip_address(entry[4][0])
            for entry in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        }
    except (OSError, ValueError):
        return ()
    return tuple(
        str(address) for address in sorted(addresses, key=lambda item: (item.version, int(item)))
    )


class ScopeRule(BaseModel):
    """A deliberately narrow authorization rule for one host pattern or CIDR."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    host: str
    schemes: frozenset[Literal["http", "https"]]
    ports: frozenset[int]
    allow_dns: bool
    profile: str = "default"
    allow_private: bool = False

    @field_validator("host")
    @classmethod
    def canonical_host(cls, value: str) -> str:
        value = value.strip().lower().rstrip(".")
        if not value or "://" in value or "@" in value or "%" in value:
            raise ValueError("host must not contain URL syntax, userinfo, or escaping")
        try:
            ipaddress.ip_network(value, strict=False)
            return value
        except ValueError:
            pass
        if "/" in value:
            raise ValueError("host must not contain a URL path")
        if value.startswith("*."):
            if value.count("*") != 1 or len(value) < 4:
                raise ValueError("wildcards must be an explicit leftmost label")
            return value
        if "*" in value or any(
            not (part and part.replace("-", "").isalnum()) for part in value.split(".")
        ):
            raise ValueError("host must be a DNS name, exact IP, CIDR, or explicit *.name wildcard")
        return value

    @field_validator("ports")
    @classmethod
    def valid_ports(cls, values: frozenset[int]) -> frozenset[int]:
        if not values or any(port < 1 or port > 65535 for port in values):
            raise ValueError("ports must be explicitly non-empty and in 1..65535")
        return values

    @model_validator(mode="after")
    def private_is_exact_and_explicit(self) -> ScopeRule:
        if self.allow_private:
            try:
                network = ipaddress.ip_network(self.host, strict=False)
            except ValueError:
                if self.host != "localhost":
                    raise ValueError(
                        "private access may only name localhost or a single loopback IP"
                    )
            else:
                if not network.is_loopback or network.num_addresses != 1:
                    raise ValueError(
                        "private access cannot authorize a loopback range or non-loopback network"
                    )
        return self

    def matches_host(self, host: str) -> bool:
        host = host.lower().rstrip(".")
        if self.host.startswith("*."):
            base = self.host[2:]
            return host.endswith("." + base) and host != base
        try:
            return ipaddress.ip_address(host) in ipaddress.ip_network(self.host, strict=False)
        except ValueError:
            return host == self.host


class ScopePolicy(BaseModel):
    """Frozen, fail-closed Rules of Engagement for a run."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    profile: str = "default"
    rules: tuple[ScopeRule, ...] = Field(min_length=1)
    automation_allowed: bool = False
    dry_run: bool = True
    max_requests: int = Field(default=25, ge=1, le=100_000)
    max_duration_seconds: float = Field(default=60.0, gt=0, le=86_400)
    max_concurrency: int = Field(default=1, ge=1, le=128)
    rate_limit_rps: float = Field(default=1.0, gt=0, le=1000)
    allowed_commands: frozenset[str] = frozenset()
    evidence_capture_max_bytes: int = Field(default=1_048_576, ge=1, le=10_485_760)
    evidence_analysis_max_bytes: int = Field(default=65_536, ge=1, le=262_144)
    retain_encrypted_raw_evidence: bool = False

    @model_validator(mode="after")
    def matching_profile_exists(self) -> ScopePolicy:
        if not any(rule.profile == self.profile for rule in self.rules):
            raise ValueError("policy profile must have at least one scope rule")
        if self.evidence_analysis_max_bytes > self.evidence_capture_max_bytes:
            raise ValueError("evidence analysis limit cannot exceed the capture limit")
        return self

    def matching_rule(self, host: str, scheme: str, port: int) -> ScopeRule | None:
        for rule in self.rules:
            if (
                rule.profile == self.profile
                and scheme in rule.schemes
                and port in rule.ports
                and rule.matches_host(host)
            ):
                return rule
        return None


@dataclass(frozen=True)
class ResolvedTarget:
    url: str
    host: str
    port: int
    scheme: str
    connect_ip: str
    rule: ScopeRule


def _is_disallowed_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return bool(
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or address.is_reserved
    )


class PolicyEngine:
    """Single policy decision point.  It never makes a network connection."""

    def __init__(self, policy: ScopePolicy, resolver: Resolver | None = None):
        self.policy = policy
        self.resolver = resolver or (lambda _host: ())

    def resolve_url(self, url: str) -> ResolvedTarget:
        parsed = urlsplit(url)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username
            or parsed.password
        ):
            raise PolicyDenied("URL must use http(s), contain a host, and contain no userinfo")
        if parsed.hostname != parsed.hostname.encode("idna").decode("ascii"):
            raise PolicyDenied("host must be canonical ASCII/IDNA")
        host = parsed.hostname.lower().rstrip(".")
        try:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError as exc:
            raise PolicyDenied("invalid URL port") from exc
        rule = self.policy.matching_rule(host, parsed.scheme, port)
        if not rule:
            raise PolicyDenied("target, scheme, port, or profile is outside scope")
        try:
            candidates = [str(ipaddress.ip_address(host))]
        except ValueError:
            if not rule.allow_dns:
                raise PolicyDenied("DNS resolution is not explicitly allowed for this rule")
            try:
                candidates = list(self.resolver(host))
            except (OSError, ValueError) as exc:
                raise PolicyDenied("resolver failed safely") from exc
        if not candidates:
            raise PolicyDenied("resolver returned no addresses")
        for candidate in candidates:
            try:
                address = ipaddress.ip_address(candidate)
            except ValueError as exc:
                raise PolicyDenied("resolver returned an invalid IP address") from exc
            if _is_disallowed_address(address) and not rule.allow_private:
                raise PolicyDenied(
                    "resolved address is private, loopback, metadata, or otherwise non-routable"
                )
            if rule.allow_private and not address.is_loopback:
                raise PolicyDenied("private rule resolved to a non-loopback address")
        # Pin the first validated address. Transports must not re-resolve the host.
        return ResolvedTarget(
            url=url, host=host, port=port, scheme=parsed.scheme, connect_ip=candidates[0], rule=rule
        )

    def assert_automation(self) -> None:
        if not self.policy.automation_allowed:
            raise PolicyDenied("automation is disabled by scope")
        if self.policy.dry_run:
            raise PolicyDenied("scope is dry-run; external actions are disabled")

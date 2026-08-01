"""P0 runtime primitives.  All outward-facing tools must use this boundary."""

from .actions import (
    ActionKind,
    ApprovalAuthority,
    ApprovalChallenge,
    ApprovalToken,
    ProposedAction,
)
from .audit import AuditLogger
from .context import RunContext
from .errors import ApprovalDenied, PolicyDenied
from .gateway import (
    CommandGateway,
    EvidenceRef,
    GatewayExecutionContext,
    HttpRequest,
    HttpResponse,
    ToolGateway,
)
from .policy import PolicyEngine, ScopePolicy, ScopeRule, system_resolver
from .transport import PinnedHttpTransport

__all__ = [
    "ActionKind",
    "ApprovalAuthority",
    "ApprovalChallenge",
    "ApprovalToken",
    "ProposedAction",
    "AuditLogger",
    "RunContext",
    "CommandGateway",
    "EvidenceRef",
    "GatewayExecutionContext",
    "HttpRequest",
    "HttpResponse",
    "ToolGateway",
    "PolicyEngine",
    "ScopePolicy",
    "ScopeRule",
    "system_resolver",
    "ApprovalDenied",
    "PolicyDenied",
    "PinnedHttpTransport",
]

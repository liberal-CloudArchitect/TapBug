class PolicyDenied(PermissionError):
    """An action was denied before an external side effect was attempted."""


class ApprovalDenied(PolicyDenied):
    """An action needs a valid, unconsumed approval token."""

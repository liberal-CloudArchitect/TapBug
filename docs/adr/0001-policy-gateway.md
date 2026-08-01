# ADR 0001: Policy-gated egress

All network and command execution is mediated by the Hermes runtime gateway.
The gateway owns scope validation, DNS/address checks, redirect validation,
rate/budget enforcement, approvals, and audit events.  Module-local `httpx`,
`requests`, `socket`, and `subprocess` calls are prohibited in the main package.

The Claude/Codex hook remains a useful outer guard, but it is not a Python
runtime trust boundary.

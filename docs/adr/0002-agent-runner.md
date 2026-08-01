# ADR 0002: Portable agent runner

Hermes defines a versioned JSON task/handoff contract and runs configured roles
in independent subprocesses.  This preserves a stable core across future Codex,
Claude Code, or other adapters.  When no process runner is configured, Hermes
uses an explicitly named single-process rules mode and never claims that it ran
multiple agents.

R2 extends this boundary with signed role manifests and a parent-owned Runner
Host. Production roles run in digest-pinned Docker containers with no network,
read-only storage, a non-root user, dropped capabilities, bounded resources and
an empty environment. They communicate only through JSONL stdin/stdout. Target
actions and model requests are declarations: the Host validates them and may
route them to its Gateway or model adapter; a child has no ambient authority.

Resumption verifies the frozen scope and hash-chained workflow events before a
completed task can be reused. Missing manifests, trust material, sandbox support
or verified evidence are fail-closed conditions.

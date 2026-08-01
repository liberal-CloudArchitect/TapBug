# Hermes CTF Lab extension

This is a separately packaged, teaching-only archive for CTF flag capture,
exploit reasoning, dynamic code synthesis, crypto/pwn solvers, and destructive
benchmark harnesses. It is **not** installed by `hermes-security-team`, and the
main Hermes runtime never imports it.

The extension is intentionally unavailable to production, bug-bounty, and
general engagement profiles. Its legacy modules require a dedicated local-lab
adapter; they must run only in an isolated Docker or loopback CTF environment
under an independently reviewed safety policy. Environment variables are not a
substitute for that policy or for a human approval.

Do not add this directory to `PYTHONPATH` in a normal Hermes installation. Any
future lab runner must enforce no-production-target and isolated-network checks
before it imports an executable module from this package.


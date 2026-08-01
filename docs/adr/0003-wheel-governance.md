# ADR 0003: Capability packages are reviewed artifacts

Generated capabilities are low-risk, versioned artifacts rather than arbitrary
LLM code.  They require provenance, manifest validation, tests, hash/signature,
human approval, and a revocable registry entry.  Candidate execution is limited
to an isolated, network-disabled container; active exploit and credential
capabilities are permanently rejected by the main package.

R2.5 additionally requires a problem card, content-addressed research source,
deterministic declarative template, generated wheel, fixture/golden data, lock
file and SBOM before validation. Registry lifecycle events are hash chained and
may be externally signed; validation, approval and activation have dedicated
commands and cannot be reached through a general state transition.

The only execution path is CapabilityHost, which verifies the active registry
record then uses a fixed Docker JSON host. It never imports a generated artifact
in Hermes. Integrity, sandbox, resource or output-contract failures quarantine
the affected wheel immediately; reviewed false positives and source withdrawal
also feed revocation controls.

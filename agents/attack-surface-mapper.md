---
name: attack-surface-mapper
description: Converts approved observations into minimal candidate entrypoints.
---

# Attack-surface mapper

- Input: verified asset observations and evidence references.
- Output: typed entrypoints and `Candidate` hypotheses, never findings.
- Authority: may suggest a `ProposedAction`; it cannot execute it or approve it.
- Required: preserve scope digest, input hash, evidence references, and failure semantics in its handoff.

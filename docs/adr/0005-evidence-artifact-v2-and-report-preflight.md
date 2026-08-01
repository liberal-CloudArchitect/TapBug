# ADR 0005: EvidenceArtifact V2 and report preflight

Status: accepted, 2026-07-13.

New runs use only version 2 domain contracts and EvidenceArtifact manifests. Evidence is owned by
the parent runtime, not role containers. Each completed artifact contains a bounded, MIME-aware,
redacted analysis copy and may contain an AES-256-GCM encrypted raw copy. The manifest is committed
last and binds run, scope, task input, role, request, action, plan, approval bundle, and approval
consumption. A missing manifest denotes an incomplete artifact.

Raw retention is disabled by default. When enabled, the operator supplies an absolute, non-symlink,
0600, exactly 32-byte key file outside both the repository and runs root. The manifest records key
ID, nonce, AAD digest, plaintext hash, and ciphertext hash; private key material is never copied into
run artifacts. The current file provider preserves a future KMS boundary without adding a dependency.

Only the parent PromotionService may construct ValidatedFinding. ReportPreflightVerifier reloads all
canonical artifacts and checks exact set equality across approval, consumption, evidence, outcome,
finding, coverage, signed review, and draft. Reporter receives a recomputable authorization receipt,
but that receipt is not authority by itself: preflight runs again immediately before formal files are
created. V1 artifacts remain audit-readable and non-promotable; they are never silently upgraded.

Rejected alternatives:

- Trusting hashes copied into a Finding was rejected because a syntactically valid path or digest
  does not prove the referenced artifact exists or belongs to the current context.
- Signing the receipt with a fourth key was rejected because its authority is derived from re-running
  deterministic verification over already signed approval and review inputs.
- Raw retention by default was rejected because it unnecessarily increases sensitive-data exposure.

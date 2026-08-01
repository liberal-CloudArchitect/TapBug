# ADR 0004: CTF isolation, data retention, and benchmark boundaries

The main distribution contains no CTF, exploit, dynamic synthesis, mutable lab,
or benchmark execution path.  Historical teaching material remains only in the
separately packaged `extensions/hermes_ctf_lab` extension and is never selected
by the main runtime.

Every core run retains only its own immutable scope snapshot, approval-consumption
markers, redacted evidence hashes, handoffs, reports, and wheel journal below
`runs/<run_id>/`.  Quality fixtures and their truth labels must be versioned and
evaluated separately from detector implementation; CTF capture rates are never a
security-detection metric.

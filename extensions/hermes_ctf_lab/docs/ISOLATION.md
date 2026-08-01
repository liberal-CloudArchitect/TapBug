# Isolation contract

- `hermes-security-team` builds only `src/hermes`; it excludes `extensions/`.
- `hermes-ctf-lab` is an opt-in package with no automatic entry point.
- The extension holds historical CTF solvers and benchmark harnesses only. It is
  not a supported capability provider for the main runtime.
- Production profiles must reject extension module names and never make this
  directory importable at runtime.
- Legacy runner scripts are retained for research traceability, not as approved
  execution instructions.


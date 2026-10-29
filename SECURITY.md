# Security policy

## Reporting a vulnerability

We only accept vulnerability reports through
[GitHub Security Advisories](https://github.com/trailofbits/fickling/security/advisories/new).
We publish the original report after a fix is released.

## What to include

- A minimal reproducer using fickling's opcode API or Python's `pickle` module.
  Do not hand-assemble pickle bytes.
- What Fickling reported and what happened during analysis or unpickling.
- A harmless proof of concept, such as printing a marker. Do not read sensitive
  files, open an interactive shell, or fetch remote code.

## What is out of scope

- Denial of service, including crashes, hangs, and excessive CPU or memory use.
  Report these through [regular GitHub issues](https://github.com/trailofbits/fickling/issues/new).
- Bypasses of the supplementary `UnusedVariables` heuristic alone. Report a
  security bypass only if the pickle evades all other Fickling checks.

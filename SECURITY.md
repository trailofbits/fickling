# Security Policy

## Reporting a vulnerability

Please report vulnerabilities through [GitHub Security Advisories](https://github.com/trailofbits/fickling/security/advisories/new). Do not open public issues for security reports.

## What to include

- A minimal reproducing test case using fickling's opcode API (`op.Proto`, `op.ShortBinUnicode`, `op.StackGlobal`, `op.Reduce`, etc.) or Python's `pickle` module. Do not submit raw byte strings.
- Use `echo` or `print` for PoCs — no shells, no sensitive file reads, no remote scripts.
- A brief impact description (e.g., "module X is not blocklisted and enables code execution"). Elaborate exploitation scenarios are not necessary.

## What is out of scope

- **`UnusedVariables` bypasses.** This is an intentionally weak, supplementary heuristic. Bypassing it alone is not a meaningful finding.

## Fixes

Do not include suggested code fixes in reports unless they have been reviewed and approved by a maintainer first. If a fix is accepted, it will include a regression test in `test/test_bypasses.py` linked to the advisory.

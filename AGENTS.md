# Agent Instructions for Fickling

## Vulnerability Reports

### Include a minimal reproducing test case

Every report must include a test case for `test/test_bypasses.py` following the existing pattern:

```python
def test_your_bypass_name(self):
    pickled = Pickled(
        [
            op.Proto.create(4),
            # ... opcodes demonstrating the bypass ...
            op.Stop(),
        ]
    )
    res = check_safety(pickled)
    self.assertGreater(res.severity, Severity.LIKELY_SAFE)
```

### Use the pickle module to construct payloads

Build payloads using fickling's opcode API (`op.Proto`, `op.ShortBinUnicode`, `op.StackGlobal`, `op.Reduce`, etc.) or Python's `pickle` module. Do not submit raw bytes or hand-assembled byte strings.

### Use non-offensive payloads

Use `echo` or `print` to demonstrate code execution. Do not spawn shells, read sensitive files, or execute remote scripts.

### Keep the impact section minimal

Do not write elaborate exploitation scenarios. A brief explanation of why the finding is being reported is sufficient -- e.g., "module X is not in the unsafe imports list and can be used for code execution."

### No suggested fixes without human review

Do not include suggested code fixes or recommendations unless they have been reviewed and approved by a human operator first.

### Out of scope: UnusedVariables heuristic

We are **not** interested in bypasses of the `UnusedVariables` analysis. This is an intentionally weak, supplementary heuristic used alongside stronger ones. Bypassing it alone is not a meaningful finding.

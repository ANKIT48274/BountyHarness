---
description: Independently verify a candidate finding before reporting
agent: vuln-verification
---

Verify this candidate finding: $ARGUMENTS

1. Locate the candidate and its original request/response evidence.
2. Reproduce safely with the smallest possible request.
3. Run the owning skill's verify workflow if available, then
   `bin/bb-run impact-verifier <workflow>`.
4. Apply the `triage-validation` seven-question gate.
5. Return: confirmed / needs-more-evidence / rejected, with exact reproduction
   steps, impact, CVSS suggestion, and evidence paths.

---
description: Generate a report for verified findings and run the quality gate
agent: pentest-reporting
---

Generate a report for: $ARGUMENTS

1. Confirm every finding passed `impact-verifier` and `triage-validation`.
2. Run `bin/bb-run reporting generate-single`, then `cvss-score`,
   `platform-export`, and `quality-check`.
3. Ensure each finding includes title, asset, endpoint, severity/CVSS,
   description, reproducible steps, exact request/payload, evidence, impact, and
   remediation.
4. Redact secrets and third-party data. Do not submit to any platform.

---
description: Initialize a BountyHarness engagement with an explicit scope file
agent: bounty-harness
---

Initialize an authorized BountyHarness engagement for: $ARGUMENTS

Steps:
1. Ask for a target domain and a local authorization/scope file if either is missing.
2. Verify the scope file exists and is readable without printing secret contents.
3. Run `bin/bb-init <target> --program <name> --scope-file <file>`.
4. Run `bin/bb-validate` and summarize the resulting `TARGET`, `PROGRAM`,
   `OUTDIR`, `EVIDENCE_DIR`, `RATE_LIMIT`, and `SCOPE_FILE` metadata.
5. Do not start any target testing in this command.

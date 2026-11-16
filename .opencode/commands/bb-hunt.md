---
description: Plan and run a bounded autonomous campaign against an authorized target
agent: bounty-harness
---

Prepare an autonomous BountyHarness campaign for: $ARGUMENTS

Safety gate (all required):
1. Confirm the target is in the written authorization/scope file.
2. Ask the user to approve intrusive testing if `--max-tier intrusive` is wanted.
3. Prefer `--dry-run` first and show the plan.
4. Keep the safety ceiling at `active-safe` when no valid scope file exists.

Then run:
`bin/bb-hunt <url> --scope-file <file> --max-tier <tier> --time-budget <budget>`

Monitor with `bin/bb-run campaign status`. Triage candidates through
`vuln-verification`; report only impact-verified findings. Stop immediately on
a circuit-breaker block.

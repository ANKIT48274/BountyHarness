---
description: Show campaign status, recent traces, and completed workflows
agent: bounty-harness
---

Report the current BountyHarness engagement status.

1. Run `bin/bb-run campaign status` if a campaign was started.
2. Summarize the last entries of `.bb/traces/runs.jsonl` (redacted fields only).
3. List available output directories under `$OUTDIR` and note which workflows
   have already run, so work is not duplicated.
4. If the circuit breaker is active for the target, say so and stop.

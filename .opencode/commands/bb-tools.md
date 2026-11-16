---
description: Inspect BountyHarness external tool availability and health
agent: bounty-harness
---

Check the BountyHarness toolchain, optionally scoped to: $ARGUMENTS

Run:
1. `bin/bb-tools list`
2. `bin/bb-tools list --missing`
3. `bin/bb-tools doctor`
4. If a skill was named, `bin/bb-tools doctor --skill <skill>`.

Summarize installed, missing, and unhealthy tools. Do not auto-install anything.
Install commands must be approved by the operator first.

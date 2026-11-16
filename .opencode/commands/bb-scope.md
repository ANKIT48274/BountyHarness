---
description: Validate the current engagement scope and authorization
agent: bounty-harness
---

Validate scope for: $ARGUMENTS

1. Run `bin/bb-validate`.
2. Read `.bb/context.json` scope metadata without exposing credentials.
3. If a URL or host was supplied, run
   `bin/bb-run scope-manager validate-url <value>` when that workflow is
   available; otherwise compare it manually against the scope file.
4. Report: in scope, out of scope, or unknown. If unknown, stop and ask the
   operator for the authoritative scope.

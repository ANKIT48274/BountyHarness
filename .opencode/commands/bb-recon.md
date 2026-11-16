---
description: Run the passive-to-active-safe recon chain for the current engagement
agent: recon
---

Run reconnaissance for the current engagement, optionally restricted to: $ARGUMENTS

Preconditions:
- `.bb/context.env` exists and `bin/bb-validate` passes.
- If the scope file is missing or empty, run passive workflows only.

Then:
1. `bin/bb-run recon passive-subdomains`
2. `bin/bb-run recon live-discovery`
3. `bin/bb-run recon js-recon`
4. `bin/bb-run domain-model classify`
5. `bin/bb-run domain-model map-surfaces`
6. `bin/bb-run domain-model profile`
7. `bin/bb-run technique-kb match`

Report the output paths and the proposed attack surface. Do not run intrusive
scanners or vulnerability payloads.

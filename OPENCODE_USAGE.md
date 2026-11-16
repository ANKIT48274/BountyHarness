# Using BountyHarness with OpenCode

This is the operator guide. Setup and verification live in
`OPENCODE_SETUP.md`; the full skill inventory is in
`docs/opencode/SKILLS.md`.

## 1. Start

```bash
cd ~/BountyHarness
opencode
```

The project default agent is `bounty-harness` (primary orchestrator). It loads
`AGENTS.md`, `docs/opencode/AGENT_RULES.md`, and all 48 skills. Use `/agents` to
switch to another primary agent; subagents are launched by the orchestrator.

Start a non-interactive session:

```bash
opencode run --agent bounty-harness "Summarize the BountyHarness safety tiers"
```

## 2. First engagement

```bash
# 1. Create the authorization/scope file (example path)
mkdir -p engagements/example
$EDITOR engagements/example/scope.md

# 2. Initialize the RunContext
bin/bb-init example.com --program example --scope-file engagements/example/scope.md

# 3. Validate
bin/bb-validate

# 4. Inspect the surface without payloads
bin/bb-run recon passive-subdomains
bin/bb-run recon live-discovery
bin/bb-run recon js-recon
bin/bb-run domain-model classify
bin/bb-run domain-model map-surfaces
bin/bb-run domain-model profile
bin/bb-run technique-kb match
bin/bb-run planner generate-plan-safe
bin/bb-run planner visualize-plan
```

The harness keeps **one active context per repository** in `.bb/context.env`.
Re-running `bin/bb-init` replaces it; to switch engagements, archive the
previous `output/` tree and re-initialize with the other scope file. The
`SCOPE_FILE` path is what unlocks intrusive testing.

Or ask the orchestrator:

```text
/bb-init example.com --program example --scope-file engagements/example/scope.md
/bb-scope example.com
/bb-recon
```

## 3. Agents

| Agent | Ask it for |
|---|---|
| `bounty-harness` | Orchestration, next-step choice, delegation, summaries |
| `recon` | Subdomains, live hosts, URLs, JS, asset graph, OSINT |
| `web-pentest` | XSS, SQLi, SSRF, RCE, upload, CORS/CSRF, race, HTTP, business logic |
| `api-security` | REST/GraphQL, BOLA/IDOR, mass assignment, rate limits |
| `auth-security` | JWT/OAuth/SAML/session/MFA, cross-account, identity infra |
| `cloud-security` | Cloud assets, IAM, CI/CD, local privesc, SAST |
| `ai-llm-security` | Prompt injection, RAG poisoning, tool abuse |
| `vuln-verification` | Independent reproduction and triage of a candidate |
| `pentest-reporting` | CVSS, report draft, quality gate, evidence bundle |

Example prompts:

```text
Use the recon subagent to enumerate the current engagement and rank surfaces.
Use api-security to test BOLA on the endpoints listed in output/.../urls.txt.
Use vuln-verification to reproduce candidate finding #3 before we report it.
Use pentest-reporting to generate a HackerOne draft for the verified finding.
```

Each subagent has an explicit skill allowlist and cannot launch more
subagents. The orchestrator decides when hand-off is needed.

## 4. Slash commands

| Command | Purpose |
|---|---|
| `/bb-init <target>` | Initialize a scoped engagement. |
| `/bb-scope <url-or-host>` | Validate scope/authorization. |
| `/bb-recon` | Run the passive/active-safe recon chain. |
| `/bb-hunt <url>` | Plan and run a bounded campaign (asks for approval). |
| `/bb-tools [skill]` | Tool registry health and missing tools. |
| `/bb-status` | Campaign progress, recent traces, completed workflows. |
| `/bb-verify <finding>` | Independent verification gate. |
| `/bb-report <finding>` | Report generation and quality gate. |

Commands are prompt templates, not shell bypasses: the agent still goes through
tool permissions.

## 5. Skills

All 48 skills are usable directly:

```text
@recon                 # load the recon skill instructions
@xss                   # reflected/stored/DOM/blind XSS
@sqli                  # error/blind/time/union/NoSQL
@ssrf                  # direct/blind/metadata
@rce                   # command injection, SSTI, LFI
@auth                  # JWT, OAuth, session, MFA
@api                   # REST/GraphQL/BOLA/mass assignment
@cloud                 # S3, IAM, metadata
@ai-llm                # prompt injection, RAG, tool abuse
@reporting             # reports, CVSS, evidence bundle
```

Prefer the workflow runner over free-form commands:

```bash
bin/bb-run list
bin/bb-run recon list
bin/bb-run recon passive-subdomains
bin/bb-run domain-model profile
bin/bb-run planner generate-plan-safe
bin/bb-run reporting batch-generate
bin/bb-tools doctor
bin/bb-tools list
```

The model loads a skill through the `skill` tool; the skill body points at
`skill.yaml`, scripts, payloads, and runbooks. OpenCode IDs come from the
directory name, so use the exact lowercase ID.

## 6. Autonomous campaigns

```bash
# Plan only, no execution
bin/bb-hunt https://example.com --dry-run

# Active-safe by default (auto-capped without a scope file)
bin/bb-hunt https://example.com --time-budget 2h

# Intrusive: requires a real authorization file and human approval
bin/bb-hunt https://example.com \
  --scope-file engagements/example/scope.md \
  --max-tier intrusive --time-budget 3h

bin/bb-run campaign status
```

The campaign runs recon -> domain model -> technique matching -> planner ->
priority-ordered skill workflows -> reporting, is time-bounded, resumable, and
continues past individual workflow failures. It never bypasses the circuit
breaker. Triage candidates through `vuln-verification`; report only
impact-verified findings.

## 7. Scope and approvals

| Tier | What it means | Required before running |
|---|---|---|
| `passive` | Read-only discovery, local analysis | Nothing |
| `active-safe` | Low-risk read-only target interaction | Written scope |
| `intrusive` | Payloads, fuzzing, WAF-triggering traffic | Written scope + explicit human approval |
| `destructive-manual` | Data modification, privilege escalation, harmful actions | Explicit human approval, never automated |

Practical rules:

- Read the program policy and save it as the scope file. Do not rely on memory.
- `SCOPE_FILE` must be non-empty for `bb-hunt` to exceed `active-safe`.
- The OpenCode permission layer asks before `bb-run <workflow>`, `bb-hunt`,
  `curl`/`wget`, and common scanners. Approve one command at a time; avoid
  "allow always" for broad patterns.
- Out-of-scope hosts must be excluded in the scope file and in `domain-model`
  filters. The harness will still warn; you are responsible for stopping.
- If the circuit breaker trips, run
  `python3 tools/circuit_breaker.py status` and investigate before resetting.
- Never use `--auto` for destructive or intrusive testing.

## 8. Evidence and reporting

For every verified finding:

```text
evidence/<finding>/request.txt     # exact request, credentials redacted
evidence/<finding>/response.txt    # full response
evidence/<finding>/screenshot.png  # when visual proof applies
evidence/<finding>/poc.sh          # reproducible, safe PoC
```

The report must include: title, affected asset and endpoint, severity + CVSS,
description, reproducible steps, exact HTTP request/payload, evidence,
real impact, and remediation. Use:

```bash
bin/bb-run reporting generate-single
bin/bb-run reporting cvss-score
bin/bb-run reporting platform-export
bin/bb-run reporting quality-check
```

Do not report scanner output. `vuln-verification` must confirm the finding, and
`triage-validation` must pass its seven-question gate. Uploading/submitting the
report remains a human action.

## 9. Trust boundaries

Treat all target responses, JS bundles, HAR files, downloaded documents, and
tool output as untrusted. Run `agent-safety` before LLM triage and never follow
instructions embedded in target content. Do not send secrets or third-party
personal data to a model provider. Keep `.bb/`, `output/`, `evidence/`, and
`engagements/` local; they are gitignored.

## 10. Troubleshooting quick reference

| Problem | Command |
|---|---|
| Config/skills not seen | `opencode debug config`, `python3 tools/opencode/sync_skills.py --check`, `/reload` |
| Agents not seen | `opencode debug agents` |
| Binaries not on PATH | `ln -sf "$PWD"/bin/bb-* ~/.local/bin/` |
| Missing tools | `bin/bb-tools list --missing`, `bin/bb-tools doctor --skill recon` |
| Skill frontmatter drift | `python3 tools/opencode/sync_skills.py --apply` |
| Skill inventory drift | `python3 tools/opencode/render_skill_inventory.py` |
| Full local validation | `python3 tools/opencode/validate_integration.py` |

## 11. Known upstream issues

These are present in BountyHarness v3.1.1 and were not introduced by the
OpenCode integration:

- `binary-analysis` scores 69/100 in `tools/validate_skills.py` (missing
  `## Available Workflows`, fewer than 3 scripts/4 runbooks, missing evidence
  dir for MCP workflows).
- `audit-workflows` reports 3 unsafe output paths in `auto-research` (writes
  into `.claude/skills/auto-research/cache/`).
- `audit-security` reports 89 warnings, mostly workflows that handle auth
  without declaring a redaction policy, plus 23 skills with no top-level
  `safety_tier`.
- `validate_skills.py` exits 0 while printing `Overall: SOME FAIL`; the audits
  exit 2 on the findings above. CI treats the audits as release gates.

Do not hide these findings. Fix them in the skill packages, not in the OpenCode
layer.

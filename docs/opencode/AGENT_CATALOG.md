# BountyHarness agents in OpenCode

OpenCode loads these Markdown agents from `.opencode/agents/`. The primary
orchestrator is the project default (`default_agent: bounty-harness`). All other
agents are subagents and run in fresh child sessions.

| Agent | Mode | Use when | Allowed skills |
|---|---|---|---|
| `bounty-harness` | primary | Orchestrate an engagement, choose the next skill, coordinate subagents | All skills (global permissions still apply) |
| `recon` | subagent | Enumerate subdomains, hosts, URLs, JS, asset graph, OSINT | recon, osint, domain-model, asset-graph, scope-manager, vuln-intel, technique-kb, planner, coverage, program-memory, agent-safety |
| `web-pentest` | subagent | Test XSS, SQLi, SSRF, RCE, upload, CORS/CSRF, race, HTTP, browser, business logic | xss, sqli, ssrf, rce, file-upload, cors-csrf, race-condition, business-logic, modern-browser, http-protocol, oob-infra, recon, technique-kb, impact-verifier, agent-safety |
| `api-security` | subagent | REST, GraphQL, BOLA/IDOR, mass assignment, rate limits | api, graphql-audit, cross-account, persona, business-logic, traffic-corpus, oob-infra, recon, domain-model, technique-kb, impact-verifier, agent-safety |
| `auth-security` | subagent | JWT, OAuth, SAML, sessions, MFA, identity infrastructure | auth, cross-account, identity-domain, persona, api, business-logic, osint, recon, technique-kb, impact-verifier, agent-safety |
| `cloud-security` | subagent | Cloud assets, IAM, CI/CD, identity infra, local privesc, SAST | cloud, privesc, identity-domain, cicd-security, sast, nuclei-scanner, recon, osint, technique-kb, impact-verifier, agent-safety |
| `ai-llm-security` | subagent | Prompt injection, RAG poisoning, tool abuse, LLM trust boundaries | ai-llm, agent-safety, api, recon, technique-kb, impact-verifier, triage-validation |
| `vuln-verification` | subagent | Independently reproduce and triage a candidate before reporting | impact-verifier, triage-validation, agent-safety, and the vulnerability skill that owns the candidate |
| `pentest-reporting` | subagent | CVSS, report generation, quality gate, evidence bundle | reporting, triage-validation, impact-verifier, enrichment, standard-catalog, program-memory, agent-safety |

## Delegation flow

```text
bounty-harness
  ├─ recon ──────────────── surface map, ranked opportunities
  ├─ web-pentest ─────────┐
  ├─ api-security ────────┤
  ├─ auth-security ───────┼─> candidate findings + evidence
  ├─ cloud-security ──────┤
  └─ ai-llm-security ─────┘
                 │
                 ▼
        vuln-verification ── confirmed / needs-evidence / rejected
                 │
                 ▼
        pentest-reporting ── report draft + quality gate
```

The orchestrator should send the smallest relevant context to each subagent:
target, scope file path (not credentials), evidence paths, and the specific
hypothesis. Subagents cannot launch further subagents.

## Permission model

All agents inherit the project rules in `opencode.json`, then apply their own
rules:

- `skill: *` is denied, then an explicit allowlist is added. This prevents a
  specialized agent from casually loading unrelated attack skills.
- `edit` is denied by default, then limited to `output/`, `evidence/`, and
  `engagements/` (reporting also gets `reports/`).
- Subagents deny `subagent: *`, so they cannot fan out further.
- The global rules still deny secret reads, destructive shell commands, pushes,
  and credential exfiltration, and still ask before network scanners,
  `bb-run <workflow>`, and `bb-hunt`.

## Adding an agent

1. Create `.opencode/agents/<name>.md`.
2. Add `description`, `mode: subagent`, a short system prompt, and an explicit
   skill allowlist.
3. Add the agent to this catalog and to `REQUIRED_AGENT_FILES` in
   `tools/opencode/validate_integration.py`.
4. Run `python3 tools/opencode/validate_integration.py` and `opencode debug agents`.

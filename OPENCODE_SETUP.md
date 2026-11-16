# OpenCode setup for BountyHarness

This guide installs and verifies the native OpenCode V2 integration for
BountyHarness. It does not change the Claude Code workflow: `CLAUDE.md` and
`.claude/skills/` remain the canonical harness assets.

- Tested OpenCode: **v2.2.7**
- Tested harness: **v3.1.1** (`v3.1.1-29-gd594684`)
- Skills: **48**
- Agents: **1 primary + 8 subagents**
- Slash commands: **8**

## 1. Requirements

| Requirement | Check |
|---|---|
| OpenCode V2 on `PATH` | `opencode --version` |
| Python 3.11+ | `python3 --version` |
| PyYAML | `python3 -c 'import yaml; print(yaml.__version__)'` |
| Git | `git --version` |
| Harness binaries | `bin/bb-init`, `bin/bb-run`, `bin/bb-hunt`, `bin/bb-tools`, `bin/bb-validate` |

OpenCode V2 is required. V1 configuration (`permission`, `bash`, `task`) is not
used. The integration relies on V2 `permissions`, `agents`, `commands`,
`skills`, and `instructions` behavior.

## 2. Install

```bash
git clone https://github.com/zyphr-labs/bounty-harness.git ~/BountyHarness
cd ~/BountyHarness
./install.sh          # optional: checks deps and symlinks bb-* onto PATH
```

If you prefer not to run the installer:

```bash
mkdir -p ~/.local/bin
ln -sf "$PWD"/bin/bb-init    ~/.local/bin/
ln -sf "$PWD"/bin/bb-run     ~/.local/bin/
ln -sf "$PWD"/bin/bb-hunt    ~/.local/bin/
ln -sf "$PWD"/bin/bb-tools   ~/.local/bin/
ln -sf "$PWD"/bin/bb-validate ~/.local/bin/
export PATH="$HOME/.local/bin:$PATH"
```

`~/.local/bin` is already on this machine's `PATH`. The `bb-*` scripts resolve
their own repository root, so they work from any directory and still use the
repository's `.bb/context.env`.

## 3. Files added for OpenCode

| File | Purpose |
|---|---|
| `opencode.json` | Project config: default orchestrator, skill source, permissions, watcher ignores. |
| `.opencode/agents/bounty-harness.md` | Primary orchestrator. |
| `.opencode/agents/recon.md` | Recon subagent. |
| `.opencode/agents/web-pentest.md` | Web application testing subagent. |
| `.opencode/agents/api-security.md` | API/GraphQL subagent. |
| `.opencode/agents/auth-security.md` | Authentication/authorization subagent. |
| `.opencode/agents/cloud-security.md` | Cloud/CI-CD/identity/privesc subagent. |
| `.opencode/agents/ai-llm-security.md` | AI/LLM security subagent. |
| `.opencode/agents/vuln-verification.md` | Independent verification gate. |
| `.opencode/agents/pentest-reporting.md` | Reporting and evidence packaging. |
| `.opencode/commands/bb-init.md` | `/bb-init` engagement bootstrap. |
| `.opencode/commands/bb-recon.md` | `/bb-recon` recon chain. |
| `.opencode/commands/bb-hunt.md` | `/bb-hunt` bounded campaign. |
| `.opencode/commands/bb-tools.md` | `/bb-tools` tool health. |
| `.opencode/commands/bb-scope.md` | `/bb-scope` scope validation. |
| `.opencode/commands/bb-verify.md` | `/bb-verify` candidate verification. |
| `.opencode/commands/bb-report.md` | `/bb-report` report generation. |
| `.opencode/commands/bb-status.md` | `/bb-status` campaign progress. |
| `docs/opencode/AGENT_RULES.md` | Mandatory preflight, approval, evidence, and secret rules. |
| `docs/opencode/AGENT_CATALOG.md` | Agent roles, skill allowlists, delegation flow. |
| `docs/opencode/SKILLS.md` | Generated inventory of all 48 skills and tiers. |
| `tools/opencode/sync_skills.py` | Adds/fixes OpenCode frontmatter without touching skill bodies. |
| `tools/opencode/render_skill_inventory.py` | Regenerates `docs/opencode/SKILLS.md` from `skill.yaml`. |
| `tools/opencode/validate_integration.py` | Local integration validator. |

## 3a. Changes to existing files

| File | Change |
|---|---|
| `AGENTS.md` | Added the OpenCode integration section, completed the 48-skill catalog, and added OpenCode verification commands. |
| `.claude/skills/*/SKILL.md` (43 files) | Added YAML frontmatter derived from `skill.yaml`; bodies, scripts, payloads, runbooks, and safety data unchanged. Five skills already had frontmatter and were untouched. |
| `Makefile` | Added `make opencode-check`. |
| `bin/bb-tools` | Fixed an upstream `set -u` failure: `SCRIPT_DIR` was referenced by the doctor path but never defined. `bb-tools doctor` now works. |
| `tools/validate_skills.py` | The redaction check now ignores YAML frontmatter so adding metadata cannot change validator scores. |
| `tools/adapters/render_adapter.py` | Resolves the canonical guide from `AGENTS.md` when `CLAUDE.md` is only an `@AGENTS.md` stub; refuses to overwrite `AGENTS.md` for the OpenCode target. |
| `docs/adapters.md` | Documented the native OpenCode integration and why adapter apply is refused. |
| `README.md`, `install.sh` | Corrected the stale “46 skills” count to 48. |

## 4. How discovery works

### Instructions

OpenCode V2 loads `AGENTS.md` and **does not** fall back to `CLAUDE.md`. This
repository's `AGENTS.md` is therefore the shared instruction source; `CLAUDE.md`
still contains `@AGENTS.md` for Claude Code.

### Skills

OpenCode automatically searches `.claude/skills/` as a project compatibility
source, so all 48 skills are discoverable without moving or duplicating them.
OpenCode only advertises a skill when its `SKILL.md` has YAML frontmatter with a
`description`. The five skills that already shipped frontmatter were left
unchanged; the other 43 received a frontmatter block derived from their
`skill.yaml`.

```bash
python3 tools/opencode/sync_skills.py --check   # must pass
python3 tools/opencode/sync_skills.py --apply   # add missing frontmatter
```

Frontmatter is additive. The original Markdown body, scripts, payloads,
runbooks, safety tiers, and evidence requirements are untouched.

### Agents and commands

OpenCode discovers `.opencode/agents/*.md` and `.opencode/commands/*.md`
automatically. No MCP server is required: the harness uses local scripts and
the shell, and adding MCP would expand the trust boundary without adding
capability. The `binary-analysis` skill mentions an optional x64dbg MCP server;
configure it yourself only if you perform Windows binary analysis.

## 5. Safety configuration

`opencode.json` contains ordered permission rules (last match wins):

- **Ask** before `bb-run <workflow>`, `bb-hunt`, `curl`, `wget`, and common
  scanners (`nmap`, `nuclei`, `ffuf`, `sqlmap`, `dalfox`, `subfinder`, `amass`,
  `httpx`, `katana`, `naabu`, `interactsh-client`).
- **Allow** safe inspection: `bb-run list`, `bb-run <skill> list`, `bb-init`,
  `bb-validate`, `bb-tools list/doctor/verify/lock`, passive recon
  (`passive-subdomains`, `ct-index-enum`), planner/domain-model/reporting/
  scope/coverage/verification workflows, `make test/validate/lint/audit`, and
  the local validators.
- **Deny** `sudo`, `su`, `doas`, shutdown/reboot, `mkfs`, raw `dd` to devices,
  `rm -rf /`, `$HOME`, or `~`, `git push`, `git reset --hard`, `git clean`,
  `curl|sh`/`wget|bash`, reading or `cat`-ing `.env`, `.bb/context.env`,
  SSH keys, `.pem`, `.key`, credentials/token JSON, `printenv`, `env`, and
  `gh auth token`.
- **Deny** reads/edits of `.env`, `.bb/context.*`, SSH keys, `.pem`, `.key`,
  and credential/token JSON. Secret reads are stricter than the OpenCode
  default (`ask`).
- **Ask** before any directory access outside the project, except
  `/tmp/opencode/*`.

The subagents additionally deny all skills except their explicit allowlist and
deny `edit` outside `output/`, `evidence/`, and `engagements/` (plus `reports/`
for reporting). They cannot launch further subagents.

These rules complement, not replace, the harness controls: scope validation,
safety tiers, rate limits, redacted traces, and the circuit breaker.

## 6. Verification

Run these from the repository root. None of them contact a target.

```bash
make opencode-check
python3 tools/opencode/validate_integration.py
python3 tools/opencode/sync_skills.py --check
make test
python3 tools/validate_skills.py
python3 tools/validate_skills.py audit-workflows
python3 tools/validate_skills.py audit-security
opencode debug config
opencode debug agents
```

Expected:

- `validate_integration.py` exits 0.
- `sync_skills.py --check` reports all skills have frontmatter.
- `make test` exits 0.
- `opencode debug agents` lists `bounty-harness`, `recon`, `web-pentest`,
  `api-security`, `auth-security`, `cloud-security`, `ai-llm-security`,
  `vuln-verification`, and `pentest-reporting`.

The skill quality validator and security audit have **pre-existing** findings
in upstream v3.1.1 (`binary-analysis` scores 69/100; 3 unsafe auto-research
output paths; warnings for missing workflow redaction). They are documented in
`OPENCODE_USAGE.md`; this integration did not introduce them.

## 7. Backups and rollback

Before changing files, copy the originals:

```bash
tar -czf /tmp/opencode/bountyharness-backup-$(date +%Y%m%d-%H%M%S).tar.gz \
  AGENTS.md CLAUDE.md .claude/skills docs/adapters.md tools/adapters install.sh
```

To roll back only the OpenCode integration:

```bash
rm -rf .opencode opencode.json OPENCODE_SETUP.md OPENCODE_USAGE.md docs/opencode tools/opencode
git checkout -- AGENTS.md README.md install.sh docs/adapters.md tools/adapters
git checkout -- .claude/skills      # removes the added frontmatter
```

Claude Code continues to work throughout: its entry point is still `CLAUDE.md`
and its skill directory was not moved.

## 8. Troubleshooting

| Symptom | Fix |
|---|---|
| `opencode: command not found` | Add `~/.opencode/bin` or the install location to `PATH`. |
| `bb-run: command not found` | Symlink `bin/bb-*` into `~/.local/bin`, or call `bin/bb-run`. |
| Skills not listed | Run `python3 tools/opencode/sync_skills.py --check`; confirm `opencode.json` includes `.claude/skills`. |
| Agent missing | Run `opencode debug agents`; confirm the file is in `.opencode/agents/*.md` with V2 frontmatter. |
| Config not applied | Run `/reload` or `opencode reload`; V2 watches config files. |
| Permission prompts in scripts | Expected for `bb-run`/`bb-hunt`; use `opencode run --auto` only in a controlled lab, never for `destructive-manual`. |
| `opencode debug config` shows global overrides | Global config is lower priority than project config, but system `/etc/opencode` is higher. Check the listed sources. |
| Skill loads the wrong content | OpenCode IDs come from the path. Use `@recon`, not the display name. |
| Missing tool | `bin/bb-tools list --missing`, then `bin/bb-tools doctor`; installs require approval. |
| Circuit breaker active | `python3 tools/circuit_breaker.py status`; reset only after investigation. |

## 9. Manual steps

1. Set a default model for your environment if the inherited model is not
   desired: `opencode models`, then add `"model": "provider/model"` to
   `opencode.json` or use `/models`.
2. Provide a written authorization/scope file before any active testing. Never
   rely on `active-safe` as a substitute for authorization.
3. Keep provider keys outside the repository (for example `~/.secrets/*.env`
   with mode 600) and reference them with `{env:VAR}` or `{file:...}`.
4. Optionally configure the x64dbg MCP server for `binary-analysis`; it is not
   needed for the other 47 skills.
5. Run the verification block above after updating BountyHarness or OpenCode.

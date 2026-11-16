#!/usr/bin/env python3
"""Local validation for the BountyHarness <-> OpenCode integration.

Runs no target traffic. Checks configuration shape, skill frontmatter, agent and
command discovery, CLI availability, safety-permission behavior, documentation,
and obvious secret leakage.

Usage:
    python3 tools/opencode/validate_integration.py
    python3 tools/opencode/validate_integration.py --json
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("Error: pyyaml is required (python3 -m pip install pyyaml)")

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SKILLS_DIR = REPO_ROOT / ".claude" / "skills"
AGENTS_DIR = REPO_ROOT / ".opencode" / "agents"
COMMANDS_DIR = REPO_ROOT / ".opencode" / "commands"
CONFIG_PATH = REPO_ROOT / "opencode.json"
BIN_DIR = REPO_ROOT / "bin"
DOCS = [
    REPO_ROOT / "OPENCODE_SETUP.md",
    REPO_ROOT / "OPENCODE_USAGE.md",
    REPO_ROOT / "docs/opencode/AGENT_RULES.md",
    REPO_ROOT / "docs/opencode/SKILLS.md",
    REPO_ROOT / "docs/opencode/AGENT_CATALOG.md",
]
REQUIRED_BINS = ["bb-init", "bb-run", "bb-hunt", "bb-tools", "bb-validate", "bb-netns"]
# The task names "Pentest Reporting Agent"; the file is pentest-reporting.md.
REQUIRED_AGENT_FILES = {
    "bounty-harness": "primary",
    "recon": "subagent",
    "web-pentest": "subagent",
    "api-security": "subagent",
    "auth-security": "subagent",
    "cloud-security": "subagent",
    "ai-llm-security": "subagent",
    "vuln-verification": "subagent",
    "pentest-reporting": "subagent",
}
SECRET_PATTERNS = [
    re.compile(r"sk_live_[A-Za-z0-9]{20,}"),
    re.compile(r"ghp_[A-Za-z0-9]{30,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
]

results: list[dict] = []


def record(ok: bool, area: str, message: str, detail: str | None = None) -> None:
    results.append({"ok": ok, "area": area, "message": message, "detail": detail})


def warn(area: str, message: str, detail: str | None = None) -> None:
    results.append({"ok": True, "warning": True, "area": area, "message": message, "detail": detail})


def fail(area: str, message: str, detail: str | None = None) -> None:
    record(False, area, message, detail)


def parse_frontmatter(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        return {}
    end = text.find("\n---\n", 4)
    if end == -1:
        return {}
    try:
        data = yaml.safe_load(text[4:end])
    except yaml.YAMLError:
        return {}
    return data if isinstance(data, dict) else {}


def load_config() -> dict:
    try:
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - report parse errors verbatim
        fail("config", f"opencode.json does not parse: {exc}")
        return {}


def check_opencode() -> None:
    binary = shutil.which("opencode")
    if not binary:
        fail("opencode", "opencode binary not found on PATH")
        return
    try:
        out = subprocess.run(
            [binary, "--version"], capture_output=True, text=True, timeout=20, check=False
        ).stdout.strip()
    except Exception as exc:  # noqa: BLE001
        fail("opencode", f"could not run opencode --version: {exc}")
        return
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", out)
    if not match:
        fail("opencode", f"could not parse OpenCode version: {out!r}")
        return
    major = int(match.group(1))
    if major < 2:
        fail("opencode", f"OpenCode {out} is V1; this integration targets V2")
    else:
        record(True, "opencode", f"OpenCode {out} detected at {binary}")


def check_config(config: dict) -> None:
    if not config:
        return
    record(True, "config", "opencode.json parses")
    if config.get("$schema") != "https://opencode.ai/config.json":
        fail("config", "missing canonical $schema")
    if config.get("default_agent") != "bounty-harness":
        fail("config", "default_agent should be bounty-harness")
    else:
        record(True, "config", "default_agent is bounty-harness")
    skills = config.get("skills")
    if not isinstance(skills, list) or ".claude/skills" not in skills:
        fail("config", "skills must include .claude/skills")
    else:
        record(True, "config", "skill source includes .claude/skills")
    instructions = config.get("instructions")
    if not isinstance(instructions, list) or "docs/opencode/AGENT_RULES.md" not in instructions:
        fail("config", "instructions must include docs/opencode/AGENT_RULES.md")
    else:
        record(True, "config", "mandatory agent rules are loaded as instructions")
    permissions = config.get("permissions")
    if not isinstance(permissions, list) or not permissions:
        fail("config", "permissions must be a non-empty list")
        return
    bad = []
    for index, rule in enumerate(permissions):
        if not isinstance(rule, dict):
            bad.append(f"rule {index}: not an object")
            continue
        for key in ("action", "resource", "effect"):
            if not isinstance(rule.get(key), str) or not rule[key]:
                bad.append(f"rule {index}: missing {key}")
        if rule.get("effect") not in {"allow", "deny", "ask"}:
            bad.append(f"rule {index}: invalid effect {rule.get('effect')!r}")
    if bad:
        fail("config", "invalid permission rules", "; ".join(bad[:8]))
    else:
        record(True, "config", f"{len(permissions)} permission rules are well formed")
    if config.get("mcp"):
        warn("config", "MCP servers are configured; confirm they are required")


def check_permissions(config: dict) -> None:
    rules = config.get("permissions", [])
    if not isinstance(rules, list):
        return

    def decide(command: str) -> str:
        effect = "ask"
        for rule in rules:
            if rule.get("action") != "shell":
                continue
            if not fnmatch.fnmatchcase(command, rule.get("resource", "")):
                continue
            effect = rule.get("effect", "ask")
        return effect

    expectations = {
        "bb-run list": "allow",
        "bb-run recon list": "allow",
        "bb-run recon passive-subdomains": "allow",
        "bb-run recon live-discovery": "ask",
        "bb-hunt example.com --dry-run": "ask",
        "sudo nmap 127.0.0.1": "deny",
        "cat .bb/context.env": "deny",
        "cat .env": "deny",
        "git push origin main": "deny",
        # Hardened policy: raw network clients, scanners, package installs and
        # direct skill-script execution are denied. Workflows must go through
        # bb-run so the authorization gate and scope proxy apply.
        "curl https://example.com": "deny",
        "python3 .claude/skills/xss/scripts/xss_reflected_probe.py": "deny",
        "pip install requests": "deny",
        "BB_APPROVED_TIER=intrusive bb-run xss reflected": "deny",
        "make test": "allow",
        "python3 tools/opencode/validate_integration.py": "allow",
    }
    wrong = []
    for command, expected in expectations.items():
        actual = decide(command)
        if actual != expected:
            wrong.append(f"{command!r}: expected {expected}, got {actual}")
    if wrong:
        fail("permissions", "safety permission expectations failed", "; ".join(wrong))
    else:
        record(True, "permissions", f"verified {len(expectations)} shell permission decisions")


def check_skills() -> None:
    if not SKILLS_DIR.is_dir():
        fail("skills", f"skills directory missing: {SKILLS_DIR}")
        return
    skill_dirs = sorted(p for p in SKILLS_DIR.iterdir() if (p / "SKILL.md").is_file())
    missing_desc = []
    missing_yaml = []
    for skill_dir in skill_dirs:
        frontmatter = parse_frontmatter(skill_dir / "SKILL.md")
        if not frontmatter.get("description"):
            missing_desc.append(skill_dir.name)
        if not (skill_dir / "skill.yaml").is_file():
            missing_yaml.append(skill_dir.name)
    if len(skill_dirs) != 48:
        fail("skills", f"expected 48 skills, found {len(skill_dirs)}")
    else:
        record(True, "skills", "48 skills discovered in .claude/skills")
    if missing_desc:
        fail("skills", f"{len(missing_desc)} skills lack OpenCode description frontmatter", ", ".join(missing_desc))
    else:
        record(True, "skills", "all skills have description frontmatter")
    if missing_yaml:
        fail("skills", f"{len(missing_yaml)} skills lack skill.yaml", ", ".join(missing_yaml))
    else:
        record(True, "skills", "all skills have skill.yaml metadata")


def check_agents() -> None:
    if not AGENTS_DIR.is_dir():
        fail("agents", f"agent directory missing: {AGENTS_DIR}")
        return
    found = []
    for name, mode in REQUIRED_AGENT_FILES.items():
        path = AGENTS_DIR / f"{name}.md"
        if not path.is_file():
            fail("agents", f"missing agent file: {path.relative_to(REPO_ROOT)}")
            continue
        frontmatter = parse_frontmatter(path)
        if not frontmatter.get("description"):
            fail("agents", f"{name}: missing description")
        if frontmatter.get("mode") != mode:
            fail("agents", f"{name}: expected mode {mode}, got {frontmatter.get('mode')!r}")
        if not path.read_text(encoding="utf-8").split("\n---\n", 1)[-1].strip():
            fail("agents", f"{name}: empty system prompt")
        found.append(name)
    if len(found) == len(REQUIRED_AGENT_FILES):
        record(True, "agents", f"{len(found)} agent definitions discovered (1 primary, {len(found) - 1} subagents)")


def check_commands() -> None:
    if not COMMANDS_DIR.is_dir():
        fail("commands", f"command directory missing: {COMMANDS_DIR}")
        return
    command_files = sorted(COMMANDS_DIR.glob("*.md"))
    if len(command_files) < 6:
        fail("commands", f"expected at least 6 slash commands, found {len(command_files)}")
        return
    for path in command_files:
        frontmatter = parse_frontmatter(path)
        if not frontmatter.get("description"):
            fail("commands", f"{path.name}: missing description")
        if not path.read_text(encoding="utf-8").split("\n---\n", 1)[-1].strip():
            fail("commands", f"{path.name}: empty template")
    record(True, "commands", f"{len(command_files)} slash commands discovered")


def check_cli() -> None:
    for name in REQUIRED_BINS:
        path = BIN_DIR / name
        if not path.is_file():
            fail("cli", f"missing binary: bin/{name}")
        elif not os.access(path, os.X_OK):
            fail("cli", f"bin/{name} is not executable")
    if all((BIN_DIR / name).is_file() for name in REQUIRED_BINS):
        record(True, "cli", "all required bin/bb-* executables exist")
    on_path = [name for name in REQUIRED_BINS if shutil.which(name)]
    if len(on_path) == len(REQUIRED_BINS):
        record(True, "cli", "all bb-* commands resolve on PATH")
    else:
        warn(
            "cli",
            "some bb-* commands are not on PATH",
            "Run: ln -sf \"$PWD\"/bin/bb-* ~/.local/bin/ (or ./install.sh)",
        )


def check_docs() -> None:
    for path in DOCS:
        if not path.is_file():
            fail("docs", f"missing documentation: {path.relative_to(REPO_ROOT)}")
    if all(path.is_file() for path in DOCS):
        record(True, "docs", "OpenCode setup, usage, agent, and skill docs exist")
    agents_md = (REPO_ROOT / "AGENTS.md").read_text(encoding="utf-8")
    for token in ("OpenCode Integration", "opencode.json", ".opencode/agents", "sync_skills.py"):
        if token not in agents_md:
            fail("docs", f"AGENTS.md missing OpenCode reference: {token}")
    record(True, "docs", "AGENTS.md references the OpenCode integration")


def check_secrets() -> None:
    paths = [CONFIG_PATH, REPO_ROOT / "AGENTS.md"]
    paths.extend(sorted(AGENTS_DIR.glob("*.md")))
    paths.extend(sorted(COMMANDS_DIR.glob("*.md")))
    paths.extend(DOCS)
    hits = []
    for path in paths:
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for pattern in SECRET_PATTERNS:
            if pattern.search(text):
                hits.append(str(path.relative_to(REPO_ROOT)))
                break
    if hits:
        fail("secrets", "potential secret pattern in integration files", ", ".join(hits))
    else:
        record(True, "secrets", "no secret patterns in integration files")


def check_skill_tiers() -> None:
    missing = []
    for skill_dir in sorted(SKILLS_DIR.iterdir()):
        skill_yaml = skill_dir / "skill.yaml"
        if not skill_yaml.is_file():
            continue
        data = yaml.safe_load(skill_yaml.read_text(encoding="utf-8")) or {}
        if not data.get("safety_tier"):
            missing.append(skill_dir.name)
    if missing:
        warn(
            "safety",
            f"{len(missing)} skills declare no top-level safety_tier (pre-existing)",
            "Workflow-level tiers still apply; review docs/opencode/SKILLS.md",
        )
    else:
        record(True, "safety", "all skills declare a top-level safety tier")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit machine-readable results")
    args = parser.parse_args()

    check_opencode()
    config = load_config()
    check_config(config)
    check_permissions(config)
    check_skills()
    check_agents()
    check_commands()
    check_cli()
    check_docs()
    check_secrets()
    check_skill_tiers()

    failures = [r for r in results if not r["ok"]]
    warnings = [r for r in results if r.get("warning")]
    if args.json:
        print(json.dumps({"results": results, "failures": len(failures), "warnings": len(warnings)}, indent=2))
    else:
        for item in results:
            prefix = "FAIL" if not item["ok"] else ("WARN" if item.get("warning") else "PASS")
            print(f"[{prefix}] {item['area']:<12} {item['message']}")
            if item.get("detail"):
                print(f"       {item['detail']}")
        print(f"\nSummary: {len(results)} checks, {len(failures)} failures, {len(warnings)} warnings")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())

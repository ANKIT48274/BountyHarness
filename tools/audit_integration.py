#!/usr/bin/env python3
"""Integration auditor for BountyHarness.

Checks the wiring between skills, workflows, the tool registry, agents and slash
commands. Exits 1 when a hard error is found, 0 when only warnings remain.

Checks
  * every skill has a top-level safety_tier (or every workflow overrides it)
  * every workflow resolves to a valid tier
  * a workflow never resolves *below* the risk tier of the tools it invokes
  * tools_required entries exist in the registry
  * tools referenced by workflow commands exist on PATH (missing = error)
  * scripts referenced by workflow commands exist (executable for direct calls)
  * destructive-manual workflows are enumerated (gate refuses them at runtime)
  * agents parse, declare a mode, and only allowlist existing skills
  * slash commands reference existing agents and skills
"""

from __future__ import annotations

import glob
import json
import os
import re
import shutil
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
TIERS = {"passive": 0, "active-safe": 1, "intrusive": 2, "destructive-manual": 3}
SCRIPT_RE = re.compile(r"(?<![\w/])((?:\./)?\.claude/skills/[A-Za-z0-9_./-]+\.(?:py|sh))")


def load_registry():
    reg = {}
    for f in glob.glob(str(REPO / "tools/registry/*.yaml")):
        data = yaml.safe_load(Path(f).read_text()) or {}
        for t in (data.get("registry") or {}).get("tools") or []:
            name = t.get("name")
            if not name:
                continue
            reg[name] = t
            if t.get("binary"):
                reg.setdefault(t["binary"], t)
    return reg


def frontmatter(path: Path):
    text = path.read_text(encoding="utf-8", errors="replace")
    if not text.startswith("---"):
        return {}, text
    end = text.find("\n---", 3)
    if end == -1:
        return {}, text
    try:
        return yaml.safe_load(text[3:end]) or {}, text[end + 4:]
    except yaml.YAMLError as exc:
        return {"__parse_error__": str(exc)}, text


def main() -> int:
    registry = load_registry()
    errors: list[str] = []
    warnings: list[str] = []
    skills = {}
    workflows = []

    for skill_yaml in sorted(glob.glob(str(REPO / ".claude/skills/*/skill.yaml"))):
        skill_dir = Path(skill_yaml).parent
        name = skill_dir.name
        try:
            doc = yaml.safe_load(Path(skill_yaml).read_text()) or {}
        except yaml.YAMLError as exc:
            errors.append(f"{name}: skill.yaml does not parse: {exc}")
            continue
        skills[name] = doc
        skill_tier = doc.get("safety_tier")
        if skill_tier not in TIERS:
            warnings.append(f"{name}: no valid top-level safety_tier ({skill_tier!r})")

        tools_required = doc.get("tools_required") or []
        for tool in tools_required:
            if tool not in registry:
                errors.append(f"{name}: tools_required '{tool}' is not in the registry")

        for wf_name, wf in (doc.get("workflows") or {}).items():
            wf = wf or {}
            cmd = wf.get("command", "") or ""
            tier = wf.get("safety_tier")
            source = "workflow"
            if tier not in TIERS:
                tier = skill_tier if skill_tier in TIERS else None
                source = "skill"
            if tier is None:
                # derive from referenced registry tools, fail closed
                derived = None
                for tok in re.findall(r"(?<![\w/$.-])([A-Za-z0-9_.+-]+)", cmd):
                    info = registry.get(os.path.basename(tok))
                    if info and info.get("risk_tier") in TIERS:
                        rt = info["risk_tier"]
                        if derived is None or TIERS[rt] > TIERS[derived]:
                            derived = rt
                tier = derived or "intrusive"
                source = "derived" if derived else "fail-closed"
            if tier not in TIERS:
                errors.append(f"{name}/{wf_name}: invalid safety tier {tier!r}")
                continue

            derived = None
            for tok in re.findall(r"(?<![\w/$.-])([A-Za-z0-9_.+-]+)", cmd):
                info = registry.get(os.path.basename(tok))
                if info and info.get("risk_tier") in TIERS:
                    rt = info["risk_tier"]
                    if derived is None or TIERS[rt] > TIERS[derived]:
                        derived = rt
            if derived and TIERS[derived] > TIERS[tier]:
                errors.append(
                    f"{name}/{wf_name}: tier '{tier}' is lower than invoked tool risk "
                    f"'{derived}' ({cmd[:80]})"
                )

            for match in SCRIPT_RE.findall(cmd):
                rel = match[2:] if match.startswith("./") else match
                script = REPO / rel
                if not script.is_file():
                    errors.append(f"{name}/{wf_name}: referenced script missing: {rel}")
                elif cmd.strip().startswith(("./" + rel, rel)) and not os.access(script, os.X_OK):
                    warnings.append(f"{name}/{wf_name}: {rel} is not executable but invoked directly")

            missing = []
            for tok in set(re.findall(r"(?<![\w/$.-])([A-Za-z0-9_.+-]+)", cmd)):
                base = os.path.basename(tok)
                info = registry.get(base)
                if info and not shutil.which(info.get("binary") or base):
                    missing.append(info.get("binary") or base)
            if missing:
                errors.append(f"{name}/{wf_name}: tool(s) not on PATH: {', '.join(sorted(set(missing)))}")

            workflows.append({"skill": name, "workflow": wf_name, "tier": tier, "source": source})

    tier_counts = {t: sum(1 for w in workflows if w["tier"] == t) for t in TIERS}

    # Agents
    agents = {}
    for f in sorted(glob.glob(str(REPO / ".opencode/agents/*.md"))):
        p = Path(f)
        meta, _ = frontmatter(p)
        agents[p.stem] = meta
        if "__parse_error__" in meta:
            errors.append(f"agent {p.stem}: frontmatter does not parse")
            continue
        if meta.get("mode") not in ("primary", "subagent", "all"):
            warnings.append(f"agent {p.stem}: missing/invalid mode")
        perms = meta.get("permissions") or []
        allowed_skills = [x.get("resource") for x in perms
                          if x.get("action") == "skill" and x.get("effect") == "allow"]
        for s in allowed_skills:
            if s in ("*", None):
                warnings.append(f"agent {p.stem}: wildcard skill allowlist")
            elif s not in skills:
                errors.append(f"agent {p.stem}: allows unknown skill '{s}'")

    # Slash commands
    commands = {}
    for f in sorted(glob.glob(str(REPO / ".opencode/commands/*.md"))):
        p = Path(f)
        meta, body = frontmatter(p)
        commands[p.stem] = meta
        agent = meta.get("agent")
        if agent and agent not in agents:
            errors.append(f"command {p.stem}: unknown agent '{agent}'")
        if not meta.get("description"):
            warnings.append(f"command {p.stem}: missing description")
        for s in re.findall(r"bb-run\s+([a-z0-9-]+)\s+([a-z0-9-]+)", body):
            if s[0] not in skills:
                errors.append(f"command {p.stem}: references unknown skill '{s[0]}'")
            elif s[1] not in (skills[s[0]].get("workflows") or {}):
                errors.append(f"command {p.stem}: references unknown workflow '{s[0]}/{s[1]}'")

    summary = {
        "skills": len(skills),
        "workflows": len(workflows),
        "tier_counts": tier_counts,
        "destructive_workflows": [w for w in workflows if w["tier"] == "destructive-manual"],
        "agents": len(agents),
        "commands": len(commands),
        "errors": errors,
        "warnings": warnings,
    }
    print(json.dumps(summary, indent=2))
    print(f"\nskills={len(skills)} workflows={len(workflows)} agents={len(agents)} "
          f"commands={len(commands)} errors={len(errors)} warnings={len(warnings)}")
    if errors:
        print("\nERRORS:")
        for e in errors:
            print(f"  - {e}")
    if warnings:
        print("\nWARNINGS:")
        for w in warnings[:40]:
            print(f"  - {w}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())

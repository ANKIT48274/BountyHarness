#!/usr/bin/env python3
"""Add OpenCode-compatible YAML frontmatter to BountyHarness SKILL.md files.

BountyHarness stores human-facing skill instructions in
``.claude/skills/<skill>/SKILL.md``. OpenCode discovers that directory natively
(project compatibility) but only advertises skills that carry a YAML
frontmatter ``description``. This adapter adds frontmatter derived from the
authoritative ``skill.yaml`` metadata without changing the Markdown body,
payloads, scripts, runbooks, or safety configuration.

Existing frontmatter is never modified, so skills that already ship
frontmatter (cicd-security, graphql-audit, meme-coin-audit, triage-validation,
web3-audit) are left byte-for-byte intact.

Usage:
    python3 tools/opencode/sync_skills.py --check
    python3 tools/opencode/sync_skills.py --apply
    python3 tools/opencode/sync_skills.py --apply --dry-run
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("Error: pyyaml is required (python3 -m pip install pyyaml)")

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SKILLS_DIR = REPO_ROOT / ".claude" / "skills"
FRONTMATTER_START = "---\n"
FRONTMATTER_END = "\n---\n\n"


def is_skill_dir(path: Path) -> bool:
    return path.is_dir() and (path / "SKILL.md").is_file() and (path / "skill.yaml").is_file()


def load_metadata(skill_yaml: Path) -> dict:
    with open(skill_yaml, encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{skill_yaml}: expected a mapping")
    return data


def has_frontmatter(text: str) -> bool:
    return text.startswith("---\n") or text.startswith("---\r\n")


def build_frontmatter(skill_id: str, metadata: dict) -> str:
    description = str(metadata.get("description") or "").strip().replace("\n", " ")
    if not description:
        description = f"BountyHarness {skill_id} security skill"
    name = str(metadata.get("name") or skill_id).strip()
    payload = {"name": name, "description": description}
    rendered = yaml.safe_dump(payload, sort_keys=False, allow_unicode=True, width=1000).strip()
    return f"{FRONTMATTER_START}{rendered}{FRONTMATTER_END}"


def iter_skills():
    if not SKILLS_DIR.is_dir():
        sys.exit(f"Error: skills directory not found: {SKILLS_DIR}")
    for path in sorted(SKILLS_DIR.iterdir()):
        if is_skill_dir(path):
            yield path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="Exit 1 if any skill lacks frontmatter")
    mode.add_argument("--apply", action="store_true", help="Add missing frontmatter in place")
    parser.add_argument("--dry-run", action="store_true", help="Show what --apply would change")
    args = parser.parse_args()

    missing = []
    added = 0
    for skill_dir in iter_skills():
        skill_md = skill_dir / "SKILL.md"
        text = skill_md.read_text(encoding="utf-8")
        if has_frontmatter(text):
            continue
        metadata = load_metadata(skill_dir / "skill.yaml")
        missing.append(skill_dir.name)
        if args.check:
            continue
        frontmatter = build_frontmatter(skill_dir.name, metadata)
        if args.dry_run:
            print(f"would update: {skill_md.relative_to(REPO_ROOT)}")
            continue
        skill_md.write_text(frontmatter + text, encoding="utf-8")
        added += 1
        print(f"updated: {skill_md.relative_to(REPO_ROOT)}")

    if args.check:
        if missing:
            print(f"Missing OpenCode frontmatter in {len(missing)} skill(s):")
            for name in missing:
                print(f"  - {name}")
            print("Run: python3 tools/opencode/sync_skills.py --apply")
            return 1
        print("All skills have OpenCode-compatible frontmatter.")
        return 0

    if args.dry_run:
        print(f"{len(missing)} skill(s) would be updated.")
    else:
        print(f"Done. {added} skill(s) updated, {len(missing) - added} already current.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

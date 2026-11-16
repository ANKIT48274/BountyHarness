#!/usr/bin/env python3
"""One-shot, idempotent normalizer for skill/workflow safety tiers.

Inserts a top-level `safety_tier:` after the skill `description:` line and
per-workflow `safety_tier:` after each workflow name, without re-serializing
YAML (preserves comments, ordering, and formatting).

Existing explicit tiers are never overwritten. Unknown workflows fall back to
the skill's declared default so nothing silently becomes permissive.
"""

import sys
from pathlib import Path

SKILLS = Path(".claude/skills")

# skill -> (top_level_tier, {workflow: tier})
TIERS = {
    # ---- control plane: local only, never contacts the target -----------------
    "agent-safety": ("passive", {}),
    "coverage": ("passive", {}),
    "skill-scientist": ("passive", {}),
    "standard-catalog": ("passive", {}),
    "technique-kb": ("passive", {}),
    # ---- recon: discovery is passive except direct target probing -------------
    "recon": ("passive", {
        "live-discovery": "active-safe",
        "js-recon": "active-safe",
        "port-scan": "active-safe",
        "tls-profile": "active-safe",
    }),
    "osint": ("passive", {}),
    "persona": ("passive", {
        "validate-sessions": "active-safe",
        "browser-capture": "active-safe",
        "browser-capture-with-screenshot": "active-safe",
        "browser-capture-with-har": "active-safe",
    }),
    # ---- vulnerability families: fail closed at intrusive --------------------
    "xss": ("intrusive", {
        "dom": "passive",
        "context-encoder": "passive",
        "csp-analysis": "active-safe",
    }),
    "sqli": ("intrusive", {}),
    "ssrf": ("intrusive", {}),
    "rce": ("intrusive", {}),
    "file-upload": ("intrusive", {}),
    "race-condition": ("intrusive", {}),
    "cors-csrf": ("intrusive", {
        "cors-matrix": "active-safe",
        "csrf-poc": "active-safe",
    }),
    "api": ("intrusive", {
        "param-discovery": "active-safe",
        "graphql": "active-safe",
    }),
    "auth": ("intrusive", {
        "token-extract": "passive",
        "jwt-analysis": "passive",
        "oauth-conformance": "active-safe",
    }),
    "ai-llm": ("intrusive", {"surface-discovery": "active-safe"}),
    "cloud": ("intrusive", {"cloud-assets": "active-safe"}),
    "mobile": ("intrusive", {
        "apk-analysis": "passive",
        "frida-ssl-bypass": "destructive-manual",
    }),
    "modern-browser": ("active-safe", {"wasm-audit": "passive", "evidence": "passive"}),
    "nuclei-scanner": ("intrusive", {
        "cve-priority": "passive",
        "validate-findings": "passive",
    }),
    "http-protocol": ("intrusive", {
        "verify": "passive",
        "url-parser-differential": "active-safe",
    }),
}


def _ensure_nl(line):
    return line if line.endswith("\n") else line + "\n"


def insert_top_level(lines, tier):
    if any(line.startswith("safety_tier:") for line in lines):
        return lines, False
    for i, line in enumerate(lines):
        if line.startswith("description:"):
            lines[i] = _ensure_nl(line)
            lines.insert(i + 1, f"safety_tier: {tier}\n")
            return lines, True
    # no description -> insert after name:
    for i, line in enumerate(lines):
        if line.startswith("name:"):
            lines[i] = _ensure_nl(line)
            lines.insert(i + 1, f"safety_tier: {tier}\n")
            return lines, True
    return lines, False


def insert_workflow_tier(lines, wf, tier):
    marker = f"  {wf}:"
    start = None
    for i, line in enumerate(lines):
        if line.rstrip() == marker:
            start = i
            break
    if start is None:
        return lines, False
    # determine the workflow block extent (next line with exactly 2-space key)
    end = len(lines)
    for j in range(start + 1, len(lines)):
        candidate = lines[j]
        if candidate.startswith("  ") and not candidate.startswith("    ") and candidate.strip() and not candidate.lstrip().startswith("#"):
            end = j
            break
    block = lines[start:end]
    if any(line.strip().startswith("safety_tier:") for line in block):
        return lines, False
    lines[start] = _ensure_nl(lines[start])
    lines.insert(start + 1, f"    safety_tier: {tier}\n")
    return lines, True


def main():
    changed = []
    for skill, (top, wf_tiers) in TIERS.items():
        p = SKILLS / skill / "skill.yaml"
        if not p.is_file():
            print(f"SKIP missing {p}", file=sys.stderr)
            continue
        lines = p.read_text(encoding="utf-8").splitlines(keepends=True)
        lines, c1 = insert_top_level(lines, top)
        c2 = []
        for wf, tier in wf_tiers.items():
            lines, c = insert_workflow_tier(lines, wf, tier)
            if c:
                c2.append(wf)
        if c1 or c2:
            p.write_text("".join(lines), encoding="utf-8")
            changed.append((skill, c1, c2))
            print(f"{skill}: top={'+' if c1 else '='} workflows={','.join(c2) or '-'}")
    print(f"\n{len(changed)} skill.yaml files updated")


if __name__ == "__main__":
    main()

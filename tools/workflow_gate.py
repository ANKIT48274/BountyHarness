#!/usr/bin/env python3
"""Authorization gate for BountyHarness workflow execution.

Enforces, before any workflow command is evaluated:

  passive            -> allowed (third-party read-only sources only)
  active-safe        -> valid scope file + target matching an in-scope pattern
  intrusive          -> the above + explicit human approval
  destructive-manual -> always refused (never automated)

Exit codes are distinct so callers and tests can assert behaviour:
  0 allowed
  3 scope file missing/empty        (active-safe+)
  4 target not in scope             (active-safe+)
  5 human approval required         (intrusive)
  6 destructive-manual refused
  7 scope file present but unparseable (no in-scope entries)
"""

import argparse
import os
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
TIER_ORDER = {"passive": 0, "active-safe": 1, "intrusive": 2, "destructive-manual": 3}
APPROVED_LEVELS = {"intrusive", "destructive-manual"}


def load_registry_tiers():
    tiers = {}
    for f in (REPO_ROOT / "tools" / "registry").glob("*.yaml"):
        try:
            data = yaml.safe_load(f.read_text()) or {}
        except Exception:
            continue
        for t in (data.get("registry", {}) or {}).get("tools", []) or []:
            tier = t.get("risk_tier")
            if not tier:
                continue
            for key in (t.get("name"), t.get("binary")):
                if key:
                    tiers[key] = tier
    return tiers


def resolve_tier(skill_doc, workflow_doc, command):
    """workflow tier > skill tier > derived-from-tools > intrusive (fail closed)."""
    for candidate in ((workflow_doc or {}).get("safety_tier"), skill_doc.get("safety_tier")):
        if isinstance(candidate, str) and candidate in TIER_ORDER:
            return candidate, "metadata"

    registry = load_registry_tiers()
    words = {os.path.basename(tok.strip("'\"")) for tok in command.replace("\\", " ").split()}
    highest = None
    for w in words:
        tier = registry.get(w)
        if tier and (highest is None or TIER_ORDER[tier] > TIER_ORDER[highest]):
            highest = tier
    if highest:
        return highest, "derived-from-tools"
    return "intrusive", "fail-closed-default"


def load_scope(scope_file):
    """Load the canonical strict matcher (ports, paths, IPv6, CIDR, exclusions)."""
    sys.path.insert(0, str(REPO_ROOT / "tools"))
    import importlib

    mod = importlib.import_module("scope_guard")
    scope = mod.load(str(scope_file))
    return scope, scope.check_target


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--skill-dir", required=True)
    ap.add_argument("--workflow", required=True)
    ap.add_argument("--command", default="")
    ap.add_argument("--target", default="")
    ap.add_argument("--port", type=int, default=0,
                    help="TARGET_PORT from the run context; used for port-scoped scope entries")
    ap.add_argument("--scheme", default="",
                    help="TARGET_SCHEME from the run context")
    ap.add_argument("--scope-file", default="")
    ap.add_argument("--print-tier", action="store_true",
                    help="print the resolved safety tier and exit (no enforcement)")
    args = ap.parse_args()

    skill_yaml = Path(args.skill_dir) / "skill.yaml"
    try:
        skill_doc = yaml.safe_load(skill_yaml.read_text()) or {}
    except Exception as exc:
        print(f"GATE ERROR: cannot read {skill_yaml}: {exc}", file=sys.stderr)
        return 4
    workflow_doc = (skill_doc.get("workflows") or {}).get(args.workflow) or {}

    tier, source = resolve_tier(skill_doc, workflow_doc, args.command)
    if args.print_tier:
        print(tier)
        return 0
    label = f"{Path(args.skill_dir).name}/{args.workflow} [{tier}, {source}]"

    # destructive-manual is never automated, at any approval level.
    if tier == "destructive-manual":
        print(f"BLOCKED: {label} is destructive-manual and is never automated.", file=sys.stderr)
        print("Run it manually under direct operator supervision.", file=sys.stderr)
        return 6

    if tier == "passive":
        return 0

    scope_file = args.scope_file or os.environ.get("SCOPE_FILE", "")
    if not scope_file or not Path(scope_file).is_file() or Path(scope_file).stat().st_size == 0:
        print(f"BLOCKED: {label} requires an authorized scope file.", file=sys.stderr)
        print("  SCOPE_FILE is missing or empty.", file=sys.stderr)
        print("  Fix: bin/bb-init <target> --program <name> --scope-file <authorization-file>", file=sys.stderr)
        return 3

    try:
        scope, is_in_scope = load_scope(scope_file)
    except Exception as exc:
        print(f"BLOCKED: scope parser failed: {exc}", file=sys.stderr)
        return 7

    if not scope.has_entries():
        if os.environ.get("BB_SCOPE_UNSTRUCTURED_OK") != "1":
            print(f"BLOCKED: {label}: scope file has no machine-readable in-scope entries.", file=sys.stderr)
            print("  Use 'in scope' / 'out of scope' sections with bare domains/IPs,", file=sys.stderr)
            print("  or set BB_SCOPE_UNSTRUCTURED_OK=1 after a human has verified the scope manually.", file=sys.stderr)
            return 7

    target = args.target or os.environ.get("TARGET", "")
    if target:
        allowed, reason = is_in_scope(
            target,
            default_port=args.port or None,
            default_scheme=args.scheme or None,
        )
        if not allowed:
            print(f"BLOCKED: target '{target}' is not authorized by the scope file.", file=sys.stderr)
            print(f"  reason: {reason}", file=sys.stderr)
            return 4

    if TIER_ORDER[tier] >= TIER_ORDER["intrusive"]:
        # Human approval is an out-of-band artifact the agent cannot mint:
        # .bb/approvals/<skill>__<workflow> containing the approved target (or '*').
        # shell deny rules block agents from writing under .bb/approvals.
        approval = Path(".bb") / "approvals" / f"{Path(args.skill_dir).name}__{args.workflow}"
        ok = False
        if approval.is_file():
            granted = approval.read_text(encoding="utf-8").strip().splitlines()
            ok = any(g.strip() in ("*", target) for g in granted if g.strip())
        if not ok and os.environ.get("BB_APPROVED_TIER", "") in APPROVED_LEVELS:
            # CI escape hatch only. A shell-capable agent can set this, so it is
            # NOT a security boundary; prefer the approval file.
            ok = True
        if not ok:
            print(f"BLOCKED: {label} requires explicit human approval.", file=sys.stderr)
            print(f"  Operator action: mkdir -p .bb/approvals && echo \"{target or '*'}\" > {approval}", file=sys.stderr)
            print("  (agents cannot write .bb/approvals; shell deny rules block it)", file=sys.stderr)
            return 5

    return 0


if __name__ == "__main__":
    sys.exit(main())

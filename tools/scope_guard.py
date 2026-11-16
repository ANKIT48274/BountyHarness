#!/usr/bin/env python3
"""Strict scope matcher for BountyHarness.

Canonical scope enforcement used by `workflow_gate.py`, `scoped_fetch.py` and
`scope_proxy.py`. It is deliberately stricter than the historical
`scope_manager.is_in_scope()` helper:

  * bare domain entries match that host only (no implicit subdomain grant);
    use `*.example.com` to authorize subdomains. Programs that explicitly
    state "example.com and all subdomains" can opt into the legacy behaviour
    with BB_SCOPE_SUBDOMAIN_INHERIT=1.
  * wildcard `*.example.com` matches subdomains but NOT the apex.
  * explicit `out of scope` sections always win over in-scope entries.
  * IPv4/IPv6 addresses and CIDR ranges are matched with `ipaddress`
    (no string-prefix false positives such as 10.0.0.1 matching 10.0.0.10).
  * optional port and path constraints are honoured:
        https://api.example.com:8443/v1/
        api.example.com:443
  * only http(s)/ws(s) URLs are accepted for URL checks.

Scope file format (unchanged, section based):

    in scope
    example.com
    *.example.com
    203.0.113.0/24
    https://api.example.com/v1/
    out of scope
    internal.example.com
    admin.example.com:8443

Lines starting with `#` are comments. A leading `!` on an entry is treated as
an exclusion even outside an `out of scope` section.

CLI:
    scope_guard.py check --scope-file scope.txt --url https://api.example.com/x
    scope_guard.py check --scope-file scope.txt --host api.example.com --port 443
    scope_guard.py dump  --scope-file scope.txt
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple
from urllib.parse import urlsplit

ALLOWED_SCHEMES = {"http", "https", "ws", "wss"}
SECTION_KEYS = {
    "in scope": "in_scope",
    "included": "in_scope",
    "out of scope": "out_of_scope",
    "excluded": "out_of_scope",
    "wildcards": "wildcards",
    "mobile": "mobile_apps",
    "mobile apps": "mobile_apps",
    "api": "apis",
    "apis": "apis",
    "ip": "ips",
    "ips": "ips",
}


@dataclass
class Entry:
    raw: str
    scheme: Optional[str] = None
    host: Optional[str] = None
    network: Optional[ipaddress._BaseNetwork] = None
    wildcard: bool = False
    port: Optional[int] = None
    path: Optional[str] = None

    def describe(self) -> str:
        bits = [self.raw]
        extra = []
        if self.scheme:
            extra.append(f"scheme={self.scheme}")
        if self.port:
            extra.append(f"port={self.port}")
        if self.path:
            extra.append(f"path={self.path}")
        if self.network:
            extra.append(f"cidr={self.network}")
        if self.wildcard:
            extra.append("wildcard")
        return bits[0] + (f" ({', '.join(extra)})" if extra else "")


@dataclass
class Scope:
    in_scope: List[Entry] = field(default_factory=list)
    out_of_scope: List[Entry] = field(default_factory=list)
    mobile_apps: List[str] = field(default_factory=list)
    apis: List[Entry] = field(default_factory=list)
    comments: List[str] = field(default_factory=list)
    path: Optional[str] = None

    # ---------- parsing ----------

    @classmethod
    def from_file(cls, path: str) -> "Scope":
        text = Path(path).read_text(encoding="utf-8", errors="replace")
        return cls.from_text(text, path=path)

    @classmethod
    def from_text(cls, text: str, path: Optional[str] = None) -> "Scope":
        scope = cls(path=path)
        section = "in_scope"
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("#"):
                scope.comments.append(stripped[1:].strip())
                continue
            key = SECTION_KEYS.get(stripped.lower())
            if key:
                section = key
                continue
            excluded = False
            if stripped.startswith("!"):
                excluded = True
                stripped = stripped[1:].strip()
                if not stripped:
                    continue
            entry = cls._parse_entry(stripped)
            if entry is None:
                continue
            if section == "mobile_apps":
                scope.mobile_apps.append(stripped)
            elif section == "apis":
                scope.apis.append(entry)
                if not excluded:
                    scope.in_scope.append(entry)
                else:
                    scope.out_of_scope.append(entry)
            elif section == "out_of_scope" or excluded:
                scope.out_of_scope.append(entry)
            else:
                scope.in_scope.append(entry)
        return scope

    @staticmethod
    def _parse_entry(raw: str) -> Optional[Entry]:
        item = raw.strip().strip(",")
        if not item:
            return None
        # URL form
        if "://" in item:
            try:
                parts = urlsplit(item)
            except ValueError:
                return None
            scheme = (parts.scheme or "").lower()
            if scheme not in ALLOWED_SCHEMES:
                # Unknown scheme in scope file: keep as opaque exclusion-safe
                # entry rather than silently granting access.
                return Entry(raw=raw, scheme=scheme, host=(parts.hostname or "").lower() or None)
            host = _normalize_host(parts.hostname or "")
            if not host:
                return None
            port = parts.port
            path = parts.path or None
            if path == "/":
                path = "/"
            return Entry(raw=raw, scheme=scheme, host=host, port=port, path=path)
        # Wildcard domain
        if item.startswith("*."):
            host = _normalize_host(item[2:])
            return Entry(raw=raw, host=host, wildcard=True) if host else None
        # CIDR / IP
        try:
            network = ipaddress.ip_network(item, strict=False)
            return Entry(raw=raw, network=network)
        except ValueError:
            pass
        # host:port (supports [v6]:port)
        host_part, port_part = _split_host_port(item)
        host = _normalize_host(host_part)
        if not host:
            return None
        return Entry(raw=raw, host=host, port=port_part)

    # ---------- matching ----------

    def has_entries(self) -> bool:
        return bool(self.in_scope)

    def _entry_matches(self, entry: Entry, host: str, port: Optional[int],
                       path: Optional[str], scheme: Optional[str]) -> bool:
        if entry.scheme and scheme:
            if entry.scheme != scheme:
                # ws(s) shares transport with http(s) for matching purposes
                alias = {"ws": "http", "wss": "https"}
                if alias.get(scheme) != entry.scheme and alias.get(entry.scheme) != scheme:
                    return False
        if entry.port is not None:
            # A port-scoped entry cannot be satisfied when the caller does not
            # know the port: "example.com" must not inherit an
            # "example.com:8443" grant. Fail closed instead.
            if port is None or entry.port != port:
                return False
        if entry.path is not None:
            if path is None:
                return False
            if not _path_prefix_match(path, entry.path):
                return False
        if entry.network is not None:
            try:
                ip = ipaddress.ip_address(host)
            except ValueError:
                return False
            return ip in entry.network
        if not entry.host:
            return False
        if entry.wildcard:
            return host.endswith("." + entry.host) and host != entry.host
        if host == entry.host:
            return True
        if os.environ.get("BB_SCOPE_SUBDOMAIN_INHERIT") == "1":
            return host.endswith("." + entry.host)
        return False

    def check(self, host: str, port: Optional[int] = None, path: Optional[str] = None,
              scheme: Optional[str] = None) -> Tuple[bool, str]:
        host = _normalize_host(host)
        if not host:
            return False, "empty or invalid host"
        for entry in self.out_of_scope:
            if self._entry_matches(entry, host, port, path, scheme):
                return False, f"explicitly out of scope: {entry.describe()}"
        for entry in self.in_scope:
            if self._entry_matches(entry, host, port, path, scheme):
                return True, f"matches in-scope entry: {entry.describe()}"
        return False, "no matching in-scope entry"

    def check_url(self, url: str) -> Tuple[bool, str]:
        if "://" not in url:
            return self.check_target(url)
        try:
            parts = urlsplit(url)
        except ValueError as exc:
            return False, f"unparseable URL: {exc}"
        scheme = (parts.scheme or "").lower()
        if scheme not in ALLOWED_SCHEMES:
            return False, f"scheme '{scheme}' is not permitted (http/https/ws/wss only)"
        if not parts.hostname:
            return False, "URL has no hostname"
        try:
            port = parts.port
        except ValueError:
            return False, "URL has an invalid port"
        if port is None:
            port = 443 if scheme in ("https", "wss") else 80
        return self.check(parts.hostname, port, parts.path or "/", scheme)

    def check_target(self, target: str, default_port: Optional[int] = None,
                     default_scheme: Optional[str] = None) -> Tuple[bool, str]:
        """Check a bare host, host:port or URL (as stored in $TARGET).

        `default_port` / `default_scheme` come from the run context
        (TARGET_PORT / TARGET_SCHEME) so port-scoped entries can still be
        evaluated when the target string omits the port.
        """
        target = (target or "").strip()
        if not target:
            return False, "empty target"
        if "://" in target:
            return self.check_url(target)
        host_part, port = _split_host_port(target.split("/")[0])
        path = None
        if "/" in target:
            path = "/" + target.split("/", 1)[1]
        if port is None:
            port = default_port
        return self.check(host_part, port, path, default_scheme)

    def summary(self) -> dict:
        return {
            "scope_file": self.path,
            "in_scope": [e.raw for e in self.in_scope],
            "out_of_scope": [e.raw for e in self.out_of_scope],
            "mobile_apps": self.mobile_apps,
            "comments": self.comments[:5],
        }


def _normalize_host(host: str) -> str:
    host = (host or "").strip().lower()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    host = host.rstrip(".")
    if not host:
        return ""
    # IPv6 literals must not be IDNA-encoded.
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host


def _split_host_port(value: str) -> Tuple[str, Optional[int]]:
    value = value.strip()
    if value.startswith("["):
        end = value.find("]")
        if end != -1:
            host = value[1:end]
            rest = value[end + 1:]
            if rest.startswith(":") and rest[1:].isdigit():
                return host, int(rest[1:])
            return host, None
    # Bare IPv6 (more than one colon, no brackets) has no port.
    if value.count(":") > 1:
        return value, None
    if ":" in value:
        host, _, port_s = value.rpartition(":")
        if port_s.isdigit():
            return host, int(port_s)
        return value, None
    return value, None


def _path_prefix_match(path: str, prefix: str) -> bool:
    if prefix == "/":
        return True
    # A trailing slash denotes a directory prefix, so "/v1/" also covers the
    # directory URL "/v1" itself (which normally redirects to "/v1/").
    if prefix.endswith("/") and path == prefix[:-1]:
        return True
    if not path.startswith(prefix):
        return False
    if prefix.endswith("/"):
        return True
    return len(path) == len(prefix) or path[len(prefix)] in ("/", "?", "#")


def load(scope_file: str) -> Scope:
    return Scope.from_file(scope_file)


def main() -> int:
    ap = argparse.ArgumentParser(description="Strict scope matcher")
    sub = ap.add_subparsers(dest="cmd", required=True)
    chk = sub.add_parser("check")
    chk.add_argument("--scope-file", required=True)
    group = chk.add_mutually_exclusive_group(required=True)
    group.add_argument("--url")
    group.add_argument("--host")
    group.add_argument("--target")
    chk.add_argument("--port", type=int)
    chk.add_argument("--path")
    chk.add_argument("--scheme")
    dump = sub.add_parser("dump")
    dump.add_argument("--scope-file", required=True)
    args = ap.parse_args()

    scope = load(args.scope_file)
    if args.cmd == "dump":
        print(json.dumps(scope.summary(), indent=2))
        return 0

    if args.url:
        allowed, reason = scope.check_url(args.url)
    elif args.target:
        allowed, reason = scope.check_target(args.target)
    else:
        allowed, reason = scope.check(args.host, args.port, args.path, args.scheme)
    print(json.dumps({"allowed": allowed, "reason": reason}))
    return 0 if allowed else 4


if __name__ == "__main__":
    sys.exit(main())

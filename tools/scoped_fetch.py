#!/usr/bin/env python3
"""Redirect-safe, DNS-pinned HTTP client bound to an authorized scope file.

Why this exists: external tools (curl, httpx, nuclei, ...) follow redirects and
re-resolve DNS on their own. This client is the harness-native path for HTTP
requests where every hop must be provably in scope:

  * the initial URL is validated with `scope_guard`
  * every redirect target is validated before it is followed
  * a redirect chain cannot escape scope or change to a non-http(s) scheme
  * the hostname is resolved once, every resolved address is checked, and the
    connection is pinned to a validated address (no TOCTOU / DNS rebinding)
  * private, loopback, link-local, reserved and multicast addresses are
    refused unless they are explicitly authorized (`--allow-private` for local
    fixtures, or an IP/CIDR entry in the scope file)

Usage:
    scoped_fetch.py --scope-file scope.txt --url https://api.example.com/v1/me
    scoped_fetch.py --scope-file scope.txt --url http://127.0.0.1:8080/ \
        --allow-private --out /tmp/opencode/evidence
    scoped_fetch.py ... --json

Exit codes: 0 ok, 2 transport error, 3 scope blocked, 4 bad arguments.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import ipaddress
import json
import socket
import ssl
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Tuple
from urllib.parse import urljoin, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
import scope_guard  # noqa: E402

REDACT_HEADERS = {"authorization", "cookie", "set-cookie", "proxy-authorization", "x-api-key"}


class ScopeBlocked(Exception):
    pass


@dataclass
class Hop:
    url: str
    status: int
    location: str | None = None
    pinned_ip: str | None = None


@dataclass
class Result:
    url: str
    status: int
    headers: List[Tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    hops: List[Hop] = field(default_factory=list)
    final_url: str = ""

    def summary(self) -> dict:
        return {
            "url": self.url,
            "final_url": self.final_url or self.url,
            "status": self.status,
            "redirects": [
                {"url": h.url, "status": h.status, "location": h.location, "pinned_ip": h.pinned_ip}
                for h in self.hops
            ],
            "body_bytes": len(self.body),
            "body_sha256": hashlib.sha256(self.body).hexdigest(),
            "headers": {k.lower(): v for k, v in self.headers if k.lower() not in REDACT_HEADERS},
        }


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, connect_ip: str, timeout: float = 15.0):
        super().__init__(host, port, timeout=timeout)
        self._connect_ip = connect_ip

    def connect(self):
        self.sock = socket.create_connection(
            (self._connect_ip, self.port), self.timeout, self.source_address
        )


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, connect_ip: str, timeout: float = 15.0,
                 context: ssl.SSLContext | None = None):
        super().__init__(host, port, timeout=timeout, context=context)
        self._connect_ip = connect_ip

    def connect(self):
        sock = socket.create_connection(
            (self._connect_ip, self.port), self.timeout, self.source_address
        )
        if self._tunnel_host:
            self.sock = sock
            self._tunnel()
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def _is_forbidden_ip(ip: ipaddress._BaseAddress) -> bool:
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
        # IPv4-mapped IPv6 such as ::ffff:169.254.169.254
        or (isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None
            and _is_forbidden_ip(ip.ipv4_mapped))
    )


def resolve_pinned(host: str, port: int, allow_private: bool,
                   dns_override: Dict[str, str] | None = None) -> str:
    """Resolve host once, validate every address, return the address to pin."""
    override = (dns_override or {}).get(host.lower())
    if override:
        addrs = [override]
    else:
        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise ScopeBlocked(f"DNS resolution failed for {host}: {exc}") from exc
        addrs = []
        for info in infos:
            ip = info[4][0]
            if ip not in addrs:
                addrs.append(ip)
    if not addrs:
        raise ScopeBlocked(f"no addresses resolved for {host}")

    for addr in addrs:
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            raise ScopeBlocked(f"resolver returned a non-IP address: {addr!r}")
        if _is_forbidden_ip(ip) and not allow_private:
            raise ScopeBlocked(
                f"{host} resolves to forbidden address {ip} "
                "(private/loopback/link-local/reserved); use --allow-private only for fixtures"
            )
    return addrs[0]


def _request_once(url: str, method: str, headers: Dict[str, str], body: bytes | None,
                  timeout: float, allow_private: bool,
                  dns_override: Dict[str, str] | None) -> Tuple[int, List[Tuple[str, str]], bytes, str]:
    parts = urlsplit(url)
    scheme = (parts.scheme or "").lower()
    host = parts.hostname or ""
    port = parts.port or (443 if scheme == "https" else 80)
    pinned = resolve_pinned(host, port, allow_private, dns_override)

    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query

    if scheme == "https":
        conn = _PinnedHTTPSConnection(host, port, pinned, timeout=timeout)
    else:
        conn = _PinnedHTTPConnection(host, port, pinned, timeout=timeout)

    hdrs = dict(headers)
    hdrs.setdefault("Host", parts.netloc)
    hdrs.setdefault("User-Agent", "BountyHarness-scoped-fetch/1.0")
    hdrs.setdefault("Accept", "*/*")
    try:
        conn.request(method, path, body=body, headers=hdrs)
        resp = conn.getresponse()
        data = resp.read()
        return resp.status, resp.getheaders(), data, pinned
    finally:
        conn.close()


def fetch(scope: scope_guard.Scope, url: str, method: str = "GET",
          headers: Dict[str, str] | None = None, body: bytes | None = None,
          timeout: float = 15.0, max_redirects: int = 5, allow_private: bool = False,
          dns_override: Dict[str, str] | None = None) -> Result:
    allowed, reason = scope.check_url(url)
    if not allowed:
        raise ScopeBlocked(f"initial URL blocked: {reason}")

    result = Result(url=url, status=0)
    current = url
    for _ in range(max_redirects + 1):
        status, resp_headers, data, pinned = _request_once(
            current, method, headers or {}, body, timeout, allow_private, dns_override
        )
        location = next((v for k, v in resp_headers if k.lower() == "location"), None)
        result.hops.append(Hop(url=current, status=status, location=location, pinned_ip=pinned))
        result.status = status
        result.headers = resp_headers
        result.body = data
        result.final_url = current

        if status in (301, 302, 303, 307, 308) and location:
            nxt = urljoin(current, location)
            ok, why = scope.check_url(nxt)
            if not ok:
                raise ScopeBlocked(f"redirect target blocked ({nxt}): {why}")
            current = nxt
            # 303 (and 301/302 for non-GET) downgrade to GET without body
            if status == 303 or (status in (301, 302) and method.upper() not in ("GET", "HEAD")):
                method, body = "GET", None
            continue
        return result

    raise ScopeBlocked(f"redirect limit exceeded ({max_redirects}) starting at {url}")


def _redact_headers(headers: Dict[str, str]) -> List[str]:
    lines = []
    for k, v in headers.items():
        lines.append(f"{k}: {'<redacted>' if k.lower() in REDACT_HEADERS else v}")
    return lines


def save_evidence(result: Result, out_dir: Path, request_headers: Dict[str, str],
                  request_body: bytes | None) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    req = [f"{'GET'} {result.url} HTTP/1.1"] + _redact_headers(request_headers)
    if request_body:
        req.append("")
        req.append(request_body.decode("utf-8", "replace"))
    (out_dir / "request.txt").write_text("\n".join(req) + "\n", encoding="utf-8")

    resp = [f"HTTP/1.1 {result.status}"]
    for k, v in result.headers:
        resp.append(f"{k}: {'<redacted>' if k.lower() in REDACT_HEADERS else v}")
    resp.append("")
    resp.append(result.body.decode("utf-8", "replace"))
    (out_dir / "response.txt").write_text("\n".join(resp), encoding="utf-8")
    (out_dir / "fetch.json").write_text(json.dumps(result.summary(), indent=2), encoding="utf-8")
    return out_dir


def main() -> int:
    ap = argparse.ArgumentParser(description="Scope-validated, DNS-pinned HTTP client")
    ap.add_argument("--scope-file", required=True)
    ap.add_argument("--url", required=True)
    ap.add_argument("--method", default="GET")
    ap.add_argument("--header", action="append", default=[], metavar="K: V")
    ap.add_argument("--data", default=None)
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--max-redirects", type=int, default=5)
    ap.add_argument("--allow-private", action="store_true",
                    help="allow loopback/private targets (local fixtures only)")
    ap.add_argument("--dns-override", action="append", default=[], metavar="HOST=IP",
                    help="test-only host pin (fixtures)")
    ap.add_argument("--out", default=None, help="evidence directory")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    headers: Dict[str, str] = {}
    for raw in args.header:
        if ":" not in raw:
            print(f"invalid header: {raw}", file=sys.stderr)
            return 4
        k, v = raw.split(":", 1)
        headers[k.strip()] = v.strip()
    override = {}
    for raw in args.dns_override:
        if "=" not in raw:
            print(f"invalid --dns-override: {raw}", file=sys.stderr)
            return 4
        h, ip = raw.split("=", 1)
        override[h.lower()] = ip

    scope = scope_guard.load(args.scope_file)
    body = args.data.encode() if args.data else None
    started = time.time()
    try:
        result = fetch(scope, args.url, args.method, headers, body, args.timeout,
                       args.max_redirects, args.allow_private, override)
    except ScopeBlocked as exc:
        print(json.dumps({"allowed": False, "reason": str(exc)}) if args.json else f"BLOCKED: {exc}",
              file=sys.stdout if args.json else sys.stderr)
        return 3
    except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
        print(json.dumps({"allowed": True, "error": str(exc)}) if args.json else f"ERROR: {exc}",
              file=sys.stdout if args.json else sys.stderr)
        return 2

    if args.out:
        save_evidence(result, Path(args.out), headers, body)

    summary = result.summary()
    summary["allowed"] = True
    summary["elapsed_ms"] = int((time.time() - started) * 1000)
    if args.json:
        print(json.dumps(summary))
    else:
        print(f"{result.status} {result.final_url} ({len(result.body)} bytes, "
              f"{len(result.hops) - 1} redirect(s))")
        for hop in result.hops[1:]:
            print(f"  -> {hop.status} {hop.url} (pinned {hop.pinned_ip})")
    return 0


if __name__ == "__main__":
    sys.exit(main())

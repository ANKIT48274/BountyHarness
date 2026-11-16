#!/usr/bin/env python3
"""Scope-enforcing forward proxy with DNS pinning.

Purpose: give HTTP(S)-speaking tools a network-level boundary they cannot
escape by following redirects. Every request (including each redirect hop, which
opens a new connection) is checked against the authorized scope file:

  * CONNECT host:port  -> host/port must be in scope
  * absolute-URI HTTP  -> scheme/host/port/path must be in scope
  * the hostname is resolved once, every address is validated, and the upstream
    socket is pinned to the validated address (defeats DNS rebinding)
  * private/loopback/link-local/reserved addresses are refused unless
    --allow-private (local fixtures) or explicitly listed as an IP/CIDR

Tools that honour HTTP_PROXY/HTTPS_PROXY/ALL_PROXY (curl, httpx, nuclei,
katana, ffuf, ...) inherit this boundary. Tools that open raw sockets or do
their own DNS (nmap, naabu, dnsx) do NOT — that requires an OS-level firewall,
documented in BOUNTY_READINESS_REPORT.md.

Usage:
    scope_proxy.py --scope-file scope.txt --port 8899 [--allow-private]
    scope_proxy.py --scope-file scope.txt --port 0 --ready-file /tmp/proxy.port

The proxy prints one JSON line on startup: {"port": <n>, "scope": "..."}.
Log: JSONL decisions to --log (default .bb/scope-proxy.log), never bodies.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import select
import signal
import socket
import socketserver
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
import scope_guard  # noqa: E402
from scoped_fetch import ScopeBlocked, resolve_pinned  # noqa: E402

CONFIG: Dict[str, object] = {}
_LOG_LOCK = threading.Lock()
HOP_HEADERS = {
    "connection", "proxy-connection", "keep-alive", "proxy-authenticate",
    "proxy-authorization", "te", "trailers", "transfer-encoding", "upgrade",
}


def log_decision(entry: dict) -> None:
    entry["ts"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    path = CONFIG.get("log")
    if not path:
        return
    line = json.dumps(entry, separators=(",", ":"))
    with _LOG_LOCK:
        try:
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError:
            pass


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "BountyHarnessScopeProxy/1.0"

    def log_message(self, fmt, *args):  # silence default stderr logging
        return

    # ---------- CONNECT (HTTPS tunnel) ----------

    def do_CONNECT(self):
        host, port = _split_authority(self.path, default=443)
        if not host:
            self.send_error(400, "malformed CONNECT target")
            return
        scope = CONFIG["scope"]
        allowed, reason = scope.check(host, port, None, None)  # type: ignore[union-attr]
        log_decision({"action": "connect", "host": host, "port": port,
                      "decision": "allow" if allowed else "block", "reason": reason})
        if not allowed:
            self.send_error(403, f"out of scope: {reason}")
            return
        try:
            pinned = resolve_pinned(host, port, bool(CONFIG["allow_private"]),
                                    CONFIG.get("dns_override"))  # type: ignore[arg-type]
            upstream = socket.create_connection((pinned, port), timeout=20)
        except (OSError, ScopeBlocked) as exc:
            log_decision({"action": "connect", "host": host, "port": port,
                          "decision": "error", "reason": str(exc)})
            self.send_error(502, f"upstream connection failed: {exc}")
            return
        log_decision({"action": "connect", "host": host, "port": port,
                      "decision": "pinned", "pinned_ip": pinned})
        self.send_response(200, "Connection Established")
        self.end_headers()
        self._tunnel(upstream)

    def _tunnel(self, upstream: socket.socket) -> None:
        client = self.connection
        upstream.settimeout(None)
        client.settimeout(None)
        sockets = [client, upstream]
        try:
            while True:
                readable, _, errored = select.select(sockets, [], sockets, 60)
                if errored:
                    break
                if not readable:
                    continue
                for sock in readable:
                    data = sock.recv(65536)
                    if not data:
                        return
                    (upstream if sock is client else client).sendall(data)
        except OSError:
            pass
        finally:
            try:
                upstream.close()
            except OSError:
                pass

    # ---------- plain HTTP (absolute URI) ----------

    def _proxy_http(self, method: str):
        if not self.path.lower().startswith(("http://", "https://")):
            self.send_error(400, "proxy requires an absolute http(s) URI")
            return
        scope = CONFIG["scope"]
        allowed, reason = scope.check_url(self.path)  # type: ignore[union-attr]
        parts = urlsplit(self.path)
        host = parts.hostname or ""
        port = parts.port or (443 if parts.scheme == "https" else 80)
        if not allowed:
            log_decision({"action": method.lower(), "host": host, "port": port,
                          "decision": "block", "reason": reason})
            self.send_error(403, f"out of scope: {reason}")
            return
        try:
            pinned = resolve_pinned(host, port, bool(CONFIG["allow_private"]),
                                    CONFIG.get("dns_override"))  # type: ignore[arg-type]
        except (OSError, ScopeBlocked) as exc:
            log_decision({"action": method.lower(), "host": host, "port": port,
                          "decision": "error", "reason": str(exc)})
            self.send_error(502, f"DNS/pin failed: {exc}")
            return

        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None
        headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP_HEADERS}
        headers["Host"] = parts.netloc

        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        if parts.scheme == "https":
            conn = http.client.HTTPSConnection(host, port, timeout=30)
            # HTTPS absolute-form is unusual through a proxy; still pin.
            conn._create_connection = lambda *a, **kw: socket.create_connection(  # type: ignore[attr-defined]
                (pinned, port), timeout=30)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=30)
            conn._create_connection = lambda *a, **kw: socket.create_connection(  # type: ignore[attr-defined]
                (pinned, port), timeout=30)
        try:
            conn.request(method, path, body=body, headers=headers)
            resp = conn.getresponse()
            data = resp.read()
        except (OSError, http.client.HTTPException) as exc:
            log_decision({"action": method.lower(), "host": host, "port": port,
                          "decision": "error", "reason": str(exc), "pinned_ip": pinned})
            self.send_error(502, f"upstream error: {exc}")
            return
        finally:
            conn.close()

        log_decision({"action": method.lower(), "host": host, "port": port,
                      "decision": "allow", "pinned_ip": pinned, "status": resp.status})
        self.send_response(resp.status, resp.reason)
        for k, v in resp.getheaders():
            if k.lower() in HOP_HEADERS or k.lower() == "content-length":
                continue
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if method != "HEAD":
            self.wfile.write(data)

    def do_GET(self):
        self._proxy_http("GET")

    def do_HEAD(self):
        self._proxy_http("HEAD")

    def do_POST(self):
        self._proxy_http("POST")

    def do_PUT(self):
        self._proxy_http("PUT")

    def do_PATCH(self):
        self._proxy_http("PATCH")

    def do_DELETE(self):
        self._proxy_http("DELETE")

    def do_OPTIONS(self):
        self._proxy_http("OPTIONS")


def _split_authority(value: str, default: int) -> tuple[str, int]:
    value = value.strip()
    if value.startswith("["):
        end = value.find("]")
        if end == -1:
            return "", default
        host = value[1:end]
        rest = value[end + 1:]
        port = int(rest[1:]) if rest.startswith(":") and rest[1:].isdigit() else default
        return host, port
    if value.count(":") == 1:
        host, _, port_s = value.partition(":")
        return host, int(port_s) if port_s.isdigit() else default
    return value, default


def main() -> int:
    ap = argparse.ArgumentParser(description="Scope-enforcing HTTP proxy")
    ap.add_argument("--scope-file", required=True)
    ap.add_argument("--port", type=int, default=8899)
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--unix-socket", default=None,
                    help="listen on an AF_UNIX socket instead of TCP (used by the isolated netns bridge)")
    ap.add_argument("--parent-death", action="store_true",
                    help="exit when the parent process dies (bb-run uses this so no proxy is orphaned)")
    ap.add_argument("--allow-private", action="store_true")
    ap.add_argument("--dns-override", action="append", default=[], metavar="HOST=IP")
    ap.add_argument("--log", default=".bb/scope-proxy.log")
    ap.add_argument("--ready-file", default=None)
    args = ap.parse_args()

    if args.parent_death:
        try:
            import ctypes
            ctypes.CDLL("libc.so.6", use_errno=True).prctl(1, signal.SIGTERM)  # PR_SET_PDEATHSIG
        except Exception:
            pass

    scope = scope_guard.load(args.scope_file)
    if not scope.has_entries():
        print("refusing to start: scope file has no in-scope entries", file=sys.stderr)
        return 7
    override = {}
    for raw in args.dns_override:
        if "=" in raw:
            h, ip = raw.split("=", 1)
            override[h.lower()] = ip

    CONFIG.update({
        "scope": scope,
        "allow_private": args.allow_private,
        "dns_override": override,
        "log": args.log,
    })

    if args.unix_socket:
        sock_path = Path(args.unix_socket)
        sock_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            sock_path.unlink()
        except FileNotFoundError:
            pass

        class ThreadingUnixServer(socketserver.ThreadingUnixStreamServer):
            daemon_threads = True
            allow_reuse_address = True

        server = ThreadingUnixServer(str(sock_path), Handler)
        try:
            os.chmod(sock_path, 0o600)
        except OSError:
            pass

        def _graceful(_signum, _frame):
            threading.Thread(target=server.shutdown, daemon=True).start()

        signal.signal(signal.SIGTERM, _graceful)
        signal.signal(signal.SIGINT, _graceful)

        if args.ready_file:
            Path(args.ready_file).write_text("unix", encoding="utf-8")
        print(json.dumps({"unix_socket": str(sock_path), "scope": args.scope_file}), flush=True)
        try:
            server.serve_forever(poll_interval=0.2)
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
            try:
                sock_path.unlink()
            except FileNotFoundError:
                pass
        return 0

    server = ThreadingHTTPServer((args.bind, args.port), Handler)
    server.daemon_threads = True

    def _graceful_tcp(_signum, _frame):
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, _graceful_tcp)
    signal.signal(signal.SIGINT, _graceful_tcp)

    port = server.server_address[1]
    if args.ready_file:
        Path(args.ready_file).write_text(str(port), encoding="utf-8")
    print(json.dumps({"port": port, "bind": args.bind, "scope": args.scope_file}), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())

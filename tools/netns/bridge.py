#!/usr/bin/env python3
"""TCP -> AF_UNIX bridge that runs INSIDE the isolated network namespace.

The isolated namespace has no external interfaces and no default route. Its
only egress is this bridge on 127.0.0.1, which forwards bytes to the host-side
scope-enforcing proxy over an AF_UNIX socket (AF_UNIX is filesystem-scoped, so
it crosses the network namespace boundary without granting L3 connectivity).

The bridge is deliberately dumb: it can only connect to the one socket path
given on the command line. It cannot be pointed at arbitrary destinations, and
it never resolves names.
"""

from __future__ import annotations

import argparse
import json
import os
import select
import signal
import socket
import socketserver
import sys
from pathlib import Path


class Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        upstream.settimeout(20)
        try:
            upstream.connect(self.server.connect_path)  # type: ignore[attr-defined]
        except OSError:
            try:
                upstream.close()
            except OSError:
                pass
            return
        upstream.settimeout(None)
        client = self.request
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


class BridgeServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> int:
    ap = argparse.ArgumentParser(description="TCP to AF_UNIX bridge (isolated netns)")
    ap.add_argument("--connect", required=True, help="host proxy AF_UNIX socket path")
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--ready-file", default=None)
    args = ap.parse_args()

    server = BridgeServer((args.bind, args.port), Handler)
    server.connect_path = args.connect  # type: ignore[attr-defined]
    port = server.server_address[1]
    if args.ready_file:
        Path(args.ready_file).write_text(str(port), encoding="utf-8")
    print(json.dumps({"bridge_port": port, "connect": args.connect}), flush=True)

    def _stop(_signum, _frame):
        server.shutdown()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""One-shot supervisor for the rootless BountyHarness network namespace.

Started by `bb-run` as:

    unshare -Urn python3 tools/netns/supervisor.py \
        --proxy-socket <host proxy AF_UNIX path> \
        --ready-file <file> --state-file <file> -- bash -c "<workflow>"

Inside the new user+network namespace it:

  1. brings up loopback,
  2. installs an nftables default-deny ruleset (IPv4 and IPv6) that permits only
     loopback and established flows,
  3. starts the TCP->AF_UNIX bridge on 127.0.0.1,
  4. exports HTTP_PROXY/HTTPS_PROXY/ALL_PROXY pointing at the bridge, clears
     NO_PROXY/no_proxy, and runs the workflow command,
  5. tears the bridge down and exits with the workflow's exit code.

Because the namespace has no external interfaces and no default route, a tool
that ignores the proxy cannot reach the network at all: raw sockets, direct DNS
and IPv6 egress all fail inside the kernel. Egress is only possible through the
host proxy, which enforces the authorized scope and pins DNS.

Exit codes: workflow code normally; 80 if isolation could not be established;
124 on timeout.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import signal
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

NFT_RULES = """
table inet bb_isolated {
    chain input {
        type filter hook input priority 0; policy drop;
        iifname "lo" accept
        ct state established,related accept
    }
    chain forward {
        type filter hook forward priority 0; policy drop;
    }
    chain output {
        type filter hook output priority 0; policy drop;
        oifname "lo" accept
        ct state established,related accept
    }
}
"""


def _parent_death_signal() -> None:
    """Ask the kernel to SIGTERM us when bb-run dies (no orphan namespaces)."""
    try:
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        libc.prctl(1, signal.SIGTERM)  # PR_SET_PDEATHSIG
    except Exception:
        pass


class _ScmpArgCmp(ctypes.Structure):
    _fields_ = [
        ("arg", ctypes.c_uint),
        ("op", ctypes.c_int),
        ("datum_a", ctypes.c_uint64),
        ("datum_b", ctypes.c_uint64),
    ]


def _install_seccomp_raw_socket_block() -> bool:
    """Deny raw/packet socket creation for the workflow (inherited across exec).

    The namespace already has no route, so raw sockets cannot reach anything.
    This closes the remaining gap by refusing to create the socket at all.
    """
    try:
        lib = ctypes.CDLL("libseccomp.so.2", use_errno=True)
    except OSError:
        return False

    SCMP_ACT_ALLOW = 0x7FFF0000
    SCMP_ACT_ERRNO = lambda e: 0x00050000 | (e & 0xFFFF)  # noqa: E731
    SCMP_CMP_EQ = 4  # libseccomp enum: NE=1, LT=2, LE=3, EQ=4, GE=5, GT=6, MASKED_EQ=7
    SCMP_CMP_MASKED_EQ = 7

    lib.seccomp_init.restype = ctypes.c_void_p
    lib.seccomp_init.argtypes = [ctypes.c_uint32]
    lib.seccomp_syscall_resolve_name.restype = ctypes.c_int
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    lib.seccomp_rule_add_array.restype = ctypes.c_int
    lib.seccomp_rule_add_array.argtypes = [
        ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint,
        ctypes.POINTER(_ScmpArgCmp),
    ]
    lib.seccomp_load.restype = ctypes.c_int
    lib.seccomp_load.argtypes = [ctypes.c_void_p]
    lib.seccomp_release.argtypes = [ctypes.c_void_p]

    ctx = lib.seccomp_init(SCMP_ACT_ALLOW)
    if not ctx:
        return False
    try:
        sys_socket = lib.seccomp_syscall_resolve_name(b"socket")
        if sys_socket < 0:
            return False
        deny = SCMP_ACT_ERRNO(1)  # EPERM
        # AF_PACKET (17) in any type
        cmp_domain = _ScmpArgCmp(0, SCMP_CMP_EQ, 17, 0)
        if lib.seccomp_rule_add_array(ctx, deny, sys_socket, 1,
                                      ctypes.byref(cmp_domain)) != 0:
            return False
        # SOCK_RAW (3) in any address family (type mask 0xf)
        cmp_type = _ScmpArgCmp(1, SCMP_CMP_MASKED_EQ, 0xF, 3)
        if lib.seccomp_rule_add_array(ctx, deny, sys_socket, 1,
                                      ctypes.byref(cmp_type)) != 0:
            return False
        try:
            ctypes.CDLL("libc.so.6", use_errno=True).prctl(38, 1)  # PR_SET_NO_NEW_PRIVS
        except Exception:
            pass
        return lib.seccomp_load(ctx) == 0
    finally:
        lib.seccomp_release(ctx)


def _run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=30, **kwargs)


def _wait_file(path: Path, timeout: float = 5.0) -> str:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            text = path.read_text(encoding="utf-8").strip()
        except OSError:
            text = ""
        if text:
            return text
        time.sleep(0.05)
    return ""


def main() -> int:
    ap = argparse.ArgumentParser(description="Isolated netns supervisor")
    ap.add_argument("--proxy-socket", required=True)
    ap.add_argument("--ready-file", required=True)
    ap.add_argument("--state-file", required=True)
    ap.add_argument("--timeout", type=int, default=0, help="workflow timeout seconds (0 = none)")
    ap.add_argument("--cwd", default=os.getcwd())
    ap.add_argument("cmd", nargs=argparse.REMAINDER)
    args = ap.parse_args()

    cmd = list(args.cmd)
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        print("supervisor: no command given", file=sys.stderr)
        return 80

    _parent_death_signal()
    if os.getppid() == 1:
        return 80

    # Internal helpers (ip/nft) live in sbin on most distributions.
    os.environ["PATH"] = "/usr/sbin:/usr/bin:/sbin:/bin:" + os.environ.get("PATH", "")

    if not Path(args.proxy_socket).exists():
        print(f"supervisor: proxy socket missing: {args.proxy_socket}", file=sys.stderr)
        return 80

    ready = Path(args.ready_file)
    state = Path(args.state_file)
    for p in (ready, state):
        p.unlink(missing_ok=True)

    # 1. loopback only
    r = _run(["ip", "link", "set", "lo", "up"])
    if r.returncode != 0:
        print(f"supervisor: cannot bring up loopback: {r.stderr.strip()}", file=sys.stderr)
        return 80

    # 2. default-deny IPv4/IPv6 firewall inside the namespace
    r = subprocess.run(["nft", "-f", "-"], input=NFT_RULES, capture_output=True,
                       text=True, timeout=30)
    if r.returncode != 0:
        print(f"supervisor: cannot install namespace firewall: {r.stderr.strip()}", file=sys.stderr)
        return 80
    dumped = subprocess.run(["nft", "list", "table", "inet", "bb_isolated"],
                            capture_output=True, text=True, timeout=30)
    firewall_rules = (dumped.stdout or "").strip() if dumped.returncode == 0 else ""

    # 3. bridge (inside this namespace)
    bridge_ready = Path(str(ready) + ".bridge")
    bridge_ready.unlink(missing_ok=True)
    bridge_py = Path(__file__).resolve().parent / "bridge.py"
    bridge = subprocess.Popen(
        [sys.executable, str(bridge_py), "--connect", args.proxy_socket,
         "--ready-file", str(bridge_ready)],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
    )
    bridge_port = _wait_file(bridge_ready, 5.0)
    if not bridge_port or bridge.poll() is not None:
        err = ""
        if bridge.stderr:
            try:
                err = bridge.stderr.read()[-300:]
            except Exception:
                pass
        print(f"supervisor: bridge failed to start: {err}", file=sys.stderr)
        try:
            bridge.kill()
        except Exception:
            pass
        return 80

    # 3b. refuse raw/packet socket creation for this process and every child.
    # The namespace already has no route, so this is defence-in-depth against
    # tools that open raw sockets for their own purposes (nmap, packet crafters).
    seccomp_state = "deny"
    if not _install_seccomp_raw_socket_block():
        seccomp_state = "unavailable"
        if os.environ.get("BB_ISOLATION_STRICT_SECCOMP", "1") == "1":
            print("supervisor: cannot install raw-socket seccomp filter "
                  "(set BB_ISOLATION_STRICT_SECCOMP=0 to allow)", file=sys.stderr)
            try:
                bridge.terminate()
                bridge.wait(timeout=5)
            except Exception:
                try:
                    bridge.kill()
                except Exception:
                    pass
            return 80

    # 4. environment: proxy is the only way out
    env = dict(os.environ)
    proxy_url = f"http://127.0.0.1:{bridge_port}"
    env["HTTP_PROXY"] = proxy_url
    env["HTTPS_PROXY"] = proxy_url
    env["ALL_PROXY"] = proxy_url
    env["NO_PROXY"] = ""
    env["no_proxy"] = ""
    env["BB_ISOLATED"] = "1"
    env["BB_ISOLATION_BRIDGE_PORT"] = str(bridge_port)
    env["BB_SCOPE_PROXY_ACTIVE"] = "1"

    started = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    state.write_text(json.dumps({
        "pid": os.getpid(),
        "bridge_port": int(bridge_port),
        "proxy_socket": args.proxy_socket,
        "started_at": started,
        "firewall": "inet bb_isolated (policy drop; loopback only)",
        "firewall_rules": firewall_rules,
        "seccomp_raw_socket": seccomp_state,
    }, indent=2), encoding="utf-8")
    ready.write_text(json.dumps({"status": "ready", "bridge_port": int(bridge_port)}),
                     encoding="utf-8")

    # 5. run the workflow inside the namespace
    child = subprocess.Popen(cmd, env=env, cwd=args.cwd)
    code = 1

    def _forward(_signum, _frame):
        try:
            child.terminate()
        except Exception:
            pass

    signal.signal(signal.SIGTERM, _forward)
    signal.signal(signal.SIGINT, _forward)

    try:
        code = child.wait(timeout=args.timeout if args.timeout > 0 else None)
    except subprocess.TimeoutExpired:
        child.terminate()
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()
        code = 124
    finally:
        try:
            bridge.terminate()
            bridge.wait(timeout=5)
        except Exception:
            try:
                bridge.kill()
            except Exception:
                pass
        ready.unlink(missing_ok=True)
        bridge_ready.unlink(missing_ok=True)

    if code < 0:
        code = 128 - code
    return code


if __name__ == "__main__":
    sys.exit(main())

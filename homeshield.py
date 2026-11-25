#!/usr/bin/env python3
"""
HomeShield CLI: Autonomous Edge Cyber-Shield & Anti-Scam Gateway for Home Networks
Supports ZTE, Huawei, FiberHome, ASUS (Asuswrt-Merlin), OpenWrt, and Managed Switches.
"""

from __future__ import annotations

import argparse
import functools
import hashlib
import http.server
import os
import re
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

# Add project root to path
PROJECT_DIR = Path(__file__).resolve().parent
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

try:
    from core.factory_mode import FactoryModeClient
    from core.telnet_client import TelnetClient
except ImportError:
    FactoryModeClient = None
    TelnetClient = None

ROUTER_IP = os.getenv("HOMESHIELD_IP") or os.getenv("ROUTERGUARD_IP", "192.168.1.1")
SCRIPT_PATH = PROJECT_DIR / "scripts" / "adblock.sh"
WATCHDOG_PATH = PROJECT_DIR / "scripts" / "watchdog.sh"
WHITELIST_PATH = PROJECT_DIR / "config" / "whitelist.txt"
CONF_PATH = PROJECT_DIR / "config" / "adblock.conf"
RUST_ARMV7_BIN = PROJECT_DIR / "rust" / "target" / "armv7-unknown-linux-musleabi" / "release" / "homeshield-daemon"


def get_telnet_session(ip: str = ROUTER_IP):
    if FactoryModeClient is None or TelnetClient is None:
        raise RuntimeError("Core ZTE factory/telnet modules not found.")
    (u, p), _, _ = FactoryModeClient.negotiate(ip)
    return TelnetClient.create_session(ip, u, p)


def _get_local_ip_for_router(router_ip: str) -> str:
    """Determine local LAN IP address on the same interface that reaches the router."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect((router_ip, 23))
        return sock.getsockname()[0]
    finally:
        sock.close()


class _QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        return


def _start_ephemeral_file_server(directory: Path):
    """Start an ephemeral HTTP server on a random free port to serve a directory over LAN."""
    handler = functools.partial(_QuietHandler, directory=str(directory))
    server = http.server.ThreadingHTTPServer(("0.0.0.0", 0), handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port


def _stop_all_supervisors(run_cmd) -> None:
    """Force-stop any running Watchdog/Adblock shell loops (which trap TERM/HUP) and Rust daemons."""
    run_cmd(
        "killall -9 watchdog.sh 2>/dev/null; "
        "killall -9 adblock.sh 2>/dev/null; "
        "killall homeshield-daemon router-guard-daemon 2>/dev/null; "
        "sleep 1; "
        "killall -9 homeshield-daemon router-guard-daemon 2>/dev/null"
    )


def _rollback_to_shell(run_cmd) -> None:
    """Immediately restore the proven BusyBox shell engine if Rust canary fails."""
    print("  [!] Auto-Rollback triggered: reverting to shell engine (watchdog.sh + adblock.sh)...")
    _stop_all_supervisors(run_cmd)
    run_cmd("rm -f /var/tmp/homeshield-daemon.canary /userconfig/homeshield-daemon")
    run_cmd("/userconfig/watchdog.sh </dev/null >/dev/null 2>&1 &")
    run_cmd("/userconfig/adblock.sh start")


def deploy_rust_canary(run_cmd, router_ip: str, bin_path: Path = RUST_ARMV7_BIN) -> bool:
    """
    Transfer ARMv7 binary via ephemeral HTTP server into router RAM (/var/tmp),
    verify exact byte size + run canary check, promote to /userconfig/, and verify
    resident daemon health with automatic rollback on any failure.
    """
    if not bin_path.exists():
        print(f"  [-] Rust ARMv7 binary not found at {bin_path}")
        return False

    expected_size = bin_path.stat().st_size
    expected_sha = hashlib.sha256(bin_path.read_bytes()).hexdigest()[:16]
    local_ip = _get_local_ip_for_router(router_ip)
    server, port = _start_ephemeral_file_server(bin_path.parent)
    url = f"http://{local_ip}:{port}/{bin_path.name}"
    canary_path = "/var/tmp/homeshield-daemon.canary"

    try:
        print(f"  -> Serving {bin_path.name} ({expected_size} bytes, sha256:{expected_sha}...) on {url}")
        dl_out = run_cmd(
            f"rm -f /var/tmp/hosts.new {canary_path}; "
            f"(trap '' TERM; exec /bin/curl -sf --connect-timeout 5 --max-time 30 '{url}' -o {canary_path}); echo DL_RC=$?"
        )
        if "DL_RC=0" not in dl_out:
            print(f"  [-] Router HTTP pull failed:\n{dl_out}")
            return False

        size_out = run_cmd(f"ls -l {canary_path} | awk '{{print \"SIZE=\" $5}}'")
        if f"SIZE={expected_size}" not in size_out:
            print(f"  [-] Size mismatch (expected SIZE={expected_size}), got:\n{size_out}")
            run_cmd(f"rm -f {canary_path}")
            return False

        print("  -> Running RAM Canary check (--version & status)...")
        canary_out = run_cmd(
            f"chmod 755 {canary_path} && {canary_path} --version && {canary_path} status; echo CANARY_RC=$?"
        )
        if "CANARY_RC=0" not in canary_out or "homeshield-daemon" not in canary_out:
            print(f"  [-] RAM Canary failed (ABI or runtime error):\n{canary_out}")
            run_cmd(f"rm -f {canary_path}")
            return False

        print("  -> RAM Canary PASSED! Promoting to /userconfig/homeshield-daemon...")
        run_cmd(
            f"cp {canary_path} /userconfig/homeshield-daemon.new && "
            f"chmod 755 /userconfig/homeshield-daemon.new && "
            f"mv /userconfig/homeshield-daemon.new /userconfig/homeshield-daemon && "
            f"rm -f {canary_path}"
        )

        print("  -> Switching supervisor from shell scripts to Rust Daemon...")
        _stop_all_supervisors(run_cmd)
        run_cmd("/userconfig/homeshield-daemon start")
        run_cmd("nohup /userconfig/homeshield-daemon daemon </dev/null >/dev/null 2>&1 &")
        time.sleep(2)

        verify_out = run_cmd(
            "ps | grep 'homeshield-daemon daemon' | grep -v grep; "
            "/userconfig/homeshield-daemon status; echo VERIFY_RC=$?"
        )
        if "VERIFY_RC=0" not in verify_out or "Rust Daemon PID" not in verify_out:
            print(f"  [-] Rust Daemon failed post-switch health check:\n{verify_out}")
            _rollback_to_shell(run_cmd)
            return False

        print("\n=== HOMESHIELD RUST DAEMON STATUS ===")
        print(verify_out)
        return True
    finally:
        server.shutdown()
        server.server_close()


def deploy_homeshield(ip: str = ROUTER_IP, engine: str = "auto") -> bool:
    print(f"[*] Deploying HomeShield Engine (mode={engine}) to {ip}...")
    if not SCRIPT_PATH.exists() or not WATCHDOG_PATH.exists():
        print("Error: Missing script templates in scripts/")
        return False

    script_content = SCRIPT_PATH.read_text(encoding="utf-8")
    watchdog_content = WATCHDOG_PATH.read_text(encoding="utf-8")
    whitelist_content = WHITELIST_PATH.read_text(encoding="utf-8") if WHITELIST_PATH.exists() else ""
    conf_content = CONF_PATH.read_text(encoding="utf-8") if CONF_PATH.exists() else ""

    use_rust = engine == "rust" or (engine == "auto" and RUST_ARMV7_BIN.exists())

    sock, run_cmd = get_telnet_session(ip)
    try:
        # 1. Config
        if conf_content:
            print("  -> Updating /userconfig/adblock.conf...")
            run_cmd(f"cat << 'EOF' > /userconfig/adblock.conf\n{conf_content}\nEOF\n")

        # 2. Whitelist
        chk_wl = run_cmd("test -f /userconfig/whitelist.txt && echo EXISTS")
        if "EXISTS" not in chk_wl and whitelist_content:
            print("  -> Creating /userconfig/whitelist.txt...")
            run_cmd(f"cat << 'EOF' > /userconfig/whitelist.txt\n{whitelist_content}\nEOF\n")

        # 3. Always install/refresh Shell Engine as proven fallback safety net
        print("  -> Installing fallback shell engine (/userconfig/adblock.sh & watchdog.sh)...")
        run_cmd(f"cat << 'EOF' > /userconfig/adblock.sh\n{script_content}\nEOF\n")
        run_cmd("chmod 755 /userconfig/adblock.sh")
        run_cmd(f"cat << 'EOF' > /userconfig/watchdog.sh\n{watchdog_content}\nEOF\n")
        run_cmd("chmod 755 /userconfig/watchdog.sh")

        if use_rust:
            if deploy_rust_canary(run_cmd, ip, RUST_ARMV7_BIN):
                return True
            if engine == "rust":
                return False
            print("  [!] Falling back to shell supervisor after Rust canary abort.")

        print("  -> Starting shell watchdog daemon...")
        _stop_all_supervisors(run_cmd)
        run_cmd("/userconfig/watchdog.sh </dev/null >/dev/null 2>&1 &")
        run_cmd("/userconfig/adblock.sh start")
        time.sleep(2)

        status = run_cmd("/userconfig/adblock.sh status")
        print("\n=== HOMESHIELD STATUS ===")
        print(status)
        return True
    finally:
        sock.close()


def _run_remote_engine_cmd(run_cmd, action: str) -> str:
    chk = run_cmd("test -x /userconfig/homeshield-daemon && echo RUST_OK")
    if "RUST_OK" in chk:
        return run_cmd(f"/userconfig/homeshield-daemon {action}")
    return run_cmd(f"/userconfig/adblock.sh {action}")


def run_action(action: str, ip: str = ROUTER_IP) -> str:
    sock, run_cmd = get_telnet_session(ip)
    try:
        return _run_remote_engine_cmd(run_cmd, action)
    finally:
        sock.close()


_VALID_DOMAIN_RE = re.compile(r"^[a-z0-9_](?:[-a-z0-9_.]*[a-z0-9])?\.[a-z0-9]*[a-z][a-z0-9]*$")


def _validate_whitelist_domain(domain: str) -> str:
    clean = domain.strip().lower()
    if not clean or len(clean) > 253 or ".." in clean or not _VALID_DOMAIN_RE.match(clean):
        raise ValueError(f"Invalid domain name for whitelist: {domain!r}")
    return clean


def manage_whitelist(subaction: str, domain: str = "", ip: str = ROUTER_IP) -> None:
    clean_domain = _validate_whitelist_domain(domain) if subaction in ("add", "remove") else ""
    sock, run_cmd = get_telnet_session(ip)
    try:
        if subaction == "list":
            res = run_cmd("cat /userconfig/whitelist.txt 2>/dev/null")
            print("=== HOMESHIELD WHITELIST ===")
            print(res)
        elif subaction == "add":
            print(f"Adding '{clean_domain}' to router whitelist...")
            run_cmd(
                f"awk -v d='{clean_domain}' 'BEGIN{{found=0}} $1==d{{found=1}} END{{exit !found}}' "
                f"/userconfig/whitelist.txt 2>/dev/null || echo '{clean_domain}' >> /userconfig/whitelist.txt"
            )
            _run_remote_engine_cmd(run_cmd, "update")
            print("Updated and reloaded dnsmasq.")
        elif subaction == "remove":
            print(f"Removing '{clean_domain}' from router whitelist...")
            run_cmd(
                f"awk -v d='{clean_domain}' '$1 != d' /userconfig/whitelist.txt > /var/tmp/wl.tmp "
                f"&& mv /var/tmp/wl.tmp /userconfig/whitelist.txt"
            )
            _run_remote_engine_cmd(run_cmd, "update")
            print("Updated and reloaded dnsmasq.")
    finally:
        sock.close()


def uninstall_homeshield(ip: str = ROUTER_IP) -> bool:
    """Level 3 Rollback: cleanly uninstall HomeShield, flush DNS rules, and restore factory state."""
    print(f"[*] Uninstalling HomeShield from {ip} (Level 3 Factory Revert)...")
    sock, run_cmd = get_telnet_session(ip)
    try:
        _stop_all_supervisors(run_cmd)
        run_cmd(
            "iptables -t nat -D PREROUTING -i br0 -p udp --dport 53 -j REDIRECT --to-ports 53 2>/dev/null; "
            "iptables -t nat -D PREROUTING -i br0 -p tcp --dport 53 -j REDIRECT --to-ports 53 2>/dev/null; "
            "iptables -D FORWARD -p tcp --dport 853 -j REJECT --reject-with tcp-reset 2>/dev/null; "
            "ip6tables -D FORWARD -i br0 -p udp --dport 53 -j REJECT 2>/dev/null; "
            "ip6tables -D FORWARD -i br0 -p tcp --dport 53 -j REJECT 2>/dev/null; "
            "ip6tables -D FORWARD -p tcp --dport 853 -j REJECT --reject-with tcp-reset 2>/dev/null"
        )
        run_cmd("echo '127.0.0.1 localhost' > /var/tmp/hosts && killall -HUP dnsmasq 2>/dev/null")
        run_cmd(
            "rm -rf /userconfig/homeshield-daemon /userconfig/router-guard-daemon "
            "/userconfig/adblock.* /userconfig/watchdog.sh /userconfig/whitelist.txt "
            "/var/tmp/adblock.* /var/tmp/homeshield-daemon.canary 2>/dev/null"
        )
        print("[+] HomeShield successfully removed. Gateway restored to clean DNS state.")
        return True
    finally:
        sock.close()


def test_sinkhole(ip: str = ROUTER_IP) -> None:
    print(f"[*] Testing HomeShield DNS Sinkhole on {ip}...")
    test_domains = ["doubleclick.net", "pagead2.googlesyndication.com", "adservice.google.com"]
    pass_domains = ["google.com", "kasikornbank.com", "apple.com"]

    print("\n--- Ad Domains (Must resolve to 0.0.0.0 & ::) ---")
    for d in test_domains:
        r4 = subprocess.run(["nslookup", d, ip], capture_output=True, text=True)
        v4 = [l.strip().split()[-1] for l in r4.stdout.splitlines() if "Address:" in l][-1] if "Address:" in r4.stdout else "ERR"
        r6 = subprocess.run(["nslookup", "-type=AAAA", d, ip], capture_output=True, text=True)
        v6 = [l.strip().split()[-1] for l in r6.stdout.splitlines() if "address" in l][-1] if "address" in r6.stdout else "ERR"
        status = "PASSED (BLOCKED)" if v4 == "0.0.0.0" else "FAILED"
        print(f"  {d:<30} -> IPv4: {v4:<10} | IPv6: {v6:<6} [{status}]")

    print("\n--- Whitelisted & Normal Domains (Must resolve to Real IP) ---")
    for d in pass_domains:
        res = subprocess.run(["nslookup", d, ip], capture_output=True, text=True)
        val = [l.strip().split()[-1] for l in res.stdout.splitlines() if "Address:" in l][-1] if "Address:" in res.stdout else "ERR"
        status = "PASSED" if val not in ("0.0.0.0", "ERR") else "BLOCKED_ERROR"
        print(f"  {d:<30} -> Real IP: {val} [{status}]")


def handle_tv_command(args) -> int:
    from core.tv_manager import TVManager
    mgr = TVManager()

    if args.tv_action == "discover":
        print(f"[*] Discovering Smart TVs on LAN via Router ({args.ip})...")
        devices = mgr.discover_tvs_from_router(args.ip)
        if not devices:
            print("[-] No candidate Smart TVs or ADB-enabled devices found in router DHCP/ARP table.")
            print("    Make sure 'Network Debugging' (ADB) is enabled on your TV.")
            return 0
        print(f"\nFound {len(devices)} device(s):")
        print(f"{'IP Address':<16} {'MAC Address':<18} {'Hostname':<25} {'ADB (5555)':<12}")
        print("-" * 75)
        for dev in devices:
            adb_str = "READY (OPEN)" if dev['adb_ready'] else "CLOSED"
            print(f"{dev['ip']:<16} {dev['mac']:<18} {dev['hostname']:<25} {adb_str:<12}")
        return 0

    elif args.tv_action == "analyze":
        if not args.tv_ip:
            print("[-] Error: --tv-ip is required for 'tv analyze' (e.g. --tv-ip 192.168.1.50)")
            return 1
        print(f"[*] Connecting to Smart TV at {args.tv_ip}:5555...")
        conn_ok, conn_msg = mgr.connect_tv(args.tv_ip)
        if not conn_ok:
            print(f"[-] Connection failed: {conn_msg}")
            return 1
        is_tv, dev_info = mgr.verify_is_tv(args.tv_ip)
        print(f"[*] Device Verified: {dev_info}")
        if not is_tv:
            print("[!] Warning: Target does not report characteristics='tv'. Proceed with caution.")
        print("[*] Fetching package facts from CleanYourTV upstream...")
        mgr.fetch_facts()
        print(f"[*] Analyzing installed packages on {args.tv_ip}...")
        report = mgr.analyze_packages(args.tv_ip)
        print("\n=== SMART TV PACKAGE AUDIT REPORT ===")
        print(f"Total Installed Packages: {report['total_packages']}")
        print(f"Currently Disabled:       {report['currently_disabled']}")
        print(f"Protected System Core:    {len(report['protected'])}")
        print(f"Candidates to Debloat:    {len(report['to_disable'])}")
        print("\nBreakdown by Category (Candidates):")
        for cat, cnt in report['summary_by_category'].items():
            print(f"  - {cat:<15}: {cnt} package(s)")

        print("\nTop Candidates to Disable:")
        for item in report['to_disable'][:15]:
            status = "(already disabled)" if item['already_disabled'] else ""
            print(f"  [{item['category'].upper()}] {item['package']} - {item['name']} {status}")
            if item['description']:
                print(f"       Info: {item['description']}")
        if len(report['to_disable']) > 15:
            print(f"  ... and {len(report['to_disable']) - 15} more packages.")
        return 0

    elif args.tv_action == "clean":
        if not args.tv_ip:
            print("[-] Error: --tv-ip is required for 'tv clean' (e.g. --tv-ip 192.168.1.50)")
            return 1
        print(f"[*] Connecting to Smart TV at {args.tv_ip}:5555...")
        conn_ok, conn_msg = mgr.connect_tv(args.tv_ip)
        if not conn_ok:
            print(f"[-] Connection failed: {conn_msg}")
            return 1
        is_tv, dev_info = mgr.verify_is_tv(args.tv_ip)
        print(f"[*] Device Verified: {dev_info}")
        if not is_tv:
            print("[!] Warning: Target does not report characteristics='tv'. Proceed with caution.")
        print(f"[*] Running Safe Debloat on {args.tv_ip} (Dry Run: {args.dry_run})...")
        res = mgr.clean_tv(args.tv_ip, dry_run=args.dry_run)
        print("\n=== CLEAN OPERATION SUMMARY ===")
        print(f"Target Packages to Disable: {res['target_packages_count']}")
        print(f"Successfully Disabled:      {res['disabled_count']}")
        print(f"Snapshot Backup Created:    {res['snapshot_file']}")
        print(f"Standalone Rollback Script: {res['rollback_script']}")
        if res['failed']:
            print(f"\nFailed to disable ({len(res['failed'])}):")
            for f in res['failed']:
                print(f"  - {f['package']}: {f['error']}")
        print("\nNote: You can rollback anytime with:")
        print(f"  python3 homeshield.py tv --tv-action restore --tv-ip {args.tv_ip}")
        print(f"  OR directly on host: sh {res['rollback_script']}")
        return 0

    elif args.tv_action == "restore":
        if not args.tv_ip:
            print("[-] Error: --tv-ip is required for 'tv restore' (e.g. --tv-ip 192.168.1.50)")
            return 1
        print(f"[*] Connecting to Smart TV at {args.tv_ip}:5555...")
        conn_ok, conn_msg = mgr.connect_tv(args.tv_ip)
        if not conn_ok:
            print(f"[-] Connection failed: {conn_msg}")
            return 1
        print(f"[*] Restoring disabled packages on {args.tv_ip}...")
        snap_path = Path(args.snapshot) if args.snapshot else None
        res = mgr.restore_from_snapshot(args.tv_ip, snap_path)
        if not res.get("success"):
            print(f"[-] Restore error: {res.get('error')}")
            return 1
        print(f"[+] Successfully restored {res['restored_count']} package(s)!")
        print(f"    Snapshot used: {res['snapshot_used']}")
        return 0

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="HomeShield: Autonomous Edge Cyber-Shield & Anti-Scam Gateway for Home Networks"
    )
    parser.add_argument(
        "action",
        choices=["deploy", "uninstall", "status", "start", "stop", "pause", "resume", "toggle", "update", "check", "test", "whitelist", "tv", "device"],
        help="Action to execute",
    )
    parser.add_argument("--domain", default="", help="Domain for whitelist add/remove")
    parser.add_argument("--whitelist-action", choices=["list", "add", "remove"], default="list",
                        help="Subaction for whitelist")
    parser.add_argument("--ip", default=ROUTER_IP, help=f"Target router IP (default: {ROUTER_IP})")
    parser.add_argument("--engine", choices=["auto", "rust", "shell"], default="auto",
                        help="Engine deployment mode (default: auto)")
    parser.add_argument("--tv-action", choices=["discover", "analyze", "clean", "restore"], default="discover",
                        help="Subaction for Smart TV management")
    parser.add_argument("--tv-ip", default="", help="Target Smart TV IP address")
    parser.add_argument("--snapshot", default="", help="Path to snapshot file for TV restore")
    parser.add_argument("--dry-run", action="store_true", help="Simulate actions without disabling packages")
    args = parser.parse_args()

    if args.action == "deploy":
        return 0 if deploy_homeshield(args.ip, engine=args.engine) else 1
    elif args.action == "uninstall":
        return 0 if uninstall_homeshield(args.ip) else 1
    elif args.action == "test":
        test_sinkhole(args.ip)
        return 0
    elif args.action in ("tv", "device"):
        return handle_tv_command(args)
    elif args.action in ("status", "start", "stop", "pause", "resume", "toggle", "update", "check"):
        act = "start" if args.action == "resume" else ("stop" if args.action == "pause" else args.action)
        print(f"Executing '{act}' on router {args.ip}...")
        res = run_action(act, args.ip)
        print(res)
        return 0
    elif args.action == "whitelist":
        manage_whitelist(args.whitelist_action, args.domain, args.ip)
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())

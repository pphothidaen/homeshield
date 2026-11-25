"""
HomeShield Smart TV Manager
Integrates CleanYourTV knowledge and ADB debloating into HomeShield.
Features:
- Decoupled 2-layer architecture (0-hop direct ADB, router zero noise discovery)
- Safe-by-design package debloating (pm disable-user only, no uninstalls)
- Protected package allowlist (never touch SystemUI, Settings, WiFi, HDMI, Launcher)
- Automated pre-execution snapshot and standalone rollback script generation
- Online upstream facts fetching from CleanYourTV repository with local caching
"""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import time
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Upstream CleanYourTV facts source
CLEANYOURTV_FACTS_URL = (
    "https://raw.githubusercontent.com/udhaykumarbala/cleanyourtv-app/main/"
    "core/spec/src/main/resources/tv/cleanyour/core/spec/facts.tsv"
)

# Project paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = PROJECT_ROOT / "config"
CACHE_FILE = CONFIG_DIR / "cleanyourtv_facts.tsv"
BACKUP_DIR = PROJECT_ROOT / "backups"

# Critical System Packages that MUST NEVER be disabled
PROTECTED_PACKAGES: Set[str] = {
    # Core Android OS & Framework
    "android",
    "com.android.systemui",
    "com.android.settings",
    "com.android.tv.settings",
    "com.android.vending",
    "com.google.android.gms",
    "com.google.android.gsf",
    "com.android.packageinstaller",
    "com.google.android.packageinstaller",
    "com.android.providers.settings",
    "com.android.providers.media",
    "com.android.bluetooth",
    "com.android.keyguard",
    "com.android.externalstorage",
    "com.android.inputmethod.latin",
    "com.google.android.inputmethod.latin",
    "com.android.server.telecom",
    # TV Display, HDMI, Input, Audio
    "com.google.android.tungsten.setupwraith",
    "com.android.tv.frameworkpackagestubs",
    # Stock Home Launchers (Preserved for 100% stability)
    "com.google.android.tvlauncher",
    "com.google.android.leanbacklauncher",
    "com.google.android.apps.tv.launcherx",
    "com.amazon.firehomestarter",
    "com.amazon.tv.launcher",
    # Critical Wireless / Connectivity
    "com.android.networkstack",
    "com.google.android.networkstack",
    # Smartphone / Tablet Core & OEM Launchers
    "com.android.phone",
    "com.android.dialer",
    "com.android.contacts",
    "com.android.mms",
    "com.android.providers.telephony",
    "com.android.wifi.resources",
    "com.miui.home",
    "com.sec.android.app.launcher",
    "com.huawei.android.launcher",
    "com.oppo.launcher",
}

# Target categories to disable in Safe Debloat Mode
SAFE_DISABLE_CATEGORIES = {"ads", "tracking", "preloads", "brand", "demo"}

# Universal Device Hostname / Vendor Identifiers for Router Lease Matching (TV, Phone, Camera, Speaker)
TV_KEYWORDS = [
    "tv", "box", "stick", "mibox", "playbox", "trueid", "bravia", "sony",
    "tcl", "xiaomi", "mitv", "redmi", "poco", "hisense", "shield", "firetv",
    "firestick", "roku", "chromecast", "google-tv", "androidtv", "smarttv",
    "vestel", "haier", "skyworth", "changhong", "panasonic", "philips", "sharp",
    "toshiba", "lg", "samsung", "galaxy", "huawei", "honor", "oppo", "vivo",
    "realme", "oneplus", "formuler", "mecool", "reolink", "dahua", "hikvision",
    "arlo", "ezviz", "echo", "alexa", "nest", "homehub", "tuya",
]

BUILTIN_DEVICE_TELEMETRY_FACTS: Dict[str, Dict[str, str]] = {
    "com.miui.analytics": {"name": "MIUI Analytics", "description": "Xiaomi background usage & ad telemetry service", "category": "tracking"},
    "com.miui.msa.global": {"name": "MIUI System Ads", "description": "Xiaomi system-wide ad serving daemon (MSA)", "category": "ads"},
    "com.xiaomi.joyose": {"name": "Xiaomi Joyose", "description": "Xiaomi cloud gaming/device telemetry & ad service", "category": "tracking"},
    "com.samsung.android.da.daagent": {"name": "Samsung Diagnostic Agent", "description": "Samsung device analytics & diagnostic uploader", "category": "tracking"},
    "com.samsung.android.rubin.app": {"name": "Samsung Customization Service", "description": "Samsung cross-app behavioral profiling service", "category": "tracking"},
    "com.huawei.bd": {"name": "Huawei BigData", "description": "Huawei/Honor HiAnalytics background telemetry reporter", "category": "tracking"},
    "com.facebook.system": {"name": "Meta App Installer", "description": "Preloaded Meta system telemetry & silent installer", "category": "preloads"},
    "com.facebook.appmanager": {"name": "Meta App Manager", "description": "Preloaded Meta background update & telemetry agent", "category": "preloads"},
    "com.facebook.services": {"name": "Meta Services", "description": "Preloaded Meta background analytics helper", "category": "preloads"},
}


class TVManager:
    """Manages Smart TV discovery, package analysis, and safe ADB debloating."""

    def __init__(self, cache_path: Optional[Path] = None, backup_dir: Optional[Path] = None):
        self.cache_file = cache_path or CACHE_FILE
        self.backup_dir = backup_dir or BACKUP_DIR
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.facts: Dict[str, Dict[str, str]] = {}

    def fetch_facts(self, force_refresh: bool = False) -> Dict[str, Dict[str, str]]:
        """
        Fetch CleanYourTV package facts from upstream GitHub or local cache.
        Returns a mapping: package_name -> {name, description, category}
        """
        raw_text = ""
        # 1. Try online fetch first as requested by user
        if force_refresh or not self.cache_file.exists():
            try:
                req = urllib.request.Request(
                    CLEANYOURTV_FACTS_URL,
                    headers={"User-Agent": "HomeShield-TVManager/1.0"}
                )
                with urllib.request.urlopen(req, timeout=8) as response:
                    raw_text = response.read().decode("utf-8")
                self.cache_file.parent.mkdir(parents=True, exist_ok=True)
                self.cache_file.write_text(raw_text, encoding="utf-8")
            except Exception as e:
                # Fallback to cache if offline
                if self.cache_file.exists():
                    raw_text = self.cache_file.read_text(encoding="utf-8")
                else:
                    raw_text = ""
        else:
            raw_text = self.cache_file.read_text(encoding="utf-8")

        # Parse TSV
        self.facts = {}
        for line in raw_text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) >= 4:
                pkg, name, desc, cat = parts[0].strip(), parts[1].strip(), parts[2].strip(), parts[3].strip()
                self.facts[pkg] = {
                    "name": name,
                    "description": desc,
                    "category": cat
                }
        return self.facts

    @staticmethod
    def is_port_open(ip: str, port: int = 5555, timeout: float = 1.0) -> bool:
        """Check if target TCP port is open."""
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False

    def discover_tvs_from_router(self, router_ip: str = "192.168.1.1") -> List[Dict[str, Any]]:
        """
        Query DHCP lease tables and ARP on router via Telnet (Zero Noise discovery).
        Then test port 5555 on candidate devices.
        """
        try:
            from core.factory_mode import FactoryModeClient
            from core.telnet_client import TelnetClient
            (u, p), _, _ = FactoryModeClient.negotiate(router_ip)
            sock, run_cmd = TelnetClient.create_session(router_ip, u, p)
        except Exception as e:
            # If router telnet fails, return empty list
            return []

        leases_output = ""
        try:
            # Check standard embedded router DHCP lease & ARP locations
            cmd = (
                "cat /tmp/dhcp.leases 2>/dev/null || "
                "cat /var/lib/misc/dnsmasq.leases 2>/dev/null || "
                "cat /var/tmp/dnsmasq.leases 2>/dev/null || "
                "cat /proc/net/arp 2>/dev/null"
            )
            leases_output = run_cmd(cmd)
        finally:
            sock.close()

        devices: List[Dict[str, Any]] = []
        seen_ips: Set[str] = set()

        for line in leases_output.splitlines():
            line = line.strip()
            if not line or line.startswith("IP address"):
                continue

            parts = line.split()
            ip_match = None
            mac_match = None
            hostname = ""

            # Check dnsmasq.leases format: epoch mac ip hostname client-id
            # or /proc/net/arp: IP type flags MAC mask device
            for token in parts:
                if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", token):
                    ip_match = token
                elif re.match(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", token):
                    mac_match = token.lower()

            if len(parts) >= 4 and parts[3] != "*" and not re.match(r"^([0-9A-Fa-f]{2}[:-]){5}", parts[3]):
                hostname = parts[3]

            if not ip_match or ip_match in seen_ips or ip_match.startswith("127."):
                continue
            seen_ips.add(ip_match)

            # Match against known TV keywords
            lower_host = hostname.lower()
            is_candidate = any(kw in lower_host for kw in TV_KEYWORDS)

            # Probe ADB port 5555
            adb_active = self.is_port_open(ip_match, 5555, timeout=0.8)
            if adb_active or is_candidate:
                devices.append({
                    "ip": ip_match,
                    "mac": mac_match or "unknown",
                    "hostname": hostname or "(unnamed)",
                    "adb_ready": adb_active,
                    "is_tv_candidate": is_candidate
                })

        return devices

    @staticmethod
    def _run_adb(args: List[str], timeout: int = 15) -> Tuple[int, str]:
        """Execute local ADB command."""
        adb_bin = shutil.which("adb") or "adb"
        cmd = [adb_bin] + args
        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return res.returncode, res.stdout + res.stderr
        except subprocess.TimeoutExpired:
            return -1, "ADB command timed out"
        except FileNotFoundError:
            return -1, "adb executable not found on host system"

    def connect_tv(self, tv_ip: str) -> Tuple[bool, str]:
        """
        Connect to Android TV over network ADB with authorization checking.
        Returns: (success: bool, message: str)
        """
        code, out = self._run_adb(["connect", f"{tv_ip}:5555"], timeout=8)
        if "connected to" in out or "already connected" in out:
            # Check device authorization status
            _, dev_out = self._run_adb(["devices"], timeout=5)
            target = f"{tv_ip}:5555"
            for line in dev_out.splitlines():
                if target in line:
                    if "unauthorized" in line:
                        return False, "Device is unauthorized. Please look at your TV screen and select 'Always allow from this computer'."
                    elif "device" in line:
                        return True, "Connected and authorized"
            return True, "Connected"
        return False, out.strip() or "Connection timed out"

    def verify_is_tv(self, tv_ip: str) -> Tuple[bool, str]:
        """
        Verify that connected device is truly an Android/Google TV (not phone/tablet).
        Checks getprop ro.build.characteristics and ro.product.model.
        """
        target = f"{tv_ip}:5555"
        _, chars = self._run_adb(["-s", target, "shell", "getprop", "ro.build.characteristics"], timeout=5)
        _, model = self._run_adb(["-s", target, "shell", "getprop", "ro.product.model"], timeout=5)
        chars = chars.strip().lower()
        model = model.strip()

        is_tv = "tv" in chars or "leanback" in chars or any(kw in model.lower() for kw in TV_KEYWORDS)
        info = f"Model: {model or 'Unknown'}, Characteristics: {chars or 'standard'}"
        return is_tv, info

    def get_installed_packages(self, tv_ip: str) -> Tuple[List[str], List[str]]:
        """
        Retrieve list of all packages and disabled packages.
        Returns: (all_packages, disabled_packages)
        """
        target = f"{tv_ip}:5555"
        # All packages
        _, all_out = self._run_adb(["-s", target, "shell", "pm", "list", "packages"])
        all_pkgs = [
            line.replace("package:", "").strip()
            for line in all_out.splitlines()
            if line.startswith("package:")
        ]

        # Disabled packages
        _, dis_out = self._run_adb(["-s", target, "shell", "pm", "list", "packages", "-d"])
        dis_pkgs = [
            line.replace("package:", "").strip()
            for line in dis_out.splitlines()
            if line.startswith("package:")
        ]
        return sorted(all_pkgs), sorted(dis_pkgs)

    def analyze_packages(self, tv_ip: str) -> Dict[str, Any]:
        """
        Analyze TV installed packages against CleanYourTV facts.
        Categorizes each package and marks action (DISABLE, KEEP, PROTECTED).
        """
        if not self.facts:
            self.fetch_facts()

        all_pkgs, disabled_pkgs = self.get_installed_packages(tv_ip)

        results = {
            "tv_ip": tv_ip,
            "total_packages": len(all_pkgs),
            "currently_disabled": len(disabled_pkgs),
            "to_disable": [],
            "protected": [],
            "safe_keep": [],
            "summary_by_category": {}
        }

        for pkg in all_pkgs:
            is_already_disabled = pkg in disabled_pkgs

            if pkg in PROTECTED_PACKAGES:
                results["protected"].append({
                    "package": pkg,
                    "reason": "Critical System / Launcher Component"
                })
                continue

            fact = self.facts.get(pkg) or BUILTIN_DEVICE_TELEMETRY_FACTS.get(pkg)
            if fact:
                cat = fact.get("category", "other")
                name = fact.get("name", pkg)
                desc = fact.get("description", "")

                results["summary_by_category"][cat] = results["summary_by_category"].get(cat, 0) + 1

                if cat in SAFE_DISABLE_CATEGORIES:
                    results["to_disable"].append({
                        "package": pkg,
                        "name": name,
                        "category": cat,
                        "description": desc,
                        "already_disabled": is_already_disabled
                    })
                else:
                    results["safe_keep"].append({
                        "package": pkg,
                        "name": name,
                        "category": cat,
                        "description": desc
                    })
            else:
                # Uncatalogued package: keep safe
                results["safe_keep"].append({
                    "package": pkg,
                    "name": pkg,
                    "category": "user/uncatalogued",
                    "description": "Not in ad/telemetry database"
                })

        return results

    def create_snapshot_and_rollback_script(
        self, tv_ip: str, all_pkgs: List[str], disabled_pkgs: List[str], target_disable: List[str]
    ) -> Tuple[Path, Path]:
        """
        Create snapshot JSON and standalone bash/sh rollback script.
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_ip = tv_ip.replace(".", "_")

        snapshot_file = self.backup_dir / f"tv_snapshot_{safe_ip}_{timestamp}.json"
        restore_sh_file = self.backup_dir / f"restore_{safe_ip}_{timestamp}.sh"

        snapshot_data = {
            "tv_ip": tv_ip,
            "timestamp": timestamp,
            "all_packages": all_pkgs,
            "originally_disabled": disabled_pkgs,
            "newly_disabled": target_disable
        }
        snapshot_file.write_text(json.dumps(snapshot_data, indent=2), encoding="utf-8")

        # Standalone POSIX sh rollback script
        restore_content = [
            "#!/bin/sh",
            f"# Standalone Rollback Script for Smart TV at {tv_ip}",
            f"# Generated by HomeShield on {timestamp}",
            "# Usage: sh restore.sh [TV_IP]",
            "",
            f'TV_TARGET="${{1:-{tv_ip}:5555}}"',
            'echo "Connecting to ${TV_TARGET}..."',
            'adb connect "${TV_TARGET}"',
            'echo "Re-enabling packages..."',
        ]
        for pkg in target_disable:
            restore_content.append(f'adb -s "${{TV_TARGET}}" shell pm enable {pkg}')

        restore_content.extend([
            "",
            'echo "Rollback complete! All packages restored."',
            ""
        ])
        restore_sh_file.write_text("\n".join(restore_content), encoding="utf-8")
        restore_sh_file.chmod(0o755)

        return snapshot_file, restore_sh_file

    def clean_tv(self, tv_ip: str, dry_run: bool = False) -> Dict[str, Any]:
        """
        Perform safe debloat on Smart TV:
        1. Analyzes packages
        2. Creates snapshot & rollback scripts
        3. Disables targeted ads/telemetry packages using 'pm disable-user --user 0'
        """
        analysis = self.analyze_packages(tv_ip)
        to_disable = [item["package"] for item in analysis["to_disable"] if not item["already_disabled"]]

        all_pkgs, dis_pkgs = self.get_installed_packages(tv_ip)
        snapshot_path, rollback_path = self.create_snapshot_and_rollback_script(
            tv_ip, all_pkgs, dis_pkgs, to_disable
        )

        disabled_count = 0
        failed = []

        if not dry_run:
            target = f"{tv_ip}:5555"
            for pkg in to_disable:
                code, out = self._run_adb([
                    "-s", target, "shell", "pm", "disable-user", "--user", "0", pkg
                ])
                if "new state: disabled" in out or code == 0:
                    disabled_count += 1
                else:
                    failed.append({"package": pkg, "error": out.strip()})

        return {
            "tv_ip": tv_ip,
            "dry_run": dry_run,
            "snapshot_file": str(snapshot_path),
            "rollback_script": str(rollback_path),
            "target_packages_count": len(to_disable),
            "disabled_count": disabled_count,
            "failed": failed,
            "categories_affected": analysis["summary_by_category"]
        }

    def restore_from_snapshot(self, tv_ip: str, snapshot_file: Optional[Path] = None) -> Dict[str, Any]:
        """
        Restore disabled packages using the latest or specified snapshot file.
        """
        if not snapshot_file:
            safe_ip = tv_ip.replace(".", "_")
            snapshots = sorted(self.backup_dir.glob(f"tv_snapshot_{safe_ip}_*.json"))
            if not snapshots:
                return {"success": False, "error": f"No snapshots found for {tv_ip} in {self.backup_dir}"}
            snapshot_file = snapshots[-1]

        data = json.loads(snapshot_file.read_text(encoding="utf-8"))
        newly_disabled = data.get("newly_disabled", [])

        target = f"{tv_ip}:5555"
        restored = 0
        failed = []

        for pkg in newly_disabled:
            code, out = self._run_adb(["-s", target, "shell", "pm", "enable", pkg])
            if "new state: enabled" in out or code == 0:
                restored += 1
            else:
                failed.append({"package": pkg, "error": out.strip()})

        return {
            "success": True,
            "tv_ip": tv_ip,
            "snapshot_used": str(snapshot_file),
            "restored_count": restored,
            "failed": failed
        }

"""
End-to-end CLI and Cargo workspace tests for homeshield-daemon (Rust).
"""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RUST_DIR = PROJECT_ROOT / "rust"
DAEMON_BIN = RUST_DIR / "target" / "release" / "homeshield-daemon"


class TestRustDaemon(unittest.TestCase):

    @unittest.skipUnless(shutil.which("cargo"), "cargo toolchain not available")
    def test_cargo_workspace_tests_and_cli_e2e(self):
        # 1. Build release binary first if needed and run Rust workspace unit & integration tests
        test_res = subprocess.run(
            ["cargo", "test", "--workspace"],
            cwd=str(RUST_DIR),
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            test_res.returncode,
            0,
            f"cargo test failed:\n{test_res.stdout}\n{test_res.stderr}",
        )

        build_res = subprocess.run(
            ["cargo", "build", "--release", "--workspace"],
            cwd=str(RUST_DIR),
            capture_output=True,
            text=True,
        )
        self.assertEqual(build_res.returncode, 0, build_res.stderr)
        self.assertTrue(DAEMON_BIN.exists())
        # Verify compact embedded footprint (< 2 MB)
        self.assertLess(DAEMON_BIN.stat().st_size, 2 * 1024 * 1024)

        # 2. Check --version and --help CLI flags
        ver = subprocess.run([str(DAEMON_BIN), "--version"], capture_output=True, text=True)
        self.assertEqual(ver.returncode, 0)
        self.assertIn("homeshield-daemon", ver.stdout)

        hlp = subprocess.run([str(DAEMON_BIN), "--help"], capture_output=True, text=True)
        self.assertEqual(hlp.returncode, 0)
        self.assertIn("watchdog | daemon", hlp.stdout)

        # 3. Full real-binary E2E CLI lifecycle inside isolated temp workspace
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            feed_file = tmp_path / "feed.txt"
            wl_file = tmp_path / "whitelist.txt"
            conf_file = tmp_path / "adblock.conf"
            backup_file = tmp_path / "backup.hosts"
            ram_hosts = tmp_path / "ram_adblock.hosts"
            base_hosts = tmp_path / "hosts.base"
            sys_hosts = tmp_path / "hosts"
            last_upd = tmp_path / "last_update"
            last_ep = tmp_path / "last_epoch"
            paused_file = tmp_path / "adblock.paused"

            sys_hosts.write_text("127.0.0.1 localhost\n", encoding="utf-8")
            wl_file.write_text("kasikornbank.com\naisplay.ais.co.th\n", encoding="utf-8")

            lines = [
                "0.0.0.0 kasikornbank.com",
                "||aisplay.ais.co.th^",
                "||ads.youtube.com^",
                "r1---sn-ad.googlevideo.com",
            ]
            for i in range(1100):
                lines.append(f"0.0.0.0 ad{i}.tracker.example.com")
            feed_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

            conf_file.write_text(
                f'BLOCKLIST_URLS="file://{feed_file}"\n'
                f"UPDATE_INTERVAL_SECONDS=604800\n"
                f'WHITELIST_FILE="{wl_file}"\n'
                f'BACKUP_FILE="{backup_file}"\n'
                f'RAM_HOSTS_FILE="{ram_hosts}"\n'
                f'BASE_HOSTS_FILE="{base_hosts}"\n'
                f'SYSTEM_HOSTS_FILE="{sys_hosts}"\n'
                f'LAST_UPDATE_FILE="{last_upd}"\n'
                f'LAST_EPOCH_FILE="{last_ep}"\n'
                f'PAUSED_FILE="{paused_file}"\n'
                f"BLOCK_DOT=1\n"
                f"BLOCK_CANARY_DOH=1\n"
                f"BLOCK_APPLE_PRIVATE_RELAY=1\n",
                encoding="utf-8",
            )

            def run_cli(*cli_args):
                return subprocess.run(
                    [str(DAEMON_BIN), "--config", str(conf_file), *cli_args],
                    capture_output=True,
                    text=True,
                )

            # Update via file:// stream
            upd = run_cli("update")
            self.assertEqual(upd.returncode, 0, upd.stderr)
            self.assertTrue(backup_file.exists())
            sys_text = sys_hosts.read_text(encoding="utf-8")
            self.assertIn("0.0.0.0 ads.youtube.com", sys_text)
            self.assertIn(":: ads.youtube.com", sys_text)
            self.assertIn("0.0.0.0 use-application-dns.net", sys_text)
            self.assertNotIn("kasikornbank.com", sys_text)
            self.assertNotIn("aisplay.ais.co.th", sys_text)

            # Status active (1100 + 2 YT/googlevideo + 1 canary + 3 apple relay = 1106)
            st_active = run_cli("status")
            self.assertEqual(st_active.returncode, 0)
            self.assertIn("STATUS: ACTIVE", st_active.stdout)
            self.assertIn("BLOCKED_DOMAINS: 1106", st_active.stdout)

            # Pause restores clean base hosts
            pau = run_cli("pause")
            self.assertEqual(pau.returncode, 0, pau.stderr)
            self.assertNotIn("ads.youtube.com", sys_hosts.read_text(encoding="utf-8"))
            self.assertIn("STATUS: PAUSED", run_cli("status").stdout)

            # Resume re-applies dual-stack sinkhole
            res = run_cli("resume")
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertIn("0.0.0.0 ads.youtube.com", sys_hosts.read_text(encoding="utf-8"))
            self.assertIn("STATUS: ACTIVE", run_cli("status").stdout)

            # Toggle flips ACTIVE -> PAUSED -> ACTIVE atomically
            tog_off = run_cli("toggle")
            self.assertEqual(tog_off.returncode, 0, tog_off.stderr)
            self.assertIn("STATUS: PAUSED", tog_off.stdout)
            self.assertNotIn("ads.youtube.com", sys_hosts.read_text(encoding="utf-8"))

            tog_on = run_cli("toggle")
            self.assertEqual(tog_on.returncode, 0, tog_on.stderr)
            self.assertIn("STATUS: ACTIVE", tog_on.stdout)
            self.assertIn("0.0.0.0 ads.youtube.com", sys_hosts.read_text(encoding="utf-8"))

            # Unknown command fails cleanly
            bad = run_cli("nonexistent-cmd")
            self.assertNotEqual(bad.returncode, 0)


if __name__ == "__main__":
    unittest.main()

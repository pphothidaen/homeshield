"""
Unit tests for Tier 0 Cloud CDN pre-compiler and HTTP Canary deploy/rollback logic.
"""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import homeshield
from scripts import compile_blocklist


class TestTier0Compiler(unittest.TestCase):

    def test_compile_lines_dedup_whitelist_and_canaries(self):
        with tempfile.TemporaryDirectory() as tmp:
            wl_path = Path(tmp) / "whitelist.txt"
            wl_path.write_text("kasikornbank.com\naisplay.ais.co.th\n", encoding="utf-8")
            wl = compile_blocklist.load_whitelist(wl_path)

            raw = [
                "# header comment",
                "0.0.0.0 doubleclick.net",
                "||s.youtube.com^",
                "r1---sn-ad.googlevideo.com",
                "0.0.0.0 kasikornbank.com",
                "||aisplay.ais.co.th^",
                "0.0.0.0 doubleclick.net",
                "0.0.0.0 localhost",
            ]
            domains = compile_blocklist.compile_lines(raw, wl)
            self.assertIn("doubleclick.net", domains)
            self.assertIn("s.youtube.com", domains)
            self.assertIn("r1---sn-ad.googlevideo.com", domains)
            self.assertIn("use-application-dns.net", domains)
            self.assertIn("mask.icloud.com", domains)
            self.assertNotIn("kasikornbank.com", domains)
            self.assertNotIn("aisplay.ais.co.th", domains)
            self.assertEqual(len(domains), 7)  # 3 parsed + 4 canaries

    def test_normalize_feed_url(self):
        blob_txt = "https://github.com/Turtlecute33/adblocktest/blob/master/src/d3host.txt"
        self.assertEqual(
            compile_blocklist.normalize_feed_url(blob_txt),
            "https://raw.githubusercontent.com/Turtlecute33/adblocktest/master/src/d3host.txt",
        )
        blob_adb = "https://github.com/Turtlecute33/adblocktest/blob/master/src/d3host.adblock"
        self.assertEqual(
            compile_blocklist.normalize_feed_url(blob_adb),
            "https://raw.githubusercontent.com/Turtlecute33/adblocktest/master/src/d3host.adblock",
        )
        regular = "https://example.com/hosts.txt"
        self.assertEqual(compile_blocklist.normalize_feed_url(regular), regular)

    def test_turtlecute_d3host_syntax_parsing(self):
        wl = set()
        # Simulated snippet from d3host.txt and d3host.adblock
        raw = [
            "# --- Amazon",
            "0.0.0.0 adtago.s3.amazonaws.com",
            "0.0.0.0 analyticsengine.s3.amazonaws.com",
            "! --- Google Ads",
            "||pagead2.googlesyndication.com^",
            "||adservice.google.com^",
        ]
        domains = compile_blocklist.compile_lines(raw, wl)
        self.assertIn("adtago.s3.amazonaws.com", domains)
        self.assertIn("analyticsengine.s3.amazonaws.com", domains)
        self.assertIn("pagead2.googlesyndication.com", domains)
        self.assertIn("adservice.google.com", domains)

    def test_load_feeds_from_conf(self):
        with tempfile.TemporaryDirectory() as tmp:
            conf_file = Path(tmp) / "adblock.conf"
            conf_file.write_text(
                'BLOCKLIST_URLS="https://github.com/Turtlecute33/adblocktest/blob/master/src/d3host.txt https://example.com/other.txt"\n',
                encoding="utf-8",
            )
            feeds = compile_blocklist.load_feeds_from_conf(conf_file)
            self.assertEqual(len(feeds), 2)
            self.assertEqual(
                feeds[0],
                "https://raw.githubusercontent.com/Turtlecute33/adblocktest/master/src/d3host.txt",
            )
            self.assertEqual(feeds[1], "https://example.com/other.txt")


class TestCanaryDeployRollback(unittest.TestCase):

    def test_canary_abi_failure_aborts_without_touching_flash(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake_bin = Path(tmp) / "homeshield-daemon"
            fake_bin.write_bytes(b"ELF_FAKE_BINARY_PAYLOAD")
            size = fake_bin.stat().st_size

            cmds = []

            def fake_run_cmd(c):
                cmds.append(c)
                if "DL_RC=$?" in c:
                    return "DL_RC=0"
                if "ls -l" in c:
                    return f"SIZE={size}"
                if "CANARY_RC=$?" in c:
                    return "Illegal instruction\nCANARY_RC=132"
                return ""

            with patch("homeshield._get_local_ip_for_router", return_value="127.0.0.1"):
                ok = homeshield.deploy_rust_canary(fake_run_cmd, "192.168.1.1", fake_bin)

            self.assertFalse(ok)
            self.assertFalse(any("/userconfig/homeshield-daemon" in c and "mv " in c for c in cmds))

    def test_post_switch_health_failure_triggers_auto_rollback(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake_bin = Path(tmp) / "homeshield-daemon"
            fake_bin.write_bytes(b"ELF_FAKE_BINARY_PAYLOAD")
            size = fake_bin.stat().st_size

            cmds = []

            def fake_run_cmd(c):
                cmds.append(c)
                if "DL_RC=$?" in c:
                    return "DL_RC=0"
                if "ls -l" in c:
                    return f"SIZE={size}"
                if "CANARY_RC=$?" in c:
                    return "homeshield-daemon 0.1.0\nSTATUS: ACTIVE\nCANARY_RC=0"
                if "VERIFY_RC=$?" in c:
                    return "STATUS: ACTIVE\nROUTER_AUTONOMY: UNMANAGED\nVERIFY_RC=0"
                return ""

            with patch("homeshield._get_local_ip_for_router", return_value="127.0.0.1"), \
                 patch("homeshield.time.sleep"):
                ok = homeshield.deploy_rust_canary(fake_run_cmd, "192.168.1.1", fake_bin)

            self.assertFalse(ok)
            self.assertTrue(any("/userconfig/watchdog.sh" in c for c in cmds))
            self.assertTrue(any("/userconfig/adblock.sh start" in c for c in cmds))

    def test_engine_shell_flag_bypasses_rust_canary(self):
        cmds = []

        class DummySock:
            def close(self):
                pass

        def fake_run_cmd(c):
            cmds.append(c)
            return "EXISTS"

        with patch("homeshield.get_telnet_session", return_value=(DummySock(), fake_run_cmd)), \
             patch("homeshield.deploy_rust_canary") as mock_canary, \
             patch("homeshield.time.sleep"):
            ok = homeshield.deploy_homeshield("192.168.1.1", engine="shell")

        self.assertTrue(ok)
        mock_canary.assert_not_called()
        self.assertTrue(any("killall -9 watchdog.sh" in c for c in cmds))
        self.assertTrue(any("/userconfig/adblock.sh start" in c for c in cmds))

    def test_uninstall_homeshield_cleans_rules_and_flash(self):
        cmds = []

        class DummySock:
            def __init__(self):
                self.closed = False

            def close(self):
                self.closed = True

        sock = DummySock()

        def fake_run_cmd(c):
            cmds.append(c)
            return ""

        with patch("homeshield.get_telnet_session", return_value=(sock, fake_run_cmd)), \
             patch("homeshield.time.sleep"):
            ok = homeshield.uninstall_homeshield("192.168.1.1")

        self.assertTrue(ok)
        self.assertTrue(sock.closed)
        self.assertTrue(any("iptables -t nat -D PREROUTING" in c for c in cmds))
        self.assertTrue(any("ip6tables -D FORWARD" in c for c in cmds))
        self.assertTrue(any("rm -rf /userconfig/homeshield-daemon" in c for c in cmds))

    def test_whitelist_domain_validation_and_exact_awk_removal(self):
        self.assertEqual(homeshield._validate_whitelist_domain("Google.COM "), "google.com")
        self.assertEqual(homeshield._validate_whitelist_domain("x.co.th"), "x.co.th")
        for bad in ("", "foo'; reboot; '", "not_a_tld", "192.168.1.1", "a..b.com", "-bad.com"):
            with self.assertRaises(ValueError):
                homeshield._validate_whitelist_domain(bad)

        cmds = []

        class DummySock:
            def close(self):
                pass

        with patch("homeshield.get_telnet_session", return_value=(DummySock(), lambda c: (cmds.append(c), "")[1])):
            homeshield.manage_whitelist("remove", "google.com", "192.168.1.1")

        self.assertTrue(any("awk -v d='google.com' '$1 != d'" in c for c in cmds))
        self.assertFalse(any("sed -i" in c for c in cmds))


if __name__ == "__main__":
    unittest.main()

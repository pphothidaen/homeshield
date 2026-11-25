"""
Unit tests for HomeShield shell scripts and anti-bypass configuration.
"""

import subprocess
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
CONFIG_DIR = PROJECT_ROOT / "config"


class TestRouterScripts(unittest.TestCase):

    def test_watchdog_syntax_and_dot_rule(self):
        watchdog_path = SCRIPTS_DIR / "watchdog.sh"
        self.assertTrue(watchdog_path.exists())

        # Syntax check via sh -n
        res = subprocess.run(["sh", "-n", str(watchdog_path)], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"watchdog.sh syntax error: {res.stderr}")

        content = watchdog_path.read_text(encoding="utf-8")
        self.assertIn("--dport 853", content)
        self.assertIn("-j REJECT --reject-with tcp-reset", content)
        self.assertIn("PREROUTING", content)
        self.assertIn("--dport 53", content)
        self.assertIn("ip6tables", content)

    def test_adblock_syntax_and_multi_source(self):
        adblock_path = SCRIPTS_DIR / "adblock.sh"
        self.assertTrue(adblock_path.exists())

        # Syntax check via sh -n
        res = subprocess.run(["sh", "-n", str(adblock_path)], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"adblock.sh syntax error: {res.stderr}")

        content = adblock_path.read_text(encoding="utf-8")
        self.assertIn("BLOCKLIST_URLS", content)
        self.assertIn("use-application-dns.net", content)
        self.assertIn("mask.icloud.com", content)

    def test_adblock_conf(self):
        conf_path = CONFIG_DIR / "adblock.conf"
        self.assertTrue(conf_path.exists())

        content = conf_path.read_text(encoding="utf-8")
        self.assertIn("hagezi", content)
        self.assertIn("StevenBlack", content)
        self.assertIn("NoYouTubeAdsDNS", content)
        self.assertIn("Turtlecute33", content)
        self.assertIn("d3host.txt", content)
        self.assertIn("d3host.adblock", content)
        self.assertIn("BLOCK_DOT=1", content)
        self.assertIn("BLOCK_CANARY_DOH=1", content)
        self.assertIn("BLOCK_APPLE_PRIVATE_RELAY=1", content)

    def test_universal_awk_parser_regression(self):
        # Test awk logic extracted from adblock.sh
        awk_script = """
        NR==FNR { if ($1 ~ /^#/ || NF==0) next; wl[$1]=1; next }
        {
            if ($0 ~ /^#/ || NF==0) next;
            d = "";
            if ($1 == "0.0.0.0" || $1 == "127.0.0.1") { d = $2; }
            else if ($0 ~ /^\\|\\|/) { d = substr($0, 3); sub(/\\^.*$/, "", d); }
            else if ($0 ~ /^[a-zA-Z0-9_][-a-zA-Z0-9_.]*\\.[a-zA-Z0-9]+$/) { d = $1; }
            if (d != "" && !(d in wl) && !seen[d]++) {
                print "0.0.0.0", d;
            }
        }
        """
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            wl_path = Path(tmp) / "whitelist.txt"
            merged_path = Path(tmp) / "merged.txt"
            wl_path.write_text("kasikornbank.com\nais.co.th\n", encoding="utf-8")
            merged_path.write_text(
                "0.0.0.0 doubleclick.net\n"
                "||s.youtube.com^\n"
                "r1---sn-test.googlevideo.com\n"
                "0.0.0.0 kasikornbank.com\n"  # whitelisted
                "||ais.co.th^\n"  # whitelisted
                "0.0.0.0 doubleclick.net\n",  # duplicate
                encoding="utf-8",
            )

            res = subprocess.run(
                ["awk", awk_script, str(wl_path), str(merged_path)],
                capture_output=True,
                text=True
            )
            self.assertEqual(res.returncode, 0)
            output = res.stdout.strip().splitlines()

            self.assertIn("0.0.0.0 doubleclick.net", output)
            self.assertIn("0.0.0.0 s.youtube.com", output)
            self.assertIn("0.0.0.0 r1---sn-test.googlevideo.com", output)
            self.assertNotIn("0.0.0.0 kasikornbank.com", output)
            self.assertNotIn("0.0.0.0 ais.co.th", output)
            self.assertEqual(len(output), 3) # only 3 distinct, non-whitelisted domains


if __name__ == "__main__":
    unittest.main()

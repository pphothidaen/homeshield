"""
Unit tests for HomeShield TVManager and CleanYourTV integration.
"""

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from core.tv_manager import PROTECTED_PACKAGES, TVManager


class TestTVManager(unittest.TestCase):

    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())
        self.cache_file = self.test_dir / "test_facts.tsv"
        self.backup_dir = self.test_dir / "backups"
        self.mgr = TVManager(cache_path=self.cache_file, backup_dir=self.backup_dir)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_facts_parsing_from_cache(self):
        sample_tsv = (
            "# package\tname\tdescription\tcategory\n"
            "com.android.adservices.api\tAndroid Ads\tAd targeting framework\tads\n"
            "com.tcl.bootadservice\tTCL Boot Ad\tStartup advert\tads\n"
            "com.amazon.device.metrics\tAmazon Metrics\tTelemetry collector\ttracking\n"
            "com.netflix.ninja\tNetflix\tStreaming App\tstreaming\n"
        )
        self.cache_file.write_text(sample_tsv, encoding="utf-8")

        facts = self.mgr.fetch_facts(force_refresh=False)
        self.assertEqual(len(facts), 4)
        self.assertIn("com.tcl.bootadservice", facts)
        self.assertEqual(facts["com.tcl.bootadservice"]["category"], "ads")
        self.assertEqual(facts["com.amazon.device.metrics"]["category"], "tracking")
        self.assertEqual(facts["com.netflix.ninja"]["category"], "streaming")

    def test_protected_packages_never_disabled(self):
        # Even if a fact mislabels a system component, it must be protected
        sample_tsv = (
            "com.android.systemui\tSystem UI\tSystem Interface\tads\n"
            "com.android.settings\tSettings\tDevice Settings\tbrand\n"
        )
        self.cache_file.write_text(sample_tsv, encoding="utf-8")
        self.mgr.fetch_facts(force_refresh=False)

        mock_installed = [
            "android",
            "com.android.systemui",
            "com.android.settings",
            "com.google.android.tvlauncher",
            "com.tcl.bootadservice",
        ]

        with patch.object(self.mgr, "get_installed_packages", return_value=(mock_installed, [])):
            report = self.mgr.analyze_packages("192.168.1.50")

            protected_pkgs = {p["package"] for p in report["protected"]}
            to_disable_pkgs = {p["package"] for p in report["to_disable"]}

            self.assertIn("android", protected_pkgs)
            self.assertIn("com.android.systemui", protected_pkgs)
            self.assertIn("com.android.settings", protected_pkgs)
            self.assertIn("com.google.android.tvlauncher", protected_pkgs)

            # System components must NEVER be in to_disable
            self.assertNotIn("com.android.systemui", to_disable_pkgs)
            self.assertNotIn("com.android.settings", to_disable_pkgs)
            self.assertNotIn("com.google.android.tvlauncher", to_disable_pkgs)

    def test_analyze_categorization(self):
        sample_tsv = (
            "com.tcl.bootadservice\tTCL Boot Ad\tStartup advert\tads\n"
            "com.amazon.device.metrics\tAmazon Metrics\tTelemetry collector\ttracking\n"
            "com.google.android.youtube.tv\tYouTube\tVideo player\tstreaming\n"
        )
        self.cache_file.write_text(sample_tsv, encoding="utf-8")
        self.mgr.fetch_facts(force_refresh=False)

        mock_installed = [
            "com.tcl.bootadservice",
            "com.amazon.device.metrics",
            "com.google.android.youtube.tv",
            "com.custom.user.app",
        ]
        with patch.object(self.mgr, "get_installed_packages", return_value=(mock_installed, [])):
            report = self.mgr.analyze_packages("192.168.1.50")

            to_disable = [p["package"] for p in report["to_disable"]]
            self.assertIn("com.tcl.bootadservice", to_disable)
            self.assertIn("com.amazon.device.metrics", to_disable)

            # Streaming and user apps should be safe_keep
            safe_keep = [p["package"] for p in report["safe_keep"]]
            self.assertIn("com.google.android.youtube.tv", safe_keep)
            self.assertIn("com.custom.user.app", safe_keep)

    def test_snapshot_and_rollback_script_generation(self):
        all_pkgs = ["app1", "app2", "app3"]
        disabled_pkgs = ["app1"]
        target_disable = ["app2", "app3"]

        snap_path, sh_path = self.mgr.create_snapshot_and_rollback_script(
            "192.168.1.50", all_pkgs, disabled_pkgs, target_disable
        )

        self.assertTrue(snap_path.exists())
        self.assertTrue(sh_path.exists())

        # Validate snapshot JSON
        snap_data = json.loads(snap_path.read_text(encoding="utf-8"))
        self.assertEqual(snap_data["tv_ip"], "192.168.1.50")
        self.assertEqual(snap_data["newly_disabled"], ["app2", "app3"])

        # Validate sh script content
        sh_content = sh_path.read_text(encoding="utf-8")
        self.assertTrue(sh_content.startswith("#!/bin/sh"))
        self.assertIn("pm enable app2", sh_content)
        self.assertIn("pm enable app3", sh_content)

    def test_clean_tv_dry_run(self):
        sample_tsv = (
            "com.tcl.bootadservice\tTCL Boot Ad\tStartup advert\tads\n"
        )
        self.cache_file.write_text(sample_tsv, encoding="utf-8")
        self.mgr.fetch_facts(force_refresh=False)

        mock_installed = ["com.tcl.bootadservice", "android"]
        with patch.object(self.mgr, "get_installed_packages", return_value=(mock_installed, [])), \
             patch.object(self.mgr, "_run_adb") as mock_adb:

            res = self.mgr.clean_tv("192.168.1.50", dry_run=True)
            self.assertTrue(res["dry_run"])
            self.assertEqual(res["target_packages_count"], 1)
            # In dry run, _run_adb should not be called to disable packages
            mock_adb.assert_not_called()

    def test_restore_from_snapshot(self):
        # Create a mock snapshot
        snap_path, _ = self.mgr.create_snapshot_and_rollback_script(
            "192.168.1.50",
            all_pkgs=["app1", "app2"],
            disabled_pkgs=[],
            target_disable=["app1", "app2"]
        )

        with patch.object(self.mgr, "_run_adb", return_value=(0, "Package app1 new state: enabled")):
            res = self.mgr.restore_from_snapshot("192.168.1.50", snap_path)
            self.assertTrue(res["success"])
            self.assertEqual(res["restored_count"], 2)


    def test_connect_tv_authorization(self):
        # Case 1: Unauthorized
        with patch.object(self.mgr, "_run_adb", side_effect=[
            (0, "connected to 192.168.1.50:5555"),
            (0, "List of devices attached\n192.168.1.50:5555\tunauthorized\n")
        ]):
            ok, msg = self.mgr.connect_tv("192.168.1.50")
            self.assertFalse(ok)
            self.assertIn("unauthorized", msg)

        # Case 2: Authorized
        with patch.object(self.mgr, "_run_adb", side_effect=[
            (0, "already connected to 192.168.1.50:5555"),
            (0, "List of devices attached\n192.168.1.50:5555\tdevice\n")
        ]):
            ok, msg = self.mgr.connect_tv("192.168.1.50")
            self.assertTrue(ok)
            self.assertIn("authorized", msg)

    def test_verify_is_tv(self):
        # Case 1: Is TV
        with patch.object(self.mgr, "_run_adb", side_effect=[
            (0, "tv,leanback"),
            (0, "BRAVIA 4K VH2")
        ]):
            is_tv, info = self.mgr.verify_is_tv("192.168.1.50")
            self.assertTrue(is_tv)
            self.assertIn("BRAVIA", info)

        # Case 2: Phone/Tablet
        with patch.object(self.mgr, "_run_adb", side_effect=[
            (0, "default"),
            (0, "Pixel 7")
        ]):
            is_tv, info = self.mgr.verify_is_tv("192.168.1.50")
            self.assertFalse(is_tv)

    def test_builtin_mobile_and_iot_oem_telemetry_detection(self):
        self.mgr.facts = {}
        mock_installed = [
            "com.android.phone",
            "com.miui.home",
            "com.miui.analytics",
            "com.miui.msa.global",
            "com.samsung.android.da.daagent",
            "com.huawei.bd",
        ]
        with patch.object(self.mgr, "get_installed_packages", return_value=(mock_installed, [])):
            report = self.mgr.analyze_packages("192.168.1.60")
            protected = {p["package"] for p in report["protected"]}
            to_disable = {p["package"] for p in report["to_disable"]}
            self.assertEqual(protected, {"com.android.phone", "com.miui.home"})
            self.assertEqual(
                to_disable,
                {"com.miui.analytics", "com.miui.msa.global", "com.samsung.android.da.daagent", "com.huawei.bd"},
            )


if __name__ == "__main__":
    unittest.main()

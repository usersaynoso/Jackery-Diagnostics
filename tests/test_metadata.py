"""Metadata and documentation regression tests."""

from __future__ import annotations

import json
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = REPO_ROOT / "custom_components" / "jackery_diagnostics" / "manifest.json"
README_PATH = REPO_ROOT / "README.md"
HACS_PATH = REPO_ROOT / "hacs.json"
STRINGS_PATH = REPO_ROOT / "custom_components" / "jackery_diagnostics" / "strings.json"
EN_PATH = (
    REPO_ROOT
    / "custom_components"
    / "jackery_diagnostics"
    / "translations"
    / "en.json"
)


class MetadataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        cls.hacs = json.loads(HACS_PATH.read_text(encoding="utf-8"))
        cls.strings = json.loads(STRINGS_PATH.read_text(encoding="utf-8"))
        cls.translations = json.loads(EN_PATH.read_text(encoding="utf-8"))
        cls.readme = README_PATH.read_text(encoding="utf-8")

    def test_manifest_matches_requested_runtime_shape(self) -> None:
        self.assertEqual(self.manifest["domain"], "jackery_diagnostics")
        self.assertEqual(self.manifest["name"], "Jackery Diagnostics")
        self.assertEqual(self.manifest["dependencies"], [])
        self.assertEqual(
            self.manifest["requirements"],
            ["pycryptodomex>=3.9.0", "socketry>=0.2.4"],
        )
        self.assertEqual(self.manifest["version"], "1.3")
        self.assertEqual(self.manifest["iot_class"], "cloud_polling")
        self.assertTrue(self.manifest["config_flow"])

    def test_hacs_metadata_matches_repository_name(self) -> None:
        self.assertEqual(self.hacs["name"], "Jackery Diagnostics")
        self.assertTrue(self.hacs["render_readme"])

    def test_readme_covers_hacs_install_and_notification_flow(self) -> None:
        self.assertIn("Custom repositories", self.readme)
        self.assertIn("Settings > Devices & Services > Integrations", self.readme)
        self.assertIn("wait about 60 seconds", self.readme.lower())
        self.assertIn("Download diagnostics", self.readme)
        self.assertIn("disable the normal Jackery Home Assistant integration", self.readme)
        self.assertIn("/config/jackery_diagnostics_results.json", self.readme)
        self.assertIn("previous_result_diff", self.readme)
        self.assertIn("charging_plan_analysis", self.readme)
        self.assertIn("Socketry", self.readme)

    def test_english_translations_match_source_strings(self) -> None:
        self.assertEqual(self.translations, self.strings)


if __name__ == "__main__":
    unittest.main()

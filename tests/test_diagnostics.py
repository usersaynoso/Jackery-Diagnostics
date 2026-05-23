"""Tests for Home Assistant diagnostics download support."""

from __future__ import annotations

import asyncio
import importlib.util
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOT = REPO_ROOT / "custom_components" / "jackery_diagnostics"
TEST_PACKAGE = "jackery_diagnostics_download_test"
_MISSING = object()


def _install_stub_module(
    stubbed_modules: dict[str, object], module_name: str, module: types.ModuleType
) -> None:
    stubbed_modules.setdefault(module_name, sys.modules.get(module_name, _MISSING))
    sys.modules[module_name] = module


def _restore_stubbed_modules(stubbed_modules: dict[str, object]) -> None:
    for module_name, previous in reversed(list(stubbed_modules.items())):
        if previous is _MISSING:
            sys.modules.pop(module_name, None)
        else:
            sys.modules[module_name] = previous


def _load_module(
    module_name: str,
    path: Path,
    stubbed_modules: dict[str, object],
):
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    _install_stub_module(stubbed_modules, module_name, module)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _redact(value, keys_to_redact):
    if isinstance(value, dict):
        return {
            key: (
                "**REDACTED**"
                if key in keys_to_redact
                else _redact(item, keys_to_redact)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact(item, keys_to_redact) for item in value]
    return value


def _install_common_stubs(stubbed_modules: dict[str, object]) -> None:
    homeassistant = types.ModuleType("homeassistant")
    homeassistant.__path__ = []
    _install_stub_module(stubbed_modules, "homeassistant", homeassistant)

    components_mod = types.ModuleType("homeassistant.components")
    components_mod.__path__ = []
    diagnostics_mod = types.ModuleType("homeassistant.components.diagnostics")
    config_entries_mod = types.ModuleType("homeassistant.config_entries")
    core_mod = types.ModuleType("homeassistant.core")
    _install_stub_module(stubbed_modules, "homeassistant.components", components_mod)
    _install_stub_module(
        stubbed_modules, "homeassistant.components.diagnostics", diagnostics_mod
    )
    _install_stub_module(
        stubbed_modules, "homeassistant.config_entries", config_entries_mod
    )
    _install_stub_module(stubbed_modules, "homeassistant.core", core_mod)
    homeassistant.components = components_mod
    homeassistant.config_entries = config_entries_mod
    homeassistant.core = core_mod
    components_mod.diagnostics = diagnostics_mod
    diagnostics_mod.async_redact_data = _redact

    class ConfigEntry:
        def __init__(self, entry_id: str, data: dict[str, object]) -> None:
            self.entry_id = entry_id
            self.data = data

    class HomeAssistant:
        pass

    config_entries_mod.ConfigEntry = ConfigEntry
    core_mod.HomeAssistant = HomeAssistant

    package_mod = types.ModuleType(TEST_PACKAGE)
    package_mod.__path__ = [str(PACKAGE_ROOT)]
    _install_stub_module(stubbed_modules, TEST_PACKAGE, package_mod)

    const_mod = types.ModuleType(f"{TEST_PACKAGE}.const")
    const_mod.DOMAIN = "jackery_diagnostics"
    const_mod.RESULTS_PATH = Path("/tmp/placeholder.json")
    _install_stub_module(stubbed_modules, f"{TEST_PACKAGE}.const", const_mod)


stubbed_modules: dict[str, object] = {}
_install_common_stubs(stubbed_modules)
diagnostics = _load_module(
    f"{TEST_PACKAGE}.diagnostics",
    PACKAGE_ROOT / "diagnostics.py",
    stubbed_modules,
)
ConfigEntry = sys.modules["homeassistant.config_entries"].ConfigEntry


def tearDownModule() -> None:
    _restore_stubbed_modules(stubbed_modules)


class FakeHass:
    def __init__(self) -> None:
        self.data = {"jackery_diagnostics": {}}

    async def async_add_executor_job(self, target, *args):
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, target, *args)


class DiagnosticsTests(unittest.IsolatedAsyncioTestCase):
    async def test_diagnostics_download_reads_saved_results_and_redacts_secrets(
        self,
    ) -> None:
        hass = FakeHass()
        entry = ConfigEntry(
            "entry-1",
            {"email": "dev@example.com", "password": "secret", "token": "token-123"},
        )
        task = asyncio.create_task(asyncio.sleep(0))
        hass.data["jackery_diagnostics"]["entry-1"] = task
        await task

        with tempfile.TemporaryDirectory() as tmpdir:
            diagnostics.RESULTS_PATH = Path(tmpdir) / "jackery_diagnostics_results.json"
            diagnostics.RESULTS_PATH.write_text(
                json.dumps(
                    {
                        "account": "dev@example.com",
                        "token": "token-123",
                        "home_assistant": {
                            "custom_components": ["other_integration"],
                        },
                        "custom_components": ["other_integration"],
                        "generated_at": "2026-05-23T12:00:00+00:00",
                        "socketry_protocol_catalog": {
                            "available": True,
                            "writable_settings": [
                                {"id": "oac", "slug": "ac", "action_id": 4}
                            ],
                        },
                        "devices": [
                            {
                                "raw": {
                                    "modelCode": 13,
                                    "modelName": "HTE1195000A",
                                    "devSn": "SN123",
                                },
                                "device_sn": "SN123",
                                "devSn": "SN123",
                                "name": "Explorer",
                                "charging_plan_analysis": {
                                    "charging_plan_keys_reported": [],
                                },
                                "tuya_fingerprint": {
                                    "has_tuya_schema_evidence": True,
                                    "field_hits": [
                                        {
                                            "field": "devId",
                                            "value_preview": "SN123",
                                        }
                                    ],
                                },
                                "property_snapshots": [
                                    {
                                        "endpoint": "/v1/device/property",
                                        "header_profile": "android_apk_1_0_7",
                                        "parameter_name": "deviceId",
                                        "parameter_value": 123,
                                        "http_status": 200,
                                        "body": json.dumps(
                                            {"data": {"devSn": "SN123"}}
                                        ),
                                        "properties": {"rb": 97},
                                    }
                                ],
                                "probes": [
                                    {
                                        "endpoint": "/v1/device/chargePlan",
                                        "interesting": True,
                                        "parameter_name": "deviceSn",
                                        "parameter_value": "SN123",
                                        "body": json.dumps(
                                            {
                                                "token": "token-123",
                                                "data": {"devSn": "SN123"},
                                            }
                                        ),
                                    }
                                ],
                                "tuya_probes": [
                                    {
                                        "endpoint": "/v1.0/devices/{device_id}/status",
                                        "parameter_name": "device_id",
                                        "parameter_value": 123,
                                        "body": json.dumps(
                                            {"data": {"devId": "SN123"}}
                                        ),
                                    }
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            result = await diagnostics.async_get_config_entry_diagnostics(hass, entry)

        self.assertEqual(result["source"], "jackery_diagnostics")
        self.assertNotIn("entry", result)
        self.assertNotIn("probe_task", result)
        self.assertNotIn("content", result["result_file"])
        self.assertEqual(result["probe"]["generated_at"], "2026-05-23T12:00:00+00:00")
        device = result["probe"]["devices"][0]
        self.assertEqual(device["model"]["modelCode"], 13)
        self.assertEqual(device["model"]["modelName"], "HTE1195000A")
        self.assertEqual(device["property_snapshots"][0]["properties"], {"rb": 97})
        self.assertTrue(device["tuya_fingerprint"]["has_tuya_schema_evidence"])
        self.assertEqual(
            device["tuya_fingerprint"]["field_hits"][0]["value_preview"],
            "**REDACTED**",
        )
        self.assertEqual(
            device["tuya_probes"][0]["parameter_value"],
            "**REDACTED**",
        )
        probe = device["interesting_probes"][0]
        self.assertEqual(probe["parameter_value"], "**REDACTED**")
        self.assertNotIn("SN123", probe["body"])
        self.assertNotIn("token-123", probe["body"])
        serialized = json.dumps(result)
        self.assertNotIn("other_integration", serialized)
        self.assertNotIn("custom_components", serialized)

    async def test_diagnostics_download_handles_missing_result_file(self) -> None:
        hass = FakeHass()
        entry = ConfigEntry("entry-1", {})

        with tempfile.TemporaryDirectory() as tmpdir:
            diagnostics.RESULTS_PATH = Path(tmpdir) / "missing.json"

            result = await diagnostics.async_get_config_entry_diagnostics(hass, entry)

        self.assertFalse(result["result_file"]["exists"])
        self.assertIsNone(result["probe"])


if __name__ == "__main__":
    unittest.main()

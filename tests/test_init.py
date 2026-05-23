"""Tests for integration setup and result persistence."""

from __future__ import annotations

import asyncio
import importlib.util
import json
import sys
import tempfile
import threading
import types
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOT = REPO_ROOT / "custom_components" / "jackery_diagnostics"
TEST_PACKAGE = "jackery_diagnostics_init_test"
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
    *,
    package: bool = False,
):
    kwargs = {}
    if package:
        kwargs["submodule_search_locations"] = [str(path.parent)]
    spec = importlib.util.spec_from_file_location(module_name, path, **kwargs)
    module = importlib.util.module_from_spec(spec)
    _install_stub_module(stubbed_modules, module_name, module)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _install_common_stubs(stubbed_modules: dict[str, object]) -> None:
    homeassistant = types.ModuleType("homeassistant")
    homeassistant.__path__ = []
    _install_stub_module(stubbed_modules, "homeassistant", homeassistant)

    config_entries_mod = types.ModuleType("homeassistant.config_entries")
    core_mod = types.ModuleType("homeassistant.core")
    _install_stub_module(
        stubbed_modules, "homeassistant.config_entries", config_entries_mod
    )
    _install_stub_module(stubbed_modules, "homeassistant.core", core_mod)
    homeassistant.config_entries = config_entries_mod
    homeassistant.core = core_mod

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

    api_mod = types.ModuleType(f"{TEST_PACKAGE}.api")

    def format_probe_notification(result):
        return f"Formatted for {result['account']}"

    def run_diagnostic_probe(email, password, token=None):
        return {
            "generated_at": "2026-04-20T10:00:00+00:00",
            "account": email,
            "token": "fresh-token",
            "fatal_error": None,
            "discovery": {},
            "devices": [],
        }

    def compare_probe_results(previous, current):
        if previous is None:
            return None
        return {"property_changes": []}

    api_mod.format_probe_notification = format_probe_notification
    api_mod.run_diagnostic_probe = run_diagnostic_probe
    api_mod.compare_probe_results = compare_probe_results
    _install_stub_module(stubbed_modules, f"{TEST_PACKAGE}.api", api_mod)

    const_mod = types.ModuleType(f"{TEST_PACKAGE}.const")
    const_mod.DOMAIN = "jackery_diagnostics"
    const_mod.INTEGRATION_VERSION = "1.8"
    const_mod.NOTIFICATION_ID = "jackery_diagnostics_results"
    const_mod.NOTIFICATION_TITLE = "Jackery Diagnostics Results"
    const_mod.RESULTS_PATH = Path("/tmp/placeholder.json")
    _install_stub_module(stubbed_modules, f"{TEST_PACKAGE}.const", const_mod)


stubbed_modules: dict[str, object] = {}
_install_common_stubs(stubbed_modules)
integration = _load_module(
    TEST_PACKAGE,
    PACKAGE_ROOT / "__init__.py",
    stubbed_modules,
    package=True,
)
ConfigEntry = sys.modules["homeassistant.config_entries"].ConfigEntry


def tearDownModule() -> None:
    _restore_stubbed_modules(stubbed_modules)


class FakeServices:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, object], bool]] = []

    async def async_call(self, domain, service, data, blocking=False):
        self.calls.append((domain, service, data, blocking))


class FakeConfigEntries:
    def __init__(self) -> None:
        self.updated_entries: list[tuple[object, dict[str, object]]] = []

    def async_update_entry(self, entry, *, data):
        entry.data = data
        self.updated_entries.append((entry, data))


class FakeHass:
    def __init__(self) -> None:
        self.data = {}
        self.services = FakeServices()
        self.config_entries = FakeConfigEntries()

    def async_create_task(self, coro):
        return asyncio.create_task(coro)

    async def async_add_executor_job(self, target, *args):
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, target, *args)


class SetupTests(unittest.IsolatedAsyncioTestCase):
    async def test_setup_entry_runs_probe_writes_results_and_creates_notification(
        self,
    ) -> None:
        hass = FakeHass()
        entry = ConfigEntry(
            "entry-1",
            {"email": "dev@example.com", "password": "secret", "token": "old-token"},
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            integration.RESULTS_PATH = Path(tmpdir) / "jackery_diagnostics_results.json"

            setup_ok = await integration.async_setup_entry(hass, entry)
            self.assertTrue(setup_ok)

            run_state = hass.data["jackery_diagnostics"]["entry-1"]
            task = run_state["task"]
            await task

            self.assertEqual(entry.data["token"], "fresh-token")
            self.assertEqual(run_state["status"], "completed")
            self.assertEqual(len(hass.services.calls), 1)
            call = hass.services.calls[0]
            self.assertEqual(call[0], "persistent_notification")
            self.assertEqual(call[1], "create")
            self.assertEqual(call[2]["notification_id"], "jackery_diagnostics_results_entry-1")

            persisted = json.loads(integration.RESULTS_PATH.read_text(encoding="utf-8"))
            self.assertEqual(persisted["account"], "dev@example.com")
            self.assertEqual(persisted["diagnostics_plugin_version"], "1.8")
            self.assertEqual(persisted["run_status"]["status"], "completed")
            self.assertEqual(persisted["run_status"]["plugin_version"], "1.8")

    async def test_setup_entry_overwrites_stale_results_while_probe_runs(
        self,
    ) -> None:
        hass = FakeHass()
        entry = ConfigEntry(
            "entry-1",
            {"email": "dev@example.com", "password": "secret", "token": "old-token"},
        )
        release_probe = threading.Event()
        original_probe = integration.run_diagnostic_probe

        def blocking_probe(email, password, token=None):
            release_probe.wait(timeout=5)
            return {
                "generated_at": "2026-04-20T10:05:00+00:00",
                "account": email,
                "token": token,
                "fatal_error": None,
                "discovery": {},
                "devices": [],
            }

        integration.run_diagnostic_probe = blocking_probe
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                integration.RESULTS_PATH = (
                    Path(tmpdir) / "jackery_diagnostics_results.json"
                )
                integration.RESULTS_PATH.write_text(
                    json.dumps(
                        {
                            "generated_at": "2026-04-20T09:00:00+00:00",
                            "devices": [{"name": "stale"}],
                        }
                    ),
                    encoding="utf-8",
                )

                setup_ok = await integration.async_setup_entry(hass, entry)
                self.assertTrue(setup_ok)

                for _ in range(100):
                    persisted = json.loads(
                        integration.RESULTS_PATH.read_text(encoding="utf-8")
                    )
                    if persisted.get("run_status", {}).get("status") == "running":
                        break
                    await asyncio.sleep(0.01)
                else:
                    self.fail("Probe did not write running status")

                self.assertEqual(persisted["devices"], [])
                self.assertEqual(persisted["run_status"]["phase"], "probe_running")
                self.assertEqual(
                    persisted["previous_result_diff"]["previous_generated_at"],
                    "2026-04-20T09:00:00+00:00",
                )

                release_probe.set()
                await hass.data["jackery_diagnostics"]["entry-1"]["task"]
        finally:
            integration.run_diagnostic_probe = original_probe

    async def test_setup_entry_persists_probe_failure_instead_of_stale_result(
        self,
    ) -> None:
        hass = FakeHass()
        entry = ConfigEntry(
            "entry-1",
            {"email": "dev@example.com", "password": "secret", "token": "old-token"},
        )
        original_probe = integration.run_diagnostic_probe

        def failing_probe(email, password, token=None):
            raise RuntimeError("boom")

        integration.run_diagnostic_probe = failing_probe
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                integration.RESULTS_PATH = (
                    Path(tmpdir) / "jackery_diagnostics_results.json"
                )
                integration.RESULTS_PATH.write_text(
                    json.dumps(
                        {
                            "generated_at": "2026-04-20T09:00:00+00:00",
                            "devices": [{"name": "stale"}],
                        }
                    ),
                    encoding="utf-8",
                )

                setup_ok = await integration.async_setup_entry(hass, entry)
                self.assertTrue(setup_ok)
                run_state = hass.data["jackery_diagnostics"]["entry-1"]
                await run_state["task"]

                persisted = json.loads(
                    integration.RESULTS_PATH.read_text(encoding="utf-8")
                )
                self.assertEqual(run_state["status"], "failed")
                self.assertEqual(persisted["devices"], [])
                self.assertEqual(persisted["fatal_error"], "RuntimeError: boom")
                self.assertEqual(persisted["run_status"]["status"], "failed")
                self.assertEqual(
                    persisted["previous_result_diff"]["previous_generated_at"],
                    "2026-04-20T09:00:00+00:00",
                )
        finally:
            integration.run_diagnostic_probe = original_probe

    async def test_unload_entry_cancels_running_task(self) -> None:
        hass = FakeHass()
        task = asyncio.create_task(asyncio.sleep(60))
        hass.data["jackery_diagnostics"] = {"entry-1": {"task": task}}
        entry = ConfigEntry("entry-1", {})

        unload_ok = await integration.async_unload_entry(hass, entry)

        self.assertTrue(unload_ok)
        self.assertTrue(task.cancelled())


if __name__ == "__main__":
    unittest.main()

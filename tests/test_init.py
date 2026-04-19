"""Tests for integration setup and result persistence."""

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
            "devices": [],
        }

    api_mod.format_probe_notification = format_probe_notification
    api_mod.run_diagnostic_probe = run_diagnostic_probe
    _install_stub_module(stubbed_modules, f"{TEST_PACKAGE}.api", api_mod)

    const_mod = types.ModuleType(f"{TEST_PACKAGE}.const")
    const_mod.DOMAIN = "jackery_diagnostics"
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

            task = hass.data["jackery_diagnostics"]["entry-1"]
            await task

            self.assertEqual(entry.data["token"], "fresh-token")
            self.assertEqual(len(hass.services.calls), 1)
            call = hass.services.calls[0]
            self.assertEqual(call[0], "persistent_notification")
            self.assertEqual(call[1], "create")
            self.assertEqual(call[2]["notification_id"], "jackery_diagnostics_results_entry-1")

            persisted = json.loads(integration.RESULTS_PATH.read_text(encoding="utf-8"))
            self.assertEqual(persisted["account"], "dev@example.com")

    async def test_unload_entry_cancels_running_task(self) -> None:
        hass = FakeHass()
        task = asyncio.create_task(asyncio.sleep(60))
        hass.data["jackery_diagnostics"] = {"entry-1": task}
        entry = ConfigEntry("entry-1", {})

        unload_ok = await integration.async_unload_entry(hass, entry)

        self.assertTrue(unload_ok)
        self.assertTrue(task.cancelled())


if __name__ == "__main__":
    unittest.main()

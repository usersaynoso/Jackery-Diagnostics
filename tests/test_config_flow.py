"""Tests for the Jackery Diagnostics config flow."""

from __future__ import annotations

import asyncio
import importlib.util
import sys
import types
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOT = REPO_ROOT / "custom_components" / "jackery_diagnostics"
TEST_PACKAGE = "jackery_diagnostics_config_flow_test"
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
    _install_stub_module(
        stubbed_modules, "homeassistant.config_entries", config_entries_mod
    )
    homeassistant.config_entries = config_entries_mod

    voluptuous = types.ModuleType("voluptuous")
    _install_stub_module(stubbed_modules, "voluptuous", voluptuous)

    def required(key):
        return key

    def schema(value):
        return value

    voluptuous.Required = required
    voluptuous.Schema = schema

    class ConfigFlow:
        def __init_subclass__(cls, *, domain=None, **kwargs):
            super().__init_subclass__(**kwargs)
            cls.DOMAIN = domain

        def __init__(self) -> None:
            self.hass = None
            self._configured_ids: set[str] = set()
            self._last_unique_id = None

        async def async_set_unique_id(self, unique_id: str) -> None:
            self._last_unique_id = unique_id

        def _abort_if_unique_id_configured(self) -> None:
            if self._last_unique_id in self._configured_ids:
                raise AbortFlow("already_configured")

        def async_show_form(self, *, step_id, data_schema, errors):
            return {
                "type": "form",
                "step_id": step_id,
                "data_schema": data_schema,
                "errors": errors,
            }

        def async_create_entry(self, *, title, data):
            return {
                "type": "create_entry",
                "title": title,
                "data": data,
            }

    class AbortFlow(Exception):
        pass

    config_entries_mod.ConfigFlow = ConfigFlow
    config_entries_mod.AbortFlow = AbortFlow

    package_mod = types.ModuleType(TEST_PACKAGE)
    package_mod.__path__ = [str(PACKAGE_ROOT)]
    _install_stub_module(stubbed_modules, TEST_PACKAGE, package_mod)

    const_mod = types.ModuleType(f"{TEST_PACKAGE}.const")
    const_mod.DOMAIN = "jackery_diagnostics"
    _install_stub_module(stubbed_modules, f"{TEST_PACKAGE}.const", const_mod)

    api_mod = types.ModuleType(f"{TEST_PACKAGE}.api")

    class JackeryAuthenticationError(Exception):
        pass

    class JackeryConnectionError(Exception):
        pass

    class JackeryDiagnosticsClient:
        login_result = "token-123"
        login_error = None
        logins: list[tuple[str, str]] = []

        def __init__(self, email: str, password: str) -> None:
            self.email = email
            self.password = password

        def login(self) -> str:
            type(self).logins.append((self.email, self.password))
            if type(self).login_error is not None:
                raise type(self).login_error
            return type(self).login_result

    api_mod.JackeryDiagnosticsClient = JackeryDiagnosticsClient
    api_mod.JackeryAuthenticationError = JackeryAuthenticationError
    api_mod.JackeryConnectionError = JackeryConnectionError
    _install_stub_module(stubbed_modules, f"{TEST_PACKAGE}.api", api_mod)


stubbed_modules: dict[str, object] = {}
_install_common_stubs(stubbed_modules)
config_flow = _load_module(
    f"{TEST_PACKAGE}.config_flow",
    PACKAGE_ROOT / "config_flow.py",
    stubbed_modules,
)
api = sys.modules[f"{TEST_PACKAGE}.api"]
AbortFlow = sys.modules["homeassistant.config_entries"].AbortFlow


def tearDownModule() -> None:
    _restore_stubbed_modules(stubbed_modules)


class FakeHass:
    async def async_add_executor_job(self, target, *args):
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, target, *args)


class ConfigFlowTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        api.JackeryDiagnosticsClient.login_result = "token-123"
        api.JackeryDiagnosticsClient.login_error = None
        api.JackeryDiagnosticsClient.logins = []

    async def test_user_form_is_shown_initially(self) -> None:
        flow = config_flow.JackeryDiagnosticsConfigFlow()
        flow.hass = FakeHass()

        result = await flow.async_step_user()

        self.assertEqual(result["type"], "form")
        self.assertEqual(result["step_id"], "user")

    async def test_successful_login_creates_entry_and_stores_token(self) -> None:
        flow = config_flow.JackeryDiagnosticsConfigFlow()
        flow.hass = FakeHass()

        result = await flow.async_step_user(
            {"email": "dev@example.com", "password": "secret"}
        )

        self.assertEqual(result["type"], "create_entry")
        self.assertEqual(result["title"], "dev@example.com")
        self.assertEqual(result["data"]["token"], "token-123")
        self.assertEqual(api.JackeryDiagnosticsClient.logins, [("dev@example.com", "secret")])

    async def test_invalid_auth_sets_form_error(self) -> None:
        flow = config_flow.JackeryDiagnosticsConfigFlow()
        flow.hass = FakeHass()
        api.JackeryDiagnosticsClient.login_error = api.JackeryAuthenticationError()

        result = await flow.async_step_user(
            {"email": "dev@example.com", "password": "bad"}
        )

        self.assertEqual(result["type"], "form")
        self.assertEqual(result["errors"]["base"], "invalid_auth")

    async def test_duplicate_account_aborts(self) -> None:
        flow = config_flow.JackeryDiagnosticsConfigFlow()
        flow.hass = FakeHass()
        flow._configured_ids.add("dev@example.com")

        with self.assertRaises(AbortFlow):
            await flow.async_step_user(
                {"email": "dev@example.com", "password": "secret"}
            )


if __name__ == "__main__":
    unittest.main()

"""Diagnostics support for the Jackery Diagnostics integration."""

from __future__ import annotations

import json
from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import DOMAIN, RESULTS_PATH

TO_REDACT = {
    "account",
    "appUserName",
    "bluetoothKey",
    "deviceCode",
    "device_id",
    "device_sn",
    "deviceSn",
    "devId",
    "devSn",
    "email",
    "macId",
    "mqttPassWord",
    "nickname",
    "password",
    "sn",
    "token",
    "userId",
}
REDACTED = "**REDACTED**"
SENSITIVE_PARAMETER_NAMES = {
    "devicecode",
    "devicesn",
    "devsn",
    "sn",
}


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant,
    entry: ConfigEntry,
) -> dict[str, Any]:
    """Return diagnostic data for Home Assistant's download diagnostics action."""
    task = hass.data.get(DOMAIN, {}).get(entry.entry_id)
    result_file = await hass.async_add_executor_job(_read_results_file)

    return _redact_download_data(
        {
            "entry": {
                "entry_id": entry.entry_id,
                "data": dict(entry.data),
            },
            "probe_task": {
                "exists": task is not None,
                "done": bool(task.done()) if task is not None else None,
                "cancelled": bool(task.cancelled()) if task is not None else None,
            },
            "result_file": result_file,
        },
    )


def _read_results_file() -> dict[str, Any]:
    """Read the saved probe result for diagnostics download."""
    if not RESULTS_PATH.exists():
        return {
            "exists": False,
            "path": str(RESULTS_PATH),
            "content": None,
        }

    try:
        return {
            "exists": True,
            "path": str(RESULTS_PATH),
            "content": json.loads(RESULTS_PATH.read_text(encoding="utf-8")),
        }
    except json.JSONDecodeError as err:
        return {
            "exists": True,
            "path": str(RESULTS_PATH),
            "content": None,
            "error": f"Invalid JSON: {err}",
        }
    except OSError as err:
        return {
            "exists": False,
            "path": str(RESULTS_PATH),
            "content": None,
            "error": str(err),
        }


def _redact_download_data(data: dict[str, Any]) -> dict[str, Any]:
    """Redact diagnostics data, including embedded raw JSON response bodies."""
    return _redact_nested(async_redact_data(data, TO_REDACT))


def _redact_nested(value: Any) -> Any:
    """Recursively redact values that Home Assistant's key redaction cannot see."""
    if isinstance(value, dict):
        sensitive_parameter = (
            str(value.get("parameter_name", "")).replace("_", "").lower()
            in SENSITIVE_PARAMETER_NAMES
        )
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            if key == "parameter_value" and sensitive_parameter:
                redacted[key] = REDACTED
            elif key == "body" and isinstance(item, str):
                redacted[key] = _redact_body_string(item)
            else:
                redacted[key] = _redact_nested(item)
        return redacted

    if isinstance(value, list):
        return [_redact_nested(item) for item in value]

    return value


def _redact_body_string(body: str) -> str:
    """Redact JSON bodies stored as strings inside the saved probe result."""
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        return body

    redacted = _redact_nested(async_redact_data(parsed, TO_REDACT))
    return json.dumps(redacted, ensure_ascii=False, separators=(",", ":"))

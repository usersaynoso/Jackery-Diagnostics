"""Home Assistant entrypoint for Jackery Diagnostics."""

from __future__ import annotations

import asyncio
import json
import logging
from contextlib import suppress
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .api import compare_probe_results, format_probe_notification, run_diagnostic_probe
from .const import DOMAIN, NOTIFICATION_ID, NOTIFICATION_TITLE, RESULTS_PATH

_LOGGER = logging.getLogger(__name__)

JackeryConfigEntry = ConfigEntry


async def async_setup(hass: HomeAssistant, config: dict[str, Any]) -> bool:
    """Set up the integration from YAML."""
    hass.data.setdefault(DOMAIN, {})
    return True


async def async_setup_entry(hass: HomeAssistant, entry: JackeryConfigEntry) -> bool:
    """Set up Jackery Diagnostics from a config entry."""
    hass.data.setdefault(DOMAIN, {})
    task = hass.async_create_task(_async_run_probe(hass, entry))
    hass.data[DOMAIN][entry.entry_id] = task
    return True


async def async_unload_entry(hass: HomeAssistant, entry: JackeryConfigEntry) -> bool:
    """Unload Jackery Diagnostics."""
    task: asyncio.Task | None = hass.data.get(DOMAIN, {}).pop(entry.entry_id, None)
    if task is not None and not task.done():
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task
    return True


async def _async_run_probe(hass: HomeAssistant, entry: JackeryConfigEntry) -> None:
    """Run the blocking probe in the executor and surface the results."""
    result = await hass.async_add_executor_job(
        run_diagnostic_probe,
        entry.data["email"],
        entry.data["password"],
        entry.data.get("token"),
    )
    previous_result = await hass.async_add_executor_job(_read_results_file)
    result["previous_result_diff"] = compare_probe_results(previous_result, result)

    if result.get("token") and result["token"] != entry.data.get("token"):
        hass.config_entries.async_update_entry(
            entry,
            data={**entry.data, "token": result["token"]},
        )

    await hass.async_add_executor_job(_write_results_file, result)
    await hass.services.async_call(
        "persistent_notification",
        "create",
        {
            "title": NOTIFICATION_TITLE,
            "notification_id": f"{NOTIFICATION_ID}_{entry.entry_id}",
            "message": format_probe_notification(result),
        },
        blocking=True,
    )


def _write_results_file(result: dict[str, Any]) -> None:
    """Persist the untruncated probe results to disk."""
    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    RESULTS_PATH.write_text(
        json.dumps(result, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    _LOGGER.info("Wrote Jackery diagnostics results to %s", RESULTS_PATH)


def _read_results_file() -> dict[str, Any] | None:
    """Read the previous result file when available."""
    if not RESULTS_PATH.exists():
        return None
    try:
        return json.loads(RESULTS_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as err:
        _LOGGER.warning(
            "Could not read previous Jackery diagnostics results: %s", err
        )
        return None

"""Home Assistant entrypoint for Jackery Diagnostics."""

from __future__ import annotations

import asyncio
import json
import logging
from contextlib import suppress
from datetime import datetime, timezone
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .api import compare_probe_results, format_probe_notification, run_diagnostic_probe
from .const import (
    DOMAIN,
    INTEGRATION_VERSION,
    NOTIFICATION_ID,
    NOTIFICATION_TITLE,
    RESULTS_PATH,
)

_LOGGER = logging.getLogger(__name__)

JackeryConfigEntry = ConfigEntry


async def async_setup(hass: HomeAssistant, config: dict[str, Any]) -> bool:
    """Set up the integration from YAML."""
    hass.data.setdefault(DOMAIN, {})
    return True


async def async_setup_entry(hass: HomeAssistant, entry: JackeryConfigEntry) -> bool:
    """Set up Jackery Diagnostics from a config entry."""
    hass.data.setdefault(DOMAIN, {})
    run_state = _new_run_state()
    task = hass.async_create_task(_async_run_probe(hass, entry, run_state))
    run_state["task"] = task
    hass.data[DOMAIN][entry.entry_id] = run_state
    return True


async def async_unload_entry(hass: HomeAssistant, entry: JackeryConfigEntry) -> bool:
    """Unload Jackery Diagnostics."""
    stored = hass.data.get(DOMAIN, {}).pop(entry.entry_id, None)
    task: asyncio.Task | None
    if isinstance(stored, dict):
        task = stored.get("task")
    else:
        task = stored
    if task is not None and not task.done():
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task
    return True


async def _async_run_probe(
    hass: HomeAssistant,
    entry: JackeryConfigEntry,
    run_state: dict[str, Any],
) -> None:
    """Run the blocking probe in the executor and surface the results."""
    previous_result = await hass.async_add_executor_job(_read_results_file)
    run_state.update({"status": "running", "phase": "probe_running"})
    await hass.async_add_executor_job(
        _write_results_file,
        _build_status_result(
            entry,
            run_state,
            previous_result,
            fatal_error=None,
        ),
    )

    try:
        result = await hass.async_add_executor_job(
            run_diagnostic_probe,
            entry.data["email"],
            entry.data["password"],
            entry.data.get("token"),
        )
    except Exception as err:  # pragma: no cover - defensive runtime guard
        error = f"{err.__class__.__name__}: {err}"
        _LOGGER.exception("Jackery diagnostics probe task failed")
        run_state.update(
            {
                "status": "failed",
                "phase": "probe_failed",
                "finished_at": _utc_now(),
                "error": error,
            }
        )
        failure_result = _build_status_result(
            entry,
            run_state,
            previous_result,
            fatal_error=error,
        )
        await hass.async_add_executor_job(_write_results_file, failure_result)
        await _async_create_notification(hass, entry, failure_result)
        return

    run_state.update(
        {
            "status": "completed",
            "phase": "probe_completed",
            "finished_at": _utc_now(),
            "error": None,
        }
    )
    result["diagnostics_plugin_version"] = INTEGRATION_VERSION
    result["run_status"] = _serializable_run_state(run_state)
    result["previous_result_diff"] = compare_probe_results(previous_result, result)

    if result.get("token") and result["token"] != entry.data.get("token"):
        hass.config_entries.async_update_entry(
            entry,
            data={**entry.data, "token": result["token"]},
        )

    await hass.async_add_executor_job(_write_results_file, result)
    await _async_create_notification(hass, entry, result)


async def _async_create_notification(
    hass: HomeAssistant,
    entry: JackeryConfigEntry,
    result: dict[str, Any],
) -> None:
    """Show the probe result summary in Home Assistant."""
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


def _new_run_state() -> dict[str, Any]:
    """Create serializable state for the current background probe run."""
    started_at = _utc_now()
    return {
        "status": "starting",
        "phase": "setup_entry",
        "started_at": started_at,
        "finished_at": None,
        "error": None,
        "plugin_version": INTEGRATION_VERSION,
    }


def _build_status_result(
    entry: JackeryConfigEntry,
    run_state: dict[str, Any],
    previous_result: dict[str, Any] | None,
    *,
    fatal_error: str | None,
) -> dict[str, Any]:
    """Build a result file that represents an in-progress or failed probe."""
    return {
        "generated_at": run_state["started_at"],
        "diagnostics_plugin_version": INTEGRATION_VERSION,
        "account": entry.data.get("email"),
        "token": entry.data.get("token"),
        "devices": [],
        "discovery": {},
        "capture_guidance": None,
        "socketry_protocol_catalog": {},
        "socketry_mqtt_capture": {},
        "fatal_error": fatal_error,
        "previous_result_diff": {
            "previous_generated_at": previous_result.get("generated_at")
            if isinstance(previous_result, dict)
            else None,
            "current_generated_at": run_state["started_at"],
            "property_changes": [],
            "probe_response_changes": [],
        }
        if isinstance(previous_result, dict)
        else None,
        "run_status": _serializable_run_state(run_state),
    }


def _serializable_run_state(run_state: dict[str, Any]) -> dict[str, Any]:
    """Return run state without the asyncio task object."""
    return {
        key: value
        for key, value in run_state.items()
        if key != "task"
    }


def _utc_now() -> str:
    """Return an ISO-8601 UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


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

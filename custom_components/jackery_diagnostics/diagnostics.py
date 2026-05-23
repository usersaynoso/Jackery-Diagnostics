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
    "deviceId",
    "device_id",
    "device_sn",
    "deviceSn",
    "devId",
    "devSn",
    "email",
    "id",
    "localKey",
    "macId",
    "mqttPassWord",
    "nickname",
    "password",
    "sn",
    "token",
    "uid",
    "userId",
    "uuid",
}
REDACTED = "**REDACTED**"
SENSITIVE_PARAMETER_NAMES = {
    "devicecode",
    "deviceid",
    "devicesn",
    "devid",
    "devsn",
    "id",
    "localkey",
    "sn",
    "uid",
    "uuid",
}


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant,
    entry: ConfigEntry,
) -> dict[str, Any]:
    """Return diagnostic data for Home Assistant's download diagnostics action."""
    result_file = await hass.async_add_executor_job(_read_results_file)
    return _redact_download_data(_build_scoped_download(result_file))


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


def _build_scoped_download(result_file: dict[str, Any]) -> dict[str, Any]:
    """Build a narrow diagnostics payload for charging-plan investigation only."""
    content = result_file.get("content")
    payload: dict[str, Any] = {
        "schema_version": 1,
        "source": DOMAIN,
        "scope": "Jackery charging-plan diagnostics only",
        "result_file": {
            "exists": result_file.get("exists", False),
            "error": result_file.get("error"),
        },
    }

    if not isinstance(content, dict):
        payload["probe"] = None
        return payload

    devices = content.get("devices", [])
    payload["probe"] = {
        "generated_at": content.get("generated_at"),
        "fatal_error": content.get("fatal_error"),
        "device_count": len(devices) if isinstance(devices, list) else 0,
        "discovery": _summarize_discovery(content.get("discovery")),
        "previous_result_diff": _scope_previous_diff(
            content.get("previous_result_diff")
        ),
        "socketry_protocol_catalog": _scope_socketry_protocol_catalog(
            content.get("socketry_protocol_catalog")
        ),
        "socketry_mqtt_capture": _scope_socketry_mqtt_capture(
            content.get("socketry_mqtt_capture")
        ),
        "devices": [
            _scope_device(device)
            for device in devices
            if isinstance(device, dict)
        ]
        if isinstance(devices, list)
        else [],
    }
    return payload


def _summarize_discovery(discovery: Any) -> dict[str, Any]:
    if not isinstance(discovery, dict):
        return {}
    return {
        "http_status": discovery.get("http_status"),
        "raw_device_count": discovery.get("raw_device_count"),
        "skipped_device_count": len(discovery.get("skipped_devices", []))
        if isinstance(discovery.get("skipped_devices"), list)
        else 0,
    }


def _scope_socketry_protocol_catalog(catalog: Any) -> dict[str, Any]:
    if not isinstance(catalog, dict):
        return {}
    return {
        "available": catalog.get("available"),
        "reason": catalog.get("reason"),
        "charging_plan_entries": catalog.get("charging_plan_entries", []),
        "writable_settings": catalog.get("writable_settings", []),
        "source_scans": catalog.get("source_scans", []),
        "mqtt_command_payload_shape": catalog.get("mqtt_command_payload_shape"),
    }


def _scope_socketry_mqtt_capture(capture: Any) -> dict[str, Any]:
    if not isinstance(capture, dict):
        return {}

    messages = capture.get("messages", [])
    observed_keys_by_device: dict[str, set[str]] = {}
    if isinstance(messages, list):
        for message in messages:
            if not isinstance(message, dict):
                continue
            device_key = str(message.get("device_sn") or message.get("device_name"))
            observed_keys_by_device.setdefault(device_key, set()).update(
                str(key) for key in message.get("keys", []) if key is not None
            )

    return {
        "available": capture.get("available"),
        "error": capture.get("error"),
        "duration_seconds": capture.get("duration_seconds"),
        "message_count": capture.get("message_count"),
        "candidate_messages": capture.get("candidate_messages", []),
        "observed_keys_by_device": [
            {"device": device, "keys": sorted(keys)}
            for device, keys in sorted(observed_keys_by_device.items())
        ],
    }


def _scope_previous_diff(diff: Any) -> dict[str, Any] | None:
    if not isinstance(diff, dict):
        return None
    return {
        "previous_generated_at": diff.get("previous_generated_at"),
        "current_generated_at": diff.get("current_generated_at"),
        "property_changes": diff.get("property_changes", []),
    }


def _scope_device(device: dict[str, Any]) -> dict[str, Any]:
    raw = device.get("raw", {})
    if not isinstance(raw, dict):
        raw = {}

    return {
        "name": device.get("name"),
        "model": {
            "modelCode": raw.get("modelCode"),
            "modelName": raw.get("modelName"),
            "devModel": raw.get("devModel"),
            "deviceName": raw.get("deviceName"),
            "devName": raw.get("devName"),
        },
        "charging_plan_analysis": device.get("charging_plan_analysis"),
        "implementation_readiness": device.get("implementation_readiness"),
        "tuya_fingerprint": device.get("tuya_fingerprint"),
        "response_catalog": device.get("response_catalog"),
        "property_snapshots": [
            _scope_property_snapshot(snapshot)
            for snapshot in device.get("property_snapshots", [])
            if isinstance(snapshot, dict)
        ],
        "socketry_device_metadata": _scope_socketry_device_metadata(
            device.get("socketry_device_metadata")
        ),
        "interesting_probes": [
            _scope_probe(probe)
            for probe in [
                *device.get("probes", []),
                *device.get("extended_probes", []),
                *device.get("post_read_probes", []),
                *device.get("method_discovery_probes", []),
            ]
            if isinstance(probe, dict) and probe.get("interesting")
        ],
        "post_read_probes": [
            _scope_probe(probe)
            for probe in device.get("post_read_probes", [])
            if isinstance(probe, dict)
        ],
        "method_discovery_probes": [
            _scope_probe(probe)
            for probe in device.get("method_discovery_probes", [])
            if isinstance(probe, dict)
        ],
        "tuya_probes": [
            _scope_probe(probe)
            for probe in device.get("tuya_probes", [])
            if isinstance(probe, dict)
        ],
    }


def _scope_property_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    return {
        "endpoint": snapshot.get("endpoint"),
        "header_profile": snapshot.get("header_profile"),
        "parameter_name": snapshot.get("parameter_name"),
        "http_status": snapshot.get("http_status"),
        "body_hash": snapshot.get("body_hash"),
        "properties": snapshot.get("properties", {}),
        "error": snapshot.get("error"),
    }


def _scope_socketry_device_metadata(metadata: Any) -> dict[str, Any]:
    if not isinstance(metadata, dict):
        return {}
    return {
        "available": metadata.get("available"),
        "reason": metadata.get("reason"),
        "reported_writable_settings": metadata.get(
            "reported_writable_settings", []
        ),
        "unknown_reported_keys": metadata.get("unknown_reported_keys", []),
        "charging_plan_entries": metadata.get("charging_plan_entries", []),
        "charging_plan_keys_reported": metadata.get(
            "charging_plan_keys_reported", []
        ),
    }


def _scope_probe(probe: dict[str, Any]) -> dict[str, Any]:
    return {
        "method": probe.get("method", "GET"),
        "endpoint": probe.get("endpoint"),
        "probe_family": probe.get("probe_family"),
        "header_profile": probe.get("header_profile"),
        "body_format": probe.get("body_format"),
        "payload_variant": probe.get("payload_variant"),
        "parameter_name": probe.get("parameter_name"),
        "parameter_value": probe.get("parameter_value"),
        "request_body": probe.get("request_body"),
        "request_body_hash": probe.get("request_body_hash"),
        "http_status": probe.get("http_status"),
        "allow": probe.get("allow"),
        "body_hash": probe.get("body_hash"),
        "body": probe.get("body"),
        "error": probe.get("error"),
    }


def _redact_nested(value: Any) -> Any:
    """Recursively redact values that Home Assistant's key redaction cannot see."""
    if isinstance(value, dict):
        sensitive_parameter = (
            str(value.get("parameter_name", "")).replace("_", "").lower()
            in SENSITIVE_PARAMETER_NAMES
        )
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            normalized_key = str(key).replace("_", "").lower()
            if normalized_key in SENSITIVE_PARAMETER_NAMES:
                redacted[key] = REDACTED
            elif key == "parameter_value" and sensitive_parameter:
                redacted[key] = REDACTED
            elif (
                key == "value_preview"
                and str(value.get("field", "")).replace("_", "").lower()
                in SENSITIVE_PARAMETER_NAMES
            ):
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

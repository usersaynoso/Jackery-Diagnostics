"""Synchronous API helpers for Jackery Diagnostics."""

from __future__ import annotations

import base64
import hashlib
import asyncio
import inspect
import json
import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

import requests
from Cryptodome.Cipher import AES, PKCS1_v1_5
from Cryptodome.PublicKey import RSA
from Cryptodome.Util.Padding import pad

from .const import (
    AES_KEY,
    AUTH_HEADERS,
    BASE_URL,
    DEVICE_LIST_ENDPOINT,
    EXTENDED_IDENTIFIER_NAMES,
    EXTENDED_PROBE_ENDPOINTS,
    FIXED_MAC_ID_SEED,
    HEADER_PROFILES,
    LOGIN_ENDPOINT,
    METHOD_DISCOVERY_ENDPOINTS,
    METHOD_DISCOVERY_METHODS,
    MQTT_CAPTURE_SECONDS,
    PROPERTY_SNAPSHOT_PROFILES,
    PROBE_ENDPOINTS,
    READ_ONLY_POST_BODY_FORMATS,
    READ_ONLY_POST_HEADER_PROFILES,
    READ_ONLY_POST_IDENTIFIER_NAMES,
    READ_ONLY_POST_PROBE_ENDPOINTS,
    REQUEST_TIMEOUT,
    RSA_PUBLIC_KEY,
    SOURCE_SCAN_TERMS,
    TUYA_CHARGING_PLAN_TERMS,
    TUYA_FINGERPRINT_FIELDS,
    TUYA_PATH_PROBE_ENDPOINTS,
)

try:
    import socketry as SocketryModule
    import socketry.properties as SocketryPropertiesModule
    from socketry import Client as SocketryClient
    from socketry.properties import MODEL_NAMES, PROPERTIES
except ModuleNotFoundError as err:  # pragma: no cover - optional runtime dependency
    if err.name in {"socketry", "aiohttp", "aiomqtt", "Crypto"}:
        SocketryModule = None
        SocketryPropertiesModule = None
        SocketryClient = None
        MODEL_NAMES = {}
        PROPERTIES = ()
    else:
        raise

_LOGGER = logging.getLogger(__name__)


class JackeryDiagnosticsError(Exception):
    """Base exception for Jackery diagnostics failures."""


class JackeryAuthenticationError(JackeryDiagnosticsError):
    """Raised when the Jackery login flow fails."""


class JackeryConnectionError(JackeryDiagnosticsError):
    """Raised when the Jackery cloud cannot be reached."""


def generate_mac_id() -> str:
    """Generate the fixed-format macId used by the Jackery app."""
    digest = hashlib.md5(FIXED_MAC_ID_SEED.encode("utf-8")).digest()
    return f"2{uuid.UUID(bytes=digest, version=3).hex}"


def build_login_payload(email: str, password: str) -> dict[str, Any]:
    """Build the clear-text login payload before encryption."""
    return {
        "account": email,
        "loginType": 2,
        "macId": generate_mac_id(),
        "password": password,
        "phone": "",
        "registerAppId": "com.hbxn.jackery",
        "verificationCode": "",
    }


def encrypt_login_payload(payload: dict[str, Any]) -> tuple[str, str]:
    """Encrypt the login payload with AES-ECB and the AES key with RSA."""
    payload_json = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    aes_cipher = AES.new(AES_KEY, AES.MODE_ECB)
    aes_encrypt_data = base64.b64encode(
        aes_cipher.encrypt(pad(payload_json.encode("utf-8"), AES.block_size))
    ).decode("utf-8")

    public_key_pem = (
        f"-----BEGIN PUBLIC KEY-----\n{RSA_PUBLIC_KEY}\n-----END PUBLIC KEY-----"
    )
    public_key = RSA.import_key(public_key_pem)
    rsa_cipher = PKCS1_v1_5.new(public_key)
    rsa_for_aes_key = base64.b64encode(rsa_cipher.encrypt(AES_KEY)).decode("utf-8")
    return aes_encrypt_data, rsa_for_aes_key


def build_login_request(email: str, password: str) -> dict[str, Any]:
    """Build the request arguments for the Jackery login call."""
    aes_encrypt_data, rsa_for_aes_key = encrypt_login_payload(
        build_login_payload(email, password)
    )
    return {
        "url": f"{BASE_URL}{LOGIN_ENDPOINT}",
        "params": {
            "aesEncryptData": aes_encrypt_data,
            "rsaForAesKey": rsa_for_aes_key,
        },
        "headers": dict(AUTH_HEADERS),
        "files": {"file": ("", b"", "application/octet-stream")},
        "timeout": REQUEST_TIMEOUT,
    }


def _build_token_headers(
    token: str, profile_name: str = "ios_app_1_0_5"
) -> dict[str, str]:
    headers = dict(HEADER_PROFILES.get(profile_name, AUTH_HEADERS))
    headers["accept"] = "*/*"
    headers["token"] = token
    return headers


def _build_post_headers(
    token: str,
    profile_name: str,
    body_format: str,
) -> dict[str, str]:
    headers = _build_token_headers(token, profile_name)
    if body_format == "json":
        headers["Content-Type"] = "application/json"
    else:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    return headers


def _parse_json(text: str) -> dict[str, Any] | None:
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def response_contains_code_404(body: str) -> bool:
    """Return True when the response body indicates a logical 404."""
    parsed = _parse_json(body)
    if parsed is not None and parsed.get("code") == 404:
        return True

    normalized = body.replace(" ", "")
    return '"code":404' in normalized


def is_interesting_response(status_code: int, body: str) -> bool:
    """Flag probe responses that are not plain not-found responses."""
    return status_code != 404 and not response_contains_code_404(body)


def _extract_devices(payload: dict[str, Any]) -> list[dict[str, Any]]:
    devices = payload.get("data", [])
    if isinstance(devices, list):
        return devices
    if isinstance(devices, dict):
        for key in ("list", "records", "items"):
            nested = devices.get(key)
            if isinstance(nested, list):
                return nested
    return []


def _device_value(device: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in device and device[key] not in (None, ""):
            return device[key]
    return None


def _device_name(device: dict[str, Any]) -> str:
    return str(
        _device_value(
            device,
            "deviceName",
            "devName",
            "devNickname",
            "name",
            "alias",
            "deviceSn",
            "devSn",
            "id",
            "devId",
        )
        or "Unknown device"
    )


def _truncate_notification_body(body: str, limit: int = 500) -> str:
    compact = " ".join(body.split())
    if len(compact) <= limit:
        return compact
    return f"{compact[: limit - 3]}..."


def _extract_property_map(body: str) -> dict[str, Any] | None:
    """Return a Jackery property map from a raw API response body."""
    payload = _parse_json(body)
    if payload is None or payload.get("code") != 0:
        return None

    data = payload.get("data")
    if isinstance(data, dict):
        properties = data.get("properties")
        if isinstance(properties, dict):
            return properties
        if all(not isinstance(value, (dict, list)) for value in data.values()):
            return data
    return None


def _response_hash(body: str) -> str:
    """Return a stable short hash for comparing full probe bodies."""
    return hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()[:16]


def _hash_jsonable(value: Any) -> str:
    """Return a stable short hash for request payload shape comparisons."""
    body = json.dumps(value, sort_keys=True, default=str, separators=(",", ":"))
    return _response_hash(body)


def _response_json_shape(body: str) -> dict[str, Any]:
    """Return a compact schema-like summary of a probe response body."""
    payload = _parse_json(body)
    if payload is None:
        return {
            "json": False,
            "body_length": len(body),
            "body_hash": _response_hash(body),
        }

    data_field = "data" if "data" in payload else "result"
    data = payload.get(data_field)
    shape: dict[str, Any] = {
        "json": True,
        "top_level_keys": sorted(str(key) for key in payload),
        "payload_field": data_field if data is not None else None,
        "code": payload.get("code"),
        "msg": payload.get("msg"),
        "success": payload.get("success"),
        "encryption": payload.get("encryption"),
        "body_hash": _response_hash(body),
    }
    if isinstance(data, dict):
        shape["data_type"] = "dict"
        shape["data_keys"] = sorted(str(key) for key in data)[:80]
        properties = data.get("properties")
        if isinstance(properties, dict):
            shape["property_key_count"] = len(properties)
            shape["property_keys"] = sorted(str(key) for key in properties)[:80]
    elif isinstance(data, list):
        shape["data_type"] = "list"
        shape["data_length"] = len(data)
        if data and isinstance(data[0], dict):
            shape["first_item_keys"] = sorted(str(key) for key in data[0])[:80]
    else:
        shape["data_type"] = type(data).__name__ if data is not None else "none"
    return shape


def _setting_to_dict(setting: Any) -> dict[str, Any]:
    """Serialize a Socketry Setting object without importing its type in tests."""
    return {
        "id": getattr(setting, "id", None),
        "slug": getattr(setting, "slug", None),
        "name": getattr(setting, "name", None),
        "group": getattr(setting, "group", None),
        "writable": bool(getattr(setting, "writable", False)),
        "action_id": getattr(setting, "action_id", None),
        "values": getattr(setting, "values", None),
        "write_id": getattr(setting, "write_id", None),
        "prop_key": getattr(setting, "prop_key", getattr(setting, "id", None)),
        "unit": getattr(setting, "unit", ""),
    }


def _is_charging_plan_setting(setting: dict[str, Any]) -> bool:
    """Return whether a Socketry setting looks like charging-plan support."""
    if str(setting.get("id")) in {"107", "108"}:
        return True
    text = (
        f"{setting.get('id', '')} "
        f"{setting.get('slug', '')} "
        f"{setting.get('name', '')}"
    ).lower()
    return "charg" in text and "plan" in text


def _source_scan(module: Any, label: str) -> dict[str, Any]:
    """Scan a local installed module for charging-plan related literals."""
    if module is None:
        return {"available": False, "label": label, "reason": "module unavailable"}

    try:
        source = inspect.getsource(module)
    except (OSError, TypeError) as err:
        return {
            "available": False,
            "label": label,
            "module_file": getattr(module, "__file__", None),
            "reason": str(err),
        }

    hits: list[dict[str, Any]] = []
    lower_source = source.lower()
    for term in SOURCE_SCAN_TERMS:
        term_text = term.lower()
        start = 0
        while True:
            index = lower_source.find(term_text, start)
            if index < 0:
                break
            snippet_start = max(0, index - 80)
            snippet_end = min(len(source), index + len(term_text) + 80)
            hits.append(
                {
                    "term": term,
                    "offset": index,
                    "snippet": " ".join(source[snippet_start:snippet_end].split()),
                }
            )
            start = index + len(term_text)
            if len(hits) >= 100:
                break
        if len(hits) >= 100:
            break

    return {
        "available": True,
        "label": label,
        "module_file": getattr(module, "__file__", None),
        "source_hash": _response_hash(source),
        "terms_found": sorted({hit["term"] for hit in hits}),
        "hits": hits[:50],
    }


def build_socketry_protocol_catalog() -> dict[str, Any]:
    """Return Socketry's reverse-engineered setting and model catalog."""
    if not PROPERTIES:
        return {
            "available": False,
            "reason": "socketry is not installed",
            "settings": [],
            "writable_settings": [],
            "model_names": {},
            "charging_plan_entries": [],
            "source_scans": [
                _source_scan(SocketryModule, "socketry"),
                _source_scan(SocketryPropertiesModule, "socketry.properties"),
            ],
        }

    settings = [_setting_to_dict(setting) for setting in PROPERTIES]
    writable_settings = [setting for setting in settings if setting["writable"]]
    charging_plan_entries = [
        setting for setting in settings if _is_charging_plan_setting(setting)
    ]
    return {
        "available": True,
        "settings": settings,
        "writable_settings": writable_settings,
        "model_names": dict(MODEL_NAMES),
        "charging_plan_entries": charging_plan_entries,
        "source_scans": [
            _source_scan(SocketryModule, "socketry"),
            _source_scan(SocketryPropertiesModule, "socketry.properties"),
        ],
        "mqtt_command_payload_shape": {
            "deviceSn": "<device serial>",
            "id": "<milliseconds timestamp>",
            "version": 0,
            "messageType": "DevicePropertyChange",
            "actionId": "<socketry setting action_id>",
            "timestamp": "<milliseconds timestamp>",
            "body": {"<setting prop_key>": "<integer value>"},
        },
    }


def build_capture_guidance() -> dict[str, Any]:
    """Describe what this integration can and cannot capture."""
    return {
        "official_mobile_app_request_capture": {
            "available_from_home_assistant": False,
            "reason": (
                "Home Assistant cannot observe HTTPS requests made by the "
                "official Jackery mobile app on a separate phone. Capture that "
                "traffic with a trusted local proxy, or provide APK-derived "
                "endpoint and payload details."
            ),
            "needed_fields": [
                "method",
                "url/path",
                "query parameters",
                "form or JSON body",
                "non-secret headers",
                "before and after response bodies",
            ],
        },
        "safe_probe_policy": (
            "This diagnostic integration performs read-only HTTP GET, HEAD, "
            "OPTIONS, and identifier-only POST probes. It does not publish MQTT "
            "commands or send setting writes."
        ),
    }


def _interesting_probe_count(device: dict[str, Any], key: str) -> int:
    return sum(1 for probe in device.get(key, []) if probe.get("interesting"))


def _successful_property_snapshots(device: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        snapshot
        for snapshot in device.get("property_snapshots", [])
        if snapshot.get("properties")
    ]


def _looks_like_charging_plan_text(value: object) -> bool:
    text = str(value).lower()
    return (
        "107" in text
        or "108" in text
        or "chargeplan" in text
        or "charge_plan" in text
        or ("charg" in text and "plan" in text)
        or ("sched" in text and "charg" in text)
        or ("tim" in text and "charg" in text)
    )


def _candidate_payload_preview(body: str, limit: int = 800) -> str:
    compact = " ".join(body.split())
    if len(compact) <= limit:
        return compact
    return f"{compact[: limit - 3]}..."


def build_response_catalog(probes: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a compact catalogue of response shapes across all probe families."""
    endpoint_statuses: dict[str, set[str]] = {}
    interesting_shapes: list[dict[str, Any]] = []
    non_empty_data: list[dict[str, Any]] = []
    body_hashes: dict[str, int] = {}

    for probe in probes:
        endpoint = str(probe.get("endpoint"))
        method = str(probe.get("method", "GET"))
        status = str(probe.get("http_status"))
        key = f"{method} {endpoint}"
        endpoint_statuses.setdefault(key, set()).add(status)
        body = str(probe.get("body", ""))
        body_hash = str(probe.get("body_hash") or _response_hash(body))
        body_hashes[body_hash] = body_hashes.get(body_hash, 0) + 1
        shape = _response_json_shape(body)

        data_type = shape.get("data_type")
        has_data = (
            data_type == "dict"
            or (data_type == "list" and shape.get("data_length", 0) > 0)
        )
        if has_data:
            non_empty_data.append(
                {
                    "method": method,
                    "endpoint": endpoint,
                    "header_profile": probe.get("header_profile"),
                    "parameter_name": probe.get("parameter_name"),
                    "body_format": probe.get("body_format"),
                    "http_status": probe.get("http_status"),
                    "shape": shape,
                }
            )
        if probe.get("interesting") or _find_charging_plan_terms(body):
            interesting_shapes.append(
                {
                    "method": method,
                    "endpoint": endpoint,
                    "header_profile": probe.get("header_profile"),
                    "parameter_name": probe.get("parameter_name"),
                    "body_format": probe.get("body_format"),
                    "http_status": probe.get("http_status"),
                    "shape": shape,
                    "charging_plan_terms": _find_charging_plan_terms(body),
                }
            )

    return {
        "endpoint_statuses": [
            {"endpoint": endpoint, "statuses": sorted(statuses)}
            for endpoint, statuses in sorted(endpoint_statuses.items())
        ],
        "unique_body_hash_count": len(body_hashes),
        "repeated_body_hashes": [
            {"body_hash": body_hash, "count": count}
            for body_hash, count in sorted(
                body_hashes.items(), key=lambda item: (-item[1], item[0])
            )
            if count > 1
        ][:25],
        "non_empty_data": non_empty_data[:50],
        "interesting_shapes": interesting_shapes[:50],
    }


def build_implementation_readiness(
    analysis: dict[str, Any],
    tuya_fingerprint: dict[str, Any],
    response_catalog: dict[str, Any],
    socketry_metadata: dict[str, Any],
) -> dict[str, Any]:
    """Explain whether diagnostics found enough evidence to implement entities."""
    expected = analysis.get("main_integration_expected_entities", {})
    switch = expected.get("charging_plan_switch", {})
    time_entity = expected.get("charging_plan_time", {})
    repeat_entity = expected.get("charging_plan_repeat", {})
    candidate_probes = analysis.get("candidate_probes", [])
    successful_candidate_reads = [
        probe
        for probe in candidate_probes
        if probe.get("http_status") == 200
        and '"code":0' in str(probe.get("body_preview", "")).replace(" ", "")
        and '"data":null' not in str(probe.get("body_preview", "")).replace(" ", "")
    ]
    socketry_has_charging_write = bool(
        socketry_metadata.get("charging_plan_entries")
    )
    tuya_has_schema = bool(tuya_fingerprint.get("has_charging_plan_schema_evidence"))
    non_empty_shapes = response_catalog.get("non_empty_data", [])

    requirements = {
        "switch_state_key": bool(
            switch.get("reported_in_property_snapshots")
            or switch.get("reported_by_socketry")
        ),
        "time_repeat_state_key": bool(
            time_entity.get("reported_in_property_snapshots")
            or time_entity.get("reported_by_socketry")
            or repeat_entity.get("reported_in_property_snapshots")
            or repeat_entity.get("reported_by_socketry")
        ),
        "read_endpoint": bool(successful_candidate_reads or tuya_has_schema),
        "write_path": bool(
            socketry_has_charging_write
            or tuya_fingerprint.get("has_charging_plan_schema_evidence")
        ),
        "payload_shape": bool(
            socketry_has_charging_write
            or tuya_fingerprint.get("charging_plan_hits")
            or successful_candidate_reads
        ),
    }
    missing = [
        name
        for name, found in requirements.items()
        if not found
    ]
    return {
        "ready_to_add_entities": not missing,
        "requirements": requirements,
        "missing": missing,
        "successful_candidate_reads": successful_candidate_reads[:10],
        "non_empty_response_shapes": non_empty_shapes[:10],
        "next_step_if_not_ready": (
            "If any requirement is missing after this release, Home Assistant "
            "diagnostics alone did not expose the charging-plan contract. The "
            "remaining source of truth is an official app HTTPS capture, "
            "APK-derived endpoint/payload, or vendor/Tuya schema access."
        ),
    }


_TUYA_FIELD_LOOKUP = {field.lower(): field for field in TUYA_FINGERPRINT_FIELDS}
_TUYA_SENSITIVE_FIELDS = {
    "devid",
    "devsn",
    "devicecode",
    "devicesn",
    "localkey",
    "sn",
    "uid",
    "uuid",
}


def _path_matches_tuya_endpoint(endpoint: object) -> bool:
    text = str(endpoint).lower()
    return (
        "iot-03" in text
        or "/v1.0/devices/" in text
        or "/v1.1/iot-03/" in text
        or "schema" in text
        or "specification" in text
        or "function" in text
        or text.endswith("/status")
        or "/status/" in text
        or "/dp" in text
        or "/dps" in text
    )


def _find_charging_plan_terms(value: object) -> list[str]:
    text = str(value).lower()
    terms: list[str] = []
    for term in TUYA_CHARGING_PLAN_TERMS:
        term_text = term.lower()
        if term_text in {"107", "108"}:
            if re.search(rf"(?<!\d){term_text}(?!\d)", text):
                terms.append(term)
        elif term_text in text:
            terms.append(term)
    return sorted(terms)


def _preview_tuya_value(field: str, value: Any) -> str:
    if field.replace("_", "").lower() in _TUYA_SENSITIVE_FIELDS:
        return "<redacted>"
    if isinstance(value, (dict, list)):
        return f"<{type(value).__name__}>"
    return _candidate_payload_preview(str(value), 120)


def _tuya_field_hits_from_value(
    value: Any,
    *,
    source: str,
    path: str = "",
) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            key_text = str(key)
            key_path = f"{path}.{key_text}" if path else key_text
            canonical = _TUYA_FIELD_LOOKUP.get(key_text.lower())
            if canonical is not None:
                hits.append(
                    {
                        "source": source,
                        "path": key_path,
                        "field": canonical,
                        "value_preview": _preview_tuya_value(canonical, item),
                    }
                )
            hits.extend(
                _tuya_field_hits_from_value(item, source=source, path=key_path)
            )
    elif isinstance(value, list):
        for index, item in enumerate(value[:100]):
            item_path = f"{path}[{index}]" if path else f"[{index}]"
            hits.extend(
                _tuya_field_hits_from_value(item, source=source, path=item_path)
            )
    return hits


def _charging_plan_hits_from_value(
    value: Any,
    *,
    source: str,
    path: str = "",
) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            key_text = str(key)
            key_path = f"{path}.{key_text}" if path else key_text
            terms = _find_charging_plan_terms(key_text)
            if terms:
                hits.append(
                    {
                        "source": source,
                        "path": key_path,
                        "terms": terms,
                        "value_preview": _preview_tuya_value(key_text, item),
                    }
                )
            hits.extend(
                _charging_plan_hits_from_value(item, source=source, path=key_path)
            )
    elif isinstance(value, list):
        for index, item in enumerate(value[:100]):
            item_path = f"{path}[{index}]" if path else f"[{index}]"
            hits.extend(
                _charging_plan_hits_from_value(item, source=source, path=item_path)
            )
    elif isinstance(value, str):
        terms = _find_charging_plan_terms(value)
        if terms:
            hits.append(
                {
                    "source": source,
                    "path": path or "<value>",
                    "terms": terms,
                    "value_preview": _candidate_payload_preview(value, 160),
                }
            )
    return hits


def build_tuya_fingerprint(
    device: dict[str, Any],
    probes: list[dict[str, Any]],
    property_snapshots: list[dict[str, Any]],
) -> dict[str, Any]:
    """Summarize Tuya-like schema and charging-plan evidence."""
    field_hits: list[dict[str, Any]] = []
    charging_hits: list[dict[str, Any]] = []

    raw = device.get("raw")
    if isinstance(raw, dict):
        field_hits.extend(_tuya_field_hits_from_value(raw, source="device.raw"))
        charging_hits.extend(_charging_plan_hits_from_value(raw, source="device.raw"))

    for snapshot in property_snapshots:
        properties = snapshot.get("properties")
        if isinstance(properties, dict):
            source = f"property_snapshot.{snapshot.get('header_profile')}"
            field_hits.extend(_tuya_field_hits_from_value(properties, source=source))
            charging_hits.extend(
                _charging_plan_hits_from_value(properties, source=source)
            )

    tuya_probe_results: list[dict[str, Any]] = []
    for probe in probes:
        body = str(probe.get("body", ""))
        endpoint = probe.get("endpoint", "")
        parsed = _parse_json(body)
        source = f"probe.{endpoint}"
        if parsed is not None:
            field_hits.extend(_tuya_field_hits_from_value(parsed, source=source))
            charging_hits.extend(_charging_plan_hits_from_value(parsed, source=source))
        else:
            charging_hits.extend(_charging_plan_hits_from_value(body, source=source))

        field_terms_present = any(
            f'"{field}"' in body or field in body for field in TUYA_FINGERPRINT_FIELDS
        )
        charging_terms = _find_charging_plan_terms(body)
        if (
            probe.get("probe_family") == "tuya_path"
            or _path_matches_tuya_endpoint(endpoint)
            or field_terms_present
            or charging_terms
        ):
            tuya_probe_results.append(
                {
                    "method": probe.get("method", "GET"),
                    "endpoint": endpoint,
                    "header_profile": probe.get("header_profile"),
                    "parameter_name": probe.get("parameter_name"),
                    "parameter_value": probe.get("parameter_value"),
                    "http_status": probe.get("http_status"),
                    "body_hash": probe.get("body_hash")
                    or _response_hash(str(probe.get("body", ""))),
                    "interesting": probe.get("interesting"),
                    "field_terms_present": bool(field_terms_present),
                    "charging_plan_terms_present": charging_terms,
                    "body_preview": _candidate_payload_preview(body),
                }
            )

    detected_fields = sorted({hit["field"] for hit in field_hits})
    detected_terms = sorted(
        {
            term
            for hit in charging_hits
            for term in hit.get("terms", [])
        }
    )
    return {
        "has_tuya_schema_evidence": bool(field_hits),
        "has_charging_plan_schema_evidence": bool(charging_hits),
        "detected_fields": detected_fields,
        "detected_charging_plan_terms": detected_terms,
        "field_hits": field_hits[:50],
        "charging_plan_hits": charging_hits[:50],
        "tuya_probe_count": len(tuya_probe_results),
        "tuya_probe_results": tuya_probe_results[:50],
        "diagnosis_hint": (
            "If Tuya fields or charging-plan terms appear here, use the returned "
            "function/status schema to map read keys and command payloads. If this "
            "section is empty, Jackery is not exposing Tuya schema through the "
            "read-only Home Assistant probe path."
        ),
    }


def format_probe_notification(results: dict[str, Any]) -> str:
    """Format probe results for a Home Assistant persistent notification."""
    lines = [
        f"Completed: {results['generated_at']}",
        f"Devices discovered: {len(results.get('devices', []))}",
    ]
    socketry_catalog = results.get("socketry_protocol_catalog", {})
    if socketry_catalog:
        writable_count = len(socketry_catalog.get("writable_settings", []))
        charging_plan_count = len(socketry_catalog.get("charging_plan_entries", []))
        lines.append(
            (
                "Socketry catalog: "
                f"{writable_count} writable setting(s), "
                f"{charging_plan_count} charging-plan candidate(s)"
            )
        )

    previous_diff = results.get("previous_result_diff")
    if previous_diff:
        changed_devices = len(previous_diff.get("property_changes", []))
        lines.append(
            (
                "Previous-run diff: "
                f"{changed_devices} device(s) with property changes"
            )
        )
    mqtt_capture = results.get("socketry_mqtt_capture", {})
    if mqtt_capture:
        if mqtt_capture.get("available"):
            lines.append(
                (
                    "Socketry MQTT capture: "
                    f"{mqtt_capture.get('message_count', 0)} message(s), "
                    f"{len(mqtt_capture.get('candidate_messages', []))} "
                    "charging-plan candidate(s)"
                )
            )
        else:
            lines.append(
                f"Socketry MQTT capture unavailable: {mqtt_capture.get('error')}"
            )

    if results.get("fatal_error"):
        lines.extend(("", f"Probe failed: {results['fatal_error']}"))
        return "\n".join(lines)

    if not results.get("devices"):
        discovery = results.get("discovery", {})
        lines.extend(("", "No devices were discovered for this account."))
        if discovery:
            lines.append(f"Discovery HTTP status: {discovery.get('http_status')}")
            lines.append(
                f"Discovery rows returned: {discovery.get('raw_device_count', 0)}"
            )
            if discovery.get("skipped_devices"):
                lines.append(
                    f"Skipped device rows: {len(discovery['skipped_devices'])}"
                )
                for skipped in discovery["skipped_devices"][:3]:
                    lines.append(
                        "  Skipped row keys: "
                        + ", ".join(sorted(skipped.get("keys", [])))
                    )
            if discovery.get("body"):
                lines.append(
                    f"Discovery response: "
                    f"{_truncate_notification_body(discovery['body'])}"
                )
        return "\n".join(lines)

    for device in results["devices"]:
        lines.extend(
            (
                "",
                (
                    f"Device: {device['name']} "
                    f"(id={device['id']}, sn={device['device_sn']})"
                ),
            )
        )
        for probe in device["probes"]:
            marker = "INTERESTING " if probe["interesting"] else ""
            lines.append(
                (
                    f"- {marker}{probe['endpoint']} via "
                    f"{probe['parameter_name']}={probe['parameter_value']} | "
                    f"HTTP {probe['http_status']}"
                )
            )
            lines.append(f"  {_truncate_notification_body(probe['body'])}")
        snapshots = _successful_property_snapshots(device)
        if snapshots:
            best_snapshot = snapshots[0]
            lines.append(
                (
                    "- Property snapshot: "
                    f"{len(best_snapshot['properties'])} key(s) via "
                    f"{best_snapshot['header_profile']} "
                    f"{best_snapshot['parameter_name']}"
                )
            )
        extended_interesting = _interesting_probe_count(device, "extended_probes")
        if extended_interesting:
            lines.append(
                f"- Extended Android probes: {extended_interesting} interesting response(s)"
            )
            shown = 0
            for probe in device.get("extended_probes", []):
                if not probe.get("interesting"):
                    continue
                lines.append(
                    (
                        f"  INTERESTING {probe['endpoint']} via "
                        f"{probe['parameter_name']}={probe['parameter_value']} | "
                        f"HTTP {probe['http_status']}"
                    )
                )
                shown += 1
                if shown >= 5:
                    break
        post_interesting = _interesting_probe_count(device, "post_read_probes")
        if post_interesting:
            lines.append(
                f"- Read-only POST probes: {post_interesting} interesting response(s)"
            )
        method_interesting = _interesting_probe_count(
            device, "method_discovery_probes"
        )
        if method_interesting:
            lines.append(
                f"- Method discovery: {method_interesting} interesting response(s)"
            )
        analysis = device.get("charging_plan_analysis")
        if analysis:
            expected = analysis.get("main_integration_expected_entities", {})
            switch = expected.get("charging_plan_switch", {})
            data = expected.get("charging_plan_time", {})
            lines.append(
                (
                    "- Charging-plan evidence: "
                    f"107 property={switch.get('reported_in_property_snapshots')}, "
                    f"108 property={data.get('reported_in_property_snapshots')}, "
                    f"candidate probes={analysis.get('candidate_probe_count', 0)}, "
                    f"MQTT candidates={len(analysis.get('mqtt_candidate_messages', []))}"
                )
            )
        tuya_fingerprint = device.get("tuya_fingerprint")
        if tuya_fingerprint:
            lines.append(
                (
                    "- Tuya fingerprint: "
                    f"schema={tuya_fingerprint.get('has_tuya_schema_evidence')}, "
                    "charging-plan schema="
                    f"{tuya_fingerprint.get('has_charging_plan_schema_evidence')}, "
                    f"probe results={tuya_fingerprint.get('tuya_probe_count', 0)}"
                )
            )
        readiness = device.get("implementation_readiness")
        if readiness:
            lines.append(
                (
                    "- Implementation readiness: "
                    f"ready={readiness.get('ready_to_add_entities')}, "
                    f"missing={', '.join(readiness.get('missing', [])) or 'none'}"
                )
            )

    return "\n".join(lines)


class JackeryDiagnosticsClient:
    """Client that performs login, discovery, and endpoint probes."""

    def __init__(self, email: str, password: str, token: str | None = None) -> None:
        self._email = email
        self._password = password
        self._token = token

    @property
    def token(self) -> str | None:
        """Return the current auth token."""
        return self._token

    def login(self) -> str:
        """Authenticate with the Jackery cloud and return a token."""
        request_args = build_login_request(self._email, self._password)
        try:
            response = requests.post(**request_args)
        except requests.RequestException as err:
            raise JackeryConnectionError(f"Login request failed: {err}") from err

        payload = _parse_json(response.text) or {}
        if response.status_code >= 400:
            msg = payload.get("msg") or response.text or f"HTTP {response.status_code}"
            raise JackeryAuthenticationError(msg)

        if payload.get("code") == 0 and payload.get("token"):
            self._token = str(payload["token"])
            return self._token

        msg = payload.get("msg") or "Login failed"
        raise JackeryAuthenticationError(f"{msg} (code: {payload.get('code')})")

    def _get(self, endpoint: str, params: dict[str, Any], *, retry: bool = True):
        if not self._token:
            self.login()

        assert self._token is not None
        try:
            response = requests.get(
                f"{BASE_URL}{endpoint}",
                headers=_build_token_headers(self._token),
                params=params,
                timeout=REQUEST_TIMEOUT,
            )
        except requests.RequestException as err:
            raise JackeryConnectionError(str(err)) from err

        payload = _parse_json(response.text)
        if retry and payload is not None and payload.get("code") == 10402:
            self.login()
            return self._get(endpoint, params, retry=False)

        return response

    def _get_with_header_profile(
        self,
        endpoint: str,
        params: dict[str, Any],
        header_profile: str,
        *,
        retry: bool = True,
    ):
        if not self._token:
            self.login()

        assert self._token is not None
        try:
            response = requests.get(
                f"{BASE_URL}{endpoint}",
                headers=_build_token_headers(self._token, header_profile),
                params=params,
                timeout=REQUEST_TIMEOUT,
            )
        except requests.RequestException as err:
            raise JackeryConnectionError(str(err)) from err

        payload = _parse_json(response.text)
        if retry and payload is not None and payload.get("code") == 10402:
            self.login()
            return self._get_with_header_profile(
                endpoint,
                params,
                header_profile,
                retry=False,
            )

        return response

    def _post_with_header_profile(
        self,
        endpoint: str,
        payload: dict[str, Any],
        header_profile: str,
        body_format: str,
        *,
        retry: bool = True,
    ):
        if not self._token:
            self.login()

        assert self._token is not None
        headers = _build_post_headers(self._token, header_profile, body_format)
        request_kwargs: dict[str, Any] = {
            "headers": headers,
            "timeout": REQUEST_TIMEOUT,
        }
        if body_format == "json":
            request_kwargs["json"] = payload
        else:
            request_kwargs["data"] = payload

        try:
            response = requests.post(
                f"{BASE_URL}{endpoint}",
                **request_kwargs,
            )
        except requests.RequestException as err:
            raise JackeryConnectionError(str(err)) from err

        response_payload = _parse_json(response.text)
        if retry and response_payload is not None and response_payload.get("code") == 10402:
            self.login()
            return self._post_with_header_profile(
                endpoint,
                payload,
                header_profile,
                body_format,
                retry=False,
            )

        return response

    def _request_with_header_profile(
        self,
        method: str,
        endpoint: str,
        header_profile: str,
        *,
        retry: bool = True,
    ):
        if not self._token:
            self.login()

        assert self._token is not None
        try:
            response = requests.request(
                method,
                f"{BASE_URL}{endpoint}",
                headers=_build_token_headers(self._token, header_profile),
                timeout=REQUEST_TIMEOUT,
            )
        except requests.RequestException as err:
            raise JackeryConnectionError(str(err)) from err

        payload = _parse_json(response.text)
        if retry and payload is not None and payload.get("code") == 10402:
            self.login()
            return self._request_with_header_profile(
                method,
                endpoint,
                header_profile,
                retry=False,
            )

        return response

    def discover_devices(self) -> list[dict[str, Any]]:
        """Return the list of bound devices."""
        return self.discover_device_details()["devices"]

    def discover_device_details(self) -> dict[str, Any]:
        """Return parsed devices together with raw discovery metadata."""
        response = self._get(DEVICE_LIST_ENDPOINT, {})
        payload = _parse_json(response.text) or {}
        if response.status_code >= 400:
            raise JackeryConnectionError(
                f"Device discovery failed with HTTP {response.status_code}"
            )

        if payload.get("code") not in (None, 0):
            raise JackeryDiagnosticsError(
                f"Device discovery failed: {payload.get('msg', 'Unknown error')}"
            )

        raw_devices = _extract_devices(payload)
        devices: list[dict[str, Any]] = []
        skipped_devices: list[dict[str, Any]] = []
        for index, device in enumerate(raw_devices):
            device_id = _device_value(device, "id", "devId", "deviceId")
            device_sn = _device_value(device, "deviceSn", "devSn", "sn")
            if device_id is None or not device_sn:
                skipped_devices.append(
                    {
                        "index": index,
                        "keys": list(device.keys()),
                        "raw": device,
                    }
                )
                continue
            devices.append(
                {
                    "id": device_id,
                    "device_sn": str(device_sn),
                    "name": _device_name(device),
                    "raw": device,
                }
            )
        return {
            "devices": devices,
            "http_status": response.status_code,
            "body": response.text,
            "raw_device_count": len(raw_devices),
            "skipped_devices": skipped_devices,
        }

    def _probe_single(
        self,
        device: dict[str, Any],
        endpoint: str,
        parameter_name: str,
        parameter_value: str | int,
    ) -> dict[str, Any]:
        try:
            response = self._get(endpoint, {parameter_name: parameter_value})
            body = response.text
            interesting = is_interesting_response(response.status_code, body)
            result = {
                "endpoint": endpoint,
                "parameter_name": parameter_name,
                "parameter_value": str(parameter_value),
                "http_status": response.status_code,
                "body": body,
                "interesting": interesting,
                "error": False,
            }
            log_method = _LOGGER.warning if interesting else _LOGGER.info
            prefix = "INTERESTING" if interesting else "Probe result"
            log_method(
                "%s for %s via %s=%s on %s: HTTP %s %s",
                prefix,
                device["name"],
                parameter_name,
                parameter_value,
                endpoint,
                response.status_code,
                body,
            )
            return result
        except JackeryDiagnosticsError as err:
            _LOGGER.error(
                "Probe error for %s via %s=%s on %s: %s",
                device["name"],
                parameter_name,
                parameter_value,
                endpoint,
                err,
            )
            return {
                "endpoint": endpoint,
                "parameter_name": parameter_name,
                "parameter_value": str(parameter_value),
                "http_status": "ERROR",
                "body": str(err),
                "interesting": False,
                "error": True,
            }
        except Exception as err:  # pragma: no cover - defensive guard
            _LOGGER.exception(
                "Unexpected probe error for %s via %s=%s on %s",
                device["name"],
                parameter_name,
                parameter_value,
                endpoint,
            )
            return {
                "endpoint": endpoint,
                "parameter_name": parameter_name,
                "parameter_value": str(parameter_value),
                "http_status": "ERROR",
                "body": str(err),
                "interesting": False,
                "error": True,
            }

    def _probe_single_extended(
        self,
        device: dict[str, Any],
        endpoint: str,
        parameter_name: str,
        parameter_value: str | int,
        header_profile: str,
    ) -> dict[str, Any]:
        """Run one extended read-only probe with a named header profile."""
        try:
            response = self._get_with_header_profile(
                endpoint,
                {parameter_name: parameter_value},
                header_profile,
            )
            body = response.text
            interesting = is_interesting_response(response.status_code, body)
            return {
                "method": "GET",
                "endpoint": endpoint,
                "header_profile": header_profile,
                "parameter_name": parameter_name,
                "parameter_value": str(parameter_value),
                "http_status": response.status_code,
                "body": body,
                "body_hash": _response_hash(body),
                "interesting": interesting,
                "error": False,
            }
        except JackeryDiagnosticsError as err:
            return {
                "method": "GET",
                "endpoint": endpoint,
                "header_profile": header_profile,
                "parameter_name": parameter_name,
                "parameter_value": str(parameter_value),
                "http_status": "ERROR",
                "body": str(err),
                "body_hash": _response_hash(str(err)),
                "interesting": False,
                "error": True,
            }
        except Exception as err:  # pragma: no cover - defensive guard
            _LOGGER.exception(
                "Unexpected extended probe error for %s via %s=%s on %s",
                device["name"],
                parameter_name,
                parameter_value,
                endpoint,
            )
            return {
                "method": "GET",
                "endpoint": endpoint,
                "header_profile": header_profile,
                "parameter_name": parameter_name,
                "parameter_value": str(parameter_value),
                "http_status": "ERROR",
                "body": str(err),
                "body_hash": _response_hash(str(err)),
                "interesting": False,
                "error": True,
            }

    def _extended_identifier_values(
        self, device: dict[str, Any]
    ) -> list[tuple[str, str | int]]:
        """Return candidate identifier parameter names for undocumented routes."""
        raw = device.get("raw", {})
        values: dict[str, Any] = {
            "deviceId": device.get("id"),
            "devId": device.get("id"),
            "id": device.get("id"),
            "deviceSn": device.get("device_sn"),
            "devSn": device.get("device_sn"),
            "sn": device.get("device_sn"),
            "deviceCode": _device_value(raw, "deviceCode", "device_code"),
        }
        identifiers: list[tuple[str, str | int]] = []
        for name in EXTENDED_IDENTIFIER_NAMES:
            value = values.get(name)
            if value not in (None, ""):
                identifiers.append((name, value))
        return identifiers

    def _post_identifier_values(
        self, device: dict[str, Any]
    ) -> list[tuple[str, str | int]]:
        """Return identifier payloads for safe read-only POST probes."""
        raw = device.get("raw", {})
        values: dict[str, Any] = {
            "deviceId": device.get("id"),
            "devId": device.get("id"),
            "id": device.get("id"),
            "deviceSn": device.get("device_sn"),
            "devSn": device.get("device_sn"),
            "sn": device.get("device_sn"),
            "deviceCode": _device_value(raw, "deviceCode", "device_code"),
        }
        identifiers: list[tuple[str, str | int]] = []
        for name in READ_ONLY_POST_IDENTIFIER_NAMES:
            value = values.get(name)
            if value not in (None, ""):
                identifiers.append((name, value))
        return identifiers

    def _post_payload_variants(
        self, device: dict[str, Any]
    ) -> list[tuple[str, dict[str, Any], str, str | int]]:
        """Return identifier-only POST bodies for likely mobile screen reads."""
        variants: list[tuple[str, dict[str, Any], str, str | int]] = [
            (name, {name: value}, name, value)
            for name, value in self._post_identifier_values(device)
        ]

        raw = device.get("raw", {})
        device_id = device.get("id")
        device_sn = device.get("device_sn")
        device_code = _device_value(raw, "deviceCode", "device_code")
        if device_id not in (None, "") and device_sn not in (None, ""):
            variants.extend(
                (
                    (
                        "deviceId_deviceSn",
                        {"deviceId": device_id, "deviceSn": device_sn},
                        "combined",
                        "<multiple identifiers>",
                    ),
                    (
                        "devId_devSn",
                        {"devId": device_id, "devSn": device_sn},
                        "combined",
                        "<multiple identifiers>",
                    ),
                    (
                        "id_sn",
                        {"id": device_id, "sn": device_sn},
                        "combined",
                        "<multiple identifiers>",
                    ),
                    (
                        "deviceId_deviceSn_page",
                        {
                            "deviceId": device_id,
                            "deviceSn": device_sn,
                            "pageNo": 1,
                            "pageSize": 20,
                        },
                        "combined",
                        "<multiple identifiers>",
                    ),
                )
            )
        if device_id not in (None, ""):
            variants.append(
                (
                    "deviceId_page",
                    {"deviceId": device_id, "pageNo": 1, "pageSize": 20},
                    "deviceId",
                    device_id,
                )
            )
        if device_code not in (None, "") and device_sn not in (None, ""):
            variants.append(
                (
                    "deviceCode_deviceSn",
                    {"deviceCode": device_code, "deviceSn": device_sn},
                    "combined",
                    "<multiple identifiers>",
                )
            )
        return variants

    def _collect_property_snapshots(
        self, device: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Collect structured property snapshots with iOS and Android headers."""
        snapshots: list[dict[str, Any]] = []
        for header_profile in PROPERTY_SNAPSHOT_PROFILES:
            try:
                response = self._get_with_header_profile(
                    "/v1/device/property",
                    {"deviceId": device["id"]},
                    header_profile,
                )
                body = response.text
                snapshots.append(
                    {
                        "endpoint": "/v1/device/property",
                        "header_profile": header_profile,
                        "parameter_name": "deviceId",
                        "parameter_value": str(device["id"]),
                        "http_status": response.status_code,
                        "body": body,
                        "body_hash": _response_hash(body),
                        "properties": _extract_property_map(body) or {},
                        "error": False,
                    }
                )
            except JackeryDiagnosticsError as err:
                snapshots.append(
                    {
                        "endpoint": "/v1/device/property",
                        "header_profile": header_profile,
                        "parameter_name": "deviceId",
                        "parameter_value": str(device["id"]),
                        "http_status": "ERROR",
                        "body": str(err),
                        "body_hash": _response_hash(str(err)),
                        "properties": {},
                        "error": True,
                    }
                )
        return snapshots

    def _collect_extended_probes(self, device: dict[str, Any]) -> list[dict[str, Any]]:
        """Run Android-header endpoint and identifier probes."""
        probes: list[dict[str, Any]] = []
        identifiers = self._extended_identifier_values(device)
        for endpoint in EXTENDED_PROBE_ENDPOINTS:
            for parameter_name, parameter_value in identifiers:
                probes.append(
                    self._probe_single_extended(
                        device,
                        endpoint,
                        parameter_name,
                        parameter_value,
                        "android_apk_1_0_7",
                    )
                )
        return probes

    def _probe_single_post_read(
        self,
        device: dict[str, Any],
        endpoint: str,
        payload: dict[str, Any],
        parameter_name: str,
        parameter_value: str | int,
        header_profile: str,
        body_format: str,
        payload_variant: str,
    ) -> dict[str, Any]:
        """Run one safe read-only POST probe with a device identifier body."""
        try:
            response = self._post_with_header_profile(
                endpoint,
                payload,
                header_profile,
                body_format,
            )
            body = response.text
            interesting = is_interesting_response(response.status_code, body)
            return {
                "method": "POST",
                "endpoint": endpoint,
                "probe_family": "post_read",
                "header_profile": header_profile,
                "body_format": body_format,
                "payload_variant": payload_variant,
                "parameter_name": parameter_name,
                "parameter_value": str(parameter_value),
                "request_body": dict(payload),
                "request_body_hash": _hash_jsonable(payload),
                "http_status": response.status_code,
                "body": body,
                "body_hash": _response_hash(body),
                "interesting": interesting,
                "error": False,
            }
        except JackeryDiagnosticsError as err:
            return {
                "method": "POST",
                "endpoint": endpoint,
                "probe_family": "post_read",
                "header_profile": header_profile,
                "body_format": body_format,
                "payload_variant": payload_variant,
                "parameter_name": parameter_name,
                "parameter_value": str(parameter_value),
                "request_body": dict(payload),
                "request_body_hash": _hash_jsonable(payload),
                "http_status": "ERROR",
                "body": str(err),
                "body_hash": _response_hash(str(err)),
                "interesting": False,
                "error": True,
            }
        except Exception as err:  # pragma: no cover - defensive guard
            _LOGGER.exception(
                "Unexpected read-only POST probe error for %s via %s=%s on %s",
                device["name"],
                parameter_name,
                parameter_value,
                endpoint,
            )
            return {
                "method": "POST",
                "endpoint": endpoint,
                "probe_family": "post_read",
                "header_profile": header_profile,
                "body_format": body_format,
                "payload_variant": payload_variant,
                "parameter_name": parameter_name,
                "parameter_value": str(parameter_value),
                "request_body": dict(payload),
                "request_body_hash": _hash_jsonable(payload),
                "http_status": "ERROR",
                "body": str(err),
                "body_hash": _response_hash(str(err)),
                "interesting": False,
                "error": True,
            }

    def _collect_post_read_probes(
        self, device: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Probe read-like mobile endpoints that may require POST bodies."""
        probes: list[dict[str, Any]] = []
        payload_variants = self._post_payload_variants(device)
        for endpoint in READ_ONLY_POST_PROBE_ENDPOINTS:
            for payload_variant, payload, parameter_name, parameter_value in payload_variants:
                for body_format in READ_ONLY_POST_BODY_FORMATS:
                    for header_profile in READ_ONLY_POST_HEADER_PROFILES:
                        probes.append(
                            self._probe_single_post_read(
                                device,
                                endpoint,
                                payload,
                                parameter_name,
                                parameter_value,
                                header_profile,
                                body_format,
                                payload_variant,
                            )
                        )
        return probes

    def _probe_method_discovery(
        self,
        device: dict[str, Any],
        endpoint: str,
        method: str,
        header_profile: str,
    ) -> dict[str, Any]:
        """Probe endpoint method availability without a request body."""
        try:
            response = self._request_with_header_profile(
                method,
                endpoint,
                header_profile,
            )
            allow_header = response.headers.get("allow") if response.headers else None
            body = response.text
            interesting = response.status_code not in {404, 405}
            return {
                "method": method,
                "endpoint": endpoint,
                "probe_family": "method_discovery",
                "header_profile": header_profile,
                "http_status": response.status_code,
                "allow": allow_header,
                "body": body,
                "body_hash": _response_hash(body),
                "interesting": interesting,
                "error": False,
            }
        except JackeryDiagnosticsError as err:
            return {
                "method": method,
                "endpoint": endpoint,
                "probe_family": "method_discovery",
                "header_profile": header_profile,
                "http_status": "ERROR",
                "allow": None,
                "body": str(err),
                "body_hash": _response_hash(str(err)),
                "interesting": False,
                "error": True,
            }
        except Exception as err:  # pragma: no cover - defensive guard
            _LOGGER.exception(
                "Unexpected method discovery probe error for %s on %s %s",
                device["name"],
                method,
                endpoint,
            )
            return {
                "method": method,
                "endpoint": endpoint,
                "probe_family": "method_discovery",
                "header_profile": header_profile,
                "http_status": "ERROR",
                "allow": None,
                "body": str(err),
                "body_hash": _response_hash(str(err)),
                "interesting": False,
                "error": True,
            }

    def _collect_method_discovery_probes(
        self, device: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Probe HEAD/OPTIONS availability for likely read endpoints."""
        probes: list[dict[str, Any]] = []
        for endpoint in METHOD_DISCOVERY_ENDPOINTS:
            for method in METHOD_DISCOVERY_METHODS:
                for header_profile in READ_ONLY_POST_HEADER_PROFILES:
                    probes.append(
                        self._probe_method_discovery(
                            device,
                            endpoint,
                            method,
                            header_profile,
                        )
                    )
        return probes

    def _tuya_path_identifier_values(
        self, device: dict[str, Any]
    ) -> dict[str, str | int | None]:
        raw = device.get("raw", {})
        return {
            "device_id": device.get("id"),
            "device_sn": device.get("device_sn"),
            "device_code": _device_value(raw, "deviceCode", "device_code"),
        }

    def _probe_tuya_path(
        self,
        device: dict[str, Any],
        endpoint_template: str,
        identifier_name: str,
        identifier_value: str | int,
    ) -> dict[str, Any]:
        """Run one read-only Tuya-style path probe."""
        rendered_endpoint = endpoint_template.replace(
            "{" + identifier_name + "}",
            quote(str(identifier_value), safe=""),
        )
        try:
            response = self._get_with_header_profile(
                rendered_endpoint,
                {},
                "android_apk_1_0_7",
            )
            body = response.text
            interesting = is_interesting_response(response.status_code, body)
            return {
                "method": "GET",
                "endpoint": endpoint_template,
                "probe_family": "tuya_path",
                "header_profile": "android_apk_1_0_7",
                "parameter_name": identifier_name,
                "parameter_value": str(identifier_value),
                "http_status": response.status_code,
                "body": body,
                "body_hash": _response_hash(body),
                "interesting": interesting,
                "error": False,
            }
        except JackeryDiagnosticsError as err:
            return {
                "method": "GET",
                "endpoint": endpoint_template,
                "probe_family": "tuya_path",
                "header_profile": "android_apk_1_0_7",
                "parameter_name": identifier_name,
                "parameter_value": str(identifier_value),
                "http_status": "ERROR",
                "body": str(err),
                "body_hash": _response_hash(str(err)),
                "interesting": False,
                "error": True,
            }
        except Exception as err:  # pragma: no cover - defensive guard
            _LOGGER.exception(
                "Unexpected Tuya path probe error for %s via %s=%s on %s",
                device["name"],
                identifier_name,
                identifier_value,
                endpoint_template,
            )
            return {
                "method": "GET",
                "endpoint": endpoint_template,
                "probe_family": "tuya_path",
                "header_profile": "android_apk_1_0_7",
                "parameter_name": identifier_name,
                "parameter_value": str(identifier_value),
                "http_status": "ERROR",
                "body": str(err),
                "body_hash": _response_hash(str(err)),
                "interesting": False,
                "error": True,
            }

    def _collect_tuya_path_probes(
        self, device: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Run read-only probes against Tuya OpenAPI-shaped paths."""
        probes: list[dict[str, Any]] = []
        identifier_values = self._tuya_path_identifier_values(device)
        for endpoint in TUYA_PATH_PROBE_ENDPOINTS:
            for identifier_name, identifier_value in identifier_values.items():
                if "{" + identifier_name + "}" not in endpoint:
                    continue
                if identifier_value in (None, ""):
                    continue
                probes.append(
                    self._probe_tuya_path(
                        device,
                        endpoint,
                        identifier_name,
                        identifier_value,
                    )
                )
        return probes

    def _supported_socketry_settings(
        self,
        properties: dict[str, Any],
    ) -> dict[str, Any]:
        """Map reported property keys to Socketry writable setting metadata."""
        catalog = build_socketry_protocol_catalog()
        if not catalog.get("available"):
            return catalog

        settings_by_id = {setting["id"]: setting for setting in catalog["settings"]}
        reported_keys = set(str(key) for key in properties)
        reported_settings = [
            settings_by_id[key]
            for key in sorted(reported_keys)
            if key in settings_by_id
        ]
        reported_writable_settings = [
            setting for setting in reported_settings if setting["writable"]
        ]
        unknown_reported_keys = sorted(reported_keys - set(settings_by_id))
        return {
            "available": True,
            "model_names": catalog["model_names"],
            "reported_settings": reported_settings,
            "reported_writable_settings": reported_writable_settings,
            "unknown_reported_keys": unknown_reported_keys,
            "charging_plan_entries": catalog["charging_plan_entries"],
            "charging_plan_keys_reported": sorted(
                key for key in reported_keys if key in {"107", "108"}
            ),
        }

    async def _async_collect_socketry_mqtt_capture(self) -> dict[str, Any]:
        """Passively listen for device property MQTT messages without writing."""
        if SocketryClient is None:
            return {
                "available": False,
                "error": "socketry is not installed",
                "duration_seconds": MQTT_CAPTURE_SECONDS,
                "messages": [],
            }

        messages: list[dict[str, Any]] = []
        client = await SocketryClient.login(self._email, self._password)
        devices = await client.fetch_devices()
        known_names = {str(device.get("devSn")): device for device in devices}

        async def _capture(device_sn: str, properties: dict[str, Any]) -> None:
            messages.append(
                {
                    "device_sn": device_sn,
                    "device_name": str(
                        known_names.get(device_sn, {}).get("devName", device_sn)
                    ),
                    "keys": sorted(str(key) for key in properties),
                    "properties": dict(properties),
                    "charging_plan_candidate": any(
                        _looks_like_charging_plan_text(key)
                        or _looks_like_charging_plan_text(value)
                        for key, value in properties.items()
                    ),
                }
            )

        subscription = await client.subscribe(_capture)
        try:
            await asyncio.sleep(MQTT_CAPTURE_SECONDS)
        finally:
            await subscription.stop()

        return {
            "available": True,
            "duration_seconds": MQTT_CAPTURE_SECONDS,
            "message_count": len(messages),
            "messages": messages,
            "candidate_messages": [
                message
                for message in messages
                if message.get("charging_plan_candidate")
            ],
        }

    def _collect_socketry_mqtt_capture(self) -> dict[str, Any]:
        """Run the passive MQTT capture in a private event loop."""
        try:
            return asyncio.run(self._async_collect_socketry_mqtt_capture())
        except Exception as err:
            _LOGGER.warning("Socketry MQTT capture failed: %s", err)
            return {
                "available": False,
                "error": str(err),
                "duration_seconds": MQTT_CAPTURE_SECONDS,
                "messages": [],
            }

    def _build_charging_plan_analysis(
        self,
        device: dict[str, Any],
        probes: list[dict[str, Any]],
        property_snapshots: list[dict[str, Any]],
        extended_probes: list[dict[str, Any]],
        post_read_probes: list[dict[str, Any]],
        method_discovery_probes: list[dict[str, Any]],
        tuya_probes: list[dict[str, Any]],
        socketry_metadata: dict[str, Any],
        mqtt_capture: dict[str, Any],
        tuya_fingerprint: dict[str, Any],
    ) -> dict[str, Any]:
        """Summarize evidence for the three charging-plan entities."""
        property_keys_by_profile = {
            snapshot["header_profile"]: sorted(
                str(key) for key in snapshot.get("properties", {})
            )
            for snapshot in property_snapshots
        }
        all_property_keys: set[str] = set()
        for keys in property_keys_by_profile.values():
            all_property_keys.update(keys)

        all_probes = [
            *probes,
            *extended_probes,
            *post_read_probes,
            *method_discovery_probes,
            *tuya_probes,
        ]
        candidate_probes = [
            {
                "method": probe.get("method", "GET"),
                "endpoint": probe.get("endpoint"),
                "header_profile": probe.get("header_profile", "ios_app_1_0_5"),
                "body_format": probe.get("body_format"),
                "parameter_name": probe.get("parameter_name"),
                "parameter_value": probe.get("parameter_value"),
                "request_body_hash": probe.get("request_body_hash"),
                "http_status": probe.get("http_status"),
                "body_hash": probe.get("body_hash")
                or _response_hash(str(probe.get("body", ""))),
                "body_preview": _candidate_payload_preview(
                    str(probe.get("body", ""))
                ),
            }
            for probe in all_probes
            if _looks_like_charging_plan_text(probe.get("endpoint", ""))
            or _looks_like_charging_plan_text(probe.get("body", ""))
        ]

        mqtt_messages = [
            message
            for message in mqtt_capture.get("messages", [])
            if str(message.get("device_sn")) == str(device.get("device_sn"))
        ]
        mqtt_candidate_messages = [
            message
            for message in mqtt_messages
            if message.get("charging_plan_candidate")
        ]
        socketry_charging_entries = socketry_metadata.get(
            "charging_plan_entries", []
        )
        charging_plan_keys_reported = sorted(
            key for key in {"107", "108"} if key in all_property_keys
        )

        return {
            "main_integration_expected_entities": {
                "charging_plan_switch": {
                    "expected_key": "107",
                    "reported_in_property_snapshots": "107" in all_property_keys,
                    "reported_by_socketry": "107"
                    in socketry_metadata.get("charging_plan_keys_reported", []),
                    "socketry_has_writable_setting": any(
                        str(entry.get("id")) == "107"
                        for entry in socketry_charging_entries
                    ),
                },
                "charging_plan_time": {
                    "expected_key": "108",
                    "reported_in_property_snapshots": "108" in all_property_keys,
                    "reported_by_socketry": "108"
                    in socketry_metadata.get("charging_plan_keys_reported", []),
                    "socketry_has_writable_setting": any(
                        str(entry.get("id")) == "108"
                        for entry in socketry_charging_entries
                    ),
                },
                "charging_plan_repeat": {
                    "expected_key": "108",
                    "reported_in_property_snapshots": "108" in all_property_keys,
                    "reported_by_socketry": "108"
                    in socketry_metadata.get("charging_plan_keys_reported", []),
                    "socketry_has_writable_setting": any(
                        str(entry.get("id")) == "108"
                        for entry in socketry_charging_entries
                    ),
                },
            },
            "property_keys_by_profile": property_keys_by_profile,
            "charging_plan_keys_reported": charging_plan_keys_reported,
            "socketry_charging_plan_entries": socketry_charging_entries,
            "candidate_probe_count": len(candidate_probes),
            "candidate_probes": candidate_probes[:25],
            "post_read_probe_count": len(post_read_probes),
            "post_read_interesting_count": _interesting_probe_count(
                {"post_read_probes": post_read_probes}, "post_read_probes"
            ),
            "method_discovery_probe_count": len(method_discovery_probes),
            "method_discovery_interesting_count": _interesting_probe_count(
                {"method_discovery_probes": method_discovery_probes},
                "method_discovery_probes",
            ),
            "mqtt_message_count": len(mqtt_messages),
            "mqtt_candidate_messages": mqtt_candidate_messages[:25],
            "tuya_fingerprint_summary": {
                "has_tuya_schema_evidence": tuya_fingerprint.get(
                    "has_tuya_schema_evidence"
                ),
                "has_charging_plan_schema_evidence": tuya_fingerprint.get(
                    "has_charging_plan_schema_evidence"
                ),
                "detected_fields": tuya_fingerprint.get("detected_fields", []),
                "detected_charging_plan_terms": tuya_fingerprint.get(
                    "detected_charging_plan_terms", []
                ),
                "tuya_probe_count": tuya_fingerprint.get("tuya_probe_count", 0),
            },
            "diagnosis_hint": (
                "If 107 and 108 are false everywhere and Socketry has no "
                "charging-plan entries, the main integration needs a different "
                "endpoint or protocol path for these three entities."
            ),
        }

    def run_probe(self) -> dict[str, Any]:
        """Run discovery and endpoint probing for all devices."""
        generated_at = datetime.now(timezone.utc).isoformat()
        try:
            discovery = self.discover_device_details()
            devices = discovery["devices"]
        except JackeryDiagnosticsError as err:
            _LOGGER.error("Diagnostic probe failed before endpoint scan: %s", err)
            return {
                "generated_at": generated_at,
                "account": self._email,
                "token": self._token,
                "devices": [],
                "discovery": {},
                "fatal_error": str(err),
            }

        device_results: list[dict[str, Any]] = []
        mqtt_capture = self._collect_socketry_mqtt_capture()
        for device in devices:
            probes: list[dict[str, Any]] = []
            for endpoint in PROBE_ENDPOINTS:
                probes.append(
                    self._probe_single(device, endpoint, "deviceId", device["id"])
                )
                probes.append(
                    self._probe_single(
                        device, endpoint, "deviceSn", device["device_sn"]
                    )
                )
            property_snapshots = self._collect_property_snapshots(device)
            snapshot_properties = {}
            for snapshot in property_snapshots:
                if snapshot.get("properties"):
                    snapshot_properties = snapshot["properties"]
                    break
            extended_probes = self._collect_extended_probes(device)
            post_read_probes = self._collect_post_read_probes(device)
            method_discovery_probes = self._collect_method_discovery_probes(device)
            tuya_probes = self._collect_tuya_path_probes(device)
            socketry_metadata = self._supported_socketry_settings(
                snapshot_properties
            )
            all_device_probes = [
                *probes,
                *extended_probes,
                *post_read_probes,
                *method_discovery_probes,
                *tuya_probes,
            ]
            tuya_fingerprint = build_tuya_fingerprint(
                device,
                all_device_probes,
                property_snapshots,
            )
            response_catalog = build_response_catalog(all_device_probes)
            charging_plan_analysis = self._build_charging_plan_analysis(
                device,
                probes,
                property_snapshots,
                extended_probes,
                post_read_probes,
                method_discovery_probes,
                tuya_probes,
                socketry_metadata,
                mqtt_capture,
                tuya_fingerprint,
            )
            implementation_readiness = build_implementation_readiness(
                charging_plan_analysis,
                tuya_fingerprint,
                response_catalog,
                socketry_metadata,
            )

            device_results.append(
                {
                    "id": device["id"],
                    "device_sn": device["device_sn"],
                    "name": device["name"],
                    "raw": device["raw"],
                    "probes": probes,
                    "property_snapshots": property_snapshots,
                    "extended_probes": extended_probes,
                    "post_read_probes": post_read_probes,
                    "method_discovery_probes": method_discovery_probes,
                    "tuya_probes": tuya_probes,
                    "tuya_fingerprint": tuya_fingerprint,
                    "response_catalog": response_catalog,
                    "socketry_device_metadata": socketry_metadata,
                    "charging_plan_analysis": charging_plan_analysis,
                    "implementation_readiness": implementation_readiness,
                }
            )

        return {
            "generated_at": generated_at,
            "account": self._email,
            "token": self._token,
            "devices": device_results,
            "discovery": discovery,
            "capture_guidance": build_capture_guidance(),
            "socketry_protocol_catalog": build_socketry_protocol_catalog(),
            "socketry_mqtt_capture": mqtt_capture,
            "fatal_error": None,
        }


def _device_identity(device: dict[str, Any]) -> str:
    return str(device.get("device_sn") or device.get("id") or device.get("name"))


def _properties_from_result_device(device: dict[str, Any]) -> dict[str, Any]:
    for snapshot in device.get("property_snapshots", []):
        properties = snapshot.get("properties")
        if isinstance(properties, dict) and properties:
            return properties

    for probe in device.get("probes", []):
        if (
            probe.get("endpoint") == "/v1/device/property"
            and probe.get("parameter_name") == "deviceId"
        ):
            properties = _extract_property_map(str(probe.get("body", "")))
            if properties:
                return properties
    return {}


def compare_probe_results(
    previous: dict[str, Any] | None,
    current: dict[str, Any],
) -> dict[str, Any] | None:
    """Compare current diagnostics with the previous saved run."""
    if not previous or previous.get("fatal_error"):
        return None

    previous_devices = {
        _device_identity(device): device for device in previous.get("devices", [])
    }
    property_changes: list[dict[str, Any]] = []
    for current_device in current.get("devices", []):
        identity = _device_identity(current_device)
        previous_device = previous_devices.get(identity)
        if previous_device is None:
            continue

        previous_properties = _properties_from_result_device(previous_device)
        current_properties = _properties_from_result_device(current_device)
        if not previous_properties and not current_properties:
            continue

        previous_keys = set(previous_properties)
        current_keys = set(current_properties)
        changed = {
            key: {
                "before": previous_properties.get(key),
                "after": current_properties.get(key),
            }
            for key in sorted(previous_keys & current_keys)
            if previous_properties.get(key) != current_properties.get(key)
        }
        added = {
            key: current_properties[key] for key in sorted(current_keys - previous_keys)
        }
        removed = {
            key: previous_properties[key]
            for key in sorted(previous_keys - current_keys)
        }
        if changed or added or removed:
            property_changes.append(
                {
                    "device": current_device.get("name"),
                    "device_id": str(current_device.get("id")),
                    "device_sn": str(current_device.get("device_sn")),
                    "added": added,
                    "removed": removed,
                    "changed": changed,
                }
            )

    return {
        "previous_generated_at": previous.get("generated_at"),
        "current_generated_at": current.get("generated_at"),
        "property_changes": property_changes,
    }


def run_diagnostic_probe(
    email: str, password: str, token: str | None = None
) -> dict[str, Any]:
    """Run the full Jackery diagnostics probe synchronously."""
    return JackeryDiagnosticsClient(email, password, token).run_probe()

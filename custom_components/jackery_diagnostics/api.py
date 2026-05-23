"""Synchronous API helpers for Jackery Diagnostics."""

from __future__ import annotations

import base64
import hashlib
import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

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
    MQTT_CAPTURE_SECONDS,
    PROPERTY_SNAPSHOT_PROFILES,
    PROBE_ENDPOINTS,
    REQUEST_TIMEOUT,
    RSA_PUBLIC_KEY,
)

try:
    from socketry import Client as SocketryClient
    from socketry.properties import MODEL_NAMES, PROPERTIES
except ModuleNotFoundError as err:  # pragma: no cover - optional runtime dependency
    if err.name in {"socketry", "aiohttp", "aiomqtt", "Crypto"}:
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
            "This diagnostic integration performs read-only HTTP GET probes and "
            "does not publish MQTT commands or send setting writes."
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
        socketry_metadata: dict[str, Any],
        mqtt_capture: dict[str, Any],
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

        all_probes = [*probes, *extended_probes]
        candidate_probes = [
            {
                "endpoint": probe.get("endpoint"),
                "header_profile": probe.get("header_profile", "ios_app_1_0_5"),
                "parameter_name": probe.get("parameter_name"),
                "parameter_value": probe.get("parameter_value"),
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
            "mqtt_message_count": len(mqtt_messages),
            "mqtt_candidate_messages": mqtt_candidate_messages[:25],
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
            socketry_metadata = self._supported_socketry_settings(
                snapshot_properties
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
                    "socketry_device_metadata": socketry_metadata,
                    "charging_plan_analysis": self._build_charging_plan_analysis(
                        device,
                        probes,
                        property_snapshots,
                        extended_probes,
                        socketry_metadata,
                        mqtt_capture,
                    ),
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

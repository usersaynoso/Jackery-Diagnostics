"""Synchronous API helpers for Jackery Diagnostics."""

from __future__ import annotations

import base64
import hashlib
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
    FIXED_MAC_ID_SEED,
    LOGIN_ENDPOINT,
    PROBE_ENDPOINTS,
    REQUEST_TIMEOUT,
    RSA_PUBLIC_KEY,
)

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


def _build_token_headers(token: str) -> dict[str, str]:
    headers = dict(AUTH_HEADERS)
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


def _device_name(device: dict[str, Any]) -> str:
    return str(
        device.get("deviceName")
        or device.get("name")
        or device.get("alias")
        or device.get("deviceSn")
        or device.get("id")
        or "Unknown device"
    )


def _truncate_notification_body(body: str, limit: int = 500) -> str:
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

    if results.get("fatal_error"):
        lines.extend(("", f"Probe failed: {results['fatal_error']}"))
        return "\n".join(lines)

    if not results.get("devices"):
        lines.extend(("", "No devices were discovered for this account."))
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

    def discover_devices(self) -> list[dict[str, Any]]:
        """Return the list of bound devices."""
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

        devices: list[dict[str, Any]] = []
        for device in _extract_devices(payload):
            device_id = device.get("id")
            device_sn = device.get("deviceSn")
            if device_id is None or not device_sn:
                continue
            devices.append(
                {
                    "id": device_id,
                    "device_sn": str(device_sn),
                    "name": _device_name(device),
                    "raw": device,
                }
            )
        return devices

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

    def run_probe(self) -> dict[str, Any]:
        """Run discovery and endpoint probing for all devices."""
        generated_at = datetime.now(timezone.utc).isoformat()
        try:
            devices = self.discover_devices()
        except JackeryDiagnosticsError as err:
            _LOGGER.error("Diagnostic probe failed before endpoint scan: %s", err)
            return {
                "generated_at": generated_at,
                "account": self._email,
                "token": self._token,
                "devices": [],
                "fatal_error": str(err),
            }

        device_results: list[dict[str, Any]] = []
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

            device_results.append(
                {
                    "id": device["id"],
                    "device_sn": device["device_sn"],
                    "name": device["name"],
                    "raw": device["raw"],
                    "probes": probes,
                }
            )

        return {
            "generated_at": generated_at,
            "account": self._email,
            "token": self._token,
            "devices": device_results,
            "fatal_error": None,
        }


def run_diagnostic_probe(
    email: str, password: str, token: str | None = None
) -> dict[str, Any]:
    """Run the full Jackery diagnostics probe synchronously."""
    return JackeryDiagnosticsClient(email, password, token).run_probe()

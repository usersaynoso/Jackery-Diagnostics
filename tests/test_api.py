"""Tests for Jackery Diagnostics API helpers."""

from __future__ import annotations

import base64
import json
import sys
import types
import unittest
from unittest.mock import Mock, patch

from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad

homeassistant = types.ModuleType("homeassistant")
homeassistant.__path__ = []
config_entries_mod = types.ModuleType("homeassistant.config_entries")
core_mod = types.ModuleType("homeassistant.core")
config_entries_mod.ConfigEntry = object
core_mod.HomeAssistant = object
sys.modules.setdefault("homeassistant", homeassistant)
sys.modules.setdefault("homeassistant.config_entries", config_entries_mod)
sys.modules.setdefault("homeassistant.core", core_mod)

from custom_components.jackery_diagnostics.api import (
    JackeryAuthenticationError,
    JackeryConnectionError,
    JackeryDiagnosticsClient,
    build_tuya_fingerprint,
    build_login_payload,
    compare_probe_results,
    encrypt_login_payload,
    format_probe_notification,
    generate_mac_id,
    is_interesting_response,
)
from custom_components.jackery_diagnostics.const import (
    AES_KEY,
    EXTENDED_IDENTIFIER_NAMES,
    EXTENDED_PROBE_ENDPOINTS,
    PROPERTY_SNAPSHOT_PROFILES,
    PROBE_ENDPOINTS,
    READ_ONLY_POST_BODY_FORMATS,
    READ_ONLY_POST_IDENTIFIER_NAMES,
    READ_ONLY_POST_PROBE_ENDPOINTS,
    TUYA_PATH_PROBE_ENDPOINTS,
)


def _read_only_probe_count(*, has_device_code: bool = False) -> int:
    """Return the number of GET responses needed after discovery."""
    legacy_count = len(PROBE_ENDPOINTS) * 2
    snapshot_count = len(PROPERTY_SNAPSHOT_PROFILES)
    identifier_count = len(EXTENDED_IDENTIFIER_NAMES)
    if not has_device_code:
        identifier_count -= 1
    tuya_path_count = len(TUYA_PATH_PROBE_ENDPOINTS) - 1
    if has_device_code:
        tuya_path_count += 1
    return (
        legacy_count
        + snapshot_count
        + (len(EXTENDED_PROBE_ENDPOINTS) * identifier_count)
        + tuya_path_count
    )


def _read_only_post_count(*, has_device_code: bool = False) -> int:
    """Return the number of read-only POST probe responses needed after login."""
    identifier_count = len(READ_ONLY_POST_IDENTIFIER_NAMES)
    if not has_device_code:
        identifier_count -= 1
    return (
        len(READ_ONLY_POST_PROBE_ENDPOINTS)
        * identifier_count
        * len(READ_ONLY_POST_BODY_FORMATS)
    )


class GenerateMacIdTests(unittest.TestCase):
    """Validate the fixed macId generation."""

    def test_generate_mac_id_matches_expected_reverse_engineered_value(self) -> None:
        self.assertEqual(generate_mac_id(), "2a24fa0ca7d6a371ebc78abe936eb0834")

    def test_login_payload_contains_expected_fields(self) -> None:
        payload = build_login_payload("dev@example.com", "secret")
        self.assertEqual(payload["account"], "dev@example.com")
        self.assertEqual(payload["password"], "secret")
        self.assertEqual(payload["registerAppId"], "com.hbxn.jackery")
        self.assertEqual(payload["macId"], generate_mac_id())

    def test_encrypt_login_payload_round_trips_aes_body(self) -> None:
        payload = build_login_payload("dev@example.com", "secret")
        encrypted_body, encrypted_key = encrypt_login_payload(payload)

        cipher = AES.new(AES_KEY, AES.MODE_ECB)
        decrypted = unpad(
            cipher.decrypt(base64.b64decode(encrypted_body)),
            AES.block_size,
        ).decode("utf-8")

        self.assertEqual(json.loads(decrypted), payload)
        self.assertTrue(encrypted_key)


class LoginAndProbeTests(unittest.TestCase):
    """Validate request building and probe execution."""

    @patch("custom_components.jackery_diagnostics.api.requests.post")
    def test_login_uses_multipart_request_shape(self, mock_post: Mock) -> None:
        mock_post.return_value = Mock(status_code=200, text='{"code":0,"token":"abc"}')

        client = JackeryDiagnosticsClient("dev@example.com", "secret")
        token = client.login()

        self.assertEqual(token, "abc")
        _, kwargs = mock_post.call_args
        self.assertEqual(kwargs["url"], "https://iot.jackeryapp.com/v1/auth/login")
        self.assertIn("aesEncryptData", kwargs["params"])
        self.assertIn("rsaForAesKey", kwargs["params"])
        self.assertEqual(kwargs["headers"]["accept-language"], "ja-JP")
        self.assertIn("file", kwargs["files"])
        self.assertEqual(kwargs["files"]["file"][0], "")

    @patch("custom_components.jackery_diagnostics.api.requests.post")
    def test_login_raises_auth_error_on_bad_code(self, mock_post: Mock) -> None:
        mock_post.return_value = Mock(
            status_code=200,
            text='{"code":401,"msg":"bad credentials"}',
        )

        with self.assertRaises(JackeryAuthenticationError):
            JackeryDiagnosticsClient("dev@example.com", "secret").login()

    @patch("custom_components.jackery_diagnostics.api.requests.get")
    @patch("custom_components.jackery_diagnostics.api.requests.post")
    def test_run_probe_scans_every_endpoint_for_both_identifiers(
        self, mock_post: Mock, mock_get: Mock
    ) -> None:
        mock_post.side_effect = [
            Mock(status_code=200, text='{"code":0,"token":"abc"}'),
            *[
                Mock(status_code=404, text='{"code":404,"msg":"not found"}')
                for _ in range(_read_only_post_count())
            ],
        ]
        mock_get.side_effect = [
            Mock(
                status_code=200,
                text=(
                    '{"code":0,"data":[{"id":123,"deviceSn":"SN123",'
                    '"deviceName":"Explorer 1000"}]}'
                ),
            ),
            *[
                Mock(status_code=404, text='{"code":404,"msg":"not found"}')
                for _ in range(_read_only_probe_count())
            ],
        ]

        with patch("custom_components.jackery_diagnostics.api.SocketryClient", None):
            result = JackeryDiagnosticsClient("dev@example.com", "secret").run_probe()

        self.assertIsNone(result["fatal_error"])
        self.assertEqual(len(result["devices"]), 1)
        self.assertEqual(len(result["devices"][0]["probes"]), len(PROBE_ENDPOINTS) * 2)
        self.assertEqual(
            len(result["devices"][0]["property_snapshots"]),
            len(PROPERTY_SNAPSHOT_PROFILES),
        )
        self.assertEqual(
            len(result["devices"][0]["extended_probes"]),
            len(EXTENDED_PROBE_ENDPOINTS) * (len(EXTENDED_IDENTIFIER_NAMES) - 1),
        )
        self.assertEqual(
            len(result["devices"][0]["post_read_probes"]),
            _read_only_post_count(),
        )
        post_probe = result["devices"][0]["post_read_probes"][0]
        self.assertEqual(post_probe["method"], "POST")
        self.assertEqual(post_probe["probe_family"], "post_read")
        self.assertEqual(post_probe["request_body"], {"deviceId": 123})
        self.assertIn(post_probe["body_format"], READ_ONLY_POST_BODY_FORMATS)
        self.assertEqual(
            len(result["devices"][0]["tuya_probes"]),
            len(TUYA_PATH_PROBE_ENDPOINTS) - 1,
        )
        self.assertIn("tuya_fingerprint", result["devices"][0])
        self.assertIn("charging_plan_analysis", result["devices"][0])
        self.assertFalse(result["socketry_mqtt_capture"]["available"])
        probe_call_params = [call.kwargs["params"] for call in mock_get.call_args_list[1:]]
        self.assertIn({"deviceId": 123}, probe_call_params)
        self.assertIn({"deviceSn": "SN123"}, probe_call_params)

    @patch("custom_components.jackery_diagnostics.api.requests.get")
    @patch("custom_components.jackery_diagnostics.api.requests.post")
    def test_run_probe_accepts_jackery_app_device_keys(
        self, mock_post: Mock, mock_get: Mock
    ) -> None:
        mock_post.side_effect = [
            Mock(status_code=200, text='{"code":0,"token":"abc"}'),
            *[
                Mock(status_code=404, text='{"code":404,"msg":"not found"}')
                for _ in range(_read_only_post_count())
            ],
        ]
        mock_get.side_effect = [
            Mock(
                status_code=200,
                text=(
                    '{"code":0,"data":[{"devId":456,"devSn":"DEV456",'
                    '"devName":"Explorer 2000 Plus"}]}'
                ),
            ),
            *[
                Mock(status_code=404, text='{"code":404,"msg":"not found"}')
                for _ in range(_read_only_probe_count())
            ],
        ]

        with patch("custom_components.jackery_diagnostics.api.SocketryClient", None):
            result = JackeryDiagnosticsClient("dev@example.com", "secret").run_probe()

        self.assertEqual(result["devices"][0]["id"], 456)
        self.assertEqual(result["devices"][0]["device_sn"], "DEV456")
        self.assertEqual(result["devices"][0]["name"], "Explorer 2000 Plus")

    @patch("custom_components.jackery_diagnostics.api.requests.get")
    @patch("custom_components.jackery_diagnostics.api.requests.post")
    def test_run_probe_records_request_errors_without_crashing(
        self, mock_post: Mock, mock_get: Mock
    ) -> None:
        mock_post.side_effect = [
            Mock(status_code=200, text='{"code":0,"token":"abc"}'),
            *[
                Mock(status_code=404, text='{"code":404}')
                for _ in range(_read_only_post_count())
            ],
        ]
        mock_get.side_effect = [
            Mock(
                status_code=200,
                text='{"code":0,"data":[{"id":123,"deviceSn":"SN123","name":"Unit"}]}',
            ),
            JackeryConnectionError("timed out"),
            *[
                Mock(status_code=404, text='{"code":404}')
                for _ in range(_read_only_probe_count() - 1)
            ],
        ]

        with patch("custom_components.jackery_diagnostics.api.SocketryClient", None):
            result = JackeryDiagnosticsClient("dev@example.com", "secret").run_probe()

        self.assertEqual(result["devices"][0]["probes"][0]["http_status"], "ERROR")
        self.assertEqual(result["devices"][0]["probes"][0]["body"], "timed out")

    def test_interesting_response_detection_matches_spec(self) -> None:
        self.assertTrue(is_interesting_response(200, '{"code":0}'))
        self.assertFalse(is_interesting_response(404, '{"code":0}'))
        self.assertFalse(is_interesting_response(200, '{"code":404}'))
        self.assertFalse(is_interesting_response(200, '{"code": 404}'))

    def test_notification_format_marks_interesting_results(self) -> None:
        notification = format_probe_notification(
            {
                "generated_at": "2026-04-20T10:00:00+00:00",
                "fatal_error": None,
                "discovery": {},
                "devices": [
                    {
                        "name": "Explorer 1000",
                        "id": 123,
                        "device_sn": "SN123",
                        "probes": [
                            {
                                "endpoint": "/v1/device/workingMode",
                                "parameter_name": "deviceId",
                                "parameter_value": "123",
                                "http_status": 200,
                                "body": '{"code":0,"data":{"mode":"custom"}}',
                                "interesting": True,
                            }
                        ],
                    }
                ],
            }
        )

        self.assertIn("INTERESTING /v1/device/workingMode", notification)
        self.assertIn("Explorer 1000", notification)

    def test_tuya_fingerprint_detects_schema_and_charging_plan_terms(self) -> None:
        fingerprint = build_tuya_fingerprint(
            {
                "raw": {
                    "productKey": "pk123",
                    "devId": "device-123",
                }
            },
            [
                {
                    "method": "GET",
                    "endpoint": "/v1.1/iot-03/devices/{device_id}/specification",
                    "probe_family": "tuya_path",
                    "header_profile": "android_apk_1_0_7",
                    "parameter_name": "device_id",
                    "parameter_value": "device-123",
                    "http_status": 200,
                    "body": json.dumps(
                        {
                            "success": True,
                            "result": {
                                "functions": [
                                    {
                                        "code": "charge_plan",
                                        "type": "Raw",
                                        "values": "{}",
                                    }
                                ],
                                "status": [
                                    {
                                        "code": "dp107",
                                        "type": "Boolean",
                                        "values": "{}",
                                    }
                                ],
                            },
                        }
                    ),
                    "body_hash": "abc",
                    "interesting": True,
                }
            ],
            [],
        )

        self.assertTrue(fingerprint["has_tuya_schema_evidence"])
        self.assertTrue(fingerprint["has_charging_plan_schema_evidence"])
        self.assertIn("productKey", fingerprint["detected_fields"])
        self.assertIn("functions", fingerprint["detected_fields"])
        self.assertIn("charge_plan", fingerprint["detected_charging_plan_terms"])
        self.assertIn("107", fingerprint["detected_charging_plan_terms"])
        dev_id_hit = next(
            hit for hit in fingerprint["field_hits"] if hit["field"] == "devId"
        )
        self.assertEqual(dev_id_hit["value_preview"], "<redacted>")

    def test_notification_includes_discovery_diagnostics_when_no_devices(self) -> None:
        notification = format_probe_notification(
            {
                "generated_at": "2026-04-20T10:00:00+00:00",
                "fatal_error": None,
                "devices": [],
                "discovery": {
                    "http_status": 200,
                    "body": '{"code":0,"data":[{"foo":"bar"}]}',
                    "raw_device_count": 1,
                    "skipped_devices": [
                        {"keys": ["foo"], "raw": {"foo": "bar"}, "index": 0}
                    ],
                },
            }
        )

        self.assertIn("No devices were discovered for this account.", notification)
        self.assertIn("Discovery HTTP status: 200", notification)
        self.assertIn("Skipped device rows: 1", notification)
        self.assertIn("Discovery response:", notification)

    def test_compare_probe_results_reports_property_changes(self) -> None:
        previous = {
            "generated_at": "2026-04-20T10:00:00+00:00",
            "fatal_error": None,
            "devices": [
                {
                    "id": 123,
                    "device_sn": "SN123",
                    "name": "Explorer 5000 Plus",
                    "property_snapshots": [
                        {"properties": {"oac": 0, "rb": 97, "old": 1}}
                    ],
                }
            ],
        }
        current = {
            "generated_at": "2026-04-20T10:05:00+00:00",
            "fatal_error": None,
            "devices": [
                {
                    "id": 123,
                    "device_sn": "SN123",
                    "name": "Explorer 5000 Plus",
                    "property_snapshots": [
                        {"properties": {"oac": 1, "rb": 97, "new": 2}}
                    ],
                }
            ],
        }

        diff = compare_probe_results(previous, current)

        assert diff is not None
        self.assertEqual(diff["previous_generated_at"], previous["generated_at"])
        self.assertEqual(len(diff["property_changes"]), 1)
        change = diff["property_changes"][0]
        self.assertEqual(change["changed"], {"oac": {"before": 0, "after": 1}})
        self.assertEqual(change["added"], {"new": 2})
        self.assertEqual(change["removed"], {"old": 1})


if __name__ == "__main__":
    unittest.main()

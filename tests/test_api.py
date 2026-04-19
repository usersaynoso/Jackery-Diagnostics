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
    build_login_payload,
    encrypt_login_payload,
    format_probe_notification,
    generate_mac_id,
    is_interesting_response,
)
from custom_components.jackery_diagnostics.const import AES_KEY, PROBE_ENDPOINTS


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
        mock_post.return_value = Mock(status_code=200, text='{"code":0,"token":"abc"}')
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
                for _ in range(len(PROBE_ENDPOINTS) * 2)
            ],
        ]

        result = JackeryDiagnosticsClient("dev@example.com", "secret").run_probe()

        self.assertIsNone(result["fatal_error"])
        self.assertEqual(len(result["devices"]), 1)
        self.assertEqual(len(result["devices"][0]["probes"]), len(PROBE_ENDPOINTS) * 2)
        probe_call_params = [call.kwargs["params"] for call in mock_get.call_args_list[1:]]
        self.assertIn({"deviceId": 123}, probe_call_params)
        self.assertIn({"deviceSn": "SN123"}, probe_call_params)

    @patch("custom_components.jackery_diagnostics.api.requests.get")
    @patch("custom_components.jackery_diagnostics.api.requests.post")
    def test_run_probe_records_request_errors_without_crashing(
        self, mock_post: Mock, mock_get: Mock
    ) -> None:
        mock_post.return_value = Mock(status_code=200, text='{"code":0,"token":"abc"}')
        mock_get.side_effect = [
            Mock(
                status_code=200,
                text='{"code":0,"data":[{"id":123,"deviceSn":"SN123","name":"Unit"}]}',
            ),
            JackeryConnectionError("timed out"),
            *[
                Mock(status_code=404, text='{"code":404}')
                for _ in range((len(PROBE_ENDPOINTS) * 2) - 1)
            ],
        ]

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


if __name__ == "__main__":
    unittest.main()

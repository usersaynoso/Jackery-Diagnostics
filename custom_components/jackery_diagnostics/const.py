"""Constants for the Jackery Diagnostics integration."""

from __future__ import annotations

from pathlib import Path

DOMAIN = "jackery_diagnostics"
BASE_URL = "https://iot.jackeryapp.com"
LOGIN_ENDPOINT = "/v1/auth/login"
DEVICE_LIST_ENDPOINT = "/v1/device/bind/list"
RESULTS_PATH = Path("/config/jackery_diagnostics_results.json")
NOTIFICATION_ID = "jackery_diagnostics_results"
NOTIFICATION_TITLE = "Jackery Diagnostics Results"
REQUEST_TIMEOUT = 15
AES_KEY = b"1234567890123456"
RSA_PUBLIC_KEY = (
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCVmzgJy/4XolxPnkfu32YtJqYGFLYq"
    "f9/rnVgURJED+8J9J3Pccd6+9L97/+7COZE5OkejsgOkqeLNC9C3r5mhpE4zk/HStss7"
    "Q8/5DqkGD1annQ+eoICo3oi0dITZ0Qll56Dowb8lXi6WHViVDdih/oeUwVJY89uJNtTW"
    "rz7t7QIDAQAB"
)
FIXED_MAC_ID_SEED = "abcd1234567890ef"
AUTH_HEADERS = {
    "app_version": "1.0.5",
    "sys_version": "17.2",
    "platform": "1",
    "User-Agent": (
        "DxPowerProject/1.0.5 (com.hb.jackery; build:2; iOS 17.2.0) Alamofire/5.8.0"
    ),
    "model": "iPad Pro (12.9-inch) (3rd generation)",
    "accept-language": "ja-JP",
}
PROBE_ENDPOINTS = (
    "/v1/device/property",
    "/v1/device/setting",
    "/v1/device/settings",
    "/v1/device/workingMode",
    "/v1/device/working_mode",
    "/v1/device/chargePlan",
    "/v1/device/charge_plan",
    "/v1/device/schedule",
    "/v1/device/timePlan",
    "/v1/device/time_plan",
    "/v1/device/mode",
    "/v1/device/config",
    "/v2/device/property",
    "/v2/device/setting",
    "/v2/device/settings",
    "/v2/device/workingMode",
    "/v2/device/working_mode",
    "/v2/device/chargePlan",
    "/v2/device/charge_plan",
    "/v2/device/schedule",
    "/v2/device/timePlan",
    "/v2/device/time_plan",
    "/v2/device/mode",
    "/v2/device/config",
)

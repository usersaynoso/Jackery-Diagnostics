# Jackery Diagnostics

`jackery_diagnostics` is a standalone Home Assistant custom integration for probing undocumented Jackery cloud API endpoints. It is intended for developers who want to discover the charging plan and working mode API surface without depending on any other Jackery integration.

The integration:

- logs in to the Jackery cloud with the same encrypted auth flow used by the mobile app
- discovers devices bound to the account
- probes a fixed list of undocumented endpoints with both `deviceId` and `deviceSn`
- probes an extended set of charging-plan candidates with Android APK-style headers
- captures structured `/v1/device/property` snapshots
- passively listens to Socketry MQTT property updates for 30 seconds without sending commands
- compares the current snapshot with the previous saved run, so testers can run it before and after changing a charging plan in the official Jackery app
- includes Socketry's reverse-engineered writable setting catalog and maps it to the properties reported by each device
- writes a per-device `charging_plan_analysis` summary for the missing `Charging Plan`, `Charging Plan Time`, and `Charging Plan Repeat` entities
- flags non-404 responses as interesting
- writes the full results to `/config/jackery_diagnostics_results.json`
- creates a persistent Home Assistant notification with a readable summary

## Install

1. Open HACS.
2. Go to `Integrations`.
3. Open the menu in the top right and choose `Custom repositories`.
4. Add `https://github.com/usersaynoso/Jackery-Diagnostics` as an `Integration` repository.
5. Install `Jackery Diagnostics`.
6. Restart Home Assistant.

## Configure

1. Open `Settings > Devices & Services > Integrations`.
2. Add `Jackery Diagnostics`.
3. Enter the same email address and password you use in the Jackery mobile app.
4. Wait about 30 seconds for the probe to finish.
5. Open Home Assistant notifications to review the results.

The credentials are used only to authenticate with the Jackery cloud and run the diagnostic probe.

## Output

- Persistent notification in Home Assistant with readable per-endpoint results
- Full untruncated JSON output at `/config/jackery_diagnostics_results.json`
- `property_snapshots` per device for before/after comparisons
- `previous_result_diff` after the second and later runs
- `socketry_protocol_catalog` with known writable property IDs, action IDs, value labels, and MQTT command payload shape
- `socketry_mqtt_capture` with passive property messages observed during the diagnostic window
- `charging_plan_analysis` per device, including direct evidence for keys `107` and `108`
- `capture_guidance` explaining what still requires a separate mobile-app HTTPS capture

## Before/after charging-plan workflow

1. Run this diagnostics integration once and keep `/config/jackery_diagnostics_results.json`.
2. Open the official Jackery app and create, edit, enable, or disable a charging plan.
3. Reload the Jackery Diagnostics integration or restart Home Assistant so the probe runs again.
4. Check `previous_result_diff` in the new JSON file for changed, added, or removed property keys.

Home Assistant cannot capture HTTPS requests made by the official Jackery mobile app on a separate phone. To provide the actual official app request, capture the phone's Jackery app traffic with a trusted local proxy and redact tokens, account details, and serial numbers before sharing.

## Notes

- This repository is independent of every other Jackery integration.
- It has no external services beyond the Jackery cloud API.
- Runtime dependencies: `pycryptodomex`, `socketry`

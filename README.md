# Jackery Diagnostics

`jackery_diagnostics` is a standalone Home Assistant custom integration for probing undocumented Jackery cloud API endpoints. It is intended for developers who want to discover the charging plan and working mode API surface without depending on any other Jackery integration.

The integration:

- logs in to the Jackery cloud with the same encrypted auth flow used by the mobile app
- discovers devices bound to the account
- probes a fixed list of undocumented endpoints with both `deviceId` and `deviceSn`
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

## Notes

- This repository is independent of every other Jackery integration.
- It has no external services beyond the Jackery cloud API.
- Runtime dependency: `pycryptodomex`

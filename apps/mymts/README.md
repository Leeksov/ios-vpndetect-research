[🇷🇺 Русская версия](README.ru.md)

# Мой МТС (MyMTS)

| Field | Value |
|---|---|
| Display name | Мой МТС |
| Bundle ID | `ru.mts.mymts` |
| CFBundleExecutable | `MtsServiceRu` |
| Version | — (binary without Info.plist) |
| Min iOS | — |
| Architectures | arm64 |
| Binary size | 32 MB |

## Paths

- Binary: [`../../MtsServiceRu`](../../MtsServiceRu)
- IDA database: `MtsServiceRu.i64` (alongside: `.id0`/`.id1`/`.id2`/`.nam`/`.til`)
- IPA: _none_ — the repo only has the extracted executable, no .app bundle.

## Notes

- Main Swift module: `MtsServiceRu`.
- Shared frameworks: `MyMtsKit`, `GeoWidgetSDK`, `SPMProxy`.
- Third-party analytics: AppsFlyer, AppMetrica (Yandex), OpenTelemetry.
- Swift code leans heavily on `NWPathMonitor` / `Combine` pipelines (`CurrentValueSubject`) — most of the network-state reactive flow goes through `GeoWidgetSDK`.
- UI snackbars and feature gates tie into Swift protocols `MyMtsKit.VpnDetectorListener` and `MyMtsKit.FeedbackMessageVpnDetectorListener`.
- Feature flags implemented via `*ConditionParam` classes in `MtsServiceRu` (e.g. `VpnEnabledConditionParam`, `MtsAnalyticsExperimentsConditionParam`).
- No obfuscation; Swift metadata is readable, Obj-C selectors are not hidden.

## Topics analysed

| Topic | File |
|---|---|
| VPN / Proxy detection | [vpn-detection.md](vpn-detection.md) |

## Related tweaks

- [`tweaks/VPNHide/`](../../tweaks/VPNHide/) — hides VPN from the app.

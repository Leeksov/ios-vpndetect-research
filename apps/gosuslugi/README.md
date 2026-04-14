[🇷🇺 Русская версия](README.ru.md)

# Gosuslugi (Госуслуги)

| Field | Value |
|---|---|
| Display name | Gosuslugi |
| Bundle ID | `com.minsvyaz.gosuslugi` |
| CFBundleExecutable | `Gosuslugi` |
| Version | 25.3.0 |
| Min iOS | 14.0 |
| Architectures | arm64 |
| Binary size | 131 MB |

## Paths

- IPA: `/Users/leeksov/Downloads/AyuGram Desktop/_Госуслуги_v25.3.0-AppAssassin.ipa`
- .app: `/Users/leeksov/Downloads/AyuGram Desktop/_extracted/Госуслуги/Payload/Gosuslugi.app/`
- Binary: `/Users/leeksov/Downloads/AyuGram Desktop/_extracted/Госуслуги/Payload/Gosuslugi.app/Gosuslugi`

## Notes

- Dual-framework implementation: `GUNetwork.VPNCheckService` + a standalone `VPNCheckService` module (with DI `VPNCheckAssembly`, `VPNCheckServiceStrings`, `VPNSnackbarMessage`).
- `vpnProtocolsKeysIdentifiers` — a list of VPN-interface substrings, **externally supplied** (remote-config / plist / DI). Unique among the analysed apps.
- Tri-state analytics `^(vpn_on)|(vpn_off)|(vpn_unknown)$`.
- Developer-only debug flag `debugDoNotShowVPNSnackbar`.

## Topics analysed

| Topic | File |
|---|---|
| VPN / Proxy detection | [vpn-detection.md](vpn-detection.md) |

## Related tweaks

- [`tweaks/VPNHide/`](../../tweaks/VPNHide/) — covers all 5 detectors (incl. per-URL `CFNetworkCopyProxiesForURL`). `com.minsvyaz.gosuslugi` is already in `Filter.plist`.

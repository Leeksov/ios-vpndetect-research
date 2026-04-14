[🇷🇺 Русская версия](README.ru.md)

# Rostic's (formerly KFC Russia)

| Field | Value |
|---|---|
| Display name | Rostic's |
| Bundle ID | `ru.yum.KFC-Russia` |
| CFBundleExecutable | `kfc` |
| Version | 10.29.0 |
| Min iOS | 16.0 |
| Architectures | arm64 |
| Binary size | 65 MB |

## Paths

- IPA: `/Users/leeksov/Downloads/AyuGram Desktop/_Rostic's__Еда_доставка,_акции_v10_29_0_AppAssassin.ipa`
- .app: `/Users/leeksov/Downloads/AyuGram Desktop/_extracted/rostics/Payload/kfc.app/`
- Binary: `/Users/leeksov/Downloads/AyuGram Desktop/_extracted/rostics/Payload/kfc.app/kfc`

Bundle ID and executable name are legacy from the KFC era (`ru.yum.KFC-Russia` / `kfc`) — the rebrand to Rostic's happened only at UI level.

## Topics analysed

| Topic | File |
|---|---|
| VPN / Proxy detection | [vpn-detection.md](vpn-detection.md) |

## Related tweaks

- [`tweaks/VPNHide/`](../../tweaks/VPNHide/) — covers Rostic's (a single AppsFlyer-style detector). Add `ru.yum.KFC-Russia` to `Filter.plist`.

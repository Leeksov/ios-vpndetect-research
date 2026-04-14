[🇷🇺 Русская версия](README.ru.md)

# Вкусно — и точка (Vkusno — i Tochka, formerly McDonald's Russia)

| Field | Value |
|---|---|
| Display name | Вкусно— и точка |
| Bundle ID | `com.mcdonaldsru.mcd` |
| CFBundleExecutable | `mcd-ios` |
| Version | 13.2.0 |
| Min iOS | 15.6 |
| Architectures | arm64 |
| Binary size | 54 MB |

## Paths

- IPA: `/Users/leeksov/Downloads/AyuGram Desktop/_Вкусно — и точка_v13.2.0-AppAssassin.ipa`
- .app: `/Users/leeksov/Downloads/AyuGram Desktop/_extracted/vkusno-i-tochka/Payload/mcd-ios.app/`
- Binary: `/Users/leeksov/Downloads/AyuGram Desktop/_extracted/vkusno-i-tochka/Payload/mcd-ios.app/mcd-ios`

Bundle ID and executable name are legacy from the McDonald's era (`com.mcdonaldsru.mcd` / `mcd-ios`) — the rebrand was UI-only.

## Topics analysed

| Topic | File |
|---|---|
| VPN / Proxy detection | [vpn-detection.md](vpn-detection.md) |

## Related tweaks

- [`tweaks/VPNHide/`](../../tweaks/VPNHide/) — covers Vkusno-i-Tochka (single Swift checker, no AppsFlyer duplicate). Add `com.mcdonaldsru.mcd` to `Filter.plist`.

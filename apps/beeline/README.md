[🇷🇺 Русская версия](README.ru.md)

# билайн (My Beeline)

| Field | Value |
|---|---|
| Display name | билайн |
| Bundle ID | `ru.beeline.mobile` |
| CFBundleExecutable | `MyBeeline` |
| Version | 5.36.0 |
| Min iOS | 16.0 |
| Architectures | arm64 |
| Binary size | 100 MB |

## Paths

- IPA: `/Users/leeksov/Downloads/AyuGram Desktop/_билайн_v5.36.0-AppAssassin.ipa`
- .app: `/Users/leeksov/Downloads/AyuGram Desktop/_extracted/билайн/Payload/MyBeeline.app/`
- Binary: `/Users/leeksov/Downloads/AyuGram Desktop/_extracted/билайн/Payload/MyBeeline.app/MyBeeline`

## Notes

- VPN detector is factored into a dedicated Swift framework `MBVpnDetector` with DI architecture (`ProxySettingsProvider` protocol + `SystemProxySettingsProvider` impl).
- VPN-pattern list is a Swift property `vpnProtocols`, probably remote-configurable (by symmetry with Gosuslugi).
- UI banner is gated by a remote feature-flag (description «Регулирует предупреждение об активном VPN» @ `0x104338e00`).
- Debug comments with ticket IDs leaked into the binary (`PRFL-9677: Добавить уведомление о включенном VPN`).

## Topics analysed

| Topic | File |
|---|---|
| VPN / Proxy detection | [vpn-detection.md](vpn-detection.md) |

## Related tweaks

- [`tweaks/VPNHide/`](../../tweaks/VPNHide/) — covers MyBeeline detection. Add `ru.beeline.mobile` to `Filter.plist` to activate.

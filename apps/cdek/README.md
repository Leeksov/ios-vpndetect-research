[🇷🇺 Русская версия](README.ru.md)

# CDEK

| Field | Value |
|---|---|
| Display name | CDEK |
| Bundle ID | `com.cdek.cdekapp` |
| CFBundleExecutable | `CDEK` |
| Version | 5.9.0 |
| Min iOS | 15.1 |
| Architectures | arm64 |
| Binary size | 17 MB |

## Paths

- IPA: `/Users/leeksov/Downloads/AyuGram Desktop/_CDEK_v5.9.0-AppAssassin.ipa`
- .app: `/Users/leeksov/Downloads/AyuGram Desktop/_extracted/CDEK/Payload/CDEK.app/`
- Binary: `/Users/leeksov/Downloads/AyuGram Desktop/_extracted/CDEK/Payload/CDEK.app/CDEK`

## Notes

- React Native app (reanimated, margelo/nitro, worklets, RNSVG).
- Native side — Swift + Obj-C (AppsFlyer SDK, Sentry, Mindbox, Firebase GoogleUtilities).
- VPN detection implemented as an RN native module: CocoaPods package `VpnDetect` (`_TtC9VpnDetect15VpnDetectModule`, JS API `isVpnConnected`).

## Topics analysed

| Topic | File |
|---|---|
| VPN / Proxy detection | [vpn-detection.md](vpn-detection.md) |

## Related tweaks

- [`tweaks/VPNHide/`](../../tweaks/VPNHide/) — covers CDEK detection. Add `com.cdek.cdekapp` to `Filter.plist`.

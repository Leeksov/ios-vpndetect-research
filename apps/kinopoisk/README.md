[🇷🇺 Русская версия](README.ru.md)

# Кинопоиск (Kinopoisk)

| Field | Value |
|---|---|
| Display name | Кинопоиск |
| Bundle ID | `ru.kinopoisk` |
| CFBundleExecutable | `Kinopoisk` |
| Version | 8.41.3 |
| Min iOS | 17.0 |
| Architectures | arm64 |
| Binary size | 165 MB |

## Paths

- IPA: `/Users/leeksov/Downloads/AyuGram Desktop/_Кинопоиск_v8.41.3-AppAssassin.ipa`
- .app: `/Users/leeksov/Downloads/AyuGram Desktop/_extracted/kinopoisk/Payload/Kinopoisk.app/`
- Binary: `/Users/leeksov/Downloads/AyuGram Desktop/_extracted/kinopoisk/Payload/Kinopoisk.app/Kinopoisk`

## Notes

- **3 local VPN detectors + server-side `/tmgrdfrend/checkvpn`** (third analysed app with server-check, after 2GIS and Amediateka).
- Reuses **two shared SDKs** with other analysed apps:
  - `MobileAdsCore.MACVpnStatusCheckerImpl` (shared with **Amediateka**)
  - Yandex AppLib `YAL*` (shared with **Yandex Market**)
- **`YALVPNConnect*`** — Yandex's own **anti-blocking proxy** (NOT a user-VPN detector), used to route region-restricted content. A full Obj-C subsystem (`YALVPNConnectManager`, `YALVPNConfig`, `YALVPNConfigApp`, `YALVPNConnectProductLocation`).
- Full-screen blocker UI with 6 analytics events (`vpn_blocker_show/hide/reload/close/settings/openurl`).
- Feature-flag `ios_block_vpn` for a server-side kill switch.
- UI text: «У вас включен VPN или в вашей стране доступен не весь каталог Кинопоиска» — Kinopoisk deliberately conflates VPN with region-availability in its messaging.

## Topics analysed

| Topic | File |
|---|---|
| VPN / Proxy detection | [vpn-detection.md](vpn-detection.md) |

## Related tweaks

- [`tweaks/VPNHide/`](../../tweaks/VPNHide/) — covers the 3 local detectors; server-side `/checkvpn` likely won't fire once local triggers are silenced. Add `ru.kinopoisk` to `Filter.plist`.

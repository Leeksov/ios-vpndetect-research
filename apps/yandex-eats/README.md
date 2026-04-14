[🇷🇺 Русская версия](README.ru.md)

# Яндекс Еда (Yandex Eats)

| Field | Value |
|---|---|
| Display name | YandexEats |
| Bundle ID | `com.appkode.foodfox` |
| CFBundleExecutable | `YandexEats` |
| Version | 8.102.1 |
| Min iOS | 16.0 |
| Architectures | arm64 |
| Binary size | 221 MB |

## Paths

- IPA: `/Users/leeksov/Downloads/AyuGram Desktop/_Yandex Eats_v8.102.1-AppAssassin.ipa`
- .app: `/Users/leeksov/Downloads/AyuGram Desktop/_extracted/yandex-eats/Payload/YandexEats.app/`
- Binary: `/Users/leeksov/Downloads/AyuGram Desktop/_extracted/yandex-eats/Payload/YandexEats.app/YandexEats`

Bundle ID — `com.appkode.foodfox` (AppKode is the original developer, FoodFox is the project name pre-acquisition by Yandex).

## Notes

- 3 local VPN detectors, **no** AppsFlyer SDK and **no** `MobileAdsCore`.
- The main Swift checker lives in **`YXFintechFoundation`** — Yandex's shared fintech foundation (likely shared across Yandex Market, Yandex Taxi, Yandex Delivery and others). Unique placement of the detector — at the payments-infrastructure layer, not general networking.
- `EatsSDKExperiments.VPNCheckConfig` — Codable struct used for remote-config (toggle the detector via A/B).
- 3 analytics events: `VpnBlockingInit`, `VpnBlockingShowen` (sic, `Showen` typo), `VpnBlockingUpdated`.
- Uses Yandex AppLib `YAL` (shared with Yandex Market and Kinopoisk).

## Topics analysed

| Topic | File |
|---|---|
| VPN / Proxy detection | [vpn-detection.md](vpn-detection.md) |

## Related tweaks

- [`tweaks/VPNHide/`](../../tweaks/VPNHide/) — covers all 3 detectors (`__SCOPED__` is wiped). Add `com.appkode.foodfox` to `Filter.plist`.

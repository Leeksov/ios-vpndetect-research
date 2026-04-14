[🇷🇺 Русская версия](README.ru.md)

# Яндекс Маркет (Yandex Market)

| Field | Value |
|---|---|
| Display name | Маркет |
| Bundle ID | `ru.yandex.blue.market` |
| CFBundleExecutable | `Beru` |
| Version | 2026.11.1 |
| Min iOS | 15.0 |
| Architectures | arm64 |
| Binary size | 139 MB |

## Paths

- IPA: `/Users/leeksov/Downloads/AyuGram Desktop/_Яндекс Маркет_v2026.11.1-AppAssassin.ipa`
- .app: `/Users/leeksov/Downloads/AyuGram Desktop/_extracted/Яндекс Маркет/Payload/Beru.app/`
- Binary: `/Users/leeksov/Downloads/AyuGram Desktop/_extracted/Яндекс Маркет/Payload/Beru.app/Beru`

CFBundleExecutable is `Beru` — legacy from the previous brand "Беру.ру" (pre-Yandex acquisition).

## Notes

- No AppsFlyer SDK (no `+[AppsFlyerUtils isVPNConnected]`). Custom implementations only.
- Two duplicate VPN detectors: Obj-C `-[YALAFHTTPClient isVPNConnected]` (Yandex AppLib) and Swift `MarketProtocols.VPNCheckerServiceImpl`.
- Unique reversed-substring semantics in the Obj-C detector: `[needle containsString:iface]` (needle contains iface), not the other way around.
- DI property `vpnCheckerService` (same pattern as Gosuslugi / Beeline / 2GIS / Amediateka).

## Topics analysed

| Topic | File |
|---|---|
| VPN / Proxy detection | [vpn-detection.md](vpn-detection.md) |

## Related tweaks

- [`tweaks/VPNHide/`](../../tweaks/VPNHide/) — covers both detectors (`__SCOPED__` is wiped → empty allKeys). Add `ru.yandex.blue.market` to `Filter.plist`.

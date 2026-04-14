[🇷🇺 Русская версия](README.ru.md)

# Amediateka

| Field | Value |
|---|---|
| Display name | Amediateka |
| Bundle ID | `com.spbtv.ag.tv.Amedia` |
| CFBundleExecutable | `Amediateka` |
| Version | 4.54.0 |
| Min iOS | 15.0 |
| Architectures | arm64 |
| Binary size | 55 MB |

## Paths

- IPA: `/Users/leeksov/Downloads/AyuGram Desktop/_Amediateka — сер…_v4.54.0-AppAssassin.ipa`
- .app: `/Users/leeksov/Downloads/AyuGram Desktop/_extracted/amediateka/Payload/Amediateka.app/`
- Binary: `/Users/leeksov/Downloads/AyuGram Desktop/_extracted/amediateka/Payload/Amediateka.app/Amediateka`

## Notes

- VPN detector lives in a **shared SDK `MobileAdsCore`** (SPB TV common framework); the main app wires it in via DI (`vpnStatusChecker`).
- Tri-state result `0/1/2` (no/yes/unknown) — same pattern as Gosuslugi.
- **Server-side check**: backend returns HTTP 403 + `code: "Vpn"`, parsed as Swift error `ShortApiError403Vpn`.
- Geo-blocking infrastructure is separate (`{{WAS_GEOBLOCKED}}`, `isGeoBlocked`).

## Topics analysed

| Topic | File |
|---|---|
| VPN / Proxy detection | [vpn-detection.md](vpn-detection.md) |

## Related tweaks

- [`tweaks/VPNHide/`](../../tweaks/VPNHide/) — covers the client-side path; server-side `403 Vpn` remains (not critical — content is licensed RU-only anyway). Add `com.spbtv.ag.tv.Amedia` to `Filter.plist`.

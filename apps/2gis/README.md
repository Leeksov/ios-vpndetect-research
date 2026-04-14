[🇷🇺 Русская версия](README.ru.md)

# 2GIS

| Field | Value |
|---|---|
| Display name | 2GIS |
| Bundle ID | `ru.doublegis.grymmobile` |
| CFBundleExecutable | `ru.doublegis.grymmobile` |
| Version | 7.21.7 |
| Min iOS | 16.0 |
| Architectures | arm64 |
| Binary size | 183 MB |

## Paths

- IPA: `/Users/leeksov/Downloads/AyuGram Desktop/_2GIS_v7.21.7-AppAssassin.ipa`
- .app: `/Users/leeksov/Downloads/AyuGram Desktop/_extracted/2GIS/Payload/ru.doublegis.grymmobile.app/`
- Binary: `/Users/leeksov/Downloads/AyuGram Desktop/_extracted/2GIS/Payload/ru.doublegis.grymmobile.app/ru.doublegis.grymmobile`

## Notes

- Architecture with 4 dedicated VPN-detection frameworks: `VNVPNCheckerAPI`, `VNVPNCheckerAPIInterfaces`, `VNVPNCheckerUI`, `VNCarPlay`.
- **Server-side** check via `/v1/vpn-detection-free` (HTTP 451 = blocked).
- Full-screen UI block via a dedicated `UIWindow` (`VPNBlockedWindow`), plus a separate CarPlay overlay with route-preservation.
- `String.hasPrefix` (not `contains`) + `lowercased()` — stricter than most.
- Jenkins CI debug paths leaked into the release binary: `/Users/user/jenkins/agent/workspace/release-v4ios/...`.

## Topics analysed

| Topic | File |
|---|---|
| VPN / Proxy detection | [vpn-detection.md](vpn-detection.md) |

## Related tweaks

- [`tweaks/VPNHide/`](../../tweaks/VPNHide/) — covers the 3 local detectors; server-side check won't fire on its own if the local triggers are silenced. Add `ru.doublegis.grymmobile` to `Filter.plist` to activate.

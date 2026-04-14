[🇷🇺 Русская версия](vpn-detection.ru.md)

# Amediateka — VPN / proxy detection

**Binary:** `Amediateka` v4.54.0 (arm64, Swift + Obj-C)
**Method:** IDA Pro / Hex-Rays.
**Bypass:** [`tweaks/VPNHide`](../../tweaks/VPNHide/) — current tweak covers the local part; server-side is bypassed **indirectly** (if the local scanner doesn't find VPN — streaming won't hit the `403 Vpn` code, or it will hit it independently of client IP).

---

## TL;DR

A streaming service → VPN detection matters for DRM / geo-blocks. Implemented in two layers:

| # | Layer | Mechanism | Address |
|---|---|---|---|
| 1 | AppsFlyer SDK (Obj-C) | `+[AppsFlyerUtils isVPNConnected]` — `__SCOPED__` → `tap/tun/ipsec/ppp` | `0x100E77BA0` |
| 2 | `MobileAdsCore.MACVpnStatusCheckerImpl` (Swift) | `__SCOPED__.allKeys` → `String.contains(needle)` over a configurable array; **tri-state** `0/1/2` (no/yes/unknown) | `0x102497218` |
| 3 | **Server-side** | API response maps to Swift error `ShortApiError403Vpn` (HTTP 403 + `code: "Vpn"`); UI shows «vpnContentPlaybackError» | `sub_100416D34` (error resolver) |

`MACVpnStatusChecker` lives in a **standalone framework `MobileAdsCore`** — SPB TV's SDK (Amediateka's publisher), most likely reused across their other apps.

`nw_path_uses_interface_type` is imported but **not for VPN** — single-pass `.cellular` reachability in `sub_100E3E03C` + `nw_path_monitor_cancel`.

**Imports:**

| Symbol | Status | Context |
|---|---|---|
| `_CFNetworkCopySystemProxySettings` | ✅ | AppsFlyer + MACVpnStatusCheckerImpl |
| `_nw_path_uses_interface_type` | ✅ | reachability (cellular only), not VPN |
| `_getifaddrs` | ❌ | **not imported** |
| `_nw_interface_get_type` / `_CFNetworkCopyProxiesForURL` / `_SCDynamicStoreCopyProxies` / `_DNSServiceQueryRecord` | ❌ | — |

---

## Detector #1 — AppsFlyer

Stock `+[AppsFlyerUtils isVPNConnected]` — `tap/tun/ipsec/ppp`. Controlled by `AppsFlyerVPNCollectionEnabled` (`0x10292d85b`).

---

## Detector #2 — `MACVpnStatusCheckerImpl.check`

Swift class in the `MobileAdsCore` framework:

| Symbol | Address |
|---|---|
| Type metadata | `$s13MobileAdsCore23MACVpnStatusCheckerImplCMa` @ `0x1024977b4` |
| Class name | `_TtC13MobileAdsCore23MACVpnStatusCheckerImpl` @ `0x1029aa630` |
| Protocol | `$s13MobileAdsCore19MACVpnStatusCheckerP` @ `0x102aa9320` |

Pseudocode of `sub_102497218`:

```swift
func check() -> Int {            // 0 = no VPN, 1 = VPN, 2 = unknown
    guard let settings = CFNetworkCopySystemProxySettings() else { return 2 }
    guard let dict     = settings as? [String: Any] else { return 2 }
    guard let scoped   = dict["__SCOPED__"] as? [String: Any] else { return 2 }

    let needles: [String] = self.configuredNeedles    // *(self+16) — instance property
    for iface in scoped.keys {
        for needle in needles {
            if iface.contains(needle) { return 1 }
        }
    }
    return 0
}
```

### Notable details

1. **Tri-state** (`0`/`1`/`2`) — same as Gosuslugi (`vpn_on`/`vpn_off`/`vpn_unknown`). Distinguishes "no VPN found" from "couldn't determine".
2. **External substring array** — stored in an instance field, not hardcoded. Likely configured via DI/init or pulled from remote-config (like Gosuslugi and Beeline).
3. **Part of a separate framework** `MobileAdsCore` — shared across SPB TV apps.

---

## Detector #3 — server-side `ShortApiError403Vpn`

`sub_100416D34` — error resolver, maps an API error code to a localised StringResource:

```
a1 == 0 → fallback / generic
a1 == 1 → "Account.Unauthorized Error"
a1 == 2 → "Errors.ShortApiError403Vpn"
```

So the backend can return HTTP 403 with marker `"Vpn"`, parsed by Swift into an enum case → resolver returns the string `Errors.ShortApiError403Vpn` → UI shows the alert.

Related strings in the same group:

| Key | Address |
|---|---|
| `vpnError.title` | `0x1028ac340` |
| `vpnError.message` | `0x1028ac400` |
| `vpnContentPlaybackError.message` | `0x1028ac320` |
| `vpnErrorKidsControl` | `0x102acad20` |
| `statusRequestingVpnError` | `0x102ad1230` |
| `{{WAS_GEOBLOCKED}}` | `0x1028ef550` (template placeholder for already-geo-blocked content) |
| `isGeoBlocked` | `0x1028f4551`, `0x102ad7071` (Bool property) |

Geo-block and VPN-block are conceptually separated: `WAS_GEOBLOCKED` is a flag that the content was **historically** unavailable in the user's region; `vpnError.*` is the alert at the moment of blocking due to VPN.

---

## UI and reactive pipeline

- `_TtC10Amediateka31VpnStreamingAlertRefreshHandler` (`0x1028bd170`) — handler for the «refresh» button in the VPN error alert. Source: `Amediateka/VpnStreamingAlertRefreshHandler.swift` (`0x1028bd1c0`).
- `vpnStatusChecker` (`0x1029aa2f0`, `0x102b086d0`) — DI injection of MACVpnStatusCheckerImpl
- `vpnConnectedTransformer` (`0x1029b2b10`, `0x102b0dab0`) — Combine/RxSwift Transformer mapping VPN status to UI state.
- `showVpnStreamingErrorAlert` (`0x102abb8c0`) — selector that triggers the alert.
- `VpnCodingKeys` (`0x1027a69b8`) — Swift Codable for VPN-related JSON (backend fields).

---

## Bypass via the existing `VPNHide` tweak

The `CFNetworkCopySystemProxySettings` hook:
- ✅ Strips VPN keys from `__SCOPED__` → AppsFlyer (`+isVPNConnected`) and `MACVpnStatusCheckerImpl.check()` both return `false` / `0`.
- Tri-state logic: returns `0` (no VPN), not `2` (unknown) — the dictionary is itself valid, just without VPN keys.

The server-side check (`HTTP 403 + "Vpn"`) is **not bypassed directly**, but:
- If your VPN provider exits from a **Russian** IP (which Amediateka requires anyway — content is RU-only) — the server returns 200, no error.
- If exiting from abroad — the server returns `403 Vpn` regardless of our hooks. That can only be caught by URLSession-response substitution (a separate swizzle), but Amediateka content isn't legally licensed outside RU — there's no point bypassing.

To activate, add to [`tweaks/VPNHide/Filter.plist`](../../tweaks/VPNHide/Filter.plist):

```
{ Filter = { Bundles = ( …, "com.spbtv.ag.tv.Amedia" ); }; }
```

---

## Comparison

| | MyMTS | MF | CDEK | DNS | CPPK | Urent | Gos | Bln | 2GIS | Nlg | Rst | V&T | **Amediateka** |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Local | 2 | 1 | 2 | 1 | 1 | 3 | 5 | 2 | 3 | 0 | 1 | 1 | **2** |
| Server-side | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ HTTP 451 | — | ❌ | ❌ | ✅ HTTP 403 + `Vpn` |
| Tri-state (on/off/unknown) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | — | ❌ | ❌ | ✅ |
| Geo-block infra separate | — | — | — | — | — | — | — | — | — | — | — | — | ✅ `{{WAS_GEOBLOCKED}}` |
| External pattern array | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ | — | ❌ | ❌ | ✅ |
| From shared SDK of another company | — | — | — | — | — | — | — | — | — | — | — | — | ✅ `MobileAdsCore` (SPB TV) |
| VPNHide coverage | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ (local) | n/a | ✅ | ✅ | ✅ (local) |

Amediateka is the **second app of 12** with server-side detection (after 2GIS), but uses HTTP 403 with a code field instead of HTTP 451. Unique trait — the detector lives **in someone else's SDK** (`MobileAdsCore` — SPB TV common SDK), and the main app only subscribes to its signals via `vpnStatusChecker` DI injection.

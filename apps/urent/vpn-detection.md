[🇷🇺 Русская версия](vpn-detection.ru.md)

# Urent — VPN / proxy detection

**Binary:** `Urent` v1.94.1 (arm64, Swift + Obj-C)
**Method:** IDA Pro / Hex-Rays.
**Bypass:** [`tweaks/VPNHide`](../../tweaks/VPNHide/) — current tweak covers it; just add `ru.urentbike.app` to [`Filter.plist`](../../tweaks/VPNHide/Filter.plist).

---

## TL;DR

Three detectors **with identical core** — `CFNetworkCopySystemProxySettings` → `__SCOPED__` → substring match against interface names. All three live in different places and duplicate each other:

| # | Where | Entry | Address |
|---|---|---|---|
| 1 | AppsFlyer SDK (Obj-C) | `+[AppsFlyerUtils isVPNConnected]` | `0x102040318` |
| 2 | Main app (Swift) | `sub_100550134` | `0x100550134` |
| 3 | `Services.framework.VpnCheckerService` (Swift) | `sub_101AB5BD0` | `0x101AB5BD0` |

Only #3 is the "production" detector, with all UI and the Combine pipeline tied to it: `VpnCheckerService` publishes a `Bool` via `vpnStatusSubject`, observers (`VpnChecherManagableObserver`) react. #1 is the stock AppsFlyer SDK logic. #2 is a duplicate, possibly a legacy check left over from refactoring.

`NWPathMonitor` is **not used** for VPN — `_nw_path_uses_interface_type` isn't imported at all. `_getifaddrs` is imported but only called from `-[GMSCellularInfo supportsData]` (GoogleMaps SDK) and one other cellular helper — not VPN.

The source path baked into one of the functions (debug string `0x1029d7740`) reveals the architecture:

```
/Users/user/builds/_csHvbAg/1/urent-mobile/urentbike-ios/
    Classes/BusinessLogicLayer/Services/Services/Source/Legacy/
    Services/Services/VpnCheckerService/OldVPNIsWorkedView.swift
```

Everything lives in the `Services` submodule as value types observed via `Combine.CurrentValueSubject`.

---

## Detector #1 — AppsFlyer

`+[AppsFlyerUtils isVPNConnected]` @ `0x102040318`. Byte-for-byte copy of the MyMTS/CDEK implementation: substrings `tap/tun/ipsec/ppp`. Uses Obj-C `rangeOfString:`. SDK flag: `AppsFlyerVPNCollectionEnabled` (string `0x1029fe005`).

No direct UI effect — affects only AppsFlyer telemetry.

---

## Detector #2 — Swift (legacy / main app) — `sub_100550134`

Swift function in the main app binary. Same scheme, implemented via `NSDictionary → [String: Any]` bridge + `StringProtocol.contains<A>`. Substrings:

| Literal | Bytes | ASCII |
|---|---|---|
| `7364980` | `74 61 70 00` | `tap` |
| `7239028` | `74 75 6E 00` | `tun` |
| `7368816` | `70 70 70 00` | `ppp` |
| `0x6365_7370_69` | `69 70 73 65 63` | `ipsec` |

No `utun` here — same "minor" 4-substring set as in AppsFlyer.

---

## Detector #3 — `Services.VpnCheckerService` (the main one) — `sub_101AB5BD0`

The most developed of the three. Substrings are kept as a stack array (5 entries), then iterated in a nested loop:

```
inited + 32  = 7364980,         0xE300000000000000   // "tap"
inited + 48  = 7239028,         0xE300000000000000   // "tun"
inited + 64  = 7368816,         0xE300000000000000   // "ppp"
inited + 80  = 0x6365737069,    0xE500000000000000   // "ipsec"
inited + 96  = 1853191285,      0xE400000000000000   // "utun"
```

Loop:

```swift
for iface in (settings["__SCOPED__"] as? [String: Any])?.keys ?? [] {
    for needle in ["tap", "tun", "ppp", "ipsec", "utun"] {
        if iface.contains(needle) { return true }
    }
}
return false
```

Swift class: `_TtC8Services17VpnCheckerService` (`0x1029d7840`). Metadata accessor: `$s8Services17VpnCheckerServiceCMa` @ `0x101ab5654`.

### Reactive pipeline

VpnCheckerService exposes several properties / methods:
- `vpnStatusSubject` (`0x1029d7870`) — `CurrentValueSubject<Bool, Never>` carrying the current state
- `vpnViewIsClosed` (`0x1029d788f`) — flag «user closed the panel manually»
- `setViewVpn()` / `removeVPNView()` / `closeVPNWorkedView()` (strings `0x1029d78b0`, `0x1029d78f0`, `0x1029d7800`)

Protocol and observers:
- `VpnChecherServiceManagable` (`$s8Services26VpnChecherServiceManagableP` @ `0x102b9493c`)
- `VpnChecherManagableObserver` (`$s8Services27VpnChecherManagableObserverP` @ `0x102b94966`)

Wrapped as `Observable<VpnChecherManagableObserver>` — classic reactive pattern.

---

## UI reaction

Set of views to surface the warning:

| View | Where |
|---|---|
| `OldVPNIsWorkedView` (`0x1029d7710`) | Legacy, old snackbar. |
| `VPNIsWorkedView` (`0x102c4e681`) | New snackbar. |
| `BottomVpnView` (`0x102bdf5dc`) | Bottom bar/sheet. |

Selectors / API:
- `turnOnVPN` / `turnOffVPN` (`0x10300b822`, `0x10300b82c`) — UI pipeline «show/hide the bar».
- `subscribeVPNStatus`
- `changeVpnVisibility`
- `closeVPNView` / `closeVpnView` / `_showVpnView`
- `isHiddenVPNView` / `_isHiddenVPNView` / `_vpnViewIsHidden`
- `showVpnToast` / `hideVpnToast` / `manualHideVpnToast` (`0x102fea486`, `0x102fea493`, `0x102fea4a0`)
- `isActiveVPN` / `vpnIsOn` / `vpnIsOff`

---

## Telemetry

| Key / string | Address |
|---|---|
| `labels.device_vpn` | `0x102934d40` |
| `is_vpn_on` | `0x10293d499` |
| `show_vpn_toast` | `0x10293f19b` |
| `hide_vpn_toast` | `0x10293f1aa` |
| `manual_hide_vpn_toast` | `0x10293f1c0` |
| `AppsFlyerVPNCollectionEnabled` | `0x1029fe005` |

Standard analytics events every time the bar appears/hides + a per-user `device_vpn` label.

---

## Mach-O imports

| Symbol | Status | Use context |
|---|---|---|
| `_CFNetworkCopySystemProxySettings` | ✅ | three VPN detectors |
| `_nw_path_uses_interface_type` | ❌ | not imported |
| `_nw_interface_get_type` | ❌ | not imported |
| `_getifaddrs` | ✅ | GoogleMaps cellular-info, not VPN |
| `_if_nametoindex` | ✅ | not VPN |
| `_sysctl` / `_sysctlbyname` | ✅ | hw model / uptime / sysctl entries (Firebase GULAppEnvironmentUtil), not VPN |
| `_getenv` | ✅ | SDK env-settings, not VPN |
| `_dlopen` / `_dlsym` | ✅ | not VPN |
| `_DNSServiceQueryRecord` | ❌ | — |
| `_SCDynamicStoreCopyProxies` | ❌ | — |

---

## Bypass via the existing `VPNHide` tweak

Our `CFNetworkCopySystemProxySettings` hook strips from `__SCOPED__` all keys with substrings `utun/tun/tap/ipsec/ppp/wg`. This covers all **three** detectors: each receives the already-cleaned dictionary and returns `false`.

Consequences:
- `vpnStatusSubject` permanently holds `false` → observers (`VpnChecherManagableObserver`) don't trigger.
- UI panels (`VPNIsWorkedView`, `BottomVpnView`, `OldVPNIsWorkedView`) don't appear.
- Analytics `labels.device_vpn = true` and `show_vpn_toast` events don't fire.

The `nw_path_uses_interface_type` hook is irrelevant for Urent (not imported — code never reaches it).

To activate, add to [`tweaks/VPNHide/Filter.plist`](../../tweaks/VPNHide/Filter.plist):

```
{ Filter = { Bundles = ( …, "ru.urentbike.app" ); }; }
```

---

## Comparison

| | MyMTS | MegaFon | CDEK | DNS-SHOP | CPPK | Urent |
|---|---|---|---|---|---|---|
| Number of detectors | 2 | 1 | 2 | 1 | 1 | **3** |
| `__SCOPED__` | ✅ | ✅ | ✅ (×2) | ✅ | ❌ | ✅ (×3) |
| `NWPathMonitor` for VPN | ✅ | ❌ | ❌ | ❌ | ✅ (indirect) | ❌ |
| Reactive (Combine) | ✅ | ❌ | — (RN) | ❌ | ❌ | ✅ (`vpnStatusSubject`) |
| UI elements | 1 snackbar | 1 alert | JS RN | 1 snackbar | 2 (alert + SwiftUI) | 3 views |
| VPNHide coverage | ✅ | ✅ | ✅ | ✅ | ⚠️ | ✅ |

Urent is so far the "most cluttered" case: triple implementation of the same thing across different code generations (AppsFlyer + legacy Swift + the current `Services.VpnCheckerService`). All three points are killed by a single hook on the system API, no tweak code changes needed.

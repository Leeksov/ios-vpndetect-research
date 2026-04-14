[🇷🇺 Русская версия](vpn-detection.ru.md)

# Vkusno — i Tochka — VPN / proxy detection

**Binary:** `mcd-ios` v13.2.0 (arm64, Swift + Obj-C)
**Method:** IDA Pro / Hex-Rays.
**Bypass:** [`tweaks/VPNHide`](../../tweaks/VPNHide/) — current tweak covers it; add `com.mcdonaldsru.mcd` to [`Filter.plist`](../../tweaks/VPNHide/Filter.plist).

---

## TL;DR

**One detector.** Custom Swift wrapper `mcd_ios.VPNChecker`, classic `__SCOPED__` scan via `StringProtocol.contains`. **No AppsFlyer** (which is unusual among the analysed restaurant/commercial apps — usually an AppsFlyer detector is present).

| # | Module | Mechanism | Address |
|---|---|---|---|
| 1 | `mcd_ios.VPNChecker` (Swift) | `CFNetworkCopySystemProxySettings` → `__SCOPED__.allKeys` → `String.contains` for `tap/tun/ppp/ipsec` | `0x1002AF1CC` |

Substrings — **4** (`tap/tun/ppp/ipsec`), no `utun` — the shortest set among the analysed apps (same as Beeline/MyMTS/CDEK via the AppsFlyer classic).

`nw_path_uses_interface_type` is imported but **not for VPN** — `sub_100C5D964` queries `.wifi/.cellular/.wired` and writes the result into `setNetworkType:` (1:1 with MegaFon, CDEK, DNS-SHOP — standard network-type classifier).

**Mach-O imports:**

| Symbol | Status | Where |
|---|---|---|
| `_CFNetworkCopySystemProxySettings` | ✅ | only `VPNChecker` (`sub_1002AF1CC`) |
| `_nw_path_uses_interface_type` | ✅ | classifier `sub_100C5D964` only, not VPN |
| `_getifaddrs` | ✅ | helper, not VPN |
| `_nw_interface_get_type` / `_CFNetworkCopyProxiesForURL` / `_SCDynamicStoreCopyProxies` / `_DNSServiceQueryRecord` | ❌ | — |

---

## Detector — `sub_1002AF1CC`

Method on Swift class `_TtC7mcd_ios10VPNChecker` (metadata accessor `$s7mcd_ios10VPNCheckerCMa` @ `0x1002af1ac`).

Pseudocode:

```swift
func isVpnEnabled() -> Bool {
    guard let settings = CFNetworkCopySystemProxySettings() as? [String: Any] else { return false }
    guard let scoped   = settings["__SCOPED__"]          as? [String: Any] else { return false }
    for iface in scoped.keys {
        if iface.contains("tap")   { return true }
        if iface.contains("tun")   { return true }
        if iface.contains("ppp")   { return true }
        if iface.contains("ipsec") { return true }
    }
    return false
}
```

Literals:

| In decomp | Bytes | ASCII |
|---|---|---|
| `7364980` | `74 61 70 00` | `tap` |
| `7239028` | `74 75 6E 00` | `tun` |
| `7368816` | `70 70 70 00` | `ppp` |
| `0x6365_7370_69` | `69 70 73 65 63` | `ipsec` |

Contains helper — standard `StringProtocol.contains<A>(_:)`.

---

## UI and reactive pipeline

### `VPNInformerView`

Swift class `_TtC7mcd_ios15VPNInformerView` (`0x1029910e0`):

| Method | Address |
|---|---|
| `initWithFrame:` | `0x1000c1448` |
| `initWithCoder:` | `0x1000c1524` |
| `.cxx_destruct` | `0x1000c154c` |
| Type metadata | `$s7mcd_ios15VPNInformerViewCMa` @ `0x1000c15c8` |

It's a **`UIView`** (not a cell, not a window) — a banner/informer overlaid on the screen on detect.

### Localisation

| Key | Address |
|---|---|
| `VPN.Informer.Title` | `0x102991180` |
| `VPN.Informer.Subtitle` | `0x102991160` |

### State / dismissal

- `vpnInformerWasHidden` (`0x102988cd0`) — flag indicating user closed the informer manually (UserDefaults persistence)
- `isNeedToHideVPNInformer` (`0x102bf25b0`) — getter aggregating checks (incl. dismissal-state and current VPN status)

### Notification

`ru.adv.mcd-dev.VPN-informer-need-to-hide` (`0x102986ef0`) — `NSNotification.Name`. Posted from 4 different places (4 xrefs from data section). Reverse-DNS name with `mcd-dev` — dev-namespace left in the release.

The receiver (observer) is `VPNInformerView`, which hides itself on this notification.

### Properties / API

| Name | Address | Purpose |
|---|---|---|
| `vpnEnabled` | `0x102a2c667`, `0x102b861a2`, `0x102c22ed0`, `0x102c2407c` | Bool property (multiple meta copies) |
| `isVpnEnabled` | `0x102c22afa` | getter |
| `setVpnEnabled:` | `0x102b79e9d` | setter (Obj-C bridge) |
| `_vpnEnabled` | `0x102c24293` | backing ivar |
| `vpnStatus` | `0x102c240a1` | enum / value-type |
| `vpn_enabled` | `0x102a2ed2a` | snake-case telemetry key |

---

## What it does **not** do

- No AppsFlyer detector (and `+[AppsFlyerUtils isVPNConnected]` doesn't appear in the function listing — the AppsFlyer SDK isn't integrated, or its VPN-checker piece is excluded).
- No server-side check.
- No remote-config flag.
- No full-screen lockout — only an informer banner with a manual-close affordance (`vpnInformerWasHidden` persists in UserDefaults).
- No CarPlay/Watch integration.

The softest VPN policy: show an informer, let the user close it, don't block functionality.

---

## Bypass via the existing `VPNHide` tweak

The `CFNetworkCopySystemProxySettings` hook strips VPN keys from `__SCOPED__` → `VPNChecker.isVpnEnabled` returns `false` → no informer, no notification.

All other hooks for this binary are NO-OPs (either not imported or called with non-VPN types).

To activate, add to [`tweaks/VPNHide/Filter.plist`](../../tweaks/VPNHide/Filter.plist):

```
{ Filter = { Bundles = ( …, "com.mcdonaldsru.mcd" ); }; }
```

Bundle ID is legacy from the McDonald's era (`com.mcdonaldsru.mcd`); didn't change in the rebrand to «Вкусно — и точка».

---

## Comparison

| | MyMTS | MF | CDEK | DNS-SHOP | CPPK | Urent | Gosuslugi | Beeline | 2GIS | Moy Nalog | Rostic's | **V&T** |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Detectors | 2 | 1 | 2 | 1 | 1 | 3 | 5 | 2 | 3+server | 0 | 1 | **1** |
| AppsFlyer-style | ✅ | — | ✅ | — | ❌ | ✅ | — | ✅ | ✅ | — | ✅ | ❌ (no AppsFlyer SDK!) |
| Substrings | 4 | 5 | 5–6 | 5 | — | 5 | configurable | unknown | 5 | — | 4 | **4** |
| Server-side | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | — | ❌ | ❌ |
| UI | snackbar | alert | RN | snackbar | alert + SwiftUI | 3 views | snackbar | toast/alert | full-screen+CarPlay | — | inline cell | **dismissable banner** |
| Sticky dismissal | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | — | ❌ | ✅ `vpnInformerWasHidden` |
| VPNHide coverage | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | n/a | ✅ | ✅ |

V&T has the softest VPN policy among detecting apps: one Swift checker with no AppsFlyer duplicate, banner can be permanently dismissed, no functionality blocking.

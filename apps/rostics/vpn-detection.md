[🇷🇺 Русская версия](vpn-detection.ru.md)

# Rostic's — VPN / proxy detection

**Binary:** `kfc` v10.29.0 (arm64, Swift + Obj-C)
**Method:** IDA Pro / Hex-Rays.
**Bypass:** [`tweaks/VPNHide`](../../tweaks/VPNHide/) — current tweak covers it; add `ru.yum.KFC-Russia` to [`Filter.plist`](../../tweaks/VPNHide/Filter.plist).

---

## TL;DR

One actual detector + a Swift wrapper with UI infrastructure:

| # | Module | Mechanism | Address |
|---|---|---|---|
| 1 | AppsFlyer SDK (Obj-C) | `+[AppsFlyerUtils isVPNConnected]` — `__SCOPED__` → `tap/tun/ipsec/ppp` | `0x1013EED10` |

`KFCGeneralModule.CheckVPN` (`$s16KFCGeneralModule8CheckVPNVMa` @ `0x10047d694`) — Swift struct (`V` in mangling) describing the check result. Its own check code isn't localised in the decomp (metadata exists, methods are anonymous / inlined), but **the behaviour is unambiguous**: the only `CFNetworkCopySystemProxySettings` call site in the binary is AppsFlyer. CheckVPN is either a wrapper over AppsFlyer or accepts a `Bool` from outside.

`NWPathMonitor` is **not used for VPN** — `sub_10018D4D0` calls `nw_path_uses_interface_type(path, .cellular)` once and immediately `nw_path_monitor_cancel`. Reachability, not VPN.

**Mach-O imports:**

| Symbol | Status | Context |
|---|---|---|
| `_CFNetworkCopySystemProxySettings` | ✅ | only AppsFlyer |
| `_nw_path_uses_interface_type` | ✅ | cellular reachability only, not VPN |
| `_getifaddrs` | ✅ | helper |
| `_nw_interface_get_type` / `_CFNetworkCopyProxiesForURL` / `_SCDynamicStoreCopyProxies` / `_DNSServiceQueryRecord` | ❌ | — |

---

## Architecture

### `KFCGeneralModule.CheckVPN` (Swift struct)

| Symbol | Address |
|---|---|
| Type metadata accessor | `$s16KFCGeneralModule8CheckVPNVMa` @ `0x10047d694` |
| Static reference | data ref @ `0x103381950` (witness / global) |

`V` in mangling (`...VMa`) — Swift value type. Used as a DTO / result-of-check.

### UI layer — `KFCUIModule.VPNMessageCell`

| Symbol | Address |
|---|---|
| Class | `_TtC11KFCUIModule14VPNMessageCell` @ `0x1031d9e10` |
| Source path | `KFCUIModule/VPNMessageCell.swift` (`0x1031d9e40`) |
| Full path | `/Users/developers/builds/PEJtp_Ma/0/mobile/mobile-ios/ios/kfc/Modules/KFCUIModule/Views/VPNMessageCell/VPNMessageCell.swift` |
| Init | `-[VPNMessageCell initWithStyle:reuseIdentifier:]` @ `0x1008fbf10` |
| ViewModel | `$s11KFCUIModule19VPNMessageCellModelVMa` @ `0x1008fc948` |

`VPNMessageCell` is a **`UITableViewCell` subclass** (init with `style:reuseIdentifier:`) that gets inserted into the common feed/menu when VPN is active. The hint shows up **inline** in the list, not modally or as a snackbar.

### Localisation

| Key | Address | Use |
|---|---|---|
| `errors.vpn_active.title` | `0x1031cac20` | error title |
| `errors.vpn_active.text` | `0x1031c9ac0` | error body |
| `screens.menu.vpn_message` | `0x1031ca970` | menu message |

All three are accessed via `NSLocalizedString(_:tableName:bundle:value:comment:)` in `sub_1007C738C` (`title`) and similar wrappers. Bundle resolver is `sub_1006F9054` (load-once via `swift_once`).

### Notification

The string `activeVPN` (`0x1033d05d3`, `0x1033d0893`) is a Swift small-string, lands in data sections twice → used as `NSNotification.Name("activeVPN")` (same pattern as CPPK). Posted from the VPN checker; observers react by showing `VPNMessageCell` or `vpnMessage` property.

### Other markers

- `vpnMessage` (`0x1033d0a6d`) — Swift property
- `AppsFlyerVPNCollectionEnabled` (`0x103250a02`) — flag in AppsFlyer SDK
- `VPNCollectionEnabled` / `setVPNCollectionEnabled:` — Obj-C accessors on AppsFlyerLib

---

## Debug artefacts

GitLab CI runner path left in the binary:

```
/Users/developers/builds/PEJtp_Ma/0/mobile/mobile-ios/ios/kfc/Modules/KFCUIModule/Views/VPNMessageCell/VPNMessageCell.swift
```

Workspace prefix `PEJtp_Ma/0/` is standard GitLab Runner format. Non-unique build path.

---

## Bypass via the existing `VPNHide` tweak

The `CFNetworkCopySystemProxySettings` hook strips VPN keys from `__SCOPED__` → AppsFlyer detector returns `false` → the chain into `CheckVPN` / `VPNMessageCell` / `errors.vpn_active.*` doesn't fire. All other hooks for this binary are NO-OPs.

To activate, add to [`tweaks/VPNHide/Filter.plist`](../../tweaks/VPNHide/Filter.plist):

```
{ Filter = { Bundles = ( …, "ru.yum.KFC-Russia" ); }; }
```

The bundle ID is legacy from the KFC era (pre-Rostic's rebrand); never changed.

---

## Comparison

| | MyMTS | MF | CDEK | DNS-SHOP | CPPK | Urent | Gosuslugi | Beeline | 2GIS | Moy Nalog | **Rostic's** |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Local detectors | 2 | 1 | 2 | 1 | 1 | 3 | 5 | 2 | 3 | 0 | **1** (AppsFlyer-only) |
| Server-side | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | — | ❌ |
| UI reaction | snackbar | alert | RN | snackbar | alert + SwiftUI | 3 views | snackbar | toast/alert | full-screen + CarPlay | — | **inline `UITableViewCell`** |
| Notification-driven (`activeVPN`) | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | — | ✅ |
| VPNHide coverage | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |

Rostic's is the least aggressive of the apps that detect: just a stock AppsFlyer shim + a UX warning via a cell in the main feed (no blocking, no modals). The team clearly treated VPN as an inconvenience rather than a threat — detection is "for the books" plus a UI hint.

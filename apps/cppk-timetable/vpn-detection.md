[🇷🇺 Русская версия](vpn-detection.ru.md)

# CPPK Timetable — VPN / proxy detection

**Binary:** `Timetable PROD` v2.7 (arm64, Swift + Obj-C)
**Method:** IDA Pro / Hex-Rays.
**Bypass:** [`tweaks/VPNHide`](../../tweaks/VPNHide/) — **coverage not guaranteed**, see "Bypass" section below.

---

## TL;DR

This app uses a **non-standard** detector. The pedestrian `CFNetworkCopySystemProxySettings` path is **not used**, and even the raw symbol `nw_path_uses_interface_type` isn't imported. Detection is built entirely on the Swift wrapper for `Network.framework`:

1. Swift class `_TtC14Timetable_PROD14NetworkMonitor` holds a property `currentConnectionType: NWInterface.InterfaceType`.
2. Function `sub_100293EF4` reads that value and compares it against a specific case of `NWInterface.InterfaceType` (presumably `.other`).
3. On match → `DispatchQueue.main.async` invokes a block that ultimately shows a VPN alert.
4. The alert is shown by `-[LaunchManager showActiveVPNWithNotification:]` (selector string `0x1006f69fe`) — a classic `NSNotification` observer keyed on `"activeVPN"` (`0x1007c8da0`).

**Mach-O imports (full picture):**

| Symbol | Status |
|---|---|
| `_CFNetworkCopySystemProxySettings` | ❌ not imported |
| `_nw_path_uses_interface_type` | ❌ not imported |
| `_nw_interface_get_type` | ❌ not imported |
| `_nw_path_enumerate_interfaces` | ❌ not imported |
| `_getifaddrs` / `_if_nametoindex` | ❌ not imported |
| `_SCDynamicStoreCopyProxies` | ❌ not imported |
| `_DNSServiceQueryRecord` | ❌ not imported |
| `_getenv` | ❌ not imported |
| `_sysctl` / `_sysctlbyname` | ✅ (not for VPN — hw model / uptime) |
| `_dlopen` / `_dlsym` | ✅ |

Striking: **not a single "VPN-oriented" C symbol** in the list. So the entire detect flows through the Swift overlay for `Network.framework` (libswiftNetwork.dylib), and the result reduces to an enum compare in Swift code in the main binary.

---

## Call chain

### `sub_100293EF4` — VPN check and alert dispatch

```
1. Get the NetworkMonitor singleton
   swift_once(&qword_1008E7C10, sub_10005A404)
2. Read NetworkMonitor.currentConnectionType
   ivar: OBJC_IVAR____TtC14Timetable_PROD14NetworkMonitor_currentConnectionType
3. Build the reference value:
   (v3 + 104)(v7, 0xFFFFFFFF, v2)   // destructiveInjectEnumTag — case projection
4. Compare via Equatable.==:
   dispatch_thunk_of_static_Equatable.==(_:_:)(v7, v4, NWInterface.InterfaceType, v12)
5. If true → DispatchQueue.main.async { sub_1002950D8() }
                                          ↳ sub_1002943EC — show UIAlertController
```

The `0xFFFFFFFF` tag at step 3 is a specific-tag injection of the enum case; after `destructiveInjectEnumTag(-1)` + `initializeWithCopy` the actual case is selected by the metadata at `unk_1008ED588` (witness table for `NWInterface.InterfaceType`). With high probability this is `.other` — that's how Network.framework marks VPN paths.

### `-[LaunchManager showActiveVPNWithNotification:]` @ `0x100294540`

A thin thunk to `sub_1002948DC`, which:
1. Bridges `NSNotification` → `Notification` (Swift).
2. Captures the passed-in `a4 = sub_100293EF4` (VPN-check closure).
3. Calls `a4()` — i.e. the check is run **on arrival of the `activeVPN` notification**.

So **NetworkMonitor itself somewhere posts `NSNotification.Name("activeVPN")`**, and `LaunchManager` observes and reacts with a UI alert. Searching for the poster (`NotificationCenter.default.post`) yields no direct hits due to static stripping and Swift mangling, but the behavioural chain is unambiguous.

### UI

Two UI paths:

1. **UIKit alert** — `sub_1002943EC`:
   - `UIAlertController(title:, message:, preferredStyle:.alert)` + 1 action
   - Message: `Возможно у Вас включен VPN. Для корректной работы приложения его стоит выключить` (`0x1007161b0`)
2. **SwiftUI view body** — `sub_1002CC9DC`:
   - `Text(_:).font(.custom("OpenSans-Bold", size: 16)) + Text(_:).font(.custom("OpenSans-Regular", size: 14))`
   - Contains the string `Из-за VPN могут быть ошибки, лучше его отключить` (`0x100716d20`)
   - Conditionally rendered from `@State` — an inline snackbar/label.

---

## Bypass via the existing `VPNHide` tweak

Covered by the `nw_interface_get_type` hook added specifically for this case. Mechanics:

1. `libswiftNetwork.dylib`, when accessing `NWInterface.type`, calls the C function `nw_interface_get_type(nw_interface_t)`. fishhook rebinds it in libswiftNetwork's GOT (our `rebind_symbols` walks all loaded images).
2. In the hook we call the original; if it returned `.other` (0) **and** the interface name (via `nw_interface_get_name`, resolved via dlsym) matches a VPN prefix (`utun/tun/tap/ipsec/ppp/wg`) — we return `.wifi` (1) instead of `.other`.
3. The Swift `currentConnectionType == .other` comparison in `sub_100293EF4` never matches → no VPN alert dispatched → no `"activeVPN"` notification.

The other hooks for this binary are NO-OPs (`CFNetworkCopySystemProxySettings`, `getifaddrs`, `nw_path_uses_interface_type` are not imported).

To activate, add to [`tweaks/VPNHide/Filter.plist`](../../tweaks/VPNHide/Filter.plist):

```
{ Filter = { Bundles = ( …, "ru.central-ppk.Timetable" ); }; }
```

If for some reason the `nw_interface_get_type` hook doesn't fire (e.g. libswiftNetwork uses a different low-level API), fallbacks:

1. Hook `nw_path_enumerate_interfaces` — wrap the block enumerator and drop VPN interfaces before the callback. Trickier than `nw_interface_get_type`.
2. Swizzle `NSNotificationCenter.defaultCenter postNotificationName:object:` with a filter on `"activeVPN"` — kill the notification at posting time. Doesn't require fishhook but is app-specific.

---

## Comparison

| | MyMTS | MegaFon | CDEK | DNS-SHOP | CPPK |
|---|---|---|---|---|---|
| `__SCOPED__` | ✅ | ✅ | ✅ (×2) | ✅ | ❌ |
| `nw_path_uses_interface_type` | ✅ | only `.cellular/.wifi` (not VPN) | only `.wifi/.cellular/.wired` (not VPN) | ❌ not imported | ❌ not directly imported, but Swift overlay may use it |
| Swift `NWInterface.InterfaceType` compare | ❌ | ❌ | ❌ | ❌ | ✅ `NetworkMonitor.currentConnectionType == .?` |
| UI reaction | snackbar | alert | JS RN | snackbar | NSNotification → UIAlertController / SwiftUI Text |
| Coverage by current VPNHide | ✅ | ✅ | ✅ | ✅ | ⚠️ under test |

CPPK is the first analysed case where detection sits entirely outside the coverage zone of fishhook on standard C symbols. A useful proving ground for tweak development.

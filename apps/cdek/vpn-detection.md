[🇷🇺 Русская версия](vpn-detection.ru.md)

# CDEK — VPN / proxy detection

**Binary:** `CDEK` v5.9.0 (arm64, React Native + Swift + Obj-C)
**Method:** IDA Pro / Hex-Rays.
**Bypass:** [`tweaks/VPNHide`](../../tweaks/VPNHide/) — current tweak covers it; just add `com.cdek.cdekapp` to [`Filter.plist`](../../tweaks/VPNHide/Filter.plist).

---

## TL;DR

React Native app (reanimated, margelo/nitro, worklets). Two detectors, **both** reduce to the same system call:

| # | Module | Mechanism | Address |
|---|---|---|---|
| 1 | AppsFlyer SDK (Obj-C) | `CFNetworkCopySystemProxySettings` → `__SCOPED__` → substrings `tap/tun/ipsec/ppp` | `0x100108FC4` |
| 2 | `VpnDetect` RN module (Swift) | same + adds `utun` and `ipsec0` | `0x1008FF3AC` |

`VpnDetect` is a CocoaPods package (string `PodsDummy_VpnDetect` @ `0x100cd3008`), by name presumably `react-native-vpn-detect` or similar. RN-exposed class: `_TtC9VpnDetect15VpnDetectModule` (`0x100c70040`), JS-API selector — `isVpnConnected` (`0x100c7006d`).

**NWPathMonitor is not used for VPN.** The single `nw_path_uses_interface_type` call site (`sub_1002E55DC`) queries `.wifi` / `.cellular` / `.wired` to determine connection type and feeds it into `setNetworkType:` — a classifier, not a VPN detector.

---

## Detector #1 — AppsFlyer: `+[AppsFlyerUtils isVPNConnected]`

**Address:** `0x100108FC4`. Byte-for-byte identical to the MyMTS implementation (`0x10142678c`): `CFNetworkCopySystemProxySettings().__SCOPED__` → `allKeys` → `rangeOfString:` for `"tap"`/`"tun"`/`"ipsec"`/`"ppp"`.

Stock AppsFlyer SDK code, used inside the SDK. Doesn't gate the app UI, but controls what's reported to AppsFlyer telemetry (flag `VPNCollectionEnabled` @ `0x100b60f17`).

---

## Detector #2 — `VpnDetect` Swift module — `sub_1008FF3AC`

Same algorithm, implemented Swift-style via `Dictionary._conditionallyBridgeFromObjectiveC` + `StringProtocol.contains<A>`. Extended substring list — 6 entries:

| Swift literal | Bytes | ASCII |
|---|---|---|
| `0x0070_6174` (`7364980`) | `74 61 70 00` | `tap` |
| `0x006E_7574` (`7239028`) | `74 75 6E 00` | `tun` |
| `0x0070_7070` (`7368816`) | `70 70 70 00` | `ppp` |
| `0x6365_7370_69` | `69 70 73 65 63` | `ipsec` |
| `0x6E75_7475` (`1853191285`) | `75 74 75 6E` | `utun` |
| `0x3063_6573_7069` | `69 70 73 65 63 30` | `ipsec0` |

Dictionary key — `__SCOPED__` (`0x4445504F43535F5F` + `0xEA00000000005F5F`).

Pseudocode:

```swift
func isVpnConnected() -> Bool {
    guard let settings = CFNetworkCopySystemProxySettings() as? [String: Any] else { return false }
    guard let scoped   = settings["__SCOPED__"]           as? [String: Any] else { return false }
    for iface in scoped.keys {
        if iface.contains("tap")    { return true }
        if iface.contains("tun")    { return true }
        if iface.contains("ppp")    { return true }
        if iface.contains("ipsec")  { return true }
        if iface.contains("utun")   { return true }
        if iface.contains("ipsec0") { return true }    // redundant — covered by "ipsec"
    }
    return false
}
```

Exported to the JS bridge via `VpnDetectModule.isVpnConnected` → UI reaction is built by the JS side (React Native Bridge / turbo module).

---

## Imports — present but not used for VPN

| Symbol | Use | Related to VPN detection |
|---|---|---|
| `_getifaddrs` | `-[RNCNetInfo ipAddress]`, `-[RNCNetInfo subnet]` — local IP | No |
| `_sysctl` / `_sysctlbyname` | `+[AFSystemInfo machineModel]`, `+[GULAppEnvironmentUtil getSysctlEntry:]` — hw model / uptime | No |
| `_nw_path_uses_interface_type` | `sub_1002E55DC` — wifi/cellular/wired classification for `setNetworkType:` | No |
| `_SCNetworkReachabilityCreateWithName` | Sentry, generic reachability | No |
| `_if_nametoindex` | one helper call site | No |
| `_dlopen` / `_dlsym` | RN/JSC/Hermes loading | No |
| `_getenv` | not imported | — |
| `_DNSServiceQueryRecord` | not imported | — |
| `_SCDynamicStoreCopyProxies` | not imported | — |

---

## Bypass via the existing `VPNHide` tweak

Our `CFNetworkCopySystemProxySettings` hook removes from `__SCOPED__` all keys containing `utun/tun/tap/ipsec/ppp/wg`. This covers both implementations:
- AppsFlyer — `rangeOfString:` will return `NSNotFound` for all 4 patterns.
- VpnDetect — `StringProtocol.contains` returns `false` for all 6 patterns (`ipsec0` is covered by the `ipsec` filter).

The `nw_path_uses_interface_type` hook is unnecessary for CDEK but doesn't break the RN network classification: `.wifi`/`.cellular`/`.wired` calls proxy through, and the `.other` filter simply never triggers (it's not requested).

To activate, add to [`tweaks/VPNHide/Filter.plist`](../../tweaks/VPNHide/Filter.plist):

```
{ Filter = { Bundles = ( "ru.mts.mymts", "ru.megafon.lk", "com.cdek.cdekapp" ); }; }
```

---

## Comparison

| | MyMTS | MegaFon | CDEK |
|---|---|---|---|
| `__SCOPED__` detector | ✅ AppsFlyer (ObjC) | ✅ Swift copy | ✅ AppsFlyer + Swift `VpnDetect` pod |
| Substrings | `tap/tun/ipsec/ppp` | +`utun` | +`utun`, +`ipsec0` |
| `NWPathMonitor` for VPN | ✅ `GeoWidgetSDK.VPNDetectorService` | ❌ | ❌ |
| App type | native Swift | native Swift | React Native (JSI/Hermes) |
| UI reaction | snackbar | alert + FAQ | handled by JS |

CDEK is the most "transparent" detect-wise: a clean algorithm from a public RN package, covered by the `CFNetworkCopySystemProxySettings` hook out of the box.

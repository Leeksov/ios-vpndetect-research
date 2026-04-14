[🇷🇺 Русская версия](vpn-detection.ru.md)

# MegaFon — VPN / proxy detection

**Binary:** `Megafon` v4.62.0 (arm64, Swift + Obj-C)
**Method:** IDA Pro / Hex-Rays.
**Bypass:** [`tweaks/VPNHide`](../../tweaks/VPNHide/) — current tweak covers it; just add `ru.megafon.lk` to [`Filter.plist`](../../tweaks/VPNHide/Filter.plist).

---

## TL;DR

A single detector, classic **AppsFlyer-style**: `CFNetworkCopySystemProxySettings.__SCOPED__` → enumerate keys → substrings `tap`/`tun`/`ppp`/`ipsec`/`utun`.

| # | Module | Mechanism | Address |
|---|---|---|---|
| 1 | `Megafon` app, `sub_1005388E0` | `CFNetworkCopySystemProxySettings` → `__SCOPED__` → substring match | `0x1005388E0` |

`NWPathMonitor` **is** in the binary, but `nw_path_uses_interface_type` is only called with `cellular` / `wifi` in `sub_1001650B0` — that's a connection-type telemetry report, **not VPN detection**.

**Not present:** `_sysctl` / `_sysctlbyname` (not imported), `_getenv` (not imported), `_DNSServiceQueryRecord` (not imported), `_dlopen` (not imported; only `_dlsym`). `_getifaddrs` is imported but used in `-[AcquireInplatService getIPAddress]` to get the local IP, not for VPN detection.

---

## Entry points

### `+[VPNMonitoringBridge checkVPNStatus]` — `0x10055A998`

```objc
+ (void)checkVPNStatus {
    VPNMonitoringController *ctrl = [Bridge shared];    // sub_1005384B0
    BOOL isRepair = stub_returns_false();               // sub_10000CE6C — just return 0
    [ctrl showIfVPNDetectedInRepair:isRepair];          // sub_100538514
}
```

### `+[VPNMonitoringBridge checkVPNStatusInRepair]` — `0x10055A9D0`

Same thing but with `isRepair = 1` (in repair-flow scenario the UI is hidden, no alert, just runs the detect).

### `sub_100538514` — reaction to detection

```
if (vpn_detected() == false || isRepair == true) {
    // show nothing, release the alert view if it was up
} else {
    MFAnalytics.track("vpn_info", "оповещение о включенном VPN", "screen_main", …);
    print("[111] ... vpn ON");
    view = VPNMonitoringAlertView();
    [window addSubview: view];
}
```

Where:
- `"vpn_info"`, `"оповещение о включенном VPN"`, `"screen_main"` — Swift small-string literals from the decompilation.
- `VPNMonitoringAlertView` — alert with text **«Отключите VPN, чтобы в приложении всё работало хорошо»** (string `0x100fc6bb0`) and a "How to disable VPN >" link to `https://lk.megafon.ru/inapp/faq/?questionId=vpn_disable` (string `0x100fc6b40`).

---

## The detector itself — `sub_1005388E0`

A Swift version, but the algorithm is **byte-for-byte AppsFlyer's `isVPNConnected`** from MyMTS.

### Pseudocode

```swift
func vpn_detected() -> Bool {
    guard let settings = CFNetworkCopySystemProxySettings() else { return false }
    guard let scoped = settings["__SCOPED__"] as? [String: Any] else { return false }

    for iface in scoped.keys {
        if iface.contains("tap")   { return true }
        if iface.contains("tun")   { return true }
        if iface.contains("ppp")   { return true }
        if iface.contains("ipsec") { return true }
        if iface.contains("utun")  { return true }
    }
    return false
}
```

### Literal decoding

In the decomp the substring literals appear as Swift small-string inline encoding (first 8 bytes — content; high byte of the second qword — count+flag `0xE0 + len`):

| In decomp | Bytes | ASCII | Count flag |
|---|---|---|---|
| `0x0070_6174` (`7364980`) | `74 61 70 00` | `tap` | `0xE3` (3) |
| `0x006E_7574` (`7239028`) | `74 75 6E 00` | `tun` | `0xE3` (3) |
| `0x0070_7070` (`7368816`) | `70 70 70 00` | `ppp` | `0xE3` (3) |
| `0x6365_7370_69` | `69 70 73 65 63` | `ipsec` | `0xE5` (5) |
| `0x6E75_7475` (`1853191285`) | `75 74 75 6E` | `utun` | `0xE4` (4) |

The first read is the `__SCOPED__` key (`0x4445504F43535F5F` + `0xEA00000000005F5F` = `__SCOPED__`, 10 chars, flag `0xEA`).

`sub_100538778` is the `String.contains(substring)` helper via `String.Iterator.next()`.

---

## What happens on a positive detect

- **UI:** `VPNMonitoringAlertView` (`Megafon/VPNMonitoringAlertView.swift`) pops up with text about disabling VPN and a FAQ link.
- **Telemetry:** `vpn_info` / `оповещение о включенном VPN` event goes to `MFAnalytics`.
- **Flag:** `MRProtoBuilder.setVpnEnabled:` is set in protobuf telemetry; field serialised as `vpn_enabled` (string `0x1010371aa`).
- **Debug log:** `print("[111] ... vpn ON")` / `print("[111] ... vpn OFF")` (strings `0x100fc5d80` / `0x100fc5d20`).

---

## Bypass via the existing `VPNHide` tweak

Our `CFNetworkCopySystemProxySettings` hook strips from `__SCOPED__` any keys containing `utun/tun/tap/ipsec/ppp/wg` — exactly the set MegaFon checks (plus `wg` for headroom). The detector receives an empty `__SCOPED__` → all `contains` calls return `false` → early `return false` → no alert and no telemetry.

The `nw_path_uses_interface_type` hook is unnecessary here (MegaFon doesn't use it for VPN), but doesn't break anything — `.cellular`/`.wifi` calls proxy through to original.

To activate, add to [`tweaks/VPNHide/Filter.plist`](../../tweaks/VPNHide/Filter.plist):

```
{ Filter = { Bundles = ( "ru.mts.mymts", "ru.megafon.lk" ); }; }
```

---

## Comparison vs MyMTS

| | MyMTS (`MtsServiceRu`) | MegaFon (`Megafon`) |
|---|---|---|
| `__SCOPED__` check | ✅ `+[AppsFlyerUtils isVPNConnected]` | ✅ `sub_1005388E0` (Swift) |
| Substrings | `tap/tun/ipsec/ppp` | `tap/tun/ppp/ipsec/utun` |
| `NWPathMonitor` for VPN | ✅ `GeoWidgetSDK.VPNDetectorService` | ❌ (used only for `cellular`/`wifi`) |
| UI reaction | snackbar «Включён VPN…» | alert window + FAQ link |
| Telemetry | AppMetrica `is_vpn_enabled` | protobuf `vpn_enabled`, MFAnalytics event |

MegaFon detects **less aggressively** than MTS — one path vs two. The current tweak fully covers it.

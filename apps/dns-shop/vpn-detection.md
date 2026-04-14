[🇷🇺 Русская версия](vpn-detection.ru.md)

# DNS-SHOP — VPN / proxy detection

**Binary:** `DNS-SHOP` v1.52.0 (arm64, Swift + Obj-C)
**Method:** IDA Pro / Hex-Rays.
**Bypass:** [`tweaks/VPNHide`](../../tweaks/VPNHide/) — current tweak covers it; just add `com.dns.DNSShop.DNS-SHOP` to [`Filter.plist`](../../tweaks/VPNHide/Filter.plist).

---

## TL;DR

A single detector — Swift struct `DNS_SHOP.VpnChecker`, classic **`__SCOPED__` scan**:

| # | Module | Mechanism | Address |
|---|---|---|---|
| 1 | `DNS_SHOP.VpnChecker` (Swift struct) | `CFNetworkCopySystemProxySettings` → `__SCOPED__` → `allKeys.contains("tap"/"tun"/"ppp"/"ipsec"/"utun")` | `0x1002B8E50` |

`NWPathMonitor` is **not used** — `_nw_path_uses_interface_type` isn't even imported.

**Mach-O imports:**

| Symbol | Status | Where |
|---|---|---|
| `_CFNetworkCopySystemProxySettings` | ✅ | only in `VpnChecker` (sub_1002B8E50) |
| `_nw_path_uses_interface_type` | ❌ not imported | — |
| `_getifaddrs` | ✅ | helper for getting IP by interface name (`sub_101DEB16C`), not VPN |
| `_getenv` | ✅ | locale / SDK env-settings, not VPN |
| `_sysctl` / `_sysctlbyname` | ✅ | uptime / hw model, not VPN |
| `_dlopen` / `_dlsym` | ✅ | dynamic loading, not VPN |
| `_DNSServiceQueryRecord` | ❌ | — |
| `_SCDynamicStoreCopyProxies` | ❌ | — |

---

## `sub_1002B8E50` — `VpnChecker.isActive`

Swift metadata: `$s8DNS_SHOP10VpnCheckerVMa` @ `0x1002b93f8` (the `V` in mangling — value type, struct).

### Pseudocode

```swift
func isActive() -> Bool {
    guard let settings = CFNetworkCopySystemProxySettings() as? [String: Any] else { return false }
    guard let scoped   = settings["__SCOPED__"]           as? [String: Any] else { return false }
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

### Literals

| In decomp | Bytes | ASCII | Small-string flag |
|---|---|---|---|
| `0x4445504F43535F5F` + `0xEA00000000005F5F` | `__SCOPED__` | — | `0xEA` (10 chars) |
| `7364980` | `74 61 70 00` | `tap` | `0xE3` |
| `7239028` | `74 75 6E 00` | `tun` | `0xE3` |
| `7368816` | `70 70 70 00` | `ppp` | `0xE3` |
| `0x6365_7370_69` | `69 70 73 65 63` | `ipsec` | `0xE5` |
| `1853191285` | `75 74 75 6E` | `utun` | `0xE4` |

`sub_1002B92A0` is the same `String.contains(substring)` helper via `String.Iterator.next()` as in MegaFon and CDEK.

---

## What happens on a positive detect

**UI:** `createVPNSnackBar()` (string `0x10377ed00`) shows a snackbar with text **«У Вас включен VPN»** (`0x1037d61d0`).

Additionally — in the in-store error message (string `0x1037c9cf0`):

> Если вы в магазине и у вас возникает эта ошибка, проверьте, что у вас *включен Wi-Fi, службы геолокации и отключен VPN*.

**Telemetry:**
- `System.vpn` (`0x1037d61c3`)
- `System.vpnInfo` (`0x1037d61ee`)
- Selector `isVPNActive` / Swift property `vpnStore`.

---

## Bypass via the existing `VPNHide` tweak

The `CFNetworkCopySystemProxySettings` hook strips from `__SCOPED__` all keys with substrings `utun/tun/tap/ipsec/ppp/wg` — exactly the 5 patterns DNS-SHOP checks. Result: `VpnChecker.isActive()` returns `false`, no snackbar, `System.vpn` telemetry stays off.

The `nw_path_uses_interface_type` hook is irrelevant for DNS-SHOP (symbol not imported, code never reaches it).

To activate, add to [`tweaks/VPNHide/Filter.plist`](../../tweaks/VPNHide/Filter.plist):

```
{ Filter = { Bundles = ( "ru.mts.mymts", "ru.megafon.lk", "com.cdek.cdekapp", "com.dns.DNSShop.DNS-SHOP" ); }; }
```

---

## Comparison

| | MyMTS | MegaFon | CDEK | DNS-SHOP |
|---|---|---|---|---|
| `__SCOPED__` detector | ✅ AppsFlyer (ObjC) | ✅ Swift copy | ✅ AppsFlyer + VpnDetect pod | ✅ Swift struct `VpnChecker` |
| Substrings | `tap/tun/ipsec/ppp` | +`utun` | +`utun`, +`ipsec0` | +`utun` |
| `NWPathMonitor` for VPN | ✅ | ❌ | ❌ | ❌ (not imported at all) |
| UI reaction | snackbar | alert + FAQ | JS (RN) | snackbar |
| Number of detectors | 2 | 1 | 2 (AppsFlyer dupe + Pod) | 1 |

DNS-SHOP is the simplest case: one Swift struct, one system call. VPNHide coverage is 1:1 with no changes to the tweak code.

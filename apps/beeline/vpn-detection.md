[🇷🇺 Русская версия](vpn-detection.ru.md)

# Beeline — VPN / proxy detection

**Binary:** `MyBeeline` v5.36.0 (arm64, Swift + Obj-C)
**Method:** IDA Pro / Hex-Rays.
**Bypass:** [`tweaks/VPNHide`](../../tweaks/VPNHide/) — current tweak covers it; just add `ru.beeline.mobile` to [`Filter.plist`](../../tweaks/VPNHide/Filter.plist).

---

## TL;DR

Two detectors, both via `CFNetworkCopySystemProxySettings.__SCOPED__`:

| # | Module | Mechanism | Address |
|---|---|---|---|
| 1 | AppsFlyer SDK (Obj-C) | `+[AppsFlyerUtils isVPNConnected]` — classic `rangeOfString:` for `tap/tun/ipsec/ppp` | `0x10423BA30` |
| 2 | `MBVpnDetector.SystemProxySettingsProvider` (Swift) | `CFNetworkCopySystemProxySettings` → `__SCOPED__.allKeys` → returns `[String]`, the consumer separately matches against `vpnProtocols` | `0x102D8AD38` |

`NWPathMonitor` **is used, but not for VPN** — `sub_100BBAF0C` calls `nw_path_uses_interface_type(path, .cellular)` for a one-shot callback and immediately `nw_path_monitor_cancel`s. Standard network reachability, `.other` is never queried.

**Mach-O imports:**

| Symbol | Status | Context |
|---|---|---|
| `_CFNetworkCopySystemProxySettings` | ✅ | 2 detectors |
| `_nw_path_uses_interface_type` | ✅ | reachability, not VPN |
| `_getifaddrs` | ❌ | not imported |
| `_nw_interface_get_type` | ❌ | not imported |
| `_CFNetworkCopyProxiesForURL` | ❌ | not imported |
| `_sysctl` / `_sysctlbyname` / `_dlopen` / `_dlsym` | ✅ | helpers, not VPN |
| `_getenv` / `_if_nametoindex` / `_SCDynamicStoreCopyProxies` / `_DNSServiceQueryRecord` | ❌ | — |

---

## Detector #1 — AppsFlyer

`+[AppsFlyerUtils isVPNConnected]` @ `0x10423BA30`. Byte-for-byte identical to MyMTS/CDEK/Urent — `rangeOfString:` for `tap/tun/ipsec/ppp`. Affects AppsFlyer telemetry (`AppsFlyerVPNCollectionEnabled` @ `0x104446505`), no UI impact.

---

## Detector #2 — `MBVpnDetector` (Swift)

A framework with DI architecture:

| Swift type | Mangled | What it is |
|---|---|---|
| `MBVpnDetector.MBVpnDetector` | `$s13MBVpnDetector13MBVpnDetectorVMa` | struct, main facade |
| `MBVpnDetector.SystemProxySettingsProvider` | `$s13MBVpnDetector27SystemProxySettingsProviderVMa` | struct, real impl |
| `MBVpnDetector.ProxySettingsProvider` | `$s13MBVpnDetector21ProxySettingsProviderP` | protocol (for test mocks) |

`sub_102D8AD38` — `SystemProxySettingsProvider`'s method that returns the **array of interface names from `__SCOPED__`**:

```swift
func getScopedInterfaces() -> [String] {
    guard let settings = CFNetworkCopySystemProxySettings() as? [String: Any] else { return [] }
    guard let scoped   = settings["__SCOPED__"]          as? [String: Any] else { return [] }
    var out: [String] = []
    for key in scoped.allKeys {
        if let s = key as? String { out.append(s) }
    }
    return out
}
```

The matching is done by the **consumer** (code in the main `MBVpnDetector.MBVpnDetector.isActive`, which we haven't dug deeper into here), using the property **`vpnProtocols`** (string `0x104f846c0`) — an array of substring patterns.

By symmetry with Gosuslugi (`vpnProtocolsKeysIdentifiers`), `vpnProtocols` is most likely also fed from remote-config. The current default content isn't visible from static analysis, but UI strings indicate the standard set (`tun/ipsec/...`).

---

## UI reaction

The app has **multiple points** where the warning is shown:

| String | Address | Context |
|---|---|---|
| `отключите VPN` | `0x1042d6880` | short toast |
| `Не удалось установить безопасное соединение с сервером. Пожалуйста, обновите приложение или отключите VPN` | `0x1042fe6c0` | TLS error |
| `если vpn выключен, сделайте снимок экрана и обратитесь в поддержку` | `0x10440e8c0` | escape instruction |
| `не получилось — попробуйте без vpn` | `0x10440e940` | retry prompt |

Debug / feature-flag infrastructure in strings:
- `PRFL-9677: Добавить уведомление о включенном VPN` (`0x104338db0`) — ticket ID under which the feature was added. Left in the binary.
- `Регулирует предупреждение об активном VPN` (`0x104338e00`) — description of the feature flag controlling the UI panel.

So the alert is **gated by a remote flag** — the server can temporarily turn off the notification even if the detector triggered.

---

## Telemetry

- `VPN_enabled` (`0x104358255`) — field sent with analytics.
- `AppsFlyerVPNCollectionEnabled` (`0x104446505`) — controls collection inside AppsFlyer SDK.

---

## Bypass via the existing `VPNHide` tweak

The `CFNetworkCopySystemProxySettings` hook strips all VPN interfaces from `__SCOPED__` → both detectors get a "clean" dict:

- Detector #1 (AppsFlyer): `rangeOfString:` matches nothing → `NO`.
- Detector #2 (`SystemProxySettingsProvider.getScopedInterfaces`): returns an array without VPN names → the consumer matching against `vpnProtocols` gets `false`.

Other hooks (`CFNetworkCopyProxiesForURL`, `nw_interface_get_type`, `nw_path_uses_interface_type`, `getifaddrs`) are NO-OPs on MyBeeline: either not imported or called with non-VPN types.

To activate, add to [`tweaks/VPNHide/Filter.plist`](../../tweaks/VPNHide/Filter.plist):

```
{ Filter = { Bundles = ( …, "ru.beeline.mobile" ); }; }
```

---

## Comparison

| | MyMTS | MegaFon | CDEK | DNS-SHOP | CPPK | Urent | Gosuslugi | Beeline |
|---|---|---|---|---|---|---|---|---|
| Detectors | 2 | 1 | 2 | 1 | 1 | 3 | 5 | 2 |
| `__SCOPED__` hardcoded | ✅ | ✅ | ✅×2 | ✅ | ❌ | ✅×3 | ✅ | ✅ (AppsFlyer) |
| `__SCOPED__` with external pattern list | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ (`vpnProtocols`) |
| `NWPathMonitor` for VPN | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| `HTTPProxy` top-level check | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ |
| `CFNetworkCopyProxiesForURL` | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ |
| Feature-flag gate on UI | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ (`PRFL-9677`) |
| Debug ticket comments in binary | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| VPNHide coverage | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

Beeline is a solid mid-complexity case: DI architecture (`ProxySettingsProvider` protocol + `SystemProxySettingsProvider` impl), remote-config VPN-pattern list like Gosuslugi, but without per-URL checks and without HTTPProxy-flag checks. Debug ticket comments leaked into the binary (`PRFL-9677`) — same as Urent with its full build path `/Users/user/builds/_csHvbAg/...`, CI traces.

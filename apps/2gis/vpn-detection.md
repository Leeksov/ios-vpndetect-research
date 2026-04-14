[🇷🇺 Русская версия](vpn-detection.ru.md)

# 2GIS — VPN / proxy detection

**Binary:** `ru.doublegis.grymmobile` v7.21.7 (arm64, Swift + Obj-C, ~183 MB)
**Method:** IDA Pro / Hex-Rays.
**Bypass:** [`tweaks/VPNHide`](../../tweaks/VPNHide/) — local detectors are covered by existing hooks; server-side block is bypassed **indirectly** (if the local scanner doesn't find VPN → no HTTP request to `/v1/vpn-detection-free` is initiated).

---

## TL;DR

The most elaborate VPN stack of all 8 analysed apps. Implemented as a set of **dedicated frameworks** with clear DI architecture:

| Framework | Role |
|---|---|
| `VNVPNCheckerAPI` | core logic: `VPNCheckerAPI`, `VPNStatusProvider`, `VPNDiagnosticsService`, `VPNRemoteConfig`, `DGIDHeadersProvider`, `GeoContextProvider` |
| `VNVPNCheckerAPIInterfaces` | protocols: `IVPNCheckerAPI`, `IVPNDiagnosticsService`, `IVPNRemoteConfig`, `IVPNStatusProvider`, `IGeoContextProvider` |
| `VNVPNCheckerUI` | UI: `VPNAlertPresenter`, `VPNAlertVC`, `VPNAlertVM`, `VPNBlockedWindow` |
| `VNCarPlay` | CarPlay full-screen block overlay (`CarPlayVPNBlockOverlayVC`) |

Three-layered detection:

| Layer | Mechanism | Address |
|---|---|---|
| AppsFlyer-style | `+[AppsFlyerUtils isVPNConnected]` — `__SCOPED__` → `rangeOfString:` for `tap/tun/ipsec/ppp` | `0x107199AAC` |
| FPNetworkInfoProvider (Obj-C) | `-[FPNetworkInfoProvider isVpnOn]` — same algorithm, directly in the app | `0x107653440` |
| **ProxySettingsScanner** (Swift) | `sub_106447010` — `__SCOPED__` → `String.hasPrefix` for `utun/tap/tun/ipsec/ppp`, returns the array of detected interfaces | `0x106447010` |
| **NWPathMonitor (`VPNStatusProvider`)** | reactively catches network changes, triggers the check | in libswiftNetwork overlay |
| **Server-side** | `GET /v1/vpn-detection-free` via `VPNCheckerAPI`; HTTP 451 = VPN detected, HTTP 200/empty = OK | `VNVPNCheckerAPI/VPNCheckerAPI.swift` |

---

## Server-side check — `VPNCheckerAPI`

The only analysed app where **the server** decides about VPN by client IP.

```
GET {vpnCheckerServerUrl}/v1/vpn-detection-free
Headers: {vpnHeaderKey}: ...
```

Configuration is in remote-config:
- `vpnCheckerServerUrl` (`0x10812a000`) — main endpoint
- `vpnCheckerFallbackServerUrl` (`0x10812a020`) — fallback
- `vpnHeaderKey` (`0x10812a03c`) — name of the custom header

Responses (from logs in the binary):

| Behaviour | Log |
|---|---|
| HTTP 451 Legal Reasons | `VPNCheckerAPI: результат — заблокирован (HTTP 451) — …` (`0x1084b8ce0`) — VPN detected |
| HTTP 200 | `VPNCheckerAPI: результат — не заблокирован (HTTP 200)` (`0x1084b8d90`) — OK |
| empty response | `VPNCheckerAPI: результат — не заблокирован (пустой ответ)` (`0x1084b8d30`) — OK |
| error + retry | `VPNCheckerAPI: первый запрос завершился с ошибкой, запускаем повторные попытки` (`0x1084b8b10`) |
| retries exhausted | `VPNCheckerAPI: все повторные попытки исчерпаны` (`0x1084b8c40`) |

---

## `VPNStatusProvider` — reactive trigger

Swift class `_TtC15VNVPNCheckerAPI17VPNStatusProvider` (`0x1084b90b0`). Subscribes to `NWPathMonitor`:

- `VPNStatusProvider: мониторинг сети запущен` (`0x1084b9110`)
- `VPNStatusProvider: сетевой путь изменился` (`0x1084b9150`)
- `VPNStatusProvider: определение VPN отключено через remote config` (`0x1084b9050`) — server-side kill switch
- `VPNStatusProvider: мониторинг сети остановлен` (`0x1084b8fd0`)

Uses `_vpnRemoteConfig` (`0x1084b8ad0`) and a service queue `ru.doublegis.grymmobile.vpn-status-provider` (`0x1084b8e10`).

The binary **does not import** `nw_path_uses_interface_type` directly — all calls go through the Swift overlay (`libswiftNetwork.dylib`).

---

## Local scanner — `sub_106447010`

Notably different from other apps — this is **not** a bool detector, but a function **returning the array** of found VPN interfaces, to be passed into `VPNCheckerAPI` as context.

```swift
func scanProxySettings() -> [String] {
    guard let settings = CFNetworkCopySystemProxySettings() as? [String: Any] else { return [] }
    guard let scoped   = settings["__SCOPED__"]          as? [String: Any] else { return [] }
    var found: [String] = []
    for (iface, info) in scoped {
        let lower = iface.lowercased()
        if lower.hasPrefix("utun") || lower.hasPrefix("tap") || lower.hasPrefix("tun")
           || lower.hasPrefix("ipsec") || lower.hasPrefix("ppp") {
            // reads a "P2P"-like flag from sub-dict <iface_info>
            if let extra = info[<key>] as? Bool, extra {
                found.append(iface)
            }
        }
    }
    return found
}
```

### Notable details

1. **`String.hasPrefix`** rather than `contains` — stricter than most (you can't hide a VPN in the suffix).
2. **`lowercased()`** before matching — case-insensitive.
3. Reads an **extra flag** from sub-dict `__SCOPED__[iface]` (key `5255760` + flag `0xE3` — 3-char string `"P2P"` or a similar marker like `kSCDynamicStoreSetupGlobal*`).

Despite all three differences our hook, which **removes** VPN keys from `__SCOPED__`, still works here — the scanner gets an empty dict → empty array → no VPN detected.

---

## UI reaction

2GIS is the **only app** that locks the entire UI behind a separate window:

| Class | Address | Role |
|---|---|---|
| `_TtC14VNVPNCheckerUI17VPNAlertPresenter` | `0x1084b92c0` | creates a UIWindow on top, presents the alert |
| `_TtC14VNVPNCheckerUI10VPNAlertVC` | `0x1084b9320` | alert view controller |
| `_TtC14VNVPNCheckerUI10VPNAlertVM` | `0x1084b94a0` | view model |
| `_TtC14VNVPNCheckerUI16VPNBlockedWindow` | `0x1084b9510` | dedicated `UIWindow` for the block |

Localisation strings: `vpnAlert.message` (`0x1084b91f0`), `vpnAlert.refreshButton` (`0x1084b9230`).

### CarPlay

A separate path for CarPlay mode:

| Class / string | Address | Role |
|---|---|---|
| `_TtC9VNCarPlay24CarPlayVPNBlockOverlayVC` | `0x108333040` | full-screen overlay in CarPlay |
| `tripToRestoreAfterVPNUnblock` | `0x108331e80` | saves the current trip |
| `routePointsToRestoreAfterVPNUnblock` | `0x108331ea0` | saves the route points |
| `[CarPlay] VPN detected, showing block screen` | `0x1083cf0d0` | log of CarPlay detect |
| `[CarPlay] VPN unblocked, restoring CarPlay` | `0x1083cf450` | restoration after unblock |
| `carPlayAppVPNBlockViewController` | `0x1083cef50` | property |
| `dashboardVPNBlockViewController` | `0x1083cef80` | property |
| `carplay.vpn block.retry button` / `carplay.vpn block.message` | `0x1083352d0`, `0x108335560` | localisation |

So when VPN is detected in CarPlay — the app **saves navigation state, blocks the screen, then on "unblock" restores the route**. Unique behaviour among the analysed apps.

---

## Debug artefacts

- `/Users/user/jenkins/agent/workspace/release-v4ios/v4ios-upload-to-testflight/v4ios/Src/CarPlay/Src/UI/CarPlayVPNBlockOverlayVC.swift` (`0x108333090`)
- `/Users/user/jenkins/agent/workspace/release-v4ios/v4ios-upload-to-testflight/v4ios/Src/VPNCheckerAPI/UI/VPNAlertVC.swift` (`0x1084b9420`)
- `VNVPNCheckerAPI/VPNCheckerAPI.swift` (`0x1084b8ba0`), `VPNStatusProvider.swift` (`0x1084b9020`), `VPNBlockedWindow.swift` (`0x1084b9580`), `VPNAlertPresenter.swift` (`0x1084b9290`), `VpnConnection` (`0x1084d7ae6`)

Jenkins CI path and full source-file paths leaked into the release binary — `DEBUG_INFORMATION_FORMAT = dwarf-with-dsym` + non-stripped debug symbols.

---

## Imports

| Symbol | Status | Context |
|---|---|---|
| `_CFNetworkCopySystemProxySettings` | ✅ | 3 detectors |
| `_nw_path_uses_interface_type` | ❌ | not imported directly |
| `_nw_interface_get_type` | ❌ | not imported |
| `_CFNetworkCopyProxiesForURL` | ❌ | not imported |
| `_getifaddrs` | ✅ | only for the IP address in `FPNetworkInfoProvider` |
| `_sysctl`/`_getenv`/`_dlopen`/`_dlsym`/`_if_nametoindex` | ✅ | not VPN |
| `_SCDynamicStoreCopyProxies`/`_DNSServiceQueryRecord` | ❌ | — |

---

## Bypass via the existing `VPNHide` tweak

Current hooks provide multi-layered coverage:

| Hook | Effect on 2GIS |
|---|---|
| `CFNetworkCopySystemProxySettings` | Strips VPN keys from `__SCOPED__` → AppsFlyer + FPNetworkInfoProvider + ProxySettingsScanner detectors all get empty arrays → all `false`. |
| `nw_interface_get_type` | If libswiftNetwork uses it for `NWInterface.type` → `VPNStatusProvider` never sees `.other` → monitoring doesn't trigger the server-check. |
| `nw_path_uses_interface_type` | Likewise, if the overlay goes through this function. |
| `CFNetworkCopyProxiesForURL` / `getifaddrs` | NO-OP (not imported / not for VPN). |

**Server-side check** (`/v1/vpn-detection-free`) — **not bypassed directly**. It won't fire only if it's **not initiated** by local scan/pathmonitor. Since we silence everything local, no one calls `VPNCheckerAPI.checkBlocked()`.

⚠️ **Exceptions**:
- If somewhere there's a **periodic timer** independent of local signals — it'll hit `/v1/vpn-detection-free` on schedule. The server returns 451 if the IP is in a VPN pool — UI will lock.
- **Fallback URL** + remote-config let MyDGS change the endpoint on the fly.

For full guarantee — add another hook to the tweak: substitute the `/v1/vpn-detection-free` response with empty (via swizzle of `NSURLSessionDataTask` / `URLSession.dataTask(with:)` filtered by URL).

To activate the current tweak, add to [`tweaks/VPNHide/Filter.plist`](../../tweaks/VPNHide/Filter.plist):

```
{ Filter = { Bundles = ( …, "ru.doublegis.grymmobile" ); }; }
```

---

## Comparison

| | MyMTS | MF | CDEK | DNS-SHOP | CPPK | Urent | Gosuslugi | Beeline | **2GIS** |
|---|---|---|---|---|---|---|---|---|---|
| Local detectors | 2 | 1 | 2 | 1 | 1 | 3 | 5 | 2 | **3** |
| Server-side detection | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ **HTTP 451** |
| Full-screen block window | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| CarPlay integration | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| State preservation (trip restore) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| Remote-config on the detector | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ |
| `String.hasPrefix` (not `contains`) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| Retry with fallback URL | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| DI architecture (protocol + impl) | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ |
| VPNHide coverage | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ (local) + ⚠️ server |

2GIS is the complexity champion. Everything that other apps do at one or two layers is here on three (local proxy + NWPath + server) with a full-screen UI block and a dedicated CarPlay layer. The team that wrote this clearly treated VPN detection as serious anti-cheat in a production game.

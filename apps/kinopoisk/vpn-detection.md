[🇷🇺 Русская версия](vpn-detection.ru.md)

# Kinopoisk — VPN / proxy detection

**Binary:** `Kinopoisk` v8.41.3 (arm64, Swift + Obj-C, ~165 MB)
**Method:** IDA Pro / Hex-Rays.
**Bypass:** [`tweaks/VPNHide`](../../tweaks/VPNHide/) — current tweak covers the local detectors; server-side `checkvpn` is bypassed **indirectly**.

---

## TL;DR

The most "complex" VPN stack among the analysed apps. Kinopoisk simultaneously **detects** the user's VPN and **manages** its own «Yandex VPN-Connect» (anti-blocking proxy for DRM/regional restrictions).

| Layer | Subsystem | Role |
|---|---|---|
| Detection | `+[AppsFlyerUtils isVPNConnected]` | stock AppsFlyer |
| Detection | `-[YALAFHTTPClient isVPNConnected]` | Obj-C, Yandex AppLib (shared with Yandex Market) |
| Detection | `MobileAdsCore.MACVpnStatusCheckerImpl` | shared SPB TV SDK (shared with Amediateka) |
| Detection (server-side) | `GET /tmgrdfrend/checkvpn` | backend check |
| Routing (NOT detection) | `YALVPNConnectManager` (full Obj-C class) | manages Yandex's own proxy for regional content |
| Config | `YALVPNConfig` / `YALVPNConfigApp` | remote-config with per-bundle-id settings + `minVersion` |
| Feature flag | `ios_block_vpn` | server-side kill switch |

**Imports:**

| Symbol | Status | Context |
|---|---|---|
| `_CFNetworkCopySystemProxySettings` | ✅ | 3 call sites (AppsFlyer + YAL + MAC) |
| `_nw_path_uses_interface_type` | ✅ | `YALNetworkMonitor.mapPathToStatus:` (cellular/wifi/wired classifier, **not VPN**) |
| `_getifaddrs` | ❌ | not imported |
| `_nw_interface_get_type` / `_CFNetworkCopyProxiesForURL` / `_SCDynamicStoreCopyProxies` / `_DNSServiceQueryRecord` | ❌ | — |

---

## Local detectors

### #1 — AppsFlyer

`+[AppsFlyerUtils isVPNConnected]` @ `0x1068C4FD0`. Stock. Controlled by `AppsFlyerVPNCollectionEnabled` (`0x1072b77f2`).

### #2 — `-[YALAFHTTPClient isVPNConnected]` @ `0x1042C992C`

Identical to the Yandex Market implementation (same Yandex AppLib): `__SCOPED__.allKeys` → `yal_foreachUsingBlock:` over a captured NSArray of needles → `[needle containsString:iface_name]` (reversed semantics). See [yandex-market/vpn-detection.md#detector-1](../yandex-market/vpn-detection.md#detector-1----yalafhttpclient-isvpnconnected) for details.

### #3 — `MobileAdsCore.MACVpnStatusCheckerImpl.check()` @ `0x106AC1378`

**Same class from the shared `MobileAdsCore` SDK as in Amediateka.** Tri-state result `0/1/2` (no/yes/unknown). Externally-supplied substring array via DI. See [amediateka/vpn-detection.md#detector-2--macvpnstatuscheckerimplcheck](../amediateka/vpn-detection.md#detector-2--macvpnstatuscheckerimplcheck) for details.

DI injection: property `vpnStatusChecker` (`0x1072e55e0`, `0x107c6dbf0`).

---

## Server-side check — `/tmgrdfrend/checkvpn`

Endpoint `0x10720234d`. Third analysed case with server-side detection (after 2GIS `/v1/vpn-detection-free` and Amediateka `403 Vpn`).

We didn't find a direct URLSession call in the decomp (most likely it's assembled from base + path somewhere in the Yandex networking layer), but the string is clear.

Activity is controlled by feature flag **`ios_block_vpn`** (`0x107213b15`) — the server can toggle the detection block on the fly.

---

## `YALVPNConnect` — NOT detection, but **routing**

A whole Obj-C subsystem to manage **Yandex's own** VPN-Connect (anti-blocking proxy for regional content):

| Class | Role |
|---|---|
| `YALVPNConnectManager` (`+shared`) | singleton managing connection status |
| `YALVPNConnectManagerObserversController` | KVO-like observers controller |
| `YALVPNConnectProductLocation` | model for "where the product is" (lat/lon) |
| `YALVPNConfig` | top-level remote-config |
| `YALVPNConfigApp` | per-bundle-id config with `appID` + `minVersion` |

Key `YALVPNConnectManager` methods:

- `+shared`, `init`, `dealloc`
- `updateWithAccountManager:`
- `setProductLocation:` / `setProductLocations:`
- `setDeviceGeoLocation:` / `setDeviceGeoLocations:`
- `setAdditionalParameters:`
- `addStatusObserver:` / `removeStatusObserver:`
- `addObservers` / `removeObservers` / `notifyObservers`
- `startMonitoring` / `stopMonitoring`
- `accountManager:didSetCurrentAccount:`
- `networkMonitorDidChangeStatus:fromOldStatus:`
- `locationTracker:didUpdateLocation:previousLocation:`
- `getAccountForStatusUpdate`
- `httpClient`
- `updateStatus:`

Subscribes to:
- `YALNetworkMonitor` (network reachability)
- `YALAccountManager` (login/logout)
- `YALLocationTracker` (geo updates)

Updates the internal "should Yandex VPN-Connect be enabled" via `YALVPNConfig.shouldBeEnabled` (`0x104300a50` — a large 0x224-byte method that parses a JSON config with `apps[]`, checks `appID == bundleID` and `version >= minVersion` via `semverComponents:greaterOrEqualThan:`).

This is **not a user-VPN detector**, but **management of Yandex's anti-blocking proxy** for regional streams. But in the binary both systems are mixed and frequently named `vpn*`.

---

## UI — full-screen "VPN Blocker"

6 analytics events indicate a fully-fledged full-screen VPN-blocker UI with several actions:

| Event | Address |
|---|---|
| `vpn_blocker_show` | `0x107208a62` |
| `vpn_blocker_hide` | `0x107208a73` |
| `vpn_blocker_reload` | `0x107208a84` |
| `vpn_blocker_close` | `0x107208a97` |
| `vpn_blocker_settings` | `0x107208aa9` |
| `vpn_blocker_openurl` | `0x107208abe` |

A full screen lockout with buttons «Reload», «Close», «Settings», «Open URL» (presumably FAQ).

### Alert texts

| Message | Address |
|---|---|
| `У вас включен VPN или в вашей стране доступен не весь каталог Кинопоиска` | `0x1070426b0` |
| `Что-то пошло не так. Возможно, вам нужно выключить VPN` | `0x1071ad950` |

The first text is telling — Kinopoisk **isn't sure** whether the issue is VPN or region availability. Consistent with the `MACVpnStatusChecker`'s tri-state logic (`unknown` case).

### Other markers

- `vpnFlag`, `vpnInactive`, `isVpnEnabled` — internal state flags
- `vpnConnectedTransformer` — Combine/Rx Transformer (like Amediateka's)
- `sessionBecameInvalidWithoutUnderlyingError` — error case, presumably mapping into the VPN blocker

---

## Bypass via the existing `VPNHide` tweak

The local part is fully covered:

| Detector | Hook | Effect |
|---|---|---|
| AppsFlyer | `CFNetworkCopySystemProxySettings` | empty `__SCOPED__` → `NO` |
| YALAFHTTPClient | `CFNetworkCopySystemProxySettings` | empty allKeys → block finds nothing → `NO` |
| MACVpnStatusCheckerImpl | `CFNetworkCopySystemProxySettings` | empty allKeys → `0` (no VPN, not unknown) |

Server-side `/tmgrdfrend/checkvpn` is **not bypassed directly**, but:
- By symmetry with 2GIS/Amediateka, the server is most likely hit only when local signals indicate something → if the local side stays silent, the backend isn't called. Verify empirically.
- Can be neutralised via URLSession swizzle + URL-matching on `/checkvpn`.

`YALVPNConnectManager` (Yandex proxy routing) doesn't need to be touched — it manages Yandex VPN-Connect, not the user detect. `__SCOPED__` hooks don't affect it.

To activate, add to [`tweaks/VPNHide/Filter.plist`](../../tweaks/VPNHide/Filter.plist):

```
{ Filter = { Bundles = ( …, "ru.kinopoisk" ); }; }
```

---

## Comparison

| | MyMTS | MF | CDEK | DNS | CPPK | Urent | Gos | Bln | 2GIS | Nlg | Rst | V&T | Amediateka | YM | **Kinopoisk** |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Local detectors | 2 | 1 | 2 | 1 | 1 | 3 | 5 | 2 | 3 | 0 | 1 | 1 | 2 | 2 | **3** |
| AppsFlyer-style | ✅ | — | ✅ | — | ❌ | ✅ | — | ✅ | ✅ | — | ✅ | ❌ | ✅ | ❌ | ✅ |
| Server-side | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ 451 | — | ❌ | ❌ | ✅ 403 Vpn | ❌ | ✅ `/checkvpn` |
| Tri-state on/off/unknown | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | — | ❌ | ❌ | ✅ | ❌ | **✅** (via MAC) |
| Shared SDK with another app | — | — | — | — | — | — | — | — | — | — | — | — | ✅ MobileAdsCore | ✅ YAL | **✅×2** (MAC + YAL) |
| Own proxy (anti-blocker) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | — | ❌ | ❌ | ❌ | ❌ | **✅** YALVPNConnect |
| Full-screen blocker UI | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ + CarPlay | — | ❌ | ❌ | ❌ | ❌ | ✅ (6 events) |
| VPNHide coverage | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ (local) | n/a | ✅ | ✅ | ✅ (local) | ✅ | ✅ (local) |

Kinopoisk is the only analysed app that has **its own VPN infrastructure for bypassing blocks** (`YALVPNConnect`) **and** multi-layered detection of the **user's** VPN. It's also the first app that reuses **two** shared SDKs with other analysed apps simultaneously: `MobileAdsCore` (with Amediateka) and Yandex AppLib YAL (with Yandex Market). An important watershed in ecosystems — Kinopoisk sits at the intersection of Yandex and the SPB TV / Mail.ru streaming world.

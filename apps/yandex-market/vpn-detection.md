[🇷🇺 Русская версия](vpn-detection.ru.md)

# Yandex Market — VPN / proxy detection

**Binary:** `Beru` v2026.11.1 (arm64, Swift + Obj-C, ~139 MB)
**Method:** IDA Pro / Hex-Rays.
**Bypass:** [`tweaks/VPNHide`](../../tweaks/VPNHide/) — current tweak covers it; add `ru.yandex.blue.market` to [`Filter.plist`](../../tweaks/VPNHide/Filter.plist).

---

## TL;DR

Three call sites for `CFNetworkCopySystemProxySettings`, all going to `__SCOPED__` scanning:

| # | Module | Mechanism | Address |
|---|---|---|---|
| 1 | `-[YALAFHTTPClient isVPNConnected]` (Obj-C, Yandex AppLib) | `__SCOPED__.allKeys` → `[needle containsString:iface]` for each needle from `unk_107E19870` | `0x102226EDC` |
| 2 | `MarketProtocols.VPNCheckerServiceImpl` (Swift) | `__SCOPED__.allKeys` → substring loop over an array of needles | `0x101EEDFDC` |
| 3 | thunk getter | returns the result of `CFNetworkCopySystemProxySettings()` for another consumer | `0x1025363D8` (8 bytes) |

`AppsFlyer SDK` is **not integrated** — `+[AppsFlyerUtils isVPNConnected]` is absent. Custom implementations only.

`NWPathMonitor` is **not used** — `_nw_path_uses_interface_type` isn't imported.

**Imports:**

| Symbol | Status | Context |
|---|---|---|
| `_CFNetworkCopySystemProxySettings` | ✅ | 3 call sites (2 detectors + 1 thunk) |
| `_nw_path_uses_interface_type` | ❌ | not imported |
| `_getifaddrs` | ✅ | helper (network info) |
| `_nw_interface_get_type` / `_CFNetworkCopyProxiesForURL` / `_SCDynamicStoreCopyProxies` / `_DNSServiceQueryRecord` | ❌ | — |

---

## Detector #1 — `-[YALAFHTTPClient isVPNConnected]`

Obj-C method on the HTTP client from Yandex internal lib (`YAL` — Yandex App Lib). Uses a block-foreach pattern:

```objc
- (BOOL)isVPNConnected {
    __block BOOL result = NO;
    CFDictionaryRef settings = CFNetworkCopySystemProxySettings();
    NSDictionary *scoped = settings[@"__SCOPED__"];
    if (![scoped isKindOfClass:NSDictionary.class] || scoped == nil) goto done;

    for (NSString *iface in [scoped allKeys]) {
        // unk_107E19870 — NSArray of hardcoded VPN-pattern needles
        [needles_array yal_foreachUsingBlock:^(id needle, BOOL *stop) {
            if ([iface isKindOfClass:NSString.class]) {
                if ([needle containsString:iface]) {  // ← reversed semantics!
                    result = YES;
                }
            }
        }];
    }
done:
    return result;
}
```

### Semantic detail

In `sub_10222BA64` (the inner block) the actual call is:

```
[needle containsString: iface_name]
```

That is — **needle contains the interface name as a substring**, not the other way around. So `unk_107E19870` is an array of **full or extended** names like `"utun0"`, `"ipsec0"`, `"tap0"`, and the check matches interfaces with base prefixes like `"utun"`, `"tap"` (because `"utun0".contains("utun")` = `YES`).

It triggers effectively on anything VPN-related, but is awkward to maintain — usually you do it the other way (`iface.contains(needle)`).

### Where `unk_107E19870` lives

A const NSArray in `__DATA_CONST`. We don't dump it, but by behaviour it's an array of `NSString` objects with VPN markers.

---

## Detector #2 — `MarketProtocols.VPNCheckerServiceImpl` (Swift)

`sub_101EEDFDC` — Swift implementation, performs analogous work via `Dictionary._unconditionallyBridgeFromObjectiveC` + a loop over allKeys + a chain of substring matches via an internal Swift-runtime helper (`sub_1015A3150`).

DI-injected via property `vpnCheckerService` (`0x106e260a0`, `0x1071cceb0`).

Swift protocol: `MarketProtocols.VPNCheckerService` (`$s15MarketProtocols17VPNCheckerServiceP` @ `0x1063d47f0`).
Concrete impl: `VPNCheckerServiceImpl` (`0x105fb5830`).

---

## Detector #3 — thunk

`sub_1025363D8` — 8 bytes, just `return CFNetworkCopySystemProxySettings()`. Used as a Swift bridge or for logging system settings.

---

## UI infrastructure

| Property / Selector | Address | Purpose |
|---|---|---|
| `isVPNInfoShown` | `0x106e26076`, `0x1071cce86` | Bool flag (probably for one-shot banner/informer display) |
| `vpnCheckerService` | `0x106e260a0`, `0x1071cceb0` | DI property for VPNCheckerService |

Everything is at the DI / stateful-flag level — **no explicit UI class like `VPNAlertVC` or `VPNInformerView`**. So the UI reaction is wired into shared components (e.g. the home-screen hero banner or the error-state controller for network errors) without a dedicated class.

---

## Bypass via the existing `VPNHide` tweak

The `CFNetworkCopySystemProxySettings` hook strips VPN keys from `__SCOPED__` → all 3 call sites get a "clean" dict:

- `[YALAFHTTPClient isVPNConnected]` → empty allKeys → block never finds a match → `NO`.
- `VPNCheckerServiceImpl` (`sub_101EEDFDC`) → empty allKeys → early `return 0`.
- Thunk getter → forwards the cleaned dict.

Other hooks for this binary are NO-OPs (symbols not imported).

To activate, add to [`tweaks/VPNHide/Filter.plist`](../../tweaks/VPNHide/Filter.plist):

```
{ Filter = { Bundles = ( …, "ru.yandex.blue.market" ); }; }
```

Legacy bundle ID: `ru.yandex.blue.market` (`Beru` — project name before Yandex acquisition, kept in executable + bundle ID).

---

## Comparison

| | MyMTS | MF | CDEK | DNS | CPPK | Urent | Gos | Bln | 2GIS | Nlg | Rst | V&T | Amediateka | **YM** |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Detectors | 2 | 1 | 2 | 1 | 1 | 3 | 5 | 2 | 3+srv | 0 | 1 | 1 | 2+srv | **2** |
| AppsFlyer-style | ✅ | — | ✅ | — | ❌ | ✅ | — | ✅ | ✅ | — | ✅ | ❌ | ✅ | ❌ (custom) |
| Custom Obj-C/Swift impl | ❌ | ✅ | ✅ | ✅ | ✅ | ✅×3 | ✅×3 | ✅ | ✅ | — | ✅ | ✅ | ✅ | **✅×2** |
| Server-side | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | — | ❌ | ❌ | ✅ | ❌ |
| `[needle containsString:iface]` (reversed semantics) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | — | ❌ | ❌ | ❌ | **✅** (unique) |
| DI property `vpnCheckerService` | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ | — | ❌ | ❌ | ✅ | ✅ |
| VPNHide coverage | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | n/a | ✅ | ✅ | ✅ | ✅ |

Yandex Market is a mid-standard case — **no** AppsFlyer scaffolding, **no** server-side, but with two duplicate implementations (Obj-C + Swift) and DI architecture. Unique trait — reversed substring-match semantics `[needle containsString:iface]` in the Obj-C detector.

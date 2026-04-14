[🇷🇺 Русская версия](vpn-detection.ru.md)

# Yandex Eats — VPN / proxy detection

**Binary:** `YandexEats` v8.102.1 (arm64, Swift + Obj-C, ~221 MB)
**Method:** IDA Pro / Hex-Rays.
**Bypass:** [`tweaks/VPNHide`](../../tweaks/VPNHide/) — current tweak covers it; add `com.appkode.foodfox` to [`Filter.plist`](../../tweaks/VPNHide/Filter.plist).

---

## TL;DR

Two-to-three call sites for `CFNetworkCopySystemProxySettings`, plus a trampoline `j__CFNetworkCopySystemProxySettings`. No AppsFlyer SDK (like Market/V&T), **no** `MobileAdsCore` (unlike Kinopoisk / Amediateka).

| # | Module | Mechanism | Address |
|---|---|---|---|
| 1 | `-[YALAFHTTPClient isVPNConnected]` (Obj-C, Yandex AppLib) | `__SCOPED__.allKeys` → `[needle containsString:iface]` (reversed semantics, like in Yandex Market) | `0x105E57318` |
| 2 | `YXFintechFoundation.VPNConnectionCheckerImpl` (Swift) | Swift wrapper over a `__SCOPED__` scan | `sub_1037CFD4C` |
| 3 | additional wrapper / consumer | uses the same dictionary | `sub_1063F7788` |

`NWPathMonitor` is **not for VPN** — `_nw_path_uses_interface_type` is only called from `-[YALNetworkMonitor mapPathToStatus:]` for cellular/wifi/wired classification.

**Mach-O imports:**

| Symbol | Status | Context |
|---|---|---|
| `_CFNetworkCopySystemProxySettings` | ✅ | 3 call sites + trampoline |
| `_nw_path_uses_interface_type` | ✅ | reachability (cellular/wifi/wired), not VPN |
| `_getifaddrs` / `_sysctl` / `_getenv` / `_dlopen` | ✅ | helpers |
| `_nw_interface_get_type` / `_CFNetworkCopyProxiesForURL` / `_SCDynamicStoreCopyProxies` / `_DNSServiceQueryRecord` | ❌ | — |

---

## Architecture

### Swift classes

| Type | Mangled | Address |
|---|---|---|
| `YXFintechFoundation.VPNConnectionCheckerImpl` (class) | `$s19YXFintechFoundation24VPNConnectionCheckerImplCMa` | `0x1061617c0` |
| `EatsSDKExperiments.VPNCheckConfig` (struct, Codable) | `$s18EatsSDKExperiments14VPNCheckConfigVMa` | `0x102d58e8c` |
| `EatsAccountManagerImpl.VpnBlockingInitAnalyticsEvent` (struct) | `$s22EatsAccountManagerImpl29VpnBlockingInitAnalyticsEventVMa` | `0x100a3f78c` |
| `EatsAccountManagerImpl.VpnBlockingShowenAnalyticsEvent` (typo!) | `$s22EatsAccountManagerImpl31VpnBlockingShowenAnalyticsEventVMa` | `0x100a3f99c` |
| `EatsAccountManagerImpl.VpnBlockingUpdatedAnalyticsEvent` (struct) | `$s22EatsAccountManagerImpl32VpnBlockingUpdatedAnalyticsEventVMa` | `0x100a3fa3c` |

### Framework breakdown

- **`YXFintechFoundation`** — Yandex Fintech Foundation. **Notable** — the VPN checker sits in the **fintech foundation** (payments / KYC), not in a generic networking layer. Most likely shared between Yandex Market, Yandex Eats, Yandex Taxi etc.
- **`EatsSDKExperiments`** — A/B experiments for Yandex Eats; `VPNCheckConfig` (Codable) is the remote-config struct holding detector parameters (on/off, pattern list, check frequency etc.).
- **`EatsAccountManagerImpl`** — account module; **3 analytics events** for VPN blocking:
  - `VpnBlockingInit` — VPN blocker shown for the first time
  - `VpnBlockingShowen` (sic, `Showen` typo instead of `Shown` — left in production)
  - `VpnBlockingUpdated` — status updated

### What's **absent**

- **AppsFlyer SDK** — no `+[AppsFlyerUtils isVPNConnected]`. Custom implementations.
- **`MobileAdsCore`** (SPB TV SDK) — absent, unlike Kinopoisk and Amediateka.
- **Server-side `/checkvpn`** — no URL endpoint found (but `EatsSDKExperiments.VPNCheckConfig` hints at A/B-configurable behaviour).

---

## Detector #1 — `-[YALAFHTTPClient isVPNConnected]` @ `0x105E57318`

Standard Yandex AppLib implementation — identical to the one in Yandex Market and Kinopoisk. See [yandex-market/vpn-detection.md](../yandex-market/vpn-detection.md#detector-1----yalafhttpclient-isvpnconnected) for details.

Reversed semantics: `[needle containsString:iface_name]`, where the needle is pulled from a const NSArray.

---

## Detector #2 — `VPNConnectionCheckerImpl` (Swift)

`sub_1037CFD4C` (~824 bytes) — Swift implementation of `YXFintechFoundation.VPNConnectionCheckerImpl`. Under the hood — standard pattern: `CFNetworkCopySystemProxySettings()` → bridge to `[String: Any]` → `__SCOPED__.allKeys` → substring match via a helper.

DI-injected via property — name not localised, but most likely `vpnChecker` or `vpnConnectionChecker`.

---

## Detector #3 — `sub_1063F7788` (~780 bytes)

Additional consumer of `CFNetworkCopySystemProxySettings`. Likely a wrapper over the same data for another layer (e.g. Sentry/telemetry or EatsAccountManager checkout flow).

---

## UI / reaction

Unlike 2GIS / Kinopoisk, **dedicated VPN classes** (like `VPNAlertVC`, `VPNBlockedWindow`) are **not found**. The reaction is probably implemented inline in the main view controllers, gated by `EatsSDKExperiments.VPNCheckConfig` (if the experiment is on — show blocker, else don't).

3 analytics events (`Init/Showen/Updated`) point to a fully stateful VPN blocker (shown → state updated → closed).

---

## Trampoline `j__CFNetworkCopySystemProxySettings` @ `0x10615BB98`

4 bytes, a direct `B` (jump) to the import. Compiler optimisation: some Swift code calls `CFNetworkCopySystemProxySettings` frequently and the compiler emitted a thunk instead of inline call. Not a separate detector.

---

## Bypass via the existing `VPNHide` tweak

The `CFNetworkCopySystemProxySettings` hook strips VPN keys from `__SCOPED__` → all 3 detectors get an empty `__SCOPED__`:

| Detector | Effect |
|---|---|
| `-[YALAFHTTPClient isVPNConnected]` | empty allKeys → block finds nothing → `NO` |
| `VPNConnectionCheckerImpl` | empty allKeys → early return false |
| `sub_1063F7788` | same |

To activate, add to [`tweaks/VPNHide/Filter.plist`](../../tweaks/VPNHide/Filter.plist):

```
{ Filter = { Bundles = ( …, "com.appkode.foodfox" ); }; }
```

Legacy bundle ID: `com.appkode.foodfox` (AppKode is the developer, FoodFox is the project name pre-acquisition by Yandex).

---

## Comparison

| | MyMTS | MF | CDEK | DNS | CPPK | Urent | Gos | Bln | 2GIS | Nlg | Rst | V&T | Amediateka | YM | Kinopoisk | **Y.Eats** |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Local detectors | 2 | 1 | 2 | 1 | 1 | 3 | 5 | 2 | 3 | 0 | 1 | 1 | 2 | 2 | 3 | **3** |
| AppsFlyer-style | ✅ | — | ✅ | — | ❌ | ✅ | — | ✅ | ✅ | — | ✅ | ❌ | ✅ | ❌ | ✅ | ❌ |
| YAL (Yandex AppLib) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | — | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ |
| MobileAdsCore (SPB TV) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | — | ❌ | ❌ | ✅ | ❌ | ✅ | ❌ |
| Custom Swift checker | ❌ | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | — | ❌ | ✅ | ❌ | ✅ | ❌ | **✅** (`YXFintechFoundation`) |
| Server-side | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | — | ❌ | ❌ | ✅ | ❌ | ✅ | ❌ |
| Detector in fintech module | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | — | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ **(unique)** |
| Remote-config struct | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ | — | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ |
| `Showen` typo in analytics | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | — | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| VPNHide coverage | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ (local) | n/a | ✅ | ✅ | ✅ (local) | ✅ | ✅ (local) | ✅ |

Yandex Eats is the **third** app with the YAL Obj-C detector (after Market and Kinopoisk), and the only one where the main Swift checker lives in **`YXFintechFoundation`** — Yandex's shared fintech foundation. Implies the same checker is used in Yandex Taxi, Yandex Market, Yandex Delivery and other Yandex services with fintech functionality, and Yandex centrally monitors VPN at the payments-infrastructure level (probably for compliance / antifraud).

The typo `VpnBlockingShowenAnalyticsEvent` (instead of `Shown`) shipped to production and stays there — characteristic of analytics written quickly, missed in review, and not cheap to rename in relational metrics tables later.

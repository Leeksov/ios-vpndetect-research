[🇷🇺 Русская версия](vpn-detection.ru.md)

# Moy Nalog (Мой налог) — VPN / proxy detection

**Binary:** `selfemployed` v4.7.1 (arm64, Obj-C + Swift)
**Method:** IDA Pro / Hex-Rays.

---

## TL;DR

**The app does not detect VPN.**

The entire detection stack found in other analysed apps is completely absent:

- No `CFNetworkCopySystemProxySettings` import
- No `nw_path_uses_interface_type` / `nw_interface_get_type` import
- No `CFNetworkCopyProxiesForURL` import
- No `SCDynamicStoreCopyProxies` / `DNSServiceQueryRecord` import
- No Swift/Obj-C strings like `isVPN*`, `vpn*`, `isProxy`, `VpnChecker`, `VPNDetector`, `VPNMonitoring` etc.
- No Russian strings «VPN», «впн», «Включён VPN» etc.
- No `__SCOPED__` string.

All hits for the regex `VPN|vpn|proxy|ipsec` are **false positives** from system libraries linked into the binary:

| Hit | Origin |
|---|---|
| `(MPLS-labeled VPN)`, `ipsecEndSystem`, `ipsecTunnel`, `ipsecUser`, `ipsec3`, `ipsec4`, `ipsec Internet Key Exchange` | OpenSSL/BoringSSL X.509 policy OID names (static part of the displayable-name table). |
| `http_proxy`, `all_proxy`, `NO_PROXY`, `SOCKS-PROXY`, `HAPROXY`, `Proxy-Connection`, `Proxy-authenticate`, `CONNECT to proxy`, `Excessive user name length for proxy auth` | libcurl — internal strings for reading `http_proxy`/`HTTPS_PROXY`/`NO_PROXY` env vars and CONNECT tunnels. |
| `isAppDelegateProxyEnabled`, `App Delegate Proxy is disabled`, `proxyOriginalDelegate`, `createAppDelegateProxy` | Firebase/FirebaseMessaging — AppDelegate swizzling. |
| `ProxyFaceReporter`, `ProxyReporter`, `ProxyFeedbackReporter`, `initFromCreatedFaceSession:withCreatedProxyReporter:` | VisionLabs / LUNA ID — biometric face recognition (used for self-employed identity verification). |
| `com.huawei.hms.push.proxy`, `hmsPushProxyDev`, `/rest/proxy/v1/apply`, `/rest/proxy/v1/cancel` | Huawei Push SDK — only for HMS devices, unrelated to VPN. |
| `isSessionScoped`, `sessionScoped`, `ItemScopedCustomParameterLimitReached` | Firebase Analytics — event filter scoping. |
| `ScopedRecognizerHandle` | C++ template for the face recognizer. |

## Imports

| Symbol | Status | Where used |
|---|---|---|
| `_getifaddrs` | ✅ | sole caller — `sub_10070AE0C`: helper that reads IP addresses to a string via `inet_ntop` (libcurl-style). **Not VPN.** |
| `_sysctl` / `_sysctlbyname` | ✅ | uptime / hw model (analytics). |
| `_getenv` | ✅ | SDK env / libcurl proxy-env reads. |
| `_dlopen` / `_dlsym` | ✅ | dynamic loading, not VPN. |
| `_if_nametoindex` | ✅ | helper (libcurl). |
| `_CFNetworkCopySystemProxySettings` | ❌ | **not imported** |
| `_nw_path_uses_interface_type` | ❌ | **not imported** |
| `_nw_interface_get_type` | ❌ | **not imported** |
| `_CFNetworkCopyProxiesForURL` | ❌ | **not imported** |
| `_SCDynamicStoreCopyProxies` | ❌ | **not imported** |
| `_DNSServiceQueryRecord` | ❌ | **not imported** |

---

## Bypass

**Not needed.** The app works over VPN and proxy as-is, doesn't probe anything, doesn't block anything, doesn't show any VPN snackbars.

There's no point adding `com.gnivts.selfemployed` to `VPNHide`'s `Filter.plist` — there's nothing to hook.

---

## Context

Moy Nalog is the Russian Federal Tax Service (FNS) app for self-employed citizens. Works with the tax API, biometrics (VisionLabs for identity verification on registration), payments. It makes sense that the FNS team **doesn't see VPN as a threat** — it's not marketing analytics, it's a government service tied to taxpayer ID (INN) and biometrics. Sanctions-style IP-geo blocking is also pointless: the app only works for Russian residents identified by passport.

Comparison with the other analysed apps:

| App | Detectors |
|---|---|
| MyMTS | 2 |
| MF | 1 |
| CDEK | 2 |
| DNS-SHOP | 1 |
| CPPK | 1 |
| Urent | 3 |
| Gosuslugi | 5 |
| Beeline | 2 |
| 2GIS | 3 + server-side |
| **Moy Nalog** | **0** |

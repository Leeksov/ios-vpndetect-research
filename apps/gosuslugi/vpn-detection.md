[🇷🇺 Русская версия](vpn-detection.ru.md)

# Gosuslugi — VPN / proxy detection

**Binary:** `Gosuslugi` v25.3.0 (arm64, Swift + Obj-C, large app — ~131 MB)
**Method:** IDA Pro / Hex-Rays.
**Bypass:** [`tweaks/VPNHide`](../../tweaks/VPNHide/) — the existing tweak covers most paths, with caveats (see below).

---

## TL;DR

The most elaborate detector among the analysed apps. Lives in **two separate frameworks**: `GUNetwork.VPNCheckService` and a standalone `VPNCheckService` framework (with its own DI container `VPNCheckAssembly`, `SpeedTestEvent` events, `VPNCheckServiceStrings` string resources). **5 different functions** are used, hooking into `CFNetworkCopySystemProxySettings` / `CFNetworkCopyProxiesForURL`:

| # | Function | Mechanism | Where |
|---|---|---|---|
| 1 | `sub_100538700` | `__SCOPED__` → **hardcoded** array of 5 substrings `tap/tun/ppp/ipsec/utun` | main app |
| 2 | `sub_10004BE1C` | `__SCOPED__` → **externally supplied** substring array (`vpnProtocolsKeysIdentifiers`) | `GUNetwork.VPNCheckService` |
| 3 | `sub_101124D5C` | same as #2 | standalone `VPNCheckService.VPNCheckService` |
| 4 | `sub_1005451AC` | `CFNetworkCopySystemProxySettings` → top-level keys `HTTPProxy` / `HTTPSProxy` | main app — catches ANY system HTTP(S) proxy |
| 5 | `sub_1005383B0` / `sub_103687240` | `CFNetworkCopyProxiesForURL(url, settings)` → checks `kCFProxyHostNameKey` of the first result | dup |

`NWPathMonitor` **is** used, but **not for VPN** — function `sub_1057E2938` (very heavy, looks like Rust-compiled code) sequentially queries `nw_path_uses_interface_type` with `.wifi`, `.wired`, `.cellular`, plus `CTTelephonyNetworkInfo.currentRadioAccessTechnology` — a **connection-type classifier** (wifi / wired / cellular / 2G-5G), produces one of those enum cases. `.other` is never queried.

**Mach-O imports (VPN-relevant only):**

| Symbol | Status | Used for |
|---|---|---|
| `_CFNetworkCopySystemProxySettings` | ✅ | 6 different functions (detectors 1–5 + AppsFlyer-like) |
| `_CFNetworkCopyProxiesForURL` | ✅ | detector 5 |
| `_nw_path_uses_interface_type` | ✅ | **not** for VPN, only wifi/cellular/wired classification |
| `_getifaddrs` | ✅ | not for VPN (network-info helpers) |
| `_sysctl` / `_sysctlbyname` / `_getenv` / `_dlopen` / `_dlsym` / `_if_nametoindex` | ✅ | not for VPN |
| `_SCDynamicStoreCopyProxies` | ❌ | — |
| `_DNSServiceQueryRecord` | ❌ | — |
| `_nw_interface_get_type` / `_nw_path_enumerate_interfaces` | ❌ | — |

---

## Detector #1 — hardcoded `__SCOPED__` scan (`sub_100538700`)

Standard algorithm, like in DNS-SHOP / MegaFon. Substrings hardcoded right in the function:

| Literal | Bytes | ASCII |
|---|---|---|
| `7364980` | `74 61 70 00` | `tap` |
| `7239028` | `74 75 6E 00` | `tun` |
| `7368816` | `70 70 70 00` | `ppp` |
| `0x6365_7370_69` | `69 70 73 65 63` | `ipsec` |
| `1853191285` | `75 74 75 6E` | `utun` |

Helper `sub_10004C1B8` is `String.contains(substring)`.

The 5-string array lives in global storage `qword_107610D08`, released via `swift_arrayDestroy(…, 5, …)`.

---

## Detectors #2 / #3 — configurable `__SCOPED__` scan

`sub_10004BE1C` (from `GUNetwork.VPNCheckService`) and `sub_101124D5C` (from the standalone `VPNCheckService` framework) — twin implementations of the same thing. They differ from #1 in that the substring array is **not hardcoded** but pulled from an instance field of the class:

```
v11 = *(v0 + 16);     // GUNetwork.VPNCheckService.vpnProtocolsKeysIdentifiers
v11 = *(v0 + 152);    // VPNCheckService.VPNCheckService.vpnProtocolsKeysIdentifiers
```

The field name is visible in string `0x1059e1df0` — `vpnProtocolsKeysIdentifiers`. It's a `[String]` array, most likely populated:
- either from an Info.plist / asset bundle,
- or from remote config (Firebase / backend flag),
- or from hardcoded defaults with override capability.

This gives Gosuslugi the ability to **add new VPN patterns without releasing an update** — if some new `wg_*` / `vpn_*` / `shadowsocks_*` interface appears tomorrow, just push an updated config. Unique among the analysed apps.

The loop is the same: for each key in `__SCOPED__` → for each substring in `vpnProtocolsKeysIdentifiers` → `String.contains()`. On match — `return 1`.

---

## Detector #4 — direct proxy check (`sub_1005451AC`)

Doesn't go into `__SCOPED__`. Reads top-level keys of the system dictionary:

| Swift literal | Bytes | ASCII |
|---|---|---|
| `0x786F725050545448` + `0xE900000000000079` | `48 54 54 50 50 72 6F 78 79` | `HTTPProxy` (9) |
| `0x6F72505350545448` + `0xEA00000000007978` | `48 54 54 50 53 50 72 6F 78 79` | `HTTPSProxy` (10) |

If **either** key is in the dict — returns `true`. So this function catches **any** system HTTP/HTTPS proxy — Charles, Proxyman, corporate PAC, WireGuard-over-HTTP-proxy and so on. Not VPN in the strict sense, but any MITM.

---

## Detector #5 — per-URL proxy resolver (`sub_1005383B0` / `sub_103687240`)

Two identical functions (a duplicate). Scheme:

```swift
let url = URL(string: "…")!         // 24 bytes long, lk.gosuslugi resource or similar
let settings = CFNetworkCopySystemProxySettings()
let proxies: CFArray = CFNetworkCopyProxiesForURL(url as CFURL, settings)
let dict = (proxies as? [[String: Any]])?.first
let host = dict?[kCFProxyHostNameKey as String] as? String
if host != expected && host != nil {
    return true     // VPN/proxy detected
}
return false
```

Logic: if a proxy resolves for a specific URL and its hostname **isn't equal** to the expected one (e.g. a trusted CDN endpoint) — the traffic is considered to be going through an external proxy/VPN.

This is the **trickiest** of the 5 checks: it fires only when the VPN actually breaks routing to a specific URL.

---

## Reaction to detection

**UI:**
- Property `isVPNEnabled` (string `0x1059e8e8b`)
- Property `vpnActiveBefore` (string `0x1059e8db8`) — to detect state change between launches
- Debug flag `debugDoNotShowVPNSnackbar` (string `0x1059e9030`) — available to developers for suppression
- Event name in logs: **`снекбар VPN`** (string `0x105a0d9e0`)
- `VPNSnackbarMessage` enum (metadata `$s15VPNCheckService18VPNSnackbarMessageOMa`) and `VPNCheckServiceStrings` — localised snackbar strings

**Analytics:**
- Event-name regex: **`^(vpn_on)|(vpn_off)|(vpn_unknown)$`** (string `0x105a6d940`)
- Three states: VPN on, off, undetermined (`vpn_unknown`)

**Additional:**
- `-[EnvironmentDataProvider isVpnEnabled]` in `GUMetricsImplementation` (`0x100536fbc`) — exposed to metrics
- `vpnEnabled` (Objective-C property, string `0x1059e0ac0`)
- `vpnService` (string `0x1059e0db1`)

---

## Bypass via the existing `VPNHide` tweak

All 5 detectors are covered:

| Detector | Hook | Effect |
|---|---|---|
| #1 (`sub_100538700`) | `CFNetworkCopySystemProxySettings` | `__SCOPED__` cleaned of VPN keys → no substring matches → `false`. |
| #2 (`sub_10004BE1C`) | `CFNetworkCopySystemProxySettings` | Same; the remote-config substring list is irrelevant since no candidate keys remain. |
| #3 (`sub_101124D5C`) | `CFNetworkCopySystemProxySettings` | Same. |
| #4 (`sub_1005451AC`) | `CFNetworkCopySystemProxySettings` | Top-level `HTTPProxy`/`HTTPSProxy`/`SOCKSProxy` and `*Enable` flags wiped → check returns `false`. |
| #5 (`sub_1005383B0` / `sub_103687240`) | `CFNetworkCopyProxiesForURL` | Hook unconditionally returns `[{ kCFProxyTypeKey: kCFProxyTypeNone }]` → `kCFProxyHostNameKey` absent → `swift_dynamicCast` to `String` fails → early `return 0` (LABEL_19/20). |

Caveat:
- ⚠️ Detectors #2/#3 use an **externally supplied** substring array from `vpnProtocolsKeysIdentifiers`. If remote config ever adds strings not in our filter (e.g. hypothetically `"shadowsocks"` or `"mesh0"`), our hook won't strip them from `__SCOPED__` and the detector could match. The current filter (`tap/tun/ppp/ipsec/utun/wg`) covers all currently known VPN tech. If needed, edit the `kVPNNeedles` array in [`Tweak.mm`](../../tweaks/VPNHide/Tweak.mm).

To activate, add to [`tweaks/VPNHide/Filter.plist`](../../tweaks/VPNHide/Filter.plist):

```
{ Filter = { Bundles = ( …, "com.minsvyaz.gosuslugi" ); }; }
```

---

## Comparison with other apps

| | MyMTS | MegaFon | CDEK | DNS-SHOP | CPPK | Urent | Gosuslugi |
|---|---|---|---|---|---|---|---|
| Number of detectors | 2 | 1 | 2 | 1 | 1 | 3 | **5** |
| `__SCOPED__` with hardcoded patterns | ✅ | ✅ | ✅ | ✅ | ❌ | ✅×3 | ✅ |
| `__SCOPED__` with remote-config patterns | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ **(unique)** |
| Top-level `HTTPProxy/HTTPSProxy` check | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| `CFNetworkCopyProxiesForURL` per-URL | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| `NWPathMonitor` for VPN | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ |
| Dual implementation in separate frameworks | ❌ | ❌ | ✅ (AppsFlyer + Pod) | ❌ | ❌ | ✅ (Services + app) | ✅ (`GUNetwork` + `VPNCheckService`) |
| Three-state analytics (on/off/**unknown**) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| Debug suppression flag | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ `debugDoNotShowVPNSnackbar` |
| VPNHide coverage | ✅ | ✅ | ✅ | ✅ | ⚠️ | ✅ | ⚠️ 4/5 out of the box |

Gosuslugi stands out heavily in detector quality. Unique traits:
- **Remote-configurable** list of VPN interface substrings (no need to wait for a release).
- Multi-pronged approach: 5 different functions covering different proxy/VPN categories.
- Three-valued analytics with an "unknown" state — they consciously work with detection ambiguity.
- Developer debug flag — clear sign the code is actively maintained.

This system is most likely part of the `GUNetwork`/`VPNCheckService` shared framework also used in other Mintsifry (Russian Ministry of Digital Development) apps.

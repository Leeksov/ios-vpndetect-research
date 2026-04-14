[🇷🇺 Русская версия](vpn-detection.ru.md)

# MyMTS — VPN / proxy detection

**Binary:** `MtsServiceRu` (arm64, iOS build, Swift + Obj-C)
**Method:** IDA Pro / Hex-Rays, confirmed via strings and xrefs.
**Bypass:** [`tweaks/VPNHide`](../../tweaks/VPNHide/).

---

## TL;DR

The app has **two independent VPN detectors**:

| # | Module | Mechanism | Address |
|---|---|---|---|
| 1 | AppsFlyer SDK (Obj-C) | `CFNetworkCopySystemProxySettings` → enumerate `__SCOPED__` keys → substrings `tap`/`tun`/`ipsec`/`ppp` | `0x10142678c` |
| 2 | `GeoWidgetSDK.VPNDetectorService` (Swift) | `NWPathMonitor` + `NWPath.usesInterfaceType(.other)` | init `0x100B94F6C`, handler `0x100B951C8` |

The result is published via `Combine` and reaches `MyMtsKit.VpnDetectorListener` subscribers: `VpnEnabledConditionParam` (feature-flag) and `ScreenManager` (snackbar «Включён VPN…»). AppMetrica gets the field `is_vpn_enabled`.

**Not present in the binary:** `getifaddrs`-based enumeration, parsing the routing table via `sysctl(net.route.0)`, `getenv("http_proxy")` checks, DNS cross-check via `DNSServiceQueryRecord`, dynamic loading of SystemConfiguration via `dlopen`, enumeration of `__dyld_image_name` to catch injected VPN dylibs.

The imports `_getifaddrs`, `_sysctl`, `_sysctlbyname`, `_getenv`, `_dlopen`, `_DNSServiceQueryRecord`, `__dyld_get_image_name` **are present** but used in unrelated places: uptime / boot timestamp (`+[AMAPlatformDescription bootTimestamp]`), hardware model (`+[AFSystemInfo machineModel]`), analytics env-parsing, OpenTelemetry mDNS services etc.

---

## Detector #1 — AppsFlyer: `+[AppsFlyerUtils isVPNConnected]`

**Address:** `0x10142678c`. Entry point — a classic Obj-C class method, returns `BOOL`.

### Pseudocode

```objc
+ (BOOL)isVPNConnected {
    CFDictionaryRef settings = CFNetworkCopySystemProxySettings();
    NSDictionary   *scoped   = settings[@"__SCOPED__"];
    for (NSString *iface in scoped.allKeys) {
        if ([iface rangeOfString:@"tap"].location   != NSNotFound ||
            [iface rangeOfString:@"tun"].location   != NSNotFound ||
            [iface rangeOfString:@"ipsec"].location != NSNotFound ||
            [iface rangeOfString:@"ppp"].location   != NSNotFound)
        {
            return YES;
        }
    }
    return NO;
}
```

### Why it works

`CFNetworkCopySystemProxySettings` returns the system proxy-settings dictionary. Under the `__SCOPED__` key sits another dictionary — per-interface settings whose keys are the **names of network interfaces** active in the system. Any VPN client bringing up its own interface (`utun0`, `ipsec0`, `ppp0`, `tap0`) will end up there. The check is by **substring**, not by prefix, so `utun0` matches as `tun`.

### Where it's used

Used only inside the AppsFlyer SDK for the `AppsFlyerVPNCollectionEnabled` / `VPNCollectionEnabled` flag. Affects what the SDK reports to its analytics. No direct UI effect — but **data is sent to AppsFlyer**, worth noting for reverse / telemetry analysis.

---

## Detector #2 — `GeoWidgetSDK.VPNDetectorService`

**Swift class:** `_TtC12GeoWidgetSDK18VPNDetectorService` (mangled), metadata accessor `$s12GeoWidgetSDK18VPNDetectorServiceCMa` at `0x100b952c0`.

**Reconstructed methods:**
- `init` — `sub_100B94F6C`
- `pathUpdateHandler` — `sub_100B951C8` (partial-applied via `sub_100B95304`)

### `init` pseudocode

```swift
init() {
    self.queue   = DispatchQueue(
        label: "network.monitor",
        qos: .unspecified,
        attributes: [],
        autoreleaseFrequency: .workItem,
        target: nil
    )
    self.monitor = NWPathMonitor()
    self.subject = CurrentValueSubject<Bool, Never>(false)

    monitor.pathUpdateHandler = { [weak self] path in
        let isVPN = path.usesInterfaceType(.other)
        self?.subject.send(isVPN)
    }
    monitor.start(queue: queue)
}
```

In disasm the queue label is visible as two 8-byte Swift small-string literals: `0x2E6B726F7774656E` + `0xEF726F74696E6F6D` → `"network.monitor"`.

### `pathUpdateHandler` pseudocode

```swift
let type: NWInterface.InterfaceType = .other   // raw = 0
let isVPN = path.usesInterfaceType(type)
subject.send(isVPN)
```

In the decomp of `sub_100B951C8`:

```
v3 = type metadata accessor for NWInterface.InterfaceType(0);
(*(VWT->destructiveInjectEnumTag))(v5, 0xFFFFFFFF, v3);   // enum tag -> .other
v6 = NWPath.usesInterfaceType(_:)(v5);
CurrentValueSubject.send(_:)(&v6);
```

### Why it works

`NWPathMonitor` (Network.framework) classifies interfaces into `NWInterface.InterfaceType`:
- `.wifi` (1), `.cellular` (2), `.wiredEthernet` (3), `.loopback` (4)
- `.other` (0) — anything that doesn't fit the above: Bluetooth tethering, **and VPN tunnels**.

If the default route goes through `utun*`/`ipsec*`/`ppp*`, Apple's `nw_path` marks the path as using `nw_interface_type_other`. Swift's `NWPath.usesInterfaceType(.other)` is a thin wrapper over the C function `nw_path_uses_interface_type(path, type)` from `libnetwork.dylib`.

### Where it's used

- Public getter `isVpnEnabled` (`objc_msgSend$isVpnEnabled`, selector string `0x1015ae766`).
- The Bool stream via `CurrentValueSubject` flows further into `MyMtsKit.VpnDetectorListener`.

---

## Where the app reacts to the VPN flag

### Subscribers (Swift protocol `MyMtsKit.VpnDetectorListener`)

Mangled protocol descriptor: `_TtP8MyMtsKit19VpnDetectorListener_` (`0x101550580`), derived `_TtP8MyMtsKit34FeedbackMessageVpnDetectorListener_` (`0x10156f9e0`).

Concrete implementations in the app:

| Class | Selector | What it does |
|---|---|---|
| `_TtC12MtsServiceRu24VpnEnabledConditionParam` | [`-updateVpnStatusWithIsActive:`](#) @ `0x10026df60` | Updates the `ConditionParam` for the feature-flag system — some features are gated when VPN is active. |
| `_TtC12MtsServiceRu13ScreenManager` | [`-updateVpnStatusWithIsActive:`](#) @ `0x1005282b0` | Shows the snackbar «Включён VPN. Данные могут не отображаться» (string `0x10156f960`). |

### Telemetry

The field `is_vpn_enabled` (string `0x1015a3186`) is sent to AppMetrica. Built from multiple call sites; refs lead into the common builder `TelemetryV2_TelemetryRequest.Device.Network.*`.

### AppsFlyer

Separate flag `AppsFlyerVPNCollectionEnabled` (string `0x101615d12`) controls VPN-info collection **inside** the AppsFlyer SDK. Enabling it lets the SDK tell its backend that the user is on VPN. Property mirrored on `AppsFlyerLib.VPNCollectionEnabled`.

---

## Not present in the binary (verified)

Verified via xref searches on the corresponding imports and strings with characteristic names. All listed imports are present in Mach-O but used **not for VPN detection**:

| Symbol / pattern | Where used | Related to VPN detection |
|---|---|---|
| `_getifaddrs` | `sub_100D7A0F8` (helper, not VPN) | No |
| `_sysctl`, `_sysctlbyname` | uptime, boot timestamp, hw model | No |
| `_getenv` | locale / language, SDK env-settings | No |
| `_DNSServiceQueryRecord` | OpenTelemetry exporter | No |
| `_dlopen` / `_dlsym` | dynamic module loading, not for SC.framework | No |
| `SCDynamicStoreCopyProxies` | **not imported** | — |
| `SCNetworkReachability*` | present, but in reachability wrappers — not for VPN | Indirectly |
| `__dyld_get_image_name` / `__dyld_image_count` | not encountered along VPN paths | No |
| Strings `"HTTPEnable"`, `"HTTPSEnable"`, `"kCFNetwork*"` | not found | — |

Strings `httpProxy` / `httpsProxy` / `ftpProxy` / `rtspProxy` at `0x101845d5c`+ are `URLSessionConfiguration.connectionProxyDictionary` keys used by `NIOExtras.NIOHTTP1ProxyConnectHandler` for error reporting, not detection.

---

## Summary

Two detectors, both via public Apple APIs:

1. Per-interface proxy-settings dictionary → match by VPN interface names.
2. `NWPathMonitor` → `.other` interface type.

Both reduce to two C imports (`CFNetworkCopySystemProxySettings`, `nw_path_uses_interface_type`), making the fishhook bypass trivial — see [`tweaks/VPNHide`](../../tweaks/VPNHide/).

Server-side detection (VPN identification by IP on the MTS-API side) is not addressed here.

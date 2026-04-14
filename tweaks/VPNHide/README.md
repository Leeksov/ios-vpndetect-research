[🇷🇺 Русская версия](README.ru.md)

# VPNHide

Universal Theos tweak that hides an active VPN/proxy from iOS apps. Low-level bypass via [fishhook](https://github.com/facebook/fishhook) (rebinds Mach-O imports) + `MSHookFunction` (patches dyld_shared_cache function prologues), no Logos hooks on Obj-C/Swift methods.

## What gets hooked

| Symbol | What the hook does |
|---|---|
| `CFNetworkCopySystemProxySettings` | Removes from `__SCOPED__` any interface keys containing `utun/tun/tap/ipsec/ppp/wg`. Also wipes top-level `HTTPEnable`, `HTTPSEnable`, `SOCKSEnable`, `HTTPProxy`, `HTTPSProxy`, `ProxyAutoConfig*` and similar flags. |
| `CFNetworkCopyProxiesForURL` | Unconditionally returns `[{ kCFProxyTypeKey: kCFProxyTypeNone }]` — a one-entry array, as if proxy resolution for the URL returned «direct connection». |
| `nw_path_uses_interface_type` | Always returns `false` for `nw_interface_type_other` (0). For other types — passes through to original. |
| `nw_interface_get_type` | If the original returned `.other` and the interface name (resolved via `nw_interface_get_name` from `dlsym`) matches a VPN prefix — returns `.wifi` instead. Covers Swift code that does `path.availableInterfaces.map(\.type)` rather than `path.usesInterfaceType(_:)`. |
| `getifaddrs` | Filters VPN interfaces out of the linked list returned by libc. |
| `sysctl` / `sysctlbyname` | Diagnostic logging only (no behaviour change). |
| `if_nameindex` | Blanks the names of VPN interfaces in the returned list. |

The first 4 (and `getifaddrs`) are installed in `__attribute__((constructor))`. fishhook covers main-app GOT; `MSHookFunction` patches actual prologues of `nw_*` symbols inside `libnetwork.dylib`/`libswiftNetwork.dylib` (which live in dyld_shared_cache, where fishhook can't reach).

## When it works

- Detection via `CFNetworkCopySystemProxySettings.__SCOPED__` + interface-name substring matching against `tun`/`ipsec`/`ppp`/… (classic AppsFlyer-style).
- Detection via `CFNetworkCopySystemProxySettings` reading top-level `HTTPProxy`/`HTTPSProxy`/`SOCKSProxy` (Gosuslugi-style).
- Detection via `CFNetworkCopyProxiesForURL` per-URL with `kCFProxyHostNameKey` check (Gosuslugi).
- Detection via `NWPathMonitor` + `NWPath.usesInterfaceType(.other)` (MyMTS).
- Detection via `NWPath.availableInterfaces.map(\.type).contains(.other)` — Swift enum comparison (CPPK `NetworkMonitor`).
- Any detection based on `getifaddrs` / `if_nameindex` enumeration.

## When it does **not** help

- Server-side detection by IP address.
- Reading the routing table via `sysctl(net.route.0)` — not hooked (add a separate hook if needed).
- DNS cross-check via `DNSServiceQueryRecord` — not hooked.
- Detectors that read socket descriptors and check interface flags directly via `ioctl(SIOCGIFFLAGS)`.
- Swift NWPathMonitor-level detectors that compare `NWInterface.name` (the string) against VPN prefixes — the name is real and we don't substitute it. Not seen yet in any of the analysed apps.

## Build

```sh
cd tweaks/VPNHide
git submodule add https://github.com/facebook/fishhook.git fishhook
make package install
```

Env vars: `THEOS`, `THEOS_DEVICE_IP`. For release: `FINALPACKAGE=1 make package`.

For prebuilt `.deb` (rootful and rootless variants) see [Releases](../../../../releases).

## App setup

[`Filter.plist`](Filter.plist) contains the list of bundle IDs the tweak attaches to. Default has all 15 analysed apps with detection. Add or remove bundle IDs as needed — full app table in the repo root: [`../../README.md`](../../README.md).

## Verifying

1. Bring up VPN (OpenVPN / WireGuard / IKEv2 — anything that creates `utun*`).
2. Launch the target app.
3. Confirm the detection triggers (snackbar, feature-gates, `is_vpn_enabled` telemetry field) don't fire.

Logs: Console.app on the device, filter by `VPNHide`.

Sample per-app analysis the hooks were derived from — [`apps/mymts/vpn-detection.md`](../../apps/mymts/vpn-detection.md).

## Caveats

- Charles/Proxyman themselves bring up a proxy interface — only use in combination with the tweak, otherwise the hook will hide proxy settings you set on purpose.
- Doesn't substitute DNS, doesn't fix IP leaks.

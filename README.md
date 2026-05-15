# ios-vpndetect-research

[🇷🇺 Русская версия](README.ru.md)

Reverse engineering of client-side VPN / proxy detection in iOS apps, plus a universal fishhook-based bypass tweak. 16 Russian-market apps analysed (banking, streaming, delivery, gov, telco, navigation).

- Per-app reverse-engineering notes → [`apps/`](apps/)
- Theos tweak (VPNHide) → [`tweaks/VPNHide/`](tweaks/VPNHide/)
- Prebuilt `.deb` packages → [Releases](../../releases) (rootful + rootless variants)
- **Binaries / IPAs are NOT shipped** in this repo (copyright + ~4 GB). See [Reproducing the analysis](#reproducing-the-analysis).

## Apps analysed

| App | Bundle ID | Executable | Version | Notes | VPN detect |
|---|---|---|---|---|---|
| Мой МТС | `ru.mts.mymts` | `MtsServiceRu` | — | [`apps/mymts/`](apps/mymts/) | [📄](apps/mymts/vpn-detection.md) |
| 2GIS | `ru.doublegis.grymmobile` | `ru.doublegis.grymmobile` | 7.21.7 | [`apps/2gis/`](apps/2gis/) | [📄](apps/2gis/vpn-detection.md) |
| CDEK | `com.cdek.cdekapp` | `CDEK` | 5.9.0 | [`apps/cdek/`](apps/cdek/) | [📄](apps/cdek/vpn-detection.md) |
| DNS-SHOP | `com.dns.DNSShop.DNS-SHOP` | `DNS-SHOP` | 1.52.0 | [`apps/dns-shop/`](apps/dns-shop/) | [📄](apps/dns-shop/vpn-detection.md) |
| Urent | `ru.urentbike.app` | `Urent` | 1.94.1 | [`apps/urent/`](apps/urent/) | [📄](apps/urent/vpn-detection.md) |
| Госуслуги | `com.minsvyaz.gosuslugi` | `Gosuslugi` | 25.3.0 | [`apps/gosuslugi/`](apps/gosuslugi/) | [📄](apps/gosuslugi/vpn-detection.md) |
| МегаФон | `ru.megafon.lk` | `Megafon` | 4.62.0 | [`apps/megafon/`](apps/megafon/) | [📄](apps/megafon/vpn-detection.md) |
| Расписание ЦППК | `ru.central-ppk.Timetable` | `Timetable PROD` | 2.7 | [`apps/cppk-timetable/`](apps/cppk-timetable/) | [📄](apps/cppk-timetable/vpn-detection.md) |
| Яндекс Маркет | `ru.yandex.blue.market` | `Beru` | 2026.11.1 | [`apps/yandex-market/`](apps/yandex-market/) | [📄](apps/yandex-market/vpn-detection.md) |
| билайн | `ru.beeline.mobile` | `MyBeeline` | 5.36.0 | [`apps/beeline/`](apps/beeline/) | [📄](apps/beeline/vpn-detection.md) |
| Яндекс Еда | `com.appkode.foodfox` | `YandexEats` | 8.102.1 | [`apps/yandex-eats/`](apps/yandex-eats/) | [📄](apps/yandex-eats/vpn-detection.md) |
| Кинопоиск | `ru.kinopoisk` | `Kinopoisk` | 8.41.3 | [`apps/kinopoisk/`](apps/kinopoisk/) | [📄](apps/kinopoisk/vpn-detection.md) |
| Amediateka | `com.spbtv.ag.tv.Amedia` | `Amediateka` | 4.54.0 | [`apps/amediateka/`](apps/amediateka/) | [📄](apps/amediateka/vpn-detection.md) |
| Мой налог | `com.gnivts.selfemployed` | `selfemployed` | 4.7.1 | [`apps/moy-nalog/`](apps/moy-nalog/) | [📄 none](apps/moy-nalog/vpn-detection.md) |
| Rostic's | `ru.yum.KFC-Russia` | `kfc` | 10.29.0 | [`apps/rostics/`](apps/rostics/) | [📄](apps/rostics/vpn-detection.md) |
| Вкусно — и точка | `com.mcdonaldsru.mcd` | `mcd-ios` | 13.2.0 | [`apps/vkusno-i-tochka/`](apps/vkusno-i-tochka/) | [📄](apps/vkusno-i-tochka/vpn-detection.md) |

All binaries are arm64 single-slice (no arm64e).

> Per-app analysis files (`apps/*/vpn-detection.md`) are written in Russian. If you need a specific one in English — open an issue.

## Cross-app findings

- **12 out of 16** apps rely on `CFNetworkCopySystemProxySettings.__SCOPED__` substring-matching against `utun / tun / tap / ipsec / ppp`. This is the "classic" pattern — fishhook neutralises it in a few lines.
- **3 apps** do **server-side** detection: 2GIS `/v1/vpn-detection-free` → HTTP 451, Amediateka `ShortApiError403Vpn`, and Yandex Passport `/tmgrdfrend/checkvpn`. For the first two you still need mitmproxy or a residential exit IP. The Yandex one, however, **is** bypassed client-side — its SDK is tolerant to the endpoint failing (it has to be, since mobile networks drop it regularly), so killing the request via an `NSURLSession` swizzle is enough. See the tweak section below.
- **Yandex Passport `/tmgrdfrend/checkvpn` is a shared-SDK endpoint** fired by at least 10 Yandex apps in this study (Mail, Metro, Kluch, Kinopoisk, Yandex Go / Taxi, Maps/Traffic, Translate, Market Blue, Rasp, IoT). One client-side hook covers the whole family.
- **2 apps** use a **remote-configurable** VPN-pattern list via `vpnProtocolsKeysIdentifiers` / `vpnProtocols` — the backend can push new needles without releasing an update.
- **Shared-SDK reuse across apps**: `MobileAdsCore.MACVpnStatusCheckerImpl` (SPB TV — Amediateka + Kinopoisk), Yandex AppLib `YAL*` (Yandex Market + Kinopoisk + Yandex Eats), `YXFintechFoundation.VPNConnectionCheckerImpl` (Yandex Eats and likely Market / Taxi / Delivery).
- **Мой налог** (Russian Federal Tax Service app) — **does not detect VPN at all**. Unique for a government app.
- **MyMTS** is the only app where detection flows through Swift `NWPathMonitor.usesInterfaceType(.other)`. The underlying C function lives in `libswiftNetwork.dylib` inside dyld_shared_cache — **fishhook can't reach it**. Requires `MSHookFunction` (jailbreak).

For a side-by-side comparison of detectors and UI reactions, see the "Сравнение" section at the bottom of any `apps/*/vpn-detection.md`.

## The tweak — VPNHide

[`tweaks/VPNHide/`](tweaks/VPNHide/) — Theos tweak. Hybrid of fishhook + MSHookFunction:

- **fishhook** rebinds main-app GOT for: `CFNetworkCopySystemProxySettings`, `CFNetworkCopyProxiesForURL`, `getifaddrs`, `sysctl`, `sysctlbyname`, `if_nameindex`.
- **MSHookFunction** patches actual prologues of shared-cache symbols: `nw_path_uses_interface_type`, `nw_interface_get_type`, `nw_interface_get_name`, `nw_path_enumerate_interfaces`. Requires a jailbreak (Substrate or ElleKit).
- **ObjC swizzle** on `-[NSURLSession dataTaskWithRequest:completionHandler:]` — kills the Yandex Passport `/tmgrdfrend/checkvpn` server-side probe by short-circuiting it with `NSURLErrorNotConnectedToInternet`. Covers the ~10 Yandex apps that embed the shared Passport SDK.

Bundle filter — [`tweaks/VPNHide/Filter.plist`](tweaks/VPNHide/Filter.plist) (currently covers all analysed apps plus the Yandex Passport-SDK family).

### Install

Get a `.deb` from [Releases](../../releases) that matches your jailbreak:

- `..._rootful.deb` — classic jailbreaks (unc0ver, checkra1n)
- `..._rootless.deb` — rootless (Dopamine, palera1n rootless)

Sideload via Sileo / Zebra / Filza, respring.

Logs: Console.app on the device, filter by `VPNHide`.

### Build from source

```sh
git clone https://github.com/Leeksov/ios-vpndetect-research.git
cd ios-vpndetect-research/tweaks/VPNHide
# fishhook/ must contain facebook/fishhook (fishhook.c, fishhook.h)
make clean package FINALPACKAGE=1                                # rootful
make clean package FINALPACKAGE=1 THEOS_PACKAGE_SCHEME=rootless  # rootless
```

Requires Theos (`$THEOS` env var) and a jailbroken device (not strictly required for rootful `.deb` build, but Substrate libs only exist on jailbroken devices at runtime).

## Reproducing the analysis

Extracted binaries and IDA databases are **not** shipped. To reproduce:

1. Obtain an IPA of the target app (from the device, or via ipatool / App-Assassin / similar — pick your tool).
2. `unzip <app>.ipa -d extracted/`
3. Binary lives at `extracted/Payload/<Name>.app/<CFBundleExecutable>`.
4. Load into IDA / Ghidra / Hopper. Addresses in `apps/<app>/vpn-detection.md` are **valid only for the version listed in the file header**.

## Repo layout

```
apps/<slug>/
├── README.md          # bundle ID, executable, version, framework stack
└── vpn-detection.md   # detailed VPN/proxy detection analysis + bypass notes

tweaks/<name>/
├── Tweak.mm           # source
├── Makefile, control, Filter.plist, README.md
└── fishhook/          # facebook/fishhook — fetched manually, not committed
```

## Licence / ethics

The reverse-engineering notes are published as research / educational material. Application binaries are the copyright of their respective owners and are **not distributed** through this repository. The VPNHide tweak bypasses client-side checks which for some apps may violate their Terms of Service. Use at your own risk.

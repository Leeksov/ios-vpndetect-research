# ios-vpndetect-research

Reverse-engineering of client-side VPN / proxy detection in iOS apps, + a universal fishhook-based bypass tweak. 16 Russian market apps analysed (banking, streaming, delivery, gov, telco, navigation).

- Per-app reverse-engineering notes → [`apps/`](apps/)
- Theos tweak (VPNHide) → [`tweaks/VPNHide/`](tweaks/VPNHide/)
- **Binaries / IPAs are NOT shipped** in this repo (copyright + ~4 GB). Instructions to obtain them — ниже.

## Приложения

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
| Мой налог | `com.gnivts.selfemployed` | `selfemployed` | 4.7.1 | [`apps/moy-nalog/`](apps/moy-nalog/) | [📄](apps/moy-nalog/vpn-detection.md) (none) |
| Rostic's | `ru.yum.KFC-Russia` | `kfc` | 10.29.0 | [`apps/rostics/`](apps/rostics/) | [📄](apps/rostics/vpn-detection.md) |
| Вкусно — и точка | `com.mcdonaldsru.mcd` | `mcd-ios` | 13.2.0 | [`apps/vkusno-i-tochka/`](apps/vkusno-i-tochka/) | [📄](apps/vkusno-i-tochka/vpn-detection.md) |

All binaries are arm64 single-slice (no arm64e).

## Ключевые выводы (cross-app)

- **12 из 16** приложений проверяют `CFNetworkCopySystemProxySettings.__SCOPED__` → substring match по `utun/tun/tap/ipsec/ppp`. Это «классика» — fishhook закрывает за 5 минут.
- **3 приложения** используют **server-side** детект (2GIS `/v1/vpn-detection-free` → 451, Amediateka `ShortApiError403Vpn`, Кинопоиск `/tmgrdfrend/checkvpn`). Клиентский bypass не помогает, нужен mitmproxy или residential IP.
- **2 приложения** используют **remote-configurable** список VPN-паттернов через `vpnProtocolsKeysIdentifiers` / `vpnProtocols` — теоретически бекенд может выкатить новые паттерны без релиза.
- **Shared SDK-переиспользование**: `MobileAdsCore.MACVpnStatusCheckerImpl` (SPB TV — Amediateka + Кинопоиск), Yandex AppLib `YAL*` (Маркет + Кинопоиск + Еда), `YXFintechFoundation.VPNConnectionCheckerImpl` (Еда + вероятно Маркет/Такси/Доставка).
- **Мой налог** (ФНС) — **не детектит VPN вообще**. Уникально для госприложения.
- MyMTS → **единственное** приложение в выборке, где детект идёт через `NWPathMonitor.usesInterfaceType(.other)` — а эта C-функция живёт в `libswiftNetwork.dylib` внутри dyld_shared_cache, **fishhook её не достанет**. Нужен MSHookFunction (jailbreak required).

Для сравнительной таблицы детекторов и реакций UI — см. секцию «Сравнение» в любом `apps/*/vpn-detection.md`.

## Твик — VPNHide

[`tweaks/VPNHide/`](tweaks/VPNHide/) — Theos-твик. Гибрид fishhook + MSHookFunction:

- **fishhook** перепривязывает main-app GOT для: `CFNetworkCopySystemProxySettings`, `CFNetworkCopyProxiesForURL`, `getifaddrs`, `sysctl`, `sysctlbyname`, `if_nameindex`.
- **MSHookFunction** патчит реальные прологи shared-cache символов: `nw_path_uses_interface_type`, `nw_interface_get_type`, `nw_interface_get_name`, `nw_path_enumerate_interfaces`. Нужен jailbreak (Substrate / ElleKit).

Фильтр бандлов — [`tweaks/VPNHide/Filter.plist`](tweaks/VPNHide/Filter.plist) (15 bundle ID на текущий момент).

## Как работать с репо

Распакованные бинарники / IDA-базы в репе **отсутствуют**. Чтобы воспроизвести анализ:

1. Достать IPA нужного приложения (с устройства или через ipatool/appfigures/AppAssassin/etc — на свой вкус).
2. `unzip <app>.ipa -d extracted/`
3. Бинарник → `extracted/Payload/<Name>.app/<CFBundleExecutable>`.
4. Открыть в IDA / Ghidra / Hopper — все адреса в `apps/<app>/vpn-detection.md` валидны **только для версии, указанной в заголовке доки**.

## Структура

```
apps/<slug>/
├── README.md          # bundle ID, executable, version, framework stack
└── vpn-detection.md   # VPN/proxy-детект в деталях + как обходится

tweaks/<name>/
├── Tweak.mm           # исходник
├── Makefile, control, Filter.plist, README.md
└── fishhook/          # git submodule (facebook/fishhook), не в репе
```

## Лицензия / этика

Reverse engineering notes публикуются как research / educational material. Бинарники приложений защищены авторским правом их владельцев и **не распространяются** через этот репозиторий. Tweak VPNHide — bypass клиентских проверок, что у некоторых приложений идёт вразрез с их ToS. Использование на свой страх.

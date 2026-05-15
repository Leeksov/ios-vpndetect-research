# ios-vpndetect-research

[🇬🇧 English version](README.md)

Reverse-engineering клиентской детекции VPN / proxy в iOS-приложениях + универсальный bypass-твик на fishhook. Разобрано 16 российских приложений (банкинг, стриминг, доставка, госуслуги, телеком, навигация).

- Per-app ревёрс-заметки → [`apps/`](apps/)
- Theos-твик (VPNHide) → [`tweaks/VPNHide/`](tweaks/VPNHide/)
- Готовые `.deb`-пакеты → [Releases](../../releases) (rootful + rootless)
- **Бинарники / IPA в репе НЕ лежат** (copyright + ~4 GB). См. [Как воспроизвести анализ](#как-воспроизвести-анализ).

## Разобранные приложения

| App | Bundle ID | Executable | Версия | Папка | VPN-детект |
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
| Мой налог | `com.gnivts.selfemployed` | `selfemployed` | 4.7.1 | [`apps/moy-nalog/`](apps/moy-nalog/) | [📄 нет](apps/moy-nalog/vpn-detection.md) |
| Rostic's | `ru.yum.KFC-Russia` | `kfc` | 10.29.0 | [`apps/rostics/`](apps/rostics/) | [📄](apps/rostics/vpn-detection.md) |
| Вкусно — и точка | `com.mcdonaldsru.mcd` | `mcd-ios` | 13.2.0 | [`apps/vkusno-i-tochka/`](apps/vkusno-i-tochka/) | [📄](apps/vkusno-i-tochka/vpn-detection.md) |

Все бинарники — arm64 single-slice (без arm64e).

## Ключевые выводы (cross-app)

- **12 из 16** приложений проверяют `CFNetworkCopySystemProxySettings.__SCOPED__` → substring match по `utun/tun/tap/ipsec/ppp`. Это «классика» — fishhook закрывает за 5 минут.
- **3 приложения** используют **server-side** детект: 2GIS `/v1/vpn-detection-free` → 451, Amediateka `ShortApiError403Vpn` и Yandex Passport `/tmgrdfrend/checkvpn`. Первым двум нужен mitmproxy или residential-IP. Yandex'овский, однако, **обходится** клиентски — его SDK толерантен к ошибке этого эндпоинта (иначе нельзя, мобильная сеть его регулярно роняет), поэтому достаточно убить запрос через `NSURLSession`-свизл. См. секцию про твик ниже.
- **Yandex Passport `/tmgrdfrend/checkvpn` — shared-SDK эндпоинт**, который дёргают как минимум 10 приложений Яндекса из этой выборки (Почта, Метро, Ключ, Кинопоиск, Яндекс Go / Такси, Карты/Пробки, Переводчик, Маркет Blue, Расписания, IoT). Один клиентский хук закрывает всё семейство сразу.
- **2 приложения** используют **remote-configurable** список VPN-паттернов через `vpnProtocolsKeysIdentifiers` / `vpnProtocols` — теоретически бэкенд может выкатить новые паттерны без релиза.
- **Shared SDK-переиспользование**: `MobileAdsCore.MACVpnStatusCheckerImpl` (SPB TV — Amediateka + Кинопоиск), Yandex AppLib `YAL*` (Маркет + Кинопоиск + Еда), `YXFintechFoundation.VPNConnectionCheckerImpl` (Еда + вероятно Маркет/Такси/Доставка).
- **Мой налог** (ФНС) — **не детектит VPN вообще**. Уникально для госприложения.
- **MyMTS** → единственное приложение в выборке, где детект идёт через Swift `NWPathMonitor.usesInterfaceType(.other)` — а эта C-функция живёт в `libswiftNetwork.dylib` внутри dyld_shared_cache, **fishhook её не достанет**. Нужен `MSHookFunction` (jailbreak required).

Для сравнительной таблицы детекторов и реакций UI — см. секцию «Сравнение» в любом `apps/*/vpn-detection.md`.

## Твик — VPNHide

[`tweaks/VPNHide/`](tweaks/VPNHide/) — Theos-твик. Гибрид fishhook + MSHookFunction:

- **fishhook** перепривязывает main-app GOT для: `CFNetworkCopySystemProxySettings`, `CFNetworkCopyProxiesForURL`, `getifaddrs`, `sysctl`, `sysctlbyname`, `if_nameindex`.
- **MSHookFunction** патчит реальные прологи shared-cache символов: `nw_path_uses_interface_type`, `nw_interface_get_type`, `nw_interface_get_name`, `nw_path_enumerate_interfaces`. Нужен jailbreak (Substrate или ElleKit).
- **ObjC-свизл** на `-[NSURLSession dataTaskWithRequest:completionHandler:]` — убивает server-side пробу Yandex Passport `/tmgrdfrend/checkvpn`, отдавая `NSURLErrorNotConnectedToInternet` в completion handler. Покрывает ~10 приложений Яндекса с общим Passport SDK.

Фильтр бандлов — [`tweaks/VPNHide/Filter.plist`](tweaks/VPNHide/Filter.plist) (сейчас включает все разобранные приложения плюс Yandex Passport-SDK семейство).

### Установка

Возьми `.deb` из [Releases](../../releases) под свой джейл:

- `..._rootful.deb` — классические джейлы (unc0ver, checkra1n)
- `..._rootless.deb` — rootless (Dopamine, palera1n rootless)

Sideload через Sileo / Zebra / Filza, респринг.

Логи: Console.app на устройстве, фильтр по `VPNHide`.

### Сборка из исходников

```sh
git clone https://github.com/Leeksov/ios-vpndetect-research.git
cd ios-vpndetect-research/tweaks/VPNHide
# в fishhook/ должен лежать facebook/fishhook (fishhook.c, fishhook.h)
make clean package FINALPACKAGE=1                                # rootful
make clean package FINALPACKAGE=1 THEOS_PACKAGE_SCHEME=rootless  # rootless
```

Требует Theos (`$THEOS` env). Для сборки сам джейл не нужен (но на нежейленом устройстве Substrate-либы недоступны в рантайме, поэтому работать не будет).

## Как воспроизвести анализ

Распакованные бинарники / IDA-базы в репе **отсутствуют**. Чтобы повторить анализ:

1. Достать IPA нужного приложения (с устройства или через ipatool / App-Assassin / etc — на свой вкус).
2. `unzip <app>.ipa -d extracted/`
3. Бинарник → `extracted/Payload/<Name>.app/<CFBundleExecutable>`.
4. Открыть в IDA / Ghidra / Hopper — все адреса в `apps/<app>/vpn-detection.md` валидны **только для версии, указанной в заголовке доки**.

## Структура

```
apps/<slug>/
├── README.md          # bundle ID, executable, версия, список фреймворков
└── vpn-detection.md   # VPN/proxy-детект в деталях + как обходится

tweaks/<name>/
├── Tweak.mm           # исходник
├── Makefile, control, Filter.plist, README.md
└── fishhook/          # facebook/fishhook — выкачивается вручную, в репе нет
```

## Лицензия / этика

Reverse-engineering notes публикуются как research / educational material. Бинарники приложений защищены авторским правом их владельцев и **не распространяются** через этот репозиторий. Tweak VPNHide — bypass клиентских проверок, что у некоторых приложений идёт вразрез с их ToS. Использование на свой страх и риск.

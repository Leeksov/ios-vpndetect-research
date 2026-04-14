# Мой МТС — детектирование VPN / Proxy

**Бинарник:** `MtsServiceRu` (arm64, iOS-сборка, Swift + Obj-C)
**Способ анализа:** IDA Pro / Hex-Rays, подтверждение по строкам и xref'ам.
**Обход:** [`tweaks/VPNHide`](../../tweaks/VPNHide/).

---

## TL;DR

В приложении **два независимых детектора** VPN:

| # | Модуль | Механизм | Адрес |
|---|---|---|---|
| 1 | AppsFlyer SDK (Obj-C) | `CFNetworkCopySystemProxySettings` → перебор ключей `__SCOPED__` → подстроки `tap`/`tun`/`ipsec`/`ppp` | `0x10142678c` |
| 2 | `GeoWidgetSDK.VPNDetectorService` (Swift) | `NWPathMonitor` + `NWPath.usesInterfaceType(.other)` | init `0x100B94F6C`, handler `0x100B951C8` |

Результат публикуется через `Combine` и поступает в `MyMtsKit.VpnDetectorListener`-подписчиков: `VpnEnabledConditionParam` (feature-flag) и `ScreenManager` (снекбар «Включён VPN…»). В AppMetrica уходит поле `is_vpn_enabled`.

**Чего в бинаре нет:** `getifaddrs`-обхода, парсинга таблицы маршрутизации через `sysctl(net.route.0)`, проверки `getenv("http_proxy")`, сравнения DNS через `DNSServiceQueryRecord`, динамической загрузки SystemConfiguration через `dlopen`, перечисления `__dyld_image_name` с целью ловить инжект VPN-dylib.

Импорты `_getifaddrs`, `_sysctl`, `_sysctlbyname`, `_getenv`, `_dlopen`, `_DNSServiceQueryRecord`, `__dyld_get_image_name` **присутствуют**, но используются в несвязанных местах: uptime / boot timestamp (`+[AMAPlatformDescription bootTimestamp]`), hardware model (`+[AFSystemInfo machineModel]`), env-парсинг аналитики, mDNS-сервисы OpenTelemetry и т.п.

---

## Детектор №1 — AppsFlyer: `+[AppsFlyerUtils isVPNConnected]`

**Адрес:** `0x10142678c`. Точка входа — классический Obj-C class method, возвращает `BOOL`.

### Псевдокод

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

### Почему это работает

`CFNetworkCopySystemProxySettings` возвращает системный словарь prox'и-настроек. Под ключом `__SCOPED__` лежит ещё один словарь — per-interface-настройки, ключи которого — **имена сетевых интерфейсов**, активных в системе. Любой VPN-клиент, поднимающий свой интерфейс (`utun0`, `ipsec0`, `ppp0`, `tap0`), окажется в этом списке. Проверка делается по **подстроке**, не по префиксу, — `utun0` матчится как `tun`.

### Где используется

Используется только AppsFlyer SDK внутри для флага `AppsFlyerVPNCollectionEnabled` / `VPNCollectionEnabled`. Влияет на то, что именно SDK репортит в свою аналитику. Прямого UI-эффекта нет, но **данные уходят к AppsFlyer** — при ревёрсе/телеметрии нужно учитывать.

---

## Детектор №2 — `GeoWidgetSDK.VPNDetectorService`

**Swift-класс:** `_TtC12GeoWidgetSDK18VPNDetectorService` (mangled), metadata accessor `$s12GeoWidgetSDK18VPNDetectorServiceCMa` по адресу `0x100b952c0`.

**Реконструированные методы:**
- `init` — `sub_100B94F6C`
- `pathUpdateHandler` — `sub_100B951C8` (партиал-аппликейт через `sub_100B95304`)

### Псевдокод `init`

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

В дизасме строка метки очереди видна как два 8-байтных литерала Swift small-string: `0x2E6B726F7774656E` + `0xEF726F74696E6F6D` → `"network.monitor"`.

### Псевдокод `pathUpdateHandler`

```swift
let type: NWInterface.InterfaceType = .other   // raw = 0
let isVPN = path.usesInterfaceType(type)
subject.send(isVPN)
```

В декомпиляции `sub_100B951C8`:

```
v3 = type metadata accessor for NWInterface.InterfaceType(0);
(*(VWT->destructiveInjectEnumTag))(v5, 0xFFFFFFFF, v3);   // enum tag -> .other
v6 = NWPath.usesInterfaceType(_:)(v5);
CurrentValueSubject.send(_:)(&v6);
```

### Почему это работает

`NWPathMonitor` (Network.framework) классифицирует интерфейсы в `NWInterface.InterfaceType`:
- `.wifi` (1), `.cellular` (2), `.wiredEthernet` (3), `.loopback` (4)
- `.other` (0) — всё, что не попадает выше: Bluetooth-tethering, **и VPN-тоннели**.

Если маршрут по умолчанию идёт через `utun*`/`ipsec*`/`ppp*`, Apple-евский `nw_path` помечает этот путь как использующий `nw_interface_type_other`. Свифтовский `NWPath.usesInterfaceType(.other)` — тонкая обёртка над C-функцией `nw_path_uses_interface_type(path, type)` из `libnetwork.dylib`.

### Где используется

- Публичный геттер `isVpnEnabled` (`objc_msgSend$isVpnEnabled`, селектор-строка `0x1015ae766`).
- Поток Bool'ов через `CurrentValueSubject` уходит дальше в `MyMtsKit.VpnDetectorListener`.

---

## Где приложение реагирует на VPN-флаг

### Подписчики (Swift protocol `MyMtsKit.VpnDetectorListener`)

Mangled protocol descriptor: `_TtP8MyMtsKit19VpnDetectorListener_` (`0x101550580`), производный `_TtP8MyMtsKit34FeedbackMessageVpnDetectorListener_` (`0x10156f9e0`).

Конкретные реализации в приложении:

| Класс | Селектор | Что делает |
|---|---|---|
| `_TtC12MtsServiceRu24VpnEnabledConditionParam` | [`-updateVpnStatusWithIsActive:`](#) @ `0x10026df60` | Обновляет `ConditionParam` для feature-flag системы — часть фич гейтится при активном VPN. |
| `_TtC12MtsServiceRu13ScreenManager` | [`-updateVpnStatusWithIsActive:`](#) @ `0x1005282b0` | Показывает снекбар «Включён VPN. Данные могут не отображаться» (строка `0x10156f960`). |

### Телеметрия

В AppMetrica отправляется поле `is_vpn_enabled` (строка `0x1015a3186`). Собирается не из одного места; ref'ы ведут в общий builder `TelemetryV2_TelemetryRequest.Device.Network.*`.

### AppsFlyer

Отдельный флаг `AppsFlyerVPNCollectionEnabled` (строка `0x101615d12`) управляет сбором VPN-информации **внутри** AppsFlyer SDK. Включение даёт SDK право рассказывать своему бекенду, что у юзера VPN. Свойство зеркалится на `AppsFlyerLib.VPNCollectionEnabled`.

---

## Чего в бинаре нет (проверено)

Проверено поиском xref'ов на соответствующие импорты и строк с характерными именами. Все перечисленные импорты в Mach-O присутствуют, но задействованы **не для VPN-детекта**:

| Символ / паттерн | Где используется | К VPN-детекту отношения |
|---|---|---|
| `_getifaddrs` | `sub_100D7A0F8` (вспомогательная, не VPN) | Нет |
| `_sysctl`, `_sysctlbyname` | uptime, boot timestamp, hw model | Нет |
| `_getenv` | локализация/язык, env-настройки SDK | Нет |
| `_DNSServiceQueryRecord` | OpenTelemetry exporter | Нет |
| `_dlopen` / `_dlsym` | динамическая загрузка модулей, не для SC.framework | Нет |
| `SCDynamicStoreCopyProxies` | **не импортируется** | — |
| `SCNetworkReachability*` | присутствует, но в reachability-обёртках — не для VPN | Косвенно |
| `__dyld_get_image_name` / `__dyld_image_count` | не встречается в путях к VPN-логике | Нет |
| Строки `"HTTPEnable"`, `"HTTPSEnable"`, `"kCFNetwork*"` | не найдены | — |

Строки `httpProxy` / `httpsProxy` / `ftpProxy` / `rtspProxy` по адресу `0x101845d5c`+ — это ключи `URLSessionConfiguration.connectionProxyDictionary` в error-репортинге `NIOExtras.NIOHTTP1ProxyConnectHandler`, не детектор.

---

## Резюме

Два детектора, оба на публичных API Apple:

1. Словарь per-interface proxy-настроек → матч по именам VPN-интерфейсов.
2. `NWPathMonitor` → `.other` interface type.

Оба сводятся к двум C-импортам (`CFNetworkCopySystemProxySettings`, `nw_path_uses_interface_type`), что делает обход через fishhook тривиальным — см. [`tweaks/VPNHide`](../../tweaks/VPNHide/).

Серверная детекция (определение VPN по IP-адресу на стороне MTS-API) этим не снимается.

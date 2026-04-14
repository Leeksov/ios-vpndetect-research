# билайн — детектирование VPN / Proxy

**Бинарник:** `MyBeeline` v5.36.0 (arm64, Swift + Obj-C)
**Способ анализа:** IDA Pro / Hex-Rays.
**Обход:** [`tweaks/VPNHide`](../../tweaks/VPNHide/) — текущий твик покрывает, достаточно добавить `ru.beeline.mobile` в [`Filter.plist`](../../tweaks/VPNHide/Filter.plist).

---

## TL;DR

Два детектора, оба через `CFNetworkCopySystemProxySettings.__SCOPED__`:

| # | Модуль | Механизм | Адрес |
|---|---|---|---|
| 1 | AppsFlyer SDK (Obj-C) | `+[AppsFlyerUtils isVPNConnected]` — классика `rangeOfString:` по `tap/tun/ipsec/ppp` | `0x10423BA30` |
| 2 | `MBVpnDetector.SystemProxySettingsProvider` (Swift) | `CFNetworkCopySystemProxySettings` → `__SCOPED__.allKeys` → возвращает `[String]`, потребитель отдельно сверяет с `vpnProtocols` | `0x102D8AD38` |

`NWPathMonitor` **используется, но не для VPN** — `sub_100BBAF0C` дёргает `nw_path_uses_interface_type(path, .cellular)` для одного-разового callback'а и тут же `nw_path_monitor_cancel`. Стандартный network-reachability, `.other` не запрашивается.

**Импорты Mach-O:**

| Символ | Статус | Контекст |
|---|---|---|
| `_CFNetworkCopySystemProxySettings` | ✅ | 2 детектора |
| `_nw_path_uses_interface_type` | ✅ | reachability, не VPN |
| `_getifaddrs` | ❌ | не импортируется |
| `_nw_interface_get_type` | ❌ | не импортируется |
| `_CFNetworkCopyProxiesForURL` | ❌ | не импортируется |
| `_sysctl` / `_sysctlbyname` / `_dlopen` / `_dlsym` | ✅ | вспомогательные, не VPN |
| `_getenv` / `_if_nametoindex` / `_SCDynamicStoreCopyProxies` / `_DNSServiceQueryRecord` | ❌ | — |

---

## Детектор №1 — AppsFlyer

`+[AppsFlyerUtils isVPNConnected]` @ `0x10423BA30`. Байт-в-байт как в MyMTS/CDEK/Urent — `rangeOfString:` по `tap/tun/ipsec/ppp`. Влияет на AppsFlyer-телеметрию (`AppsFlyerVPNCollectionEnabled` @ `0x104446505`), на UI не выходит.

---

## Детектор №2 — `MBVpnDetector` (Swift)

Framework с DI-архитектурой:

| Swift-тип | Mangled | Что это |
|---|---|---|
| `MBVpnDetector.MBVpnDetector` | `$s13MBVpnDetector13MBVpnDetectorVMa` | struct, главный фасад |
| `MBVpnDetector.SystemProxySettingsProvider` | `$s13MBVpnDetector27SystemProxySettingsProviderVMa` | struct, реальный impl |
| `MBVpnDetector.ProxySettingsProvider` | `$s13MBVpnDetector21ProxySettingsProviderP` | протокол (для моков в тестах) |

`sub_102D8AD38` — метод `SystemProxySettingsProvider`'а, возвращающий **массив имён интерфейсов из `__SCOPED__`**:

```swift
func getScopedInterfaces() -> [String] {
    guard let settings = CFNetworkCopySystemProxySettings() as? [String: Any] else { return [] }
    guard let scoped   = settings["__SCOPED__"]          as? [String: Any] else { return [] }
    var out: [String] = []
    for key in scoped.allKeys {
        if let s = key as? String { out.append(s) }
    }
    return out
}
```

Матчинг делает **потребитель** (код в основной `MBVpnDetector.MBVpnDetector.isActive`, который мы здесь не раскопали дальше), используя свойство **`vpnProtocols`** (строка `0x104f846c0`) — это массив подстрок-паттернов.

По симметрии с Gosuslugi (`vpnProtocolsKeysIdentifiers`) — скорее всего, `vpnProtocols` тоже может подкачиваться из remote-config. Текущее дефолтное содержимое в рантайм-фреймворке не видно из статики, но UI-строки указывают на стандартный набор (`tun/ipsec/...`).

---

## UI-реакция

В приложении **несколько точек** показа предупреждения:

| Строка | Адрес | Контекст |
|---|---|---|
| `отключите VPN` | `0x1042d6880` | короткий toast |
| `Не удалось установить безопасное соединение с сервером. Пожалуйста, обновите приложение или отключите VPN` | `0x1042fe6c0` | ошибка TLS |
| `если vpn выключен, сделайте снимок экрана и обратитесь в поддержку` | `0x10440e8c0` | escape-инструкция |
| `не получилось — попробуйте без vpn` | `0x10440e940` | ретрай-prompt |

Дебаг/feature-flag инфраструктура в строках:
- `PRFL-9677: Добавить уведомление о включенном VPN` (`0x104338db0`) — ID тикета, по которому фича внедрена. Остался в бинарнике.
- `Регулирует предупреждение об активном VPN` (`0x104338e00`) — описание feature-флага, управляющего UI-плашкой.

То есть показ алерта **gate'ится remote-flag'ом** — сервер может временно отключить уведомление, даже если детектор сработал.

---

## Телеметрия

- `VPN_enabled` (`0x104358255`) — поле, отправляемое вместе с аналитикой.
- `AppsFlyerVPNCollectionEnabled` (`0x104446505`) — управляет сбором внутри AppsFlyer SDK.

---

## Обход существующим `VPNHide`-твиком

Хук `CFNetworkCopySystemProxySettings` вырезает из `__SCOPED__` все VPN-интерфейсы → оба детектора получают «чистый» словарь:

- Детектор №1 (AppsFlyer): `rangeOfString:` ни по чему не матчится → `NO`.
- Детектор №2 (`SystemProxySettingsProvider.getScopedInterfaces`): возвращает массив, в котором нет VPN-имён → потребитель, матчащий по `vpnProtocols`, получает `false`.

Остальные хуки (`CFNetworkCopyProxiesForURL`, `nw_interface_get_type`, `nw_path_uses_interface_type`, `getifaddrs`) на MyBeeline — NO-OP: либо не импортируются, либо вызываются с non-VPN типами.

Для активации добавить в [`tweaks/VPNHide/Filter.plist`](../../tweaks/VPNHide/Filter.plist):

```
{ Filter = { Bundles = ( …, "ru.beeline.mobile" ); }; }
```

---

## Сравнение

| | MyMTS | МегаФон | CDEK | DNS-SHOP | ЦППК | Urent | Госуслуги | билайн |
|---|---|---|---|---|---|---|---|---|
| Детекторов | 2 | 1 | 2 | 1 | 1 | 3 | 5 | 2 |
| `__SCOPED__` hardcoded | ✅ | ✅ | ✅×2 | ✅ | ❌ | ✅×3 | ✅ | ✅ (AppsFlyer) |
| `__SCOPED__` с внешним списком паттернов | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ (`vpnProtocols`) |
| `NWPathMonitor` для VPN | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| `HTTPProxy` top-level check | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ |
| `CFNetworkCopyProxiesForURL` | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ |
| Feature-flag gate на UI | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ (`PRFL-9677`) |
| Debug-комменты тикетов в бинаре | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| Покрытие VPNHide | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

билайн — добротный средне-комплексный кейс: архитектура с DI (`ProxySettingsProvider` protocol + `SystemProxySettingsProvider` impl), remote-config список VPN-паттернов как у Госуслуг, но без per-URL проверок и без HTTPProxy-flag'ов. В бинарник попали **debug-коммиты** (`PRFL-9677`) — как и у Urent с полным путём сборки `/Users/user/builds/_csHvbAg/...`, следы CI.

[🇬🇧 English version](vpn-detection.md)

# 2GIS — детектирование VPN / Proxy

**Бинарник:** `ru.doublegis.grymmobile` v7.21.7 (arm64, Swift + Obj-C, ~183 MB)
**Способ анализа:** IDA Pro / Hex-Rays.
**Обход:** [`tweaks/VPNHide`](../../tweaks/VPNHide/) — локальные детекторы закрываются существующими хуками; server-side блокировка обходится **косвенно** (если локальный сканер не нашёл VPN → HTTP-запрос к `/v1/vpn-detection-free` не инициируется).

---

## TL;DR

Наиболее развитый VPN-стек из 8 разобранных приложений. Реализован как набор **отдельных фреймворков** с чёткой DI-архитектурой:

| Framework | Что делает |
|---|---|
| `VNVPNCheckerAPI` | основная логика: `VPNCheckerAPI`, `VPNStatusProvider`, `VPNDiagnosticsService`, `VPNRemoteConfig`, `DGIDHeadersProvider`, `GeoContextProvider` |
| `VNVPNCheckerAPIInterfaces` | протоколы: `IVPNCheckerAPI`, `IVPNDiagnosticsService`, `IVPNRemoteConfig`, `IVPNStatusProvider`, `IGeoContextProvider` |
| `VNVPNCheckerUI` | UI: `VPNAlertPresenter`, `VPNAlertVC`, `VPNAlertVM`, `VPNBlockedWindow` |
| `VNCarPlay` | CarPlay full-screen block overlay (`CarPlayVPNBlockOverlayVC`) |

Трёхслойная детекция:

| Слой | Механизм | Адрес |
|---|---|---|
| AppsFlyer-style | `+[AppsFlyerUtils isVPNConnected]` — `__SCOPED__` → `rangeOfString:` по `tap/tun/ipsec/ppp` | `0x107199AAC` |
| FPNetworkInfoProvider (Obj-C) | `-[FPNetworkInfoProvider isVpnOn]` — тот же алгоритм, прямо в приложении | `0x107653440` |
| **ProxySettingsScanner** (Swift) | `sub_106447010` — `__SCOPED__` → `String.hasPrefix` по `utun/tap/tun/ipsec/ppp`, возвращает массив обнаруженных интерфейсов | `0x106447010` |
| **NWPathMonitor (`VPNStatusProvider`)** | реактивно ловит изменения сети, триггерит check | в libswiftNetwork overlay |
| **Server-side** | `GET /v1/vpn-detection-free` через `VPNCheckerAPI`; HTTP 451 = VPN detected, HTTP 200/empty = OK | `VNVPNCheckerAPI/VPNCheckerAPI.swift` |

---

## Server-side check — `VPNCheckerAPI`

Единственное приложение из разобранных, где **сервер** принимает решение о VPN по IP клиента.

```
GET {vpnCheckerServerUrl}/v1/vpn-detection-free
Headers: {vpnHeaderKey}: ...
```

Конфигурация вынесена в remote-config:
- `vpnCheckerServerUrl` (`0x10812a000`) — основной endpoint
- `vpnCheckerFallbackServerUrl` (`0x10812a020`) — fallback
- `vpnHeaderKey` (`0x10812a03c`) — имя кастомного header'а

Ответы (из логов в бинарнике):

| Поведение | Лог |
|---|---|
| HTTP 451 Legal Reasons | `VPNCheckerAPI: результат — заблокирован (HTTP 451) — …` (`0x1084b8ce0`) — VPN detected |
| HTTP 200 | `VPNCheckerAPI: результат — не заблокирован (HTTP 200)` (`0x1084b8d90`) — OK |
| пустой ответ | `VPNCheckerAPI: результат — не заблокирован (пустой ответ)` (`0x1084b8d30`) — OK |
| ошибка + retry | `VPNCheckerAPI: первый запрос завершился с ошибкой, запускаем повторные попытки` (`0x1084b8b10`) |
| исчерпаны попытки | `VPNCheckerAPI: все повторные попытки исчерпаны` (`0x1084b8c40`) |

---

## `VPNStatusProvider` — реактивный триггер

Swift-класс `_TtC15VNVPNCheckerAPI17VPNStatusProvider` (`0x1084b90b0`). Подписан на `NWPathMonitor`:

- `VPNStatusProvider: мониторинг сети запущен` (`0x1084b9110`)
- `VPNStatusProvider: сетевой путь изменился` (`0x1084b9150`)
- `VPNStatusProvider: определение VPN отключено через remote config` (`0x1084b9050`) — kill switch на сервере
- `VPNStatusProvider: мониторинг сети остановлен` (`0x1084b8fd0`)

Использует `_vpnRemoteConfig` (`0x1084b8ad0`) и сервис в очереди `ru.doublegis.grymmobile.vpn-status-provider` (`0x1084b8e10`).

Бинарник **не импортирует** `nw_path_uses_interface_type` напрямую — все вызовы идут через Swift overlay (`libswiftNetwork.dylib`).

---

## Локальный scanner — `sub_106447010`

Заметно отличается от прочих приложений — это **не** bool-detector, а функция, **возвращающая массив** найденных VPN-интерфейсов, чтобы потом уйти с ним в `VPNCheckerAPI` как контекст.

```swift
func scanProxySettings() -> [String] {
    guard let settings = CFNetworkCopySystemProxySettings() as? [String: Any] else { return [] }
    guard let scoped   = settings["__SCOPED__"]          as? [String: Any] else { return [] }
    var found: [String] = []
    for (iface, info) in scoped {
        let lower = iface.lowercased()
        if lower.hasPrefix("utun") || lower.hasPrefix("tap") || lower.hasPrefix("tun")
           || lower.hasPrefix("ipsec") || lower.hasPrefix("ppp") {
            // поднимает из sub-dict <iface_info> ключ "P2P"-like (readback)
            if let extra = info[<key>] as? Bool, extra {
                found.append(iface)
            }
        }
    }
    return found
}
```

### Особенности

1. **`String.hasPrefix`**, не `contains` — строже, чем у большинства (нельзя спрятать VPN в суффиксе).
2. **`lowercased()`** перед матчингом — регистронезависимо.
3. Читает **доп-флаг** из sub-dict `__SCOPED__[iface]` (ключ `5255760` + flag `0xE3` — 3-char строка `"P2P"` или аналогичный маркер `kSCDynamicStoreSetupGlobal*`).

Из-за всех трёх отличий наш хук, который **удаляет** VPN-ключи из `__SCOPED__`, здесь всё равно работает — сканер получит пустой dict → пустой массив → VPN не детектирован.

---

## UI-реакция

2GIS — **единственное приложение**, которое блокирует весь интерфейс на отдельное окно:

| Класс | Адрес | Что делает |
|---|---|---|
| `_TtC14VNVPNCheckerUI17VPNAlertPresenter` | `0x1084b92c0` | создаёт UIWindow поверх, показывает алерт |
| `_TtC14VNVPNCheckerUI10VPNAlertVC` | `0x1084b9320` | View controller алерта |
| `_TtC14VNVPNCheckerUI10VPNAlertVM` | `0x1084b94a0` | ViewModel |
| `_TtC14VNVPNCheckerUI16VPNBlockedWindow` | `0x1084b9510` | отдельный `UIWindow` для блока |

Строки локализации: `vpnAlert.message` (`0x1084b91f0`), `vpnAlert.refreshButton` (`0x1084b9230`).

### CarPlay

Отдельный путь для CarPlay-режима:

| Класс/строка | Адрес | Что делает |
|---|---|---|
| `_TtC9VNCarPlay24CarPlayVPNBlockOverlayVC` | `0x108333040` | full-screen overlay в CarPlay |
| `tripToRestoreAfterVPNUnblock` | `0x108331e80` | сохраняет текущий маршрут |
| `routePointsToRestoreAfterVPNUnblock` | `0x108331ea0` | сохраняет точки маршрута |
| `[CarPlay] VPN detected, showing block screen` | `0x1083cf0d0` | лог детекта в CarPlay |
| `[CarPlay] VPN unblocked, restoring CarPlay` | `0x1083cf450` | восстановление после разблокировки |
| `carPlayAppVPNBlockViewController` | `0x1083cef50` | property |
| `dashboardVPNBlockViewController` | `0x1083cef80` | property |
| `carplay.vpn block.retry button` / `carplay.vpn block.message` | `0x1083352d0`, `0x108335560` | локализация |

То есть при обнаружении VPN в CarPlay — приложение **сохраняет состояние навигации, блокирует экран, а после «разблокировки» восстанавливает маршрут**. Это уникальное поведение среди разобранных.

---

## Debug-артефакты

- `/Users/user/jenkins/agent/workspace/release-v4ios/v4ios-upload-to-testflight/v4ios/Src/CarPlay/Src/UI/CarPlayVPNBlockOverlayVC.swift` (`0x108333090`)
- `/Users/user/jenkins/agent/workspace/release-v4ios/v4ios-upload-to-testflight/v4ios/Src/VPNCheckerAPI/UI/VPNAlertVC.swift` (`0x1084b9420`)
- `VNVPNCheckerAPI/VPNCheckerAPI.swift` (`0x1084b8ba0`), `VPNStatusProvider.swift` (`0x1084b9020`), `VPNBlockedWindow.swift` (`0x1084b9580`), `VPNAlertPresenter.swift` (`0x1084b9290`), `VpnConnection` (`0x1084d7ae6`)

Jenkins CI-путь и full source-file paths слиты в релизный бинарь — `DEBUG_INFORMATION_FORMAT = dwarf-with-dsym` + не вырезанные debug-символы.

---

## Импорты

| Символ | Статус | Контекст |
|---|---|---|
| `_CFNetworkCopySystemProxySettings` | ✅ | 3 детектора |
| `_nw_path_uses_interface_type` | ❌ | не импортируется напрямую |
| `_nw_interface_get_type` | ❌ | не импортируется |
| `_CFNetworkCopyProxiesForURL` | ❌ | не импортируется |
| `_getifaddrs` | ✅ | только для IP-адреса в `FPNetworkInfoProvider` |
| `_sysctl`/`_getenv`/`_dlopen`/`_dlsym`/`_if_nametoindex` | ✅ | не VPN |
| `_SCDynamicStoreCopyProxies`/`_DNSServiceQueryRecord` | ❌ | — |

---

## Обход существующим `VPNHide`-твиком

Текущие хуки дают многослойное покрытие:

| Хук | Эффект на 2GIS |
|---|---|
| `CFNetworkCopySystemProxySettings` | Удаляет VPN-ключи из `__SCOPED__` → детекторы AppsFlyer + FPNetworkInfoProvider + ProxySettingsScanner получают пустые массивы → all `false`. |
| `nw_interface_get_type` | Если libswiftNetwork использует его для `NWInterface.type` → `VPNStatusProvider` никогда не увидит `.other` → мониторинг не триггерит server-check. |
| `nw_path_uses_interface_type` | Аналогично, если overlay ходит через эту функцию. |
| `CFNetworkCopyProxiesForURL` / `getifaddrs` | NO-OP (не импортируется / не для VPN). |

**Server-side check** (`/v1/vpn-detection-free`) — **не обходится напрямую**. Он не сработает, только если **не был инициирован** локальным scan/pathmonitor. Т.к. всё локальное мы глушим, никто не дёрнет `VPNCheckerAPI.checkBlocked()`.

⚠️ **Исключения**:
- Если где-то в коде есть **периодический timer**, независимый от локальных сигналов — он будет бить в `/v1/vpn-detection-free` по расписанию. Сервер вернёт 451 если IP принадлежит VPN-пулу — UI заблокируется.
- **Fallback URL** + remote-config позволяют MyDGS менять endpoint на лету.

Для гарантии — добавить в твик ещё один хук: подменять ответ `/v1/vpn-detection-free` на пустой (через swizzle `NSURLSessionDataTask` / `URLSession.dataTask(with:)` на совпадение URL).

Для активации текущего твика добавить в [`tweaks/VPNHide/Filter.plist`](../../tweaks/VPNHide/Filter.plist):

```
{ Filter = { Bundles = ( …, "ru.doublegis.grymmobile" ); }; }
```

---

## Сравнение

| | MyMTS | МФ | CDEK | DNS-SHOP | ЦППК | Urent | Госуслуги | билайн | **2GIS** |
|---|---|---|---|---|---|---|---|---|---|
| Локальных детекторов | 2 | 1 | 2 | 1 | 1 | 3 | 5 | 2 | **3** |
| Server-side detection | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ **HTTP 451** |
| Full-screen block window | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| CarPlay integration | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| State preservation (trip restore) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| Remote-config на детектор | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ |
| `String.hasPrefix` (не `contains`) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| Retry с fallback-URL | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| DI-архитектура (protocol + impl) | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ |
| Покрытие VPNHide | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ (локал.) + ⚠️ server |

2GIS — чемпион по комплексности. Всё, что у других апп минимум одно-двухслойно, тут делается на 3 уровнях (local proxy + NWPath + server) с full-screen UI-блоком и отдельным CarPlay-слоем. Команда, которая это писала, явно относилась к VPN-детекту как к serious anti-cheat'у в производственной игре.

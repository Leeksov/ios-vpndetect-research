# Urent — детектирование VPN / Proxy

**Бинарник:** `Urent` v1.94.1 (arm64, Swift + Obj-C)
**Способ анализа:** IDA Pro / Hex-Rays.
**Обход:** [`tweaks/VPNHide`](../../tweaks/VPNHide/) — текущий твик покрывает, достаточно добавить `ru.urentbike.app` в [`Filter.plist`](../../tweaks/VPNHide/Filter.plist).

---

## TL;DR

Три детектора **с идентичным ядром** — `CFNetworkCopySystemProxySettings` → `__SCOPED__` → substring-match по именам интерфейсов. Все три живут в разных местах и дублируют друг друга:

| # | Где | Вход | Адрес |
|---|---|---|---|
| 1 | AppsFlyer SDK (Obj-C) | `+[AppsFlyerUtils isVPNConnected]` | `0x102040318` |
| 2 | Основной app (Swift) | `sub_100550134` | `0x100550134` |
| 3 | `Services.framework.VpnCheckerService` (Swift) | `sub_101AB5BD0` | `0x101AB5BD0` |

Только #3 — «продакшен»-детект, с которым связан весь UI и Combine-пайплайн: `VpnCheckerService` публикует `Bool` через `vpnStatusSubject`, подписчики (`VpnChecherManagableObserver`) реагируют. #1 — стандартная вшитая логика AppsFlyer SDK. #2 — дубль, возможно legacy-проверка, оставшаяся при рефакторинге.

`NWPathMonitor` для VPN **не используется** — `_nw_path_uses_interface_type` вообще не импортируется. `_getifaddrs` импортируется, но дёргается только из `-[GMSCellularInfo supportsData]` (GoogleMaps SDK) и ещё одного cellular-helper'а — не VPN.

Исходник одной из функций (путь в debug-строке `0x1029d7740`) — выдаёт архитектуру:

```
/Users/user/builds/_csHvbAg/1/urent-mobile/urentbike-ios/
    Classes/BusinessLogicLayer/Services/Services/Source/Legacy/
    Services/Services/VpnCheckerService/OldVPNIsWorkedView.swift
```

Всё живёт в подмодуле `Services` как value-типы, наблюдаемые через `Combine.CurrentValueSubject`.

---

## Детектор №1 — AppsFlyer

`+[AppsFlyerUtils isVPNConnected]` @ `0x102040318`. Байт-в-байт копия реализации из MyMTS/CDEK: подстроки `tap/tun/ipsec/ppp`. Использует Obj-C API `rangeOfString:`. Флаг SDK: `AppsFlyerVPNCollectionEnabled` (строка `0x1029fe005`).

Прямого UI-эффекта нет — влияет только на AppsFlyer-телеметрию.

---

## Детектор №2 — Swift (legacy / main app) — `sub_100550134`

Swift-функция в основном app-бинарнике. Схема та же, реализована через bridge `NSDictionary → [String: Any]` + `StringProtocol.contains<A>`. Подстроки:

| Литерал | Байты | ASCII |
|---|---|---|
| `7364980` | `74 61 70 00` | `tap` |
| `7239028` | `74 75 6E 00` | `tun` |
| `7368816` | `70 70 70 00` | `ppp` |
| `0x6365_7370_69` | `69 70 73 65 63` | `ipsec` |

`utun` здесь нет — тот же «младший» набор из 4 подстрок, что и в AppsFlyer.

---

## Детектор №3 — `Services.VpnCheckerService` (основной) — `sub_101AB5BD0`

Самый развитый из трёх. Подстроки держатся **массивом** в стеке (5 штук), затем перебираются во вложенном цикле:

```
inited + 32  = 7364980,         0xE300000000000000   // "tap"
inited + 48  = 7239028,         0xE300000000000000   // "tun"
inited + 64  = 7368816,         0xE300000000000000   // "ppp"
inited + 80  = 0x6365737069,    0xE500000000000000   // "ipsec"
inited + 96  = 1853191285,      0xE400000000000000   // "utun"
```

Цикл:

```swift
for iface in (settings["__SCOPED__"] as? [String: Any])?.keys ?? [] {
    for needle in ["tap", "tun", "ppp", "ipsec", "utun"] {
        if iface.contains(needle) { return true }
    }
}
return false
```

Swift-класс: `_TtC8Services17VpnCheckerService` (`0x1029d7840`). Metadata accessor: `$s8Services17VpnCheckerServiceCMa` @ `0x101ab5654`.

### Реактивный pipeline

Класс VpnCheckerService экспонирует несколько свойств / методов:
- `vpnStatusSubject` (`0x1029d7870`) — `CurrentValueSubject<Bool, Never>` с текущим состоянием
- `vpnViewIsClosed` (`0x1029d788f`) — флаг «юзер закрыл шторку вручную»
- `setViewVpn()` / `removeVPNView()` / `closeVPNWorkedView()` (строки `0x1029d78b0`, `0x1029d78f0`, `0x1029d7800`)

Протокол и observer'ы:
- `VpnChecherServiceManagable` (`$s8Services26VpnChecherServiceManagableP` @ `0x102b9493c`)
- `VpnChecherManagableObserver` (`$s8Services27VpnChecherManagableObserverP` @ `0x102b94966`)

В обёртке типа `Observable<VpnChecherManagableObserver>` — классический reactive pattern.

---

## UI-реакция

Набор view'ек для показа предупреждения:

| View | Где |
|---|---|
| `OldVPNIsWorkedView` (`0x1029d7710`) | Legacy, старый снекбар. |
| `VPNIsWorkedView` (`0x102c4e681`) | Новый снекбар. |
| `BottomVpnView` (`0x102bdf5dc`) | Нижняя плашка/шторка. |

Selectors / API:
- `turnOnVPN` / `turnOffVPN` (`0x10300b822`, `0x10300b82c`) — пайплайн из UI «показать/спрятать плашку».
- `subscribeVPNStatus`
- `changeVpnVisibility`
- `closeVPNView` / `closeVpnView` / `_showVpnView`
- `isHiddenVPNView` / `_isHiddenVPNView` / `_vpnViewIsHidden`
- `showVpnToast` / `hideVpnToast` / `manualHideVpnToast` (`0x102fea486`, `0x102fea493`, `0x102fea4a0`)
- `isActiveVPN` / `vpnIsOn` / `vpnIsOff`

---

## Телеметрия

| Ключ / строка | Адрес |
|---|---|
| `labels.device_vpn` | `0x102934d40` |
| `is_vpn_on` | `0x10293d499` |
| `show_vpn_toast` | `0x10293f19b` |
| `hide_vpn_toast` | `0x10293f1aa` |
| `manual_hide_vpn_toast` | `0x10293f1c0` |
| `AppsFlyerVPNCollectionEnabled` | `0x1029fe005` |

Обычный analytics-event каждый раз, когда плашка появляется/скрывается, + per-user label `device_vpn`.

---

## Импорты Mach-O

| Символ | Статус | Контекст использования |
|---|---|---|
| `_CFNetworkCopySystemProxySettings` | ✅ | три VPN-детектора |
| `_nw_path_uses_interface_type` | ❌ | не импортируется |
| `_nw_interface_get_type` | ❌ | не импортируется |
| `_getifaddrs` | ✅ | GoogleMaps cellular-info, не VPN |
| `_if_nametoindex` | ✅ | не VPN |
| `_sysctl` / `_sysctlbyname` | ✅ | hw model / uptime / sysctl entries (Firebase GULAppEnvironmentUtil), не VPN |
| `_getenv` | ✅ | env-настройки SDK, не VPN |
| `_dlopen` / `_dlsym` | ✅ | не VPN |
| `_DNSServiceQueryRecord` | ❌ | — |
| `_SCDynamicStoreCopyProxies` | ❌ | — |

---

## Обход существующим `VPNHide`-твиком

Наш хук `CFNetworkCopySystemProxySettings` вырезает из `__SCOPED__` все ключи с подстроками `utun/tun/tap/ipsec/ppp/wg`. Это покрывает все **три** детектора: каждый из них получает на вход уже «очищенный» словарь и возвращает `false`.

Следствия:
- `vpnStatusSubject` постоянно содержит `false` → Observer'ы (`VpnChecherManagableObserver`) не триггерятся.
- UI-плашки (`VPNIsWorkedView`, `BottomVpnView`, `OldVPNIsWorkedView`) не поднимаются.
- Аналитика `labels.device_vpn = true` и события `show_vpn_toast` не уходят.

Хук `nw_path_uses_interface_type` для Urent иррелевантен (не импортируется — код туда не попадает).

Для активации добавить в [`tweaks/VPNHide/Filter.plist`](../../tweaks/VPNHide/Filter.plist):

```
{ Filter = { Bundles = ( …, "ru.urentbike.app" ); }; }
```

---

## Сравнение

| | MyMTS | МегаФон | CDEK | DNS-SHOP | ЦППК | Urent |
|---|---|---|---|---|---|---|
| Количество детекторов | 2 | 1 | 2 | 1 | 1 | **3** |
| `__SCOPED__` | ✅ | ✅ | ✅ (×2) | ✅ | ❌ | ✅ (×3) |
| `NWPathMonitor` для VPN | ✅ | ❌ | ❌ | ❌ | ✅ (косвенно) | ❌ |
| Reactive (Combine) | ✅ | ❌ | — (RN) | ❌ | ❌ | ✅ (`vpnStatusSubject`) |
| UI-элементов | 1 снекбар | 1 алерт | JS RN | 1 снекбар | 2 (alert + SwiftUI) | 3 view'ки |
| Покрытие VPNHide | ✅ | ✅ | ✅ | ✅ | ⚠️ | ✅ |

Urent — пока «самый замусоренный» кейс: тройная реализация одного и того же через разные поколения кода (AppsFlyer + legacy Swift + актуальный `Services.VpnCheckerService`). Все три точки бьются одним хуком на системный API, в коде твика ничего менять не надо.

[🇬🇧 English version](vpn-detection.md)

# Rostic's — детектирование VPN / Proxy

**Бинарник:** `kfc` v10.29.0 (arm64, Swift + Obj-C)
**Способ анализа:** IDA Pro / Hex-Rays.
**Обход:** [`tweaks/VPNHide`](../../tweaks/VPNHide/) — текущий твик покрывает; добавить `ru.yum.KFC-Russia` в [`Filter.plist`](../../tweaks/VPNHide/Filter.plist).

---

## TL;DR

Один реальный детектор + Swift-обёртка с UI-инфраструктурой:

| # | Модуль | Механизм | Адрес |
|---|---|---|---|
| 1 | AppsFlyer SDK (Obj-C) | `+[AppsFlyerUtils isVPNConnected]` — `__SCOPED__` → `tap/tun/ipsec/ppp` | `0x1013EED10` |

`KFCGeneralModule.CheckVPN` (`$s16KFCGeneralModule8CheckVPNVMa` @ `0x10047d694`) — Swift-структура (`V` в манглинге), описывающая результат проверки. Её собственный код проверки в декомпиляции не локализуется (метаданные есть, методы анонимные / inline'нутые), но **поведение однозначное**: единственный callsite `CFNetworkCopySystemProxySettings` в бинарнике — это AppsFlyer. CheckVPN либо обёрнут поверх AppsFlyer, либо принимает `Bool` извне.

`NWPathMonitor` **не используется для VPN** — `sub_10018D4D0` дёргает `nw_path_uses_interface_type(path, .cellular)` единоразово и тут же `nw_path_monitor_cancel`. Reachability, не VPN.

**Импорты Mach-O:**

| Символ | Статус | Контекст |
|---|---|---|
| `_CFNetworkCopySystemProxySettings` | ✅ | только AppsFlyer |
| `_nw_path_uses_interface_type` | ✅ | только cellular reachability, не VPN |
| `_getifaddrs` | ✅ | вспомогательный |
| `_nw_interface_get_type` / `_CFNetworkCopyProxiesForURL` / `_SCDynamicStoreCopyProxies` / `_DNSServiceQueryRecord` | ❌ | — |

---

## Архитектура

### `KFCGeneralModule.CheckVPN` (Swift struct)

| Symbol | Адрес |
|---|---|
| Type metadata accessor | `$s16KFCGeneralModule8CheckVPNVMa` @ `0x10047d694` |
| Static reference | data ref @ `0x103381950` (witness / global) |

`V` в манглинге (`...VMa`) — это Swift value type. Используется как DTO/result-of-check.

### UI-слой — `KFCUIModule.VPNMessageCell`

| Symbol | Адрес |
|---|---|
| Class | `_TtC11KFCUIModule14VPNMessageCell` @ `0x1031d9e10` |
| Source path | `KFCUIModule/VPNMessageCell.swift` (`0x1031d9e40`) |
| Полный путь | `/Users/developers/builds/PEJtp_Ma/0/mobile/mobile-ios/ios/kfc/Modules/KFCUIModule/Views/VPNMessageCell/VPNMessageCell.swift` |
| Init | `-[VPNMessageCell initWithStyle:reuseIdentifier:]` @ `0x1008fbf10` |
| ViewModel | `$s11KFCUIModule19VPNMessageCellModelVMa` @ `0x1008fc948` |

`VPNMessageCell` — это **`UITableViewCell`-subclass** (init with `style:reuseIdentifier:`), который вставляется в общий feed/menu при активном VPN. Подсказка показывается **inline** в списке, а не модально или снекбаром.

### Локализация

| Ключ | Адрес | Использование |
|---|---|---|
| `errors.vpn_active.title` | `0x1031cac20` | заголовок ошибки |
| `errors.vpn_active.text` | `0x1031c9ac0` | тело ошибки |
| `screens.menu.vpn_message` | `0x1031ca970` | сообщение в меню |

Все три используются через `NSLocalizedString(_:tableName:bundle:value:comment:)` в `sub_1007C738C` (`title`) и аналогичных wrapper'ах. Bundle resolver — функция `sub_1006F9054` (load-once через `swift_once`).

### Notification

Строка `activeVPN` (`0x1033d05d3`, `0x1033d0893`) — Swift small-string, попадает в data-секции дважды → используется как `NSNotification.Name("activeVPN")` (паттерн как у ЦППК). Постится из VPN-checker'а, наблюдатели реагируют показом `VPNMessageCell` или `vpnMessage`-property.

### Прочие маркеры

- `vpnMessage` (`0x1033d0a6d`) — Swift property
- `AppsFlyerVPNCollectionEnabled` (`0x103250a02`) — флаг в AppsFlyer SDK
- `VPNCollectionEnabled` / `setVPNCollectionEnabled:` — Obj-C accessors AppsFlyerLib

---

## Debug-артефакты

GitLab CI runner-путь оставлен в бинарнике:

```
/Users/developers/builds/PEJtp_Ma/0/mobile/mobile-ios/ios/kfc/Modules/KFCUIModule/Views/VPNMessageCell/VPNMessageCell.swift
```

Workspace prefix `PEJtp_Ma/0/` — стандартный GitLab Runner format. Неуникальный путь сборки.

---

## Обход существующим `VPNHide`-твиком

Хук `CFNetworkCopySystemProxySettings` вырезает VPN-ключи из `__SCOPED__` → AppsFlyer-детектор возвращает `false` → цепочка дальше в `CheckVPN` / `VPNMessageCell` / `errors.vpn_active.*` не запускается. Все остальные хуки на этом бинарнике — NO-OP.

Для активации добавить в [`tweaks/VPNHide/Filter.plist`](../../tweaks/VPNHide/Filter.plist):

```
{ Filter = { Bundles = ( …, "ru.yum.KFC-Russia" ); }; }
```

Bundle ID — legacy KFC-эпохи (до ребрендинга в Rostic's), не менялся.

---

## Сравнение

| | MyMTS | МФ | CDEK | DNS-SHOP | ЦППК | Urent | Госуслуги | билайн | 2GIS | Мой налог | **Rostic's** |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Локальных детекторов | 2 | 1 | 2 | 1 | 1 | 3 | 5 | 2 | 3 | 0 | **1** (AppsFlyer-only) |
| Server-side | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | — | ❌ |
| UI-реакция | снекбар | алерт | RN | снекбар | alert + SwiftUI | 3 view'ки | snackbar | toast/alert | full-screen + CarPlay | — | **inline `UITableViewCell`** |
| Notification-driven (`activeVPN`) | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | — | ✅ |
| Покрытие VPNHide | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | n/a | ✅ |

Rostic's — наименее агрессивный из приложений с детектом: только стандартный AppsFlyer-шим + UX-warning через cell в общем feed'е (без блокировки, без модалок). Команда явно отнеслась к VPN как к неудобству, а не угрозе — детект есть «для галочки» и UI-подсказки.

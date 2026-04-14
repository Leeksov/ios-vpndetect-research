[🇬🇧 English version](vpn-detection.md)

# Кинопоиск — детектирование VPN / Proxy

**Бинарник:** `Kinopoisk` v8.41.3 (arm64, Swift + Obj-C, ~165 MB)
**Способ анализа:** IDA Pro / Hex-Rays.
**Обход:** [`tweaks/VPNHide`](../../tweaks/VPNHide/) — текущий твик покрывает локальные детекторы; server-side `checkvpn` обходится **косвенно**.

---

## TL;DR

Самый «комплексный» VPN-стек среди разобранных. Кинопоиск одновременно **детектит** пользовательский VPN и **управляет** собственным «Yandex VPN-Connect» (anti-blocking прокси для DRM/региональных ограничений).

| Слой | Подсистема | Назначение |
|---|---|---|
| Detection | `+[AppsFlyerUtils isVPNConnected]` | стандарт AppsFlyer |
| Detection | `-[YALAFHTTPClient isVPNConnected]` | Obj-C, Yandex AppLib (общая с Я.Маркет) |
| Detection | `MobileAdsCore.MACVpnStatusCheckerImpl` | shared SDK SPB TV (общий с Amediateka) |
| Detection (server-side) | `GET /tmgrdfrend/checkvpn` | бекенд-проверка |
| Routing (НЕ detection) | `YALVPNConnectManager` (full Obj-C класс) | управляет собственным Yandex-прокси для регионального контента |
| Config | `YALVPNConfig` / `YALVPNConfigApp` | remote-config с per-bundle-id настройками + `minVersion` |
| Feature-flag | `ios_block_vpn` | сервер-side kill switch |

**Импорты:**

| Символ | Статус | Контекст |
|---|---|---|
| `_CFNetworkCopySystemProxySettings` | ✅ | 3 callsite (AppsFlyer + YAL + MAC) |
| `_nw_path_uses_interface_type` | ✅ | `YALNetworkMonitor.mapPathToStatus:` (cellular/wifi/wired classifier, **не VPN**) |
| `_getifaddrs` | ❌ | не импортируется |
| `_nw_interface_get_type` / `_CFNetworkCopyProxiesForURL` / `_SCDynamicStoreCopyProxies` / `_DNSServiceQueryRecord` | ❌ | — |

---

## Локальные детекторы

### №1 — AppsFlyer

`+[AppsFlyerUtils isVPNConnected]` @ `0x1068C4FD0`. Стандарт. Управляется `AppsFlyerVPNCollectionEnabled` (`0x1072b77f2`).

### №2 — `-[YALAFHTTPClient isVPNConnected]` @ `0x1042C992C`

Идентичен реализации в Яндекс Маркет (тот же Yandex AppLib): `__SCOPED__.allKeys` → `yal_foreachUsingBlock:` поверх captured-NSArray needles → `[needle containsString:iface_name]` (обратная семантика). См. [yandex-market/vpn-detection.ru.md#детектор-1](../yandex-market/vpn-detection.ru.md#детектор-1----yalafhttpclient-isvpnconnected) для деталей.

### №3 — `MobileAdsCore.MACVpnStatusCheckerImpl.check()` @ `0x106AC1378`

**Тот же class из shared-SDK `MobileAdsCore`, что и в Amediateka.** Тристейт-результат `0/1/2` (no/yes/unknown). Externally-supplied массив подстрок через DI. См. [amediateka/vpn-detection.ru.md#детектор-2](../amediateka/vpn-detection.ru.md#детектор-2----macvpnstatuscheckerimplcheck) для деталей.

DI-инжект: property `vpnStatusChecker` (`0x1072e55e0`, `0x107c6dbf0`).

---

## Server-side check — `/tmgrdfrend/checkvpn`

Endpoint `0x10720234d`. Третий разобранный кейс с server-side детектом (после 2GIS `/v1/vpn-detection-free` и Amediateka `403 Vpn`).

Не нашли в декомпиляции прямой URLSession-вызов (скорее всего, собирается из base + path где-то в Yandex networking layer), но ясно по строке.

Активность контролируется feature-flag'ом **`ios_block_vpn`** (`0x107213b15`) — сервер может отключить детект-блок на лету.

---

## `YALVPNConnect` — НЕ detection, а **роутинг**

Целая Obj-C подсистема для управления **собственным** VPN-Connect от Yandex (анти-блок прокси для регионального контента):

| Класс | Назначение |
|---|---|
| `YALVPNConnectManager` (`+shared`) | синглтон, managing connection-status |
| `YALVPNConnectManagerObserversController` | KVO-подобный observers controller |
| `YALVPNConnectProductLocation` | модель «где находится продукт» (lat/lon) |
| `YALVPNConfig` | remote-config верхний уровень |
| `YALVPNConfigApp` | per-bundle-id config с `appID` + `minVersion` |

Ключевые методы `YALVPNConnectManager`:

- `+shared`, `init`, `dealloc`
- `updateWithAccountManager:`
- `setProductLocation:` / `setProductLocations:`
- `setDeviceGeoLocation:` / `setDeviceGeoLocations:`
- `setAdditionalParameters:`
- `addStatusObserver:` / `removeStatusObserver:`
- `addObservers` / `removeObservers` / `notifyObservers`
- `startMonitoring` / `stopMonitoring`
- `accountManager:didSetCurrentAccount:`
- `networkMonitorDidChangeStatus:fromOldStatus:`
- `locationTracker:didUpdateLocation:previousLocation:`
- `getAccountForStatusUpdate`
- `httpClient`
- `updateStatus:`

Он подписывается на:
- `YALNetworkMonitor` (network reachability)
- `YALAccountManager` (login/logout)
- `YALLocationTracker` (geo updates)

И обновляет внутренний «должен ли быть включен Yandex VPN-Connect» через `YALVPNConfig.shouldBeEnabled` (`0x104300a50` — большой метод 0x224 байт, парсит JSON-config с `apps[]`, проверяет `appID == bundleID` и `version >= minVersion` через `semverComponents:greaterOrEqualThan:`).

Это **не детектор пользовательского VPN**, а **управление включением Yandex'ового анти-блок прокси** для региональных стримов. Но в бинарнике обе системы перемешаны и часто называются `vpn*`.

---

## UI — "VPN Blocker" full-screen

6 analytics-событий указывают на полноценный full-screen VPN-blocker UI с несколькими действиями:

| Event | Адрес |
|---|---|
| `vpn_blocker_show` | `0x107208a62` |
| `vpn_blocker_hide` | `0x107208a73` |
| `vpn_blocker_reload` | `0x107208a84` |
| `vpn_blocker_close` | `0x107208a97` |
| `vpn_blocker_settings` | `0x107208aa9` |
| `vpn_blocker_openurl` | `0x107208abe` |

Это полноценная экран-блокировка с кнопками: «Перезагрузить», «Закрыть», «Настройки», «Открыть URL» (видимо, FAQ).

### Тексты алертов

| Сообщение | Адрес |
|---|---|
| `У вас включен VPN или в вашей стране доступен не весь каталог Кинопоиска` | `0x1070426b0` |
| `Что-то пошло не так. Возможно, вам нужно выключить VPN` | `0x1071ad950` |

Первый текст характерен — Кинопоиск **не уверен**, проблема в VPN или в region availability. Это последовательно с тристейт-логикой `MACVpnStatusChecker`'а (`unknown` case).

### Прочие markers

- `vpnFlag`, `vpnInactive`, `isVpnEnabled` — internal state-флаги
- `vpnConnectedTransformer` — Combine/Rx Transformer (как у Amediateka)
- `sessionBecameInvalidWithoutUnderlyingError` — error case, видимо мапящийся в VPN-blocker

---

## Обход существующим `VPNHide`-твиком

Локальная часть закрывается полностью:

| Детектор | Хук | Эффект |
|---|---|---|
| AppsFlyer | `CFNetworkCopySystemProxySettings` | пустой `__SCOPED__` → `NO` |
| YALAFHTTPClient | `CFNetworkCopySystemProxySettings` | пустой allKeys → block ничего не находит → `NO` |
| MACVpnStatusCheckerImpl | `CFNetworkCopySystemProxySettings` | пустой allKeys → `0` (no VPN, не unknown) |

Server-side `/tmgrdfrend/checkvpn` **не обходится напрямую**, но:
- По симметрии с 2GIS/Amediateka, скорее всего сервер бьёт только когда локальные сигналы что-то показали → если локалка молчит, бекенд не дёргается. Эмпирически проверять.
- Можно обнулить через swizzle URLSession + URL-matching на `/checkvpn`.

`YALVPNConnectManager` (Yandex-прокси routing) **не нужно** трогать — это управление Yandex VPN-Connect, а не детект пользователя. Хуки на `__SCOPED__` его не задевают.

Для активации добавить в [`tweaks/VPNHide/Filter.plist`](../../tweaks/VPNHide/Filter.plist):

```
{ Filter = { Bundles = ( …, "ru.kinopoisk" ); }; }
```

---

## Сравнение

| | MyMTS | МФ | CDEK | DNS | ЦППК | Urent | Гос | бил | 2GIS | Налог | Rost | В&Т | Amediateka | YM | **Кинопоиск** |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Лок. детекторов | 2 | 1 | 2 | 1 | 1 | 3 | 5 | 2 | 3 | 0 | 1 | 1 | 2 | 2 | **3** |
| AppsFlyer-style | ✅ | — | ✅ | — | ❌ | ✅ | — | ✅ | ✅ | — | ✅ | ❌ | ✅ | ❌ | ✅ |
| Server-side | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ 451 | — | ❌ | ❌ | ✅ 403 Vpn | ❌ | ✅ `/checkvpn` |
| Тристейт on/off/unknown | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | — | ❌ | ❌ | ✅ | ❌ | **✅** (через MAC) |
| Shared SDK с другим app | — | — | — | — | — | — | — | — | — | — | — | — | ✅ MobileAdsCore | ✅ YAL | **✅×2** (MAC + YAL) |
| Свой proxy (anti-blocker) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | — | ❌ | ❌ | ❌ | ❌ | **✅** YALVPNConnect |
| Full-screen blocker UI | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ + CarPlay | — | ❌ | ❌ | ❌ | ❌ | ✅ (6 событий) |
| Покрытие VPNHide | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ (лок.) | n/a | ✅ | ✅ | ✅ (лок.) | ✅ | ✅ (лок.) |

Кинопоиск — единственное приложение в выборке, где есть **собственная VPN-инфраструктура для обхода блокировок** (`YALVPNConnect`) **и** многослойный детект **пользовательского** VPN. Также первое приложение, переиспользующее **сразу два** shared-SDK с другими разобранными апп: `MobileAdsCore` (с Amediateka) и Yandex AppLib YAL (с Я.Маркет). Это важный водораздел в экосистемах — Кинопоиск находится на пересечении Yandex и SPB TV / Mail.ru стримингового мира.

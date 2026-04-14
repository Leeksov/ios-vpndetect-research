# Amediateka — детектирование VPN / Proxy

**Бинарник:** `Amediateka` v4.54.0 (arm64, Swift + Obj-C)
**Способ анализа:** IDA Pro / Hex-Rays.
**Обход:** [`tweaks/VPNHide`](../../tweaks/VPNHide/) — текущий твик покрывает локальную часть; server-side обходится **косвенно** (если локальный сканер не нашёл VPN — стриминг не упрётся в `403 Vpn`-код, либо упрётся, но независимо от IP клиента).

---

## TL;DR

Стриминговый сервис → детект VPN важен для DRM-/гео-блокировок. Реализован двухслойно:

| # | Слой | Механизм | Адрес |
|---|---|---|---|
| 1 | AppsFlyer SDK (Obj-C) | `+[AppsFlyerUtils isVPNConnected]` — `__SCOPED__` → `tap/tun/ipsec/ppp` | `0x100E77BA0` |
| 2 | `MobileAdsCore.MACVpnStatusCheckerImpl` (Swift) | `__SCOPED__.allKeys` → `String.contains(needle)` по конфигурируемому массиву; **тристейт** `0/1/2` (no/yes/unknown) | `0x102497218` |
| 3 | **Server-side** | API-ответ маппится в Swift-error `ShortApiError403Vpn` (HTTP 403 + `code: "Vpn"`); UI показывает «vpnContentPlaybackError» | `sub_100416D34` (error-resolver) |

`MACVpnStatusChecker` живёт в **отдельном фреймворке `MobileAdsCore`** — это SDK SPB TV (издателя Amediateka), переиспользуемый, скорее всего, и в других их приложениях.

`nw_path_uses_interface_type` импортируется, но **не для VPN** — single-pass `.cellular` reachability в `sub_100E3E03C` + `nw_path_monitor_cancel`.

**Импорты:**

| Символ | Статус | Контекст |
|---|---|---|
| `_CFNetworkCopySystemProxySettings` | ✅ | AppsFlyer + MACVpnStatusCheckerImpl |
| `_nw_path_uses_interface_type` | ✅ | reachability (cellular only), не VPN |
| `_getifaddrs` | ❌ | **не импортируется** |
| `_nw_interface_get_type` / `_CFNetworkCopyProxiesForURL` / `_SCDynamicStoreCopyProxies` / `_DNSServiceQueryRecord` | ❌ | — |

---

## Детектор №1 — AppsFlyer

Стандартный `+[AppsFlyerUtils isVPNConnected]` — `tap/tun/ipsec/ppp`. Управляется флагом `AppsFlyerVPNCollectionEnabled` (`0x10292d85b`).

---

## Детектор №2 — `MACVpnStatusCheckerImpl.check`

Swift-class в фреймворке `MobileAdsCore`:

| Symbol | Адрес |
|---|---|
| Type metadata | `$s13MobileAdsCore23MACVpnStatusCheckerImplCMa` @ `0x1024977b4` |
| Class name | `_TtC13MobileAdsCore23MACVpnStatusCheckerImpl` @ `0x1029aa630` |
| Protocol | `$s13MobileAdsCore19MACVpnStatusCheckerP` @ `0x102aa9320` |

Псевдокод `sub_102497218`:

```swift
func check() -> Int {            // 0 = no VPN, 1 = VPN, 2 = unknown
    guard let settings = CFNetworkCopySystemProxySettings() else { return 2 }
    guard let dict     = settings as? [String: Any] else { return 2 }
    guard let scoped   = dict["__SCOPED__"] as? [String: Any] else { return 2 }

    let needles: [String] = self.configuredNeedles    // *(self+16) — instance property
    for iface in scoped.keys {
        for needle in needles {
            if iface.contains(needle) { return 1 }
        }
    }
    return 0
}
```

### Особенности

1. **Тристейт** (`0`/`1`/`2`) — как у Госуслуг (`vpn_on`/`vpn_off`/`vpn_unknown`). Различает «не нашли VPN» и «не смогли узнать».
2. **Внешний массив подстрок** — хранится в instance-поле, а не захардкожен. Скорее всего — конфигурируется через DI/init или подкачивается из remote-config (как в Госуслугах и Beeline).
3. **Часть отдельного фреймворка** `MobileAdsCore` — общая для SPB TV-приложений.

---

## Детектор №3 — server-side `ShortApiError403Vpn`

`sub_100416D34` — error-resolver, маппит код API-ошибки в локализованный StringResource:

```
a1 == 0 → fallback / generic
a1 == 1 → "Account.Unauthorized Error"
a1 == 2 → "Errors.ShortApiError403Vpn"
```

То есть бекенд может вернуть HTTP 403 с маркером `"Vpn"`, который Swift-парсер маппит в Swift-enum case → resolver выдаёт строку `Errors.ShortApiError403Vpn` → UI показывает алерт.

Дополнительные строки в этой же группе:

| Ключ | Адрес |
|---|---|
| `vpnError.title` | `0x1028ac340` |
| `vpnError.message` | `0x1028ac400` |
| `vpnContentPlaybackError.message` | `0x1028ac320` |
| `vpnErrorKidsControl` | `0x102acad20` |
| `statusRequestingVpnError` | `0x102ad1230` |
| `{{WAS_GEOBLOCKED}}` | `0x1028ef550` (template-плейсхолдер для уже-гео-блокированного контента) |
| `isGeoBlocked` | `0x1028f4551`, `0x102ad7071` (Bool property) |

Геоблок и VPN-блок разнесены концептуально: `WAS_GEOBLOCKED` — флаг, что контент **исторически** был недоступен в регионе пользователя; `vpnError.*` — алерт прямо в момент блокировки за VPN.

---

## UI и реактивный pipeline

- `_TtC10Amediateka31VpnStreamingAlertRefreshHandler` (`0x1028bd170`) — обработчик «refresh»-кнопки в VPN-error-алерте. Source: `Amediateka/VpnStreamingAlertRefreshHandler.swift` (`0x1028bd1c0`).
- `vpnStatusChecker` (`0x1029aa2f0`, `0x102b086d0`) — DI-инжект instance MACVpnStatusCheckerImpl
- `vpnConnectedTransformer` (`0x1029b2b10`, `0x102b0dab0`) — Combine/RxSwift Transformer, мапящий VPN-статус в UI-state.
- `showVpnStreamingErrorAlert` (`0x102abb8c0`) — selector, вызывающий показ алерта.
- `VpnCodingKeys` (`0x1027a69b8`) — Swift Codable для VPN-related JSON (бекенд-поля).

---

## Обход существующим `VPNHide`-твиком

Хук `CFNetworkCopySystemProxySettings`:
- ✅ Удаляет VPN-ключи из `__SCOPED__` → AppsFlyer (`+isVPNConnected`) и `MACVpnStatusCheckerImpl.check()` оба возвращают `false` / `0`.
- Тристейт-логика: вернётся `0` (no VPN), не `2` (unknown) — словарь сам по себе валидный, просто без VPN-ключей.

Server-side check (`HTTP 403 + "Vpn"`) **не обходится напрямую**, но:
- Если ваш VPN-провайдер выходит с **российского** IP (что для Amediateka и так требование, контент только для РФ) — сервер вернёт 200, ошибки не будет.
- Если выходит из-за рубежа — сервер вернёт `403 Vpn` независимо от наших хуков. Это ловится только подменой ответа URLSession (отдельный swizzle), но Amediateka-контент юридически не лицензирован за пределами РФ — толку от обхода нет.

Для активации добавить в [`tweaks/VPNHide/Filter.plist`](../../tweaks/VPNHide/Filter.plist):

```
{ Filter = { Bundles = ( …, "com.spbtv.ag.tv.Amedia" ); }; }
```

---

## Сравнение

| | MyMTS | МФ | CDEK | DNS | ЦППК | Urent | Гос | бил | 2GIS | Налог | Rost | В&Т | **Amediateka** |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Локальных | 2 | 1 | 2 | 1 | 1 | 3 | 5 | 2 | 3 | 0 | 1 | 1 | **2** |
| Server-side | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ HTTP 451 | — | ❌ | ❌ | ✅ HTTP 403 + `Vpn` |
| Тристейт (on/off/unknown) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | — | ❌ | ❌ | ✅ |
| Геоблок-инфраструктура отдельно | — | — | — | — | — | — | — | — | — | — | — | — | ✅ `{{WAS_GEOBLOCKED}}` |
| Внешний массив паттернов | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ | — | ❌ | ❌ | ✅ |
| Из shared SDK другой компании | — | — | — | — | — | — | — | — | — | — | — | — | ✅ `MobileAdsCore` (SPB TV) |
| Покрытие VPNHide | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ (лок.) | n/a | ✅ | ✅ | ✅ (лок.) |

Amediateka — **второе приложение из 12** с server-side детектом (после 2GIS), но использует HTTP 403 с code-полем вместо HTTP 451. Уникальная черта — детектор живёт **в чужом SDK** (`MobileAdsCore` — SPB TV common SDK), а главное приложение лишь подписано на его сигналы через `vpnStatusChecker` DI-injection.

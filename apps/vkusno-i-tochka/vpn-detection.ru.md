[🇬🇧 English version](vpn-detection.md)

# Вкусно — и точка — детектирование VPN / Proxy

**Бинарник:** `mcd-ios` v13.2.0 (arm64, Swift + Obj-C)
**Способ анализа:** IDA Pro / Hex-Rays.
**Обход:** [`tweaks/VPNHide`](../../tweaks/VPNHide/) — текущий твик покрывает; добавить `com.mcdonaldsru.mcd` в [`Filter.plist`](../../tweaks/VPNHide/Filter.plist).

---

## TL;DR

**Один детектор.** Своя Swift-обёртка `mcd_ios.VPNChecker`, классический `__SCOPED__`-scan через `StringProtocol.contains`. Без AppsFlyer (что выделяет среди других ресторанных/коммерческих апп — обычно AppsFlyer-детектор присутствует).

| # | Модуль | Механизм | Адрес |
|---|---|---|---|
| 1 | `mcd_ios.VPNChecker` (Swift) | `CFNetworkCopySystemProxySettings` → `__SCOPED__.allKeys` → `String.contains` по `tap/tun/ppp/ipsec` | `0x1002AF1CC` |

Подстроки — **4 штуки** (`tap/tun/ppp/ipsec`), без `utun` — самый «короткий» набор из разобранных приложений (как у Beeline/MyMTS/CDEK через AppsFlyer-классику).

`nw_path_uses_interface_type` импортируется, но **не для VPN** — `sub_100C5D964` опрашивает `.wifi/.cellular/.wired` и пишет результат в `setNetworkType:` (один-в-один как у Megafon, CDEK, DNS-SHOP — стандартный network-type classifier).

**Импорты Mach-O:**

| Символ | Статус | Где |
|---|---|---|
| `_CFNetworkCopySystemProxySettings` | ✅ | только `VPNChecker` (`sub_1002AF1CC`) |
| `_nw_path_uses_interface_type` | ✅ | только classifier `sub_100C5D964`, не VPN |
| `_getifaddrs` | ✅ | вспомогательный, не VPN |
| `_nw_interface_get_type` / `_CFNetworkCopyProxiesForURL` / `_SCDynamicStoreCopyProxies` / `_DNSServiceQueryRecord` | ❌ | — |

---

## Детектор — `sub_1002AF1CC`

Метод Swift-класса `_TtC7mcd_ios10VPNChecker` (metadata accessor `$s7mcd_ios10VPNCheckerCMa` @ `0x1002af1ac`).

Псевдокод:

```swift
func isVpnEnabled() -> Bool {
    guard let settings = CFNetworkCopySystemProxySettings() as? [String: Any] else { return false }
    guard let scoped   = settings["__SCOPED__"]          as? [String: Any] else { return false }
    for iface in scoped.keys {
        if iface.contains("tap")   { return true }
        if iface.contains("tun")   { return true }
        if iface.contains("ppp")   { return true }
        if iface.contains("ipsec") { return true }
    }
    return false
}
```

Литералы:

| В декомпиляции | Байты | ASCII |
|---|---|---|
| `7364980` | `74 61 70 00` | `tap` |
| `7239028` | `74 75 6E 00` | `tun` |
| `7368816` | `70 70 70 00` | `ppp` |
| `0x6365_7370_69` | `69 70 73 65 63` | `ipsec` |

Хелпер contains — стандартный `StringProtocol.contains<A>(_:)`.

---

## UI и реактивный pipeline

### `VPNInformerView`

Swift-класс `_TtC7mcd_ios15VPNInformerView` (`0x1029910e0`):

| Метод | Адрес |
|---|---|
| `initWithFrame:` | `0x1000c1448` |
| `initWithCoder:` | `0x1000c1524` |
| `.cxx_destruct` | `0x1000c154c` |
| Type metadata | `$s7mcd_ios15VPNInformerViewCMa` @ `0x1000c15c8` |

Это **`UIView`** (не cell, не window) — банер/информер, накладываемый на экран при детекте.

### Локализация

| Ключ | Адрес |
|---|---|
| `VPN.Informer.Title` | `0x102991180` |
| `VPN.Informer.Subtitle` | `0x102991160` |

### State / dismissal

- `vpnInformerWasHidden` (`0x102988cd0`) — флаг, что юзер закрыл информер вручную (UserDefaults persistance)
- `isNeedToHideVPNInformer` (`0x102bf25b0`) — getter, агрегирующий проверки (вкл. dismissal-state и текущий VPN-статус)

### Notification

`ru.adv.mcd-dev.VPN-informer-need-to-hide` (`0x102986ef0`) — `NSNotification.Name`. Постится из 4 разных мест (4 xref'а от data-секции). Имя в reverse-DNS формате с `mcd-dev` — оставлен dev-namespace в релизе.

Получатель (наблюдатель) — `VPNInformerView`, который при получении этого уведомления скрывает себя.

### Свойства / API

| Имя | Адрес | Назначение |
|---|---|---|
| `vpnEnabled` | `0x102a2c667`, `0x102b861a2`, `0x102c22ed0`, `0x102c2407c` | Bool property (несколько copy в meta) |
| `isVpnEnabled` | `0x102c22afa` | геттер |
| `setVpnEnabled:` | `0x102b79e9d` | сеттер (Obj-C bridge) |
| `_vpnEnabled` | `0x102c24293` | backing ivar |
| `vpnStatus` | `0x102c240a1` | enum/value-type |
| `vpn_enabled` | `0x102a2ed2a` | snake-case telemetry-ключ |

---

## Что **не** делает

- Нет AppsFlyer-детектора (и `+[AppsFlyerUtils isVPNConnected]` не встречается в листинге функций — AppsFlyer SDK не интегрирован, либо его VPN-checker-кусок исключён).
- Нет server-side check.
- Нет remote-config флага.
- Нет full-screen блокировки — только информер-баннер с возможностью вручную закрыть (`vpnInformerWasHidden` сохраняется в UserDefaults).
- Нет CarPlay/Watch-интеграции.

Самая «мягкая» политика по VPN: показать информер, дать закрыть, не блокировать функционал.

---

## Обход существующим `VPNHide`-твиком

Хук `CFNetworkCopySystemProxySettings` вырезает VPN-ключи из `__SCOPED__` → `VPNChecker.isVpnEnabled` возвращает `false` → информер не показывается, нотификация не постится.

Все остальные хуки на этом бинарнике — NO-OP (либо не импортируются, либо вызываются с не-VPN типами).

Для активации добавить в [`tweaks/VPNHide/Filter.plist`](../../tweaks/VPNHide/Filter.plist):

```
{ Filter = { Bundles = ( …, "com.mcdonaldsru.mcd" ); }; }
```

Bundle ID — legacy McDonald's-эпохи (`com.mcdonaldsru.mcd`), не менялся при ребрендинге в «Вкусно — и точка».

---

## Сравнение

| | MyMTS | МФ | CDEK | DNS-SHOP | ЦППК | Urent | Госуслуги | билайн | 2GIS | Мой налог | Rostic's | **В&Т** |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Детекторов | 2 | 1 | 2 | 1 | 1 | 3 | 5 | 2 | 3+server | 0 | 1 | **1** |
| AppsFlyer-style | ✅ | — | ✅ | — | ❌ | ✅ | — | ✅ | ✅ | — | ✅ | ❌ (нет AppsFlyer SDK!) |
| Подстроки | 4 | 5 | 5–6 | 5 | — | 5 | конфиг. | unknown | 5 | — | 4 | **4** |
| Server-side | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | — | ❌ | ❌ |
| UI | snackbar | alert | RN | snackbar | alert + SwiftUI | 3 view | snackbar | toast/alert | full-screen+CarPlay | — | inline cell | **dismissable banner** |
| Sticky dismissal | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | — | ❌ | ✅ `vpnInformerWasHidden` |
| Покрытие VPNHide | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | n/a | ✅ | ✅ |

«В&Т» — самая мягкая политика среди приложений с детектом: один Swift-checker без AppsFlyer-дублирования, баннер можно скрыть навсегда, никакого блокирования функционала.

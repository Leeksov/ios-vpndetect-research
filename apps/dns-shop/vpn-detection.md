# DNS-SHOP — детектирование VPN / Proxy

**Бинарник:** `DNS-SHOP` v1.52.0 (arm64, Swift + Obj-C)
**Способ анализа:** IDA Pro / Hex-Rays.
**Обход:** [`tweaks/VPNHide`](../../tweaks/VPNHide/) — текущий твик покрывает, достаточно добавить `com.dns.DNSShop.DNS-SHOP` в [`Filter.plist`](../../tweaks/VPNHide/Filter.plist).

---

## TL;DR

Один детектор — Swift-struct `DNS_SHOP.VpnChecker`, классический **`__SCOPED__`-scan**:

| # | Модуль | Механизм | Адрес |
|---|---|---|---|
| 1 | `DNS_SHOP.VpnChecker` (Swift struct) | `CFNetworkCopySystemProxySettings` → `__SCOPED__` → `allKeys.contains("tap"/"tun"/"ppp"/"ipsec"/"utun")` | `0x1002B8E50` |

`NWPathMonitor` **не используется** — `_nw_path_uses_interface_type` вообще не импортируется в бинарник.

**Импорты Mach-O:**

| Символ | Статус | Где применяется |
|---|---|---|
| `_CFNetworkCopySystemProxySettings` | ✅ | только в `VpnChecker` (sub_1002B8E50) |
| `_nw_path_uses_interface_type` | ❌ не импортируется | — |
| `_getifaddrs` | ✅ | утилита получения IP по имени интерфейса (`sub_101DEB16C`), не VPN |
| `_getenv` | ✅ | локаль / env-настройки SDK, не VPN |
| `_sysctl` / `_sysctlbyname` | ✅ | uptime / hw model, не VPN |
| `_dlopen` / `_dlsym` | ✅ | dynamic loading, не VPN |
| `_DNSServiceQueryRecord` | ❌ | — |
| `_SCDynamicStoreCopyProxies` | ❌ | — |

---

## `sub_1002B8E50` — `VpnChecker.isActive`

Swift metadata: `$s8DNS_SHOP10VpnCheckerVMa` @ `0x1002b93f8` (буква `V` — value type, struct).

### Псевдокод

```swift
func isActive() -> Bool {
    guard let settings = CFNetworkCopySystemProxySettings() as? [String: Any] else { return false }
    guard let scoped   = settings["__SCOPED__"]           as? [String: Any] else { return false }
    for iface in scoped.keys {
        if iface.contains("tap")   { return true }
        if iface.contains("tun")   { return true }
        if iface.contains("ppp")   { return true }
        if iface.contains("ipsec") { return true }
        if iface.contains("utun")  { return true }
    }
    return false
}
```

### Литералы

| В декомпиляции | Байты | ASCII | Small-string flag |
|---|---|---|---|
| `0x4445504F43535F5F` + `0xEA00000000005F5F` | `__SCOPED__` | — | `0xEA` (10 chars) |
| `7364980` | `74 61 70 00` | `tap` | `0xE3` |
| `7239028` | `74 75 6E 00` | `tun` | `0xE3` |
| `7368816` | `70 70 70 00` | `ppp` | `0xE3` |
| `0x6365_7370_69` | `69 70 73 65 63` | `ipsec` | `0xE5` |
| `1853191285` | `75 74 75 6E` | `utun` | `0xE4` |

`sub_1002B92A0` — тот же `String.contains(substring)` хелпер через `String.Iterator.next()`, что в Megafon и CDEK.

---

## Что происходит при детекте

**UI:** метод `createVPNSnackBar()` (строка `0x10377ed00`) показывает снекбар с текстом **«У Вас включен VPN»** (`0x1037d61d0`).

Дополнительно — в сообщении об ошибке в магазине (строка `0x1037c9cf0`):

> Если вы в магазине и у вас возникает эта ошибка, проверьте, что у вас *включен Wi-Fi, службы геолокации и отключен VPN*.

**Телеметрия:**
- `System.vpn` (`0x1037d61c3`)
- `System.vpnInfo` (`0x1037d61ee`)
- Selector `isVPNActive` / Swift property `vpnStore`.

---

## Обход существующим `VPNHide`-твиком

Хук `CFNetworkCopySystemProxySettings` вырезает из `__SCOPED__` все ключи с подстроками `utun/tun/tap/ipsec/ppp/wg` — ровно те же 5 паттернов, что проверяет DNS-SHOP. Итог: `VpnChecker.isActive()` возвращает `false`, снекбар не появляется, `System.vpn`-телеметрия остаётся выключенной.

Хук `nw_path_uses_interface_type` для DNS-SHOP иррелевантен (символ не импортируется, код туда не попадает).

Для активации добавить в [`tweaks/VPNHide/Filter.plist`](../../tweaks/VPNHide/Filter.plist):

```
{ Filter = { Bundles = ( "ru.mts.mymts", "ru.megafon.lk", "com.cdek.cdekapp", "com.dns.DNSShop.DNS-SHOP" ); }; }
```

---

## Сравнение

| | MyMTS | МегаФон | CDEK | DNS-SHOP |
|---|---|---|---|---|
| `__SCOPED__`-детектор | ✅ AppsFlyer (ObjC) | ✅ Swift-копия | ✅ AppsFlyer + VpnDetect pod | ✅ Swift struct `VpnChecker` |
| Подстроки | `tap/tun/ipsec/ppp` | +`utun` | +`utun`, +`ipsec0` | +`utun` |
| `NWPathMonitor` для VPN | ✅ | ❌ | ❌ | ❌ (вообще не импортируется) |
| UI-реакция | снекбар | алерт + FAQ | JS (RN) | снекбар |
| Количество детекторов | 2 | 1 | 2 (дубль AppsFlyer + Pod) | 1 |

DNS-SHOP — самый простой кейс: один Swift-struct, один системный вызов. Покрытие VPNHide'ом — 1:1 без изменений в коде твика.

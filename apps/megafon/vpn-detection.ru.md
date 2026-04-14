[🇬🇧 English version](vpn-detection.md)

# МегаФон — детектирование VPN / Proxy

**Бинарник:** `Megafon` v4.62.0 (arm64, Swift + Obj-C)
**Способ анализа:** IDA Pro / Hex-Rays.
**Обход:** [`tweaks/VPNHide`](../../tweaks/VPNHide/) — текущий твик покрывает, достаточно добавить `ru.megafon.lk` в [`Filter.plist`](../../tweaks/VPNHide/Filter.plist).

---

## TL;DR

Один детектор, классический **AppsFlyer-style**: `CFNetworkCopySystemProxySettings.__SCOPED__` → перебор ключей → подстроки `tap`/`tun`/`ppp`/`ipsec`/`utun`.

| # | Модуль | Механизм | Адрес |
|---|---|---|---|
| 1 | `Megafon` app, `sub_1005388E0` | `CFNetworkCopySystemProxySettings` → `__SCOPED__` → substring match | `0x1005388E0` |

`NWPathMonitor` в бинаре **есть**, но `nw_path_uses_interface_type` вызывается только с `cellular` / `wifi` в `sub_1001650B0` — это репорт типа подключения для телеметрии, **не VPN-детект**.

**Чего в бинаре нет:** `_sysctl` / `_sysctlbyname` (не импортируются), `_getenv` (не импортируется), `_DNSServiceQueryRecord` (не импортируется), `_dlopen` (не импортируется; только `_dlsym`). `_getifaddrs` импортируется, но используется в `-[AcquireInplatService getIPAddress]` для получения локального IP, а не для VPN-детекта.

---

## Entry points

### `+[VPNMonitoringBridge checkVPNStatus]` — `0x10055A998`

```objc
+ (void)checkVPNStatus {
    VPNMonitoringController *ctrl = [Bridge shared];    // sub_1005384B0
    BOOL isRepair = stub_returns_false();               // sub_10000CE6C — просто return 0
    [ctrl showIfVPNDetectedInRepair:isRepair];          // sub_100538514
}
```

### `+[VPNMonitoringBridge checkVPNStatusInRepair]` — `0x10055A9D0`

То же самое, но с `isRepair = 1` (при проверке в сценарии ремонта интерфейс UI скрывается, в алерт не падаем — только сам detect прогоняется).

### `sub_100538514` — реакция на детект

```
if (vpn_detected() == false || isRepair == true) {
    // ничего не показываем, релизим alert view, если он висел
} else {
    MFAnalytics.track("vpn_info", "оповещение о включенном VPN", "screen_main", …);
    print("[111] ... vpn ON");
    view = VPNMonitoringAlertView();
    [window addSubview: view];
}
```

Где:
- `"vpn_info"`, `"оповещение о включенном VPN"`, `"screen_main"` — Swift small-string литералы из декомпиляции.
- `VPNMonitoringAlertView` — алерт с текстом **«Отключите VPN, чтобы в приложении всё работало хорошо»** (строка `0x100fc6bb0`) и линком «Как отключить VPN >» на `https://lk.megafon.ru/inapp/faq/?questionId=vpn_disable` (строка `0x100fc6b40`).

---

## Сам детектор — `sub_1005388E0`

Swift-версия, но алгоритм — **один в один AppsFlyer `isVPNConnected`** из MyMTS.

### Псевдокод

```swift
func vpn_detected() -> Bool {
    guard let settings = CFNetworkCopySystemProxySettings() else { return false }
    guard let scoped = settings["__SCOPED__"] as? [String: Any] else { return false }

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

### Расшифровка литералов

В декомпиляции строки подстрок видны как Swift small-string inline-кодировка (первые 8 байт — содержимое, старший байт второго qword — count+flag `0xE0 + len`):

| В декомпиляции | Байты | ASCII | Count flag |
|---|---|---|---|
| `0x0070_6174` (`7364980`) | `74 61 70 00` | `tap` | `0xE3` (3) |
| `0x006E_7574` (`7239028`) | `74 75 6E 00` | `tun` | `0xE3` (3) |
| `0x0070_7070` (`7368816`) | `70 70 70 00` | `ppp` | `0xE3` (3) |
| `0x6365_7370_69` | `69 70 73 65 63` | `ipsec` | `0xE5` (5) |
| `0x6E75_7475` (`1853191285`) | `75 74 75 6E` | `utun` | `0xE4` (4) |

Первое чтение — ключ `__SCOPED__` (`0x4445504F43535F5F` + `0xEA00000000005F5F` = `__SCOPED__`, 10 chars, flag `0xEA`).

`sub_100538778` — хелпер «`String.contains(substring)`» через `String.Iterator.next()`.

---

## Что происходит при срабатывании

- **UI:** всплывает `VPNMonitoringAlertView` (`Megafon/VPNMonitoringAlertView.swift`) с текстом про отключение VPN и ссылкой на FAQ.
- **Телеметрия:** событие `vpn_info`/`оповещение о включенном VPN` уходит в `MFAnalytics`.
- **Флаг:** `MRProtoBuilder.setVpnEnabled:` выставляется в protobuf-телеметрии; поле сериализуется как `vpn_enabled` (строка `0x1010371aa`).
- **Debug log:** `print("[111] ... vpn ON")` / `print("[111] ... vpn OFF")` (строки `0x100fc5d80` / `0x100fc5d20`).

---

## Обход существующим `VPNHide`-твиком

Наш хук `CFNetworkCopySystemProxySettings` удаляет из `__SCOPED__` ключи, содержащие `utun/tun/tap/ipsec/ppp/wg` — ровно тот набор, что чекает Megafon (плюс `wg` как задел). Детектор получит пустой `__SCOPED__` → все `contains` вернут `false` → ранний `return false` → никакого алерта и телеметрии.

Хук `nw_path_uses_interface_type` здесь лишний (Megafon не использует его для VPN), но и не мешает — вызовы с `.cellular`/`.wifi` проксируются оригиналу.

Для активации добавить в [`tweaks/VPNHide/Filter.plist`](../../tweaks/VPNHide/Filter.plist):

```
{ Filter = { Bundles = ( "ru.mts.mymts", "ru.megafon.lk" ); }; }
```

---

## Резюме vs MyMTS

| | MyMTS (`MtsServiceRu`) | МегаФон (`Megafon`) |
|---|---|---|
| Проверка `__SCOPED__` | ✅ `+[AppsFlyerUtils isVPNConnected]` | ✅ `sub_1005388E0` (Swift) |
| Подстроки | `tap/tun/ipsec/ppp` | `tap/tun/ppp/ipsec/utun` |
| `NWPathMonitor` для VPN | ✅ `GeoWidgetSDK.VPNDetectorService` | ❌ (используется только для `cellular`/`wifi`) |
| UI-реакция | снекбар «Включён VPN…» | алерт-окно + FAQ-ссылка |
| Телеметрия | AppMetrica `is_vpn_enabled` | protobuf `vpn_enabled`, MFAnalytics event |

МегаФон детектит **слабее** МТС — один путь вместо двух. Текущий твик его полностью закрывает.

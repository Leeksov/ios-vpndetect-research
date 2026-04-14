# CDEK — детектирование VPN / Proxy

**Бинарник:** `CDEK` v5.9.0 (arm64, React Native + Swift + Obj-C)
**Способ анализа:** IDA Pro / Hex-Rays.
**Обход:** [`tweaks/VPNHide`](../../tweaks/VPNHide/) — текущий твик покрывает, достаточно добавить `com.cdek.cdekapp` в [`Filter.plist`](../../tweaks/VPNHide/Filter.plist).

---

## TL;DR

Приложение на React Native (reanimated, margelo/nitro, worklets). Два детектора, **оба** сводятся к одному и тому же системному вызову:

| # | Модуль | Механизм | Адрес |
|---|---|---|---|
| 1 | AppsFlyer SDK (Obj-C) | `CFNetworkCopySystemProxySettings` → `__SCOPED__` → substrings `tap/tun/ipsec/ppp` | `0x100108FC4` |
| 2 | `VpnDetect` RN-модуль (Swift) | то же самое + дополнительно `utun` и `ipsec0` | `0x1008FF3AC` |

`VpnDetect` — CocoaPods-пакет (строка `PodsDummy_VpnDetect` @ `0x100cd3008`), судя по имени — `react-native-vpn-detect` или аналог. React Native exposed-класс: `_TtC9VpnDetect15VpnDetectModule` (`0x100c70040`), JS-API-селектор — `isVpnConnected` (`0x100c7006d`).

**NWPathMonitor не используется для VPN.** Единственный `nw_path_uses_interface_type`-колл-сайт (`sub_1002E55DC`) запрашивает `.wifi` / `.cellular` / `.wired` для определения типа подключения и передаёт его в `setNetworkType:` — классификатор, а не VPN-детект.

---

## Детектор №1 — AppsFlyer: `+[AppsFlyerUtils isVPNConnected]`

**Адрес:** `0x100108FC4`. Байт-в-байт совпадает с реализацией в MyMTS (`0x10142678c`): `CFNetworkCopySystemProxySettings().__SCOPED__` → `allKeys` → `rangeOfString:` по `"tap"`/`"tun"`/`"ipsec"`/`"ppp"`.

Стандартный код AppsFlyer SDK, используется внутри SDK. Не гейтит UI приложения, но управляет тем, что репортится в AppsFlyer-телеметрию (флаг `VPNCollectionEnabled` @ `0x100b60f17`).

---

## Детектор №2 — `VpnDetect` Swift-модуль — `sub_1008FF3AC`

Тот же алгоритм, реализованный по-свифтовски через `Dictionary._conditionallyBridgeFromObjectiveC` + `StringProtocol.contains<A>`. Расширенный список подстрок — 6 штук:

| Swift-литерал | Байты | ASCII |
|---|---|---|
| `0x0070_6174` (`7364980`) | `74 61 70 00` | `tap` |
| `0x006E_7574` (`7239028`) | `74 75 6E 00` | `tun` |
| `0x0070_7070` (`7368816`) | `70 70 70 00` | `ppp` |
| `0x6365_7370_69` | `69 70 73 65 63` | `ipsec` |
| `0x6E75_7475` (`1853191285`) | `75 74 75 6E` | `utun` |
| `0x3063_6573_7069` | `69 70 73 65 63 30` | `ipsec0` |

Ключ словаря — `__SCOPED__` (`0x4445504F43535F5F` + `0xEA00000000005F5F`).

Псевдокод:

```swift
func isVpnConnected() -> Bool {
    guard let settings = CFNetworkCopySystemProxySettings() as? [String: Any] else { return false }
    guard let scoped   = settings["__SCOPED__"]           as? [String: Any] else { return false }
    for iface in scoped.keys {
        if iface.contains("tap")    { return true }
        if iface.contains("tun")    { return true }
        if iface.contains("ppp")    { return true }
        if iface.contains("ipsec")  { return true }
        if iface.contains("utun")   { return true }
        if iface.contains("ipsec0") { return true }    // избыточно — покрывается "ipsec"
    }
    return false
}
```

Экспортируется в JS-bridge через `VpnDetectModule.isVpnConnected` → реакцию в UI строит JS-часть (React Native Bridge / turbo module).

---

## Импорты — что есть, но не задействовано для VPN

| Символ | Использование | К VPN-детекту |
|---|---|---|
| `_getifaddrs` | `-[RNCNetInfo ipAddress]`, `-[RNCNetInfo subnet]` — получение локального IP | Нет |
| `_sysctl` / `_sysctlbyname` | `+[AFSystemInfo machineModel]`, `+[GULAppEnvironmentUtil getSysctlEntry:]` — hw-model/uptime | Нет |
| `_nw_path_uses_interface_type` | `sub_1002E55DC` — классификация wifi/cellular/wired для `setNetworkType:` | Нет |
| `_SCNetworkReachabilityCreateWithName` | Sentry, общий reachability | Нет |
| `_if_nametoindex` | один вспомогательный колл-сайт | Нет |
| `_dlopen` / `_dlsym` | RN/JSC/Hermes loading | Нет |
| `_getenv` | не импортируется | — |
| `_DNSServiceQueryRecord` | не импортируется | — |
| `_SCDynamicStoreCopyProxies` | не импортируется | — |

---

## Обход существующим `VPNHide`-твиком

Наш хук на `CFNetworkCopySystemProxySettings` удаляет из `__SCOPED__` все ключи, содержащие `utun/tun/tap/ipsec/ppp/wg`. Это покрывает обе реализации:
- AppsFlyer — `rangeOfString:` вернёт `NSNotFound` по всем 4 паттернам.
- VpnDetect — `StringProtocol.contains` вернёт `false` по всем 6 паттернам (`ipsec0` попадает под фильтр `ipsec`).

Хук `nw_path_uses_interface_type` для CDEK избыточен, но не ломает RN-сетевую классификацию: вызовы с `.wifi`/`.cellular`/`.wired` проксируются оригиналу, а фильтр на `.other` здесь просто никогда не срабатывает (не запрашивается).

Для активации добавить в [`tweaks/VPNHide/Filter.plist`](../../tweaks/VPNHide/Filter.plist):

```
{ Filter = { Bundles = ( "ru.mts.mymts", "ru.megafon.lk", "com.cdek.cdekapp" ); }; }
```

---

## Сравнение

| | MyMTS | МегаФон | CDEK |
|---|---|---|---|
| `__SCOPED__`-детектор | ✅ AppsFlyer (ObjC) | ✅ Swift-копия | ✅ AppsFlyer + Swift `VpnDetect` pod |
| Подстроки | `tap/tun/ipsec/ppp` | +`utun` | +`utun`, +`ipsec0` |
| `NWPathMonitor` для VPN | ✅ `GeoWidgetSDK.VPNDetectorService` | ❌ | ❌ |
| Тип приложения | native Swift | native Swift | React Native (JSI/Hermes) |
| UI-реакция | снекбар | алерт + FAQ | решается JS-частью |

CDEK — наиболее «прозрачный» в плане детектa: чистый алгоритм из публичного RN-пакета, покрывается хуком `CFNetworkCopySystemProxySettings` из коробки.

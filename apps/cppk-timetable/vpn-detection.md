# Расписание ЦППК — детектирование VPN / Proxy

**Бинарник:** `Timetable PROD` v2.7 (arm64, Swift + Obj-C)
**Способ анализа:** IDA Pro / Hex-Rays.
**Обход:** [`tweaks/VPNHide`](../../tweaks/VPNHide/) — **покрытие не гарантировано**, см. раздел «Обход» ниже.

---

## TL;DR

В этом приложении — **нестандартный** детектор. Прозаичный `CFNetworkCopySystemProxySettings`-путь здесь **не используется**, и даже raw-символ `nw_path_uses_interface_type` в бинарник не импортирован. Детект полностью построен на Swift-обёртке `Network.framework`:

1. Swift-класс `_TtC14Timetable_PROD14NetworkMonitor` хранит property `currentConnectionType: NWInterface.InterfaceType`.
2. Функция `sub_100293EF4` читает это значение и сравнивает с конкретным case `NWInterface.InterfaceType` (предположительно `.other`).
3. Если совпало → через `DispatchQueue.main.async` вызывается блок, который в итоге показывает VPN-алерт.
4. Алерт показывает `-[LaunchManager showActiveVPNWithNotification:]` (строка селектора `0x1006f69fe`) — классический observer `NSNotification` с именем `"activeVPN"` (`0x1007c8da0`).

**Импорты Mach-O (полностью):**

| Символ | Статус |
|---|---|
| `_CFNetworkCopySystemProxySettings` | ❌ не импортируется |
| `_nw_path_uses_interface_type` | ❌ не импортируется |
| `_nw_interface_get_type` | ❌ не импортируется |
| `_nw_path_enumerate_interfaces` | ❌ не импортируется |
| `_getifaddrs` / `_if_nametoindex` | ❌ не импортируется |
| `_SCDynamicStoreCopyProxies` | ❌ не импортируется |
| `_DNSServiceQueryRecord` | ❌ не импортируется |
| `_getenv` | ❌ не импортируется |
| `_sysctl` / `_sysctlbyname` | ✅ (не для VPN — hw model/uptime) |
| `_dlopen` / `_dlsym` | ✅ |

Интересно: из всего списка **ни одного «VPN-ориентированного» C-символа**. Значит весь детект крутится в Swift overlay для `Network.framework` (libswiftNetwork.dylib), а результат сводится к enum-сравнению в Swift-коде главного бинаря.

---

## Цепочка вызовов

### `sub_100293EF4` — VPN-проверка и диспатч алерта

```
1. Получает синглтон NetworkMonitor
   swift_once(&qword_1008E7C10, sub_10005A404)
2. Читает NetworkMonitor.currentConnectionType
   ivar: OBJC_IVAR____TtC14Timetable_PROD14NetworkMonitor_currentConnectionType
3. Готовит значение-эталон:
   (v3 + 104)(v7, 0xFFFFFFFF, v2)   // destructiveInjectEnumTag — проекция case'а
4. Сравнивает через Equatable.==:
   dispatch_thunk_of_static_Equatable.==(_:_:)(v7, v4, NWInterface.InterfaceType, v12)
5. Если true → DispatchQueue.main.async { sub_1002950D8() }
                                          ↳ sub_1002943EC — показ UIAlertController
```

Тэг `0xFFFFFFFF` на шаге 3 — это specific-tag инъекция enum case'а; после `destructiveInjectEnumTag(-1)` + `initializeWithCopy` сам case выбирается по адресу метаданных `unk_1008ED588` (witness table для `NWInterface.InterfaceType`). С высокой вероятностью это `.other` — именно так Network.framework помечает VPN-пути.

### `-[LaunchManager showActiveVPNWithNotification:]` @ `0x100294540`

Тонкий thunk к `sub_1002948DC`, который:
1. Bridge-ит `NSNotification` → `Notification` (Swift).
2. Захватывает переданный `a4 = sub_100293EF4` (VPN-check закрытие).
3. Вызывает `a4()` — то есть проверка запускается **по прилёту нотификации `activeVPN`**.

Таким образом — **NetworkMonitor где-то сам по себе постит `NSNotification.Name("activeVPN")`**, а `LaunchManager` наблюдает и реагирует UI-алертом. Поиск постера (`NotificationCenter.default.post`) из-за static-stripping и Swift-манглинга не даёт прямых хитов, но поведенческая цепочка однозначна.

### UI

Два UI-пути:

1. **UIKit alert** — `sub_1002943EC`:
   - `UIAlertController(title:, message:, preferredStyle:.alert)` + 1 action
   - Message: `Возможно у Вас включен VPN. Для корректной работы приложения его стоит выключить` (`0x1007161b0`)
2. **SwiftUI view body** — `sub_1002CC9DC`:
   - `Text(_:).font(.custom("OpenSans-Bold", size: 16)) + Text(_:).font(.custom("OpenSans-Regular", size: 14))`
   - Содержит строку `Из-за VPN могут быть ошибки, лучше его отключить` (`0x100716d20`)
   - Render conditionально от `@State` — это inline-snackbar/label.

---

## Обход существующим `VPNHide`-твиком

Закрывается хуком `nw_interface_get_type`, добавленным в твик специально под этот кейс. Механика:

1. `libswiftNetwork.dylib` при доступе к `NWInterface.type` зовёт C-функцию `nw_interface_get_type(nw_interface_t)`. fishhook перепривязывает её в GOT libswiftNetwork (наш `rebind_symbols` ходит по всем загруженным образам).
2. В хуке мы вызываем оригинал; если он вернул `.other` (0) **и** имя интерфейса (через `nw_interface_get_name`, резолвится dlsym'ом) матчится по VPN-префиксам (`utun/tun/tap/ipsec/ppp/wg`) — возвращаем `.wifi` (1) вместо `.other`.
3. Swift-сравнение `currentConnectionType == .other` в `sub_100293EF4` никогда не совпадает → VPN-алерт не диспатчится → нотификация `"activeVPN"` не постится.

Остальные хуки на этом бинарнике — NO-OP (символы `CFNetworkCopySystemProxySettings`, `getifaddrs`, `nw_path_uses_interface_type` не импортируются).

Для активации добавить в [`tweaks/VPNHide/Filter.plist`](../../tweaks/VPNHide/Filter.plist):

```
{ Filter = { Bundles = ( …, "ru.central-ppk.Timetable" ); }; }
```

Если по какой-то причине `nw_interface_get_type`-hook не сработает (например, libswiftNetwork использует иной low-level API) — fallback'и:

1. Хукать `nw_path_enumerate_interfaces` — перехват block-enumerator'а, выкидываем VPN-интерфейсы перед колбэком. Сложнее, чем `nw_interface_get_type`.
2. Swizzle `NSNotificationCenter.defaultCenter postNotificationName:object:` с фильтром по `"activeVPN"` — гасим нотификацию в момент публикации. Не требует fishhook'а, но привязан к конкретному приложению.

---

## Сравнение

| | MyMTS | МегаФон | CDEK | DNS-SHOP | ЦППК |
|---|---|---|---|---|---|
| `__SCOPED__` | ✅ | ✅ | ✅ (×2) | ✅ | ❌ |
| `nw_path_uses_interface_type` | ✅ | только `.cellular/.wifi` (не VPN) | только `.wifi/.cellular/.wired` (не VPN) | ❌ не импортируется | ❌ не импортируется напрямую, но Swift overlay может использовать |
| Swift `NWInterface.InterfaceType` compare | ❌ | ❌ | ❌ | ❌ | ✅ `NetworkMonitor.currentConnectionType == .?` |
| UI-реакция | снекбар | алерт | JS RN | снекбар | NSNotification → UIAlertController / SwiftUI Text |
| Покрытие текущим VPNHide | ✅ | ✅ | ✅ | ✅ | ⚠️ under test |

ЦППК — первый из разобранных кейсов, где детект полностью выведен из зоны покрытия fishhook-хуков на стандартные C-символы. Хороший полигон для развития твика.

# Яндекс Маркет — детектирование VPN / Proxy

**Бинарник:** `Beru` v2026.11.1 (arm64, Swift + Obj-C, ~139 MB)
**Способ анализа:** IDA Pro / Hex-Rays.
**Обход:** [`tweaks/VPNHide`](../../tweaks/VPNHide/) — текущий твик покрывает; добавить `ru.yandex.blue.market` в [`Filter.plist`](../../tweaks/VPNHide/Filter.plist).

---

## TL;DR

Три callsite на `CFNetworkCopySystemProxySettings`, все выходят на `__SCOPED__` сканирование:

| # | Модуль | Механизм | Адрес |
|---|---|---|---|
| 1 | `-[YALAFHTTPClient isVPNConnected]` (Obj-C, Yandex AppLib) | `__SCOPED__.allKeys` → `[needle containsString:iface]` для каждого needle из `unk_107E19870` | `0x102226EDC` |
| 2 | `MarketProtocols.VPNCheckerServiceImpl` (Swift) | `__SCOPED__.allKeys` → substring-loop по array of needles | `0x101EEDFDC` |
| 3 | thunk-getter | возвращает результат `CFNetworkCopySystemProxySettings()` для другого consumer'а | `0x1025363D8` (8 bytes) |

`AppsFlyer SDK` **не интегрирован** — `+[AppsFlyerUtils isVPNConnected]` не присутствует. Свои реализации.

`NWPathMonitor` **не используется** — `_nw_path_uses_interface_type` не импортируется.

**Импорты:**

| Символ | Статус | Контекст |
|---|---|---|
| `_CFNetworkCopySystemProxySettings` | ✅ | 3 callsite (2 детектора + 1 thunk) |
| `_nw_path_uses_interface_type` | ❌ | не импортируется |
| `_getifaddrs` | ✅ | вспомогательный (network info) |
| `_nw_interface_get_type` / `_CFNetworkCopyProxiesForURL` / `_SCDynamicStoreCopyProxies` / `_DNSServiceQueryRecord` | ❌ | — |

---

## Детектор №1 — `-[YALAFHTTPClient isVPNConnected]`

Obj-C метод HTTP-клиента из Yandex internal lib (`YAL` — Yandex App Lib). Использует Block-foreach pattern:

```objc
- (BOOL)isVPNConnected {
    __block BOOL result = NO;
    CFDictionaryRef settings = CFNetworkCopySystemProxySettings();
    NSDictionary *scoped = settings[@"__SCOPED__"];
    if (![scoped isKindOfClass:NSDictionary.class] || scoped == nil) goto done;

    for (NSString *iface in [scoped allKeys]) {
        // unk_107E19870 — NSArray needles захардкоженных VPN-паттернов
        [needles_array yal_foreachUsingBlock:^(id needle, BOOL *stop) {
            if ([iface isKindOfClass:NSString.class]) {
                if ([needle containsString:iface]) {  // ← обратная семантика!
                    result = YES;
                }
            }
        }];
    }
done:
    return result;
}
```

### Особенность семантики

В `sub_10222BA64` (внутренний block) реально вызывается:

```
[needle containsString: iface_name]
```

То есть **needle содержит имя интерфейса как подстроку**, а не наоборот. Это значит, `unk_107E19870` — массив **полных или удлинённых** имён вроде `"utun0"`, `"ipsec0"`, `"tap0"`, и проверка ловит интерфейсы с базовыми префиксами вроде `"utun"`, `"tap"` (потому что `"utun0".contains("utun")` = `YES`).

Эффективно срабатывает на всё VPN-related, но мейнтейнить такой реверс-логике не очень удобно — обычно делают наоборот (`iface.contains(needle)`).

### Где живёт `unk_107E19870`

Const NSArray в `__DATA_CONST`. Не дампим, но судя по поведенческой логике — это массив объектов `NSString` с VPN-маркерами.

---

## Детектор №2 — `MarketProtocols.VPNCheckerServiceImpl` (Swift)

`sub_101EEDFDC` — Swift implementation, выполняет аналогичную работу через `Dictionary._unconditionallyBridgeFromObjectiveC` + цикл по allKeys + цепочка substring-match'ей через помощник из internal Swift-runtime (`sub_1015A3150`).

DI-инжект через property `vpnCheckerService` (`0x106e260a0`, `0x1071cceb0`).

Swift protocol: `MarketProtocols.VPNCheckerService` (`$s15MarketProtocols17VPNCheckerServiceP` @ `0x1063d47f0`).
Concrete impl: `VPNCheckerServiceImpl` (`0x105fb5830`).

---

## Детектор №3 — thunk

`sub_1025363D8` — 8 байт, просто `return CFNetworkCopySystemProxySettings()`. Используется как Swift bridge или для логирования системных настроек.

---

## UI-инфраструктура

| Свойство / Selector | Адрес | Назначение |
|---|---|---|
| `isVPNInfoShown` | `0x106e26076`, `0x1071cce86` | Bool-флаг (видимо, для one-shot показа баннера/информера) |
| `vpnCheckerService` | `0x106e260a0`, `0x1071cceb0` | DI-property для VPNCheckerService |

Всё на уровне DI и stateful-флагов — **без явного UI-класса вроде `VPNAlertVC` или `VPNInformerView`**. Это значит UI-реакция вшита в общие компоненты (например, в hero-баннер главного экрана или в error-state контроллер при сетевых ошибках) и не имеет dedicated класса.

---

## Обход существующим `VPNHide`-твиком

Хук `CFNetworkCopySystemProxySettings` вырезает VPN-ключи из `__SCOPED__` → все 3 callsite получают «чистый» словарь:

- `[YALAFHTTPClient isVPNConnected]` → пустой allKeys → block ни разу не находит match → `NO`.
- `VPNCheckerServiceImpl` (`sub_101EEDFDC`) → пустой allKeys → ранний `return 0`.
- Thunk-getter → отдаёт уже очищенный словарь дальше.

Остальные хуки на этом бинарнике — NO-OP (символы не импортируются).

Для активации добавить в [`tweaks/VPNHide/Filter.plist`](../../tweaks/VPNHide/Filter.plist):

```
{ Filter = { Bundles = ( …, "ru.yandex.blue.market" ); }; }
```

Bundle ID legacy: `ru.yandex.blue.market` (`Beru` — название проекта до поглощения Яндексом, осталось в executable + bundle ID).

---

## Сравнение

| | MyMTS | МФ | CDEK | DNS | ЦППК | Urent | Гос | бил | 2GIS | Налог | Rost | В&Т | Amediateka | **YM** |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Детекторов | 2 | 1 | 2 | 1 | 1 | 3 | 5 | 2 | 3+srv | 0 | 1 | 1 | 2+srv | **2** |
| AppsFlyer-style | ✅ | — | ✅ | — | ❌ | ✅ | — | ✅ | ✅ | — | ✅ | ❌ | ✅ | ❌ (свои реализации) |
| Свои Obj-C/Swift импл. | ❌ | ✅ | ✅ | ✅ | ✅ | ✅×3 | ✅×3 | ✅ | ✅ | — | ✅ | ✅ | ✅ | **✅×2** |
| Server-side | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | — | ❌ | ❌ | ✅ | ❌ |
| `[needle containsString:iface]` (reversed semantics) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | — | ❌ | ❌ | ❌ | **✅** (уникально) |
| DI-property `vpnCheckerService` | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ | — | ❌ | ❌ | ✅ | ✅ |
| Покрытие VPNHide | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | n/a | ✅ | ✅ | ✅ | ✅ |

Яндекс Маркет — средне-стандартный вариант, **без** AppsFlyer-обвязки, **без** server-side, но с двумя дублирующими реализациями (Obj-C + Swift) и DI-архитектурой. Уникальная черта — обратная семантика substring-матча `[needle containsString:iface]` в Obj-C-детекторе.

[🇬🇧 English version](vpn-detection.md)

# Госуслуги — детектирование VPN / Proxy

**Бинарник:** `Gosuslugi` v25.3.0 (arm64, Swift + Obj-C, большое приложение — ~131 MB)
**Способ анализа:** IDA Pro / Hex-Rays.
**Обход:** [`tweaks/VPNHide`](../../tweaks/VPNHide/) — существующий твик покрывает большинство путей, но с оговорками (см. ниже).

---

## TL;DR

Самый «навороченный» детектор из разобранных. Живёт в **двух отдельных фреймворках**: `GUNetwork.VPNCheckService` и отдельный framework `VPNCheckService` (со своим DI-контейнером `VPNCheckAssembly`, событиями `SpeedTestEvent`, строковыми ресурсами `VPNCheckServiceStrings`). Используются **5 разных функций**, хукающихся на `CFNetworkCopySystemProxySettings` / `CFNetworkCopyProxiesForURL`:

| # | Функция | Механизм | Где |
|---|---|---|---|
| 1 | `sub_100538700` | `__SCOPED__` → **hardcoded** массив из 5 подстрок `tap/tun/ppp/ipsec/utun` | main app |
| 2 | `sub_10004BE1C` | `__SCOPED__` → **externally supplied** массив подстрок (`vpnProtocolsKeysIdentifiers`) | `GUNetwork.VPNCheckService` |
| 3 | `sub_101124D5C` | то же, что №2 | отдельный `VPNCheckService.VPNCheckService` |
| 4 | `sub_1005451AC` | `CFNetworkCopySystemProxySettings` → top-level keys `HTTPProxy` / `HTTPSProxy` | main app — ловит ЛЮБОЙ системный HTTP(S)-proxy |
| 5 | `sub_1005383B0` / `sub_103687240` | `CFNetworkCopyProxiesForURL(url, settings)` → проверка `kCFProxyHostNameKey` первого результата | dup |

`NWPathMonitor` **используется**, но **не для VPN** — функция `sub_1057E2938` (очень жирная, похожа на Rust-скомпилированный код) опрашивает `nw_path_uses_interface_type` последовательно с `.wifi`, `.wired`, `.cellular`, плюс `CTTelephonyNetworkInfo.currentRadioAccessTechnology` — это **классификатор типа подключения** (wifi / wired / cellular / 2G-5G), выдаёт один из enum-case'ов. `.other` никогда не запрашивается.

**Импорты Mach-O (только VPN-релевантные):**

| Символ | Статус | Используется для |
|---|---|---|
| `_CFNetworkCopySystemProxySettings` | ✅ | 6 разных функций (детекторы 1–5 + AppsFlyer-like) |
| `_CFNetworkCopyProxiesForURL` | ✅ | детекторы 5 |
| `_nw_path_uses_interface_type` | ✅ | **не** для VPN, только классификация wifi/cellular/wired |
| `_getifaddrs` | ✅ | не для VPN (вспомогательные network-info) |
| `_sysctl` / `_sysctlbyname` / `_getenv` / `_dlopen` / `_dlsym` / `_if_nametoindex` | ✅ | не для VPN |
| `_SCDynamicStoreCopyProxies` | ❌ | — |
| `_DNSServiceQueryRecord` | ❌ | — |
| `_nw_interface_get_type` / `_nw_path_enumerate_interfaces` | ❌ | — |

---

## Детектор №1 — hardcoded `__SCOPED__`-scan (`sub_100538700`)

Стандартный алгоритм, как в DNS-SHOP / Megafon. Подстроки захардкожены прямо в функции:

| Литерал | Байты | ASCII |
|---|---|---|
| `7364980` | `74 61 70 00` | `tap` |
| `7239028` | `74 75 6E 00` | `tun` |
| `7368816` | `70 70 70 00` | `ppp` |
| `0x6365_7370_69` | `69 70 73 65 63` | `ipsec` |
| `1853191285` | `75 74 75 6E` | `utun` |

Хелпер `sub_10004C1B8` — `String.contains(substring)`.

Массив из 5 строк лежит в global storage `qword_107610D08`, собирается через `swift_arrayDestroy(…, 5, …)` при релизе.

---

## Детекторы №2/3 — configurable `__SCOPED__`-scan

`sub_10004BE1C` (из `GUNetwork.VPNCheckService`) и `sub_101124D5C` (из отдельного `VPNCheckService`-framework) — двойные реализации одного и того же. Отличаются от №1 тем, что массив подстрок **не захардкожен**, а берётся из instance-поля класса:

```
v11 = *(v0 + 16);     // GUNetwork.VPNCheckService.vpnProtocolsKeysIdentifiers
v11 = *(v0 + 152);    // VPNCheckService.VPNCheckService.vpnProtocolsKeysIdentifiers
```

Название поля виден в строке `0x1059e1df0` — `vpnProtocolsKeysIdentifiers`. Это массив `[String]`, скорее всего заполняется:
- либо из Info.plist / asset-бандла,
- либо из remote config (Firebase / бекендовский флаг),
- либо из hardcoded-дефолтов с возможностью override.

Это даёт Госуслугам возможность **добавлять новые VPN-паттерны без релиза** — если завтра появится какой-нибудь новый `wg_*` / `vpn_*` / `shadowsocks_*` интерфейс, достаточно пушнуть обновлённый конфиг. Уникальная для разобранных приложений особенность.

Цикл одинаковый: для каждого ключа в `__SCOPED__` → для каждой подстроки в `vpnProtocolsKeysIdentifiers` → `String.contains()`. Если совпало — `return 1`.

---

## Детектор №4 — прямой proxy-check (`sub_1005451AC`)

Не ходит в `__SCOPED__`. Читает top-level ключи системного словаря:

| Swift-литерал | Байты | ASCII |
|---|---|---|
| `0x786F725050545448` + `0xE900000000000079` | `48 54 54 50 50 72 6F 78 79` | `HTTPProxy` (9) |
| `0x6F72505350545448` + `0xEA00000000007978` | `48 54 54 50 53 50 72 6F 78 79` | `HTTPSProxy` (10) |

Если **хоть один** из ключей есть в словаре — возвращает `true`. То есть эта функция ловит **любой** системный HTTP/HTTPS-proxy — Charles, Proxyman, корпоративный PAC, WireGuard-через-HTTP-прокси и т.п. Не VPN в узком смысле, а вообще любой MITM.

---

## Детектор №5 — per-URL proxy-resolver (`sub_1005383B0` / `sub_103687240`)

Две идентичные функции (дубль). Схема:

```swift
let url = URL(string: "…")!         // длина 24 байта, ресурс lk.gosuslugi или похожий
let settings = CFNetworkCopySystemProxySettings()
let proxies: CFArray = CFNetworkCopyProxiesForURL(url as CFURL, settings)
let dict = (proxies as? [[String: Any]])?.first
let host = dict?[kCFProxyHostNameKey as String] as? String
if host != expected && host != nil {
    return true     // VPN/proxy detected
}
return false
```

Логика: если для конкретного URL резолвится proxy, и его hostname **не равен** заранее ожидаемому (например, доверенному CDN-endpoint'у) — считается, что трафик идёт через внешний прокси/VPN.

Это **самая хитрая** из 5 проверок: она срабатывает **только тогда, когда VPN реально ломает маршрутизацию** к конкретным URL.

---

## Реакция на детект

**UI:**
- Свойство `isVPNEnabled` (строка `0x1059e8e8b`)
- Свойство `vpnActiveBefore` (строка `0x1059e8db8`) — для детекции изменения состояния между запусками
- Debug-флаг `debugDoNotShowVPNSnackbar` (строка `0x1059e9030`) — доступен разработчикам для подавления
- Ивент-имя в логах: **`снекбар VPN`** (строка `0x105a0d9e0`)
- `VPNSnackbarMessage` enum (metadata `$s15VPNCheckService18VPNSnackbarMessageOMa`) и `VPNCheckServiceStrings` — локализованные строки для снекбара

**Analytics:**
- Регулярка на имя события: **`^(vpn_on)|(vpn_off)|(vpn_unknown)$`** (строка `0x105a6d940`)
- Три состояния: VPN включён, выключен, не определено (`vpn_unknown`)

**Дополнительно:**
- `-[EnvironmentDataProvider isVpnEnabled]` в `GUMetricsImplementation` (`0x100536fbc`) — экспозиция в метрики
- `vpnEnabled` (Objective-C property, строка `0x1059e0ac0`)
- `vpnService` (строка `0x1059e0db1`)

---

## Обход существующим `VPNHide`-твиком

Все 5 детекторов закрываются:

| Детектор | Хук | Эффект |
|---|---|---|
| №1 (`sub_100538700`) | `CFNetworkCopySystemProxySettings` | `__SCOPED__` очищен от VPN-ключей → ни одна подстрока не матчится → `false`. |
| №2 (`sub_10004BE1C`) | `CFNetworkCopySystemProxySettings` | То же; remote-config список подстрок роли не играет, т.к. ключей-кандидатов не остаётся. |
| №3 (`sub_101124D5C`) | `CFNetworkCopySystemProxySettings` | То же. |
| №4 (`sub_1005451AC`) | `CFNetworkCopySystemProxySettings` | Top-level `HTTPProxy`/`HTTPSProxy`/`SOCKSProxy` и `*Enable`-флаги вычищены → проверка даёт `false`. |
| №5 (`sub_1005383B0` / `sub_103687240`) | `CFNetworkCopyProxiesForURL` | Хук безусловно возвращает `[{ kCFProxyTypeKey: kCFProxyTypeNone }]` → `kCFProxyHostNameKey` отсутствует → `swift_dynamicCast` на `String` падает → ранний `return 0` (LABEL_19/20). |

Ограничение:
- ⚠️ Детекторы №2/№3 используют **externally-supplied** массив подстрок из `vpnProtocolsKeysIdentifiers`. Если remote config когда-нибудь добавит туда такие строки, которых нет в нашем фильтре (например, гипотетический `"shadowsocks"` или `"mesh0"`), наш хук их не вычистит из `__SCOPED__`, и детектор сможет их матчнуть. Текущий фильтр (`tap/tun/ppp/ipsec/utun/wg`) покрывает все известные сейчас VPN-технологии. При необходимости расширить — править массив `kVPNNeedles` в [`Tweak.mm`](../../tweaks/VPNHide/Tweak.mm).

Для активации добавить в [`tweaks/VPNHide/Filter.plist`](../../tweaks/VPNHide/Filter.plist):

```
{ Filter = { Bundles = ( …, "com.minsvyaz.gosuslugi" ); }; }
```

---

## Сравнение с другими приложениями

| | MyMTS | МегаФон | CDEK | DNS-SHOP | ЦППК | Urent | Госуслуги |
|---|---|---|---|---|---|---|---|
| Кол-во детекторов | 2 | 1 | 2 | 1 | 1 | 3 | **5** |
| `__SCOPED__` с hardcoded паттернами | ✅ | ✅ | ✅ | ✅ | ❌ | ✅×3 | ✅ |
| `__SCOPED__` с remote-config паттернами | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ **(уникально)** |
| Top-level `HTTPProxy/HTTPSProxy` check | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| `CFNetworkCopyProxiesForURL` per-URL | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| `NWPathMonitor` для VPN | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ |
| Двойная реализация в отдельных фреймворках | ❌ | ❌ | ✅ (AppsFlyer + Pod) | ❌ | ❌ | ✅ (Services + app) | ✅ (`GUNetwork` + `VPNCheckService`) |
| Three-state analytics (on/off/**unknown**) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| Debug-flag подавления | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ `debugDoNotShowVPNSnackbar` |
| Покрытие VPNHide | ✅ | ✅ | ✅ | ✅ | ⚠️ | ✅ | ⚠️ 4/5 из коробки |

Gosuslugi — сильно выделяется по качеству детектора. Уникальные черты:
- **Remote-configurable** список подстрок VPN-интерфейсов (не надо ждать релиза).
- Multi-pronged approach: 5 различных функций, покрывающих разные категории прокси/VPN.
- Трёхзначная аналитика с состоянием «unknown» — значит, они осознанно работают с неопределённостью детекта.
- Debug-флаг для разработчиков — видно, что код активно поддерживается.

Скорее всего, эта система — часть `GUNetwork`/`VPNCheckService` shared framework, который используется и в других приложениях Минцифры.

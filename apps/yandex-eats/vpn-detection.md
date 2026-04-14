# Яндекс Еда — детектирование VPN / Proxy

**Бинарник:** `YandexEats` v8.102.1 (arm64, Swift + Obj-C, ~221 MB)
**Способ анализа:** IDA Pro / Hex-Rays.
**Обход:** [`tweaks/VPNHide`](../../tweaks/VPNHide/) — текущий твик покрывает; добавить `com.appkode.foodfox` в [`Filter.plist`](../../tweaks/VPNHide/Filter.plist).

---

## TL;DR

Два-три callsite на `CFNetworkCopySystemProxySettings`, плюс trampoline `j__CFNetworkCopySystemProxySettings`. Без AppsFlyer SDK (как у Маркет/В&Т), **без** `MobileAdsCore` (в отличие от Кинопоиска / Amediateka).

| # | Модуль | Механизм | Адрес |
|---|---|---|---|
| 1 | `-[YALAFHTTPClient isVPNConnected]` (Obj-C, Yandex AppLib) | `__SCOPED__.allKeys` → `[needle containsString:iface]` (reversed semantics, как в Я.Маркете) | `0x105E57318` |
| 2 | `YXFintechFoundation.VPNConnectionCheckerImpl` (Swift) | Swift wrapper над `__SCOPED__`-сканом | `sub_1037CFD4C` |
| 3 | дополнительный wrapper / consumer | использует тот же словарь | `sub_1063F7788` |

`NWPathMonitor` **не для VPN** — `_nw_path_uses_interface_type` дёргается только из `-[YALNetworkMonitor mapPathToStatus:]` для cellular/wifi/wired classification.

**Импорты Mach-O:**

| Символ | Статус | Контекст |
|---|---|---|
| `_CFNetworkCopySystemProxySettings` | ✅ | 3 callsite + trampoline |
| `_nw_path_uses_interface_type` | ✅ | reachability (cellular/wifi/wired), не VPN |
| `_getifaddrs` / `_sysctl` / `_getenv` / `_dlopen` | ✅ | вспомогательные |
| `_nw_interface_get_type` / `_CFNetworkCopyProxiesForURL` / `_SCDynamicStoreCopyProxies` / `_DNSServiceQueryRecord` | ❌ | — |

---

## Архитектура

### Swift-классы

| Тип | Mangled | Адрес |
|---|---|---|
| `YXFintechFoundation.VPNConnectionCheckerImpl` (class) | `$s19YXFintechFoundation24VPNConnectionCheckerImplCMa` | `0x1061617c0` |
| `EatsSDKExperiments.VPNCheckConfig` (struct, Codable) | `$s18EatsSDKExperiments14VPNCheckConfigVMa` | `0x102d58e8c` |
| `EatsAccountManagerImpl.VpnBlockingInitAnalyticsEvent` (struct) | `$s22EatsAccountManagerImpl29VpnBlockingInitAnalyticsEventVMa` | `0x100a3f78c` |
| `EatsAccountManagerImpl.VpnBlockingShowenAnalyticsEvent` (typo!) | `$s22EatsAccountManagerImpl31VpnBlockingShowenAnalyticsEventVMa` | `0x100a3f99c` |
| `EatsAccountManagerImpl.VpnBlockingUpdatedAnalyticsEvent` (struct) | `$s22EatsAccountManagerImpl32VpnBlockingUpdatedAnalyticsEventVMa` | `0x100a3fa3c` |

### Расшифровка фреймворков

- **`YXFintechFoundation`** — Yandex Fintech Foundation. **Любопытно** — VPN-checker лежит в **финтех-фундаменте** (платёжные модули / KYC), не в общем networking-слое. Скорее всего, шарится между Я.Маркет, Я.Еда, Я.Такси и др.
- **`EatsSDKExperiments`** — A/B-эксперименты Я.Еды; `VPNCheckConfig` (Codable) — это remote-config структура, хранящая параметры детектора (вкл./выкл., список паттернов, частота проверок и т.п.).
- **`EatsAccountManagerImpl`** — модуль работы с аккаунтом; **3 analytics-события** для VPN-блокировки:
  - `VpnBlockingInit` — VPN-blocker впервые показан
  - `VpnBlockingShowen` (sic, опечатка `Showen` вместо `Shown` — оставлена в проде)
  - `VpnBlockingUpdated` — статус обновился

### Что **отсутствует**

- **AppsFlyer SDK** — нет `+[AppsFlyerUtils isVPNConnected]`. Свои реализации.
- **`MobileAdsCore`** (SPB TV SDK) — нет, в отличие от Кинопоиска и Amediateka.
- **Server-side `/checkvpn`** — не найдено URL endpoint'а (но `EatsSDKExperiments.VPNCheckConfig` намекает на конфигурируемое поведение через A/B).

---

## Детектор №1 — `-[YALAFHTTPClient isVPNConnected]` @ `0x105E57318`

Стандартная Yandex AppLib реализация — идентична той, что в Я.Маркете и Кинопоиске. См. [yandex-market/vpn-detection.md](../yandex-market/vpn-detection.md#детектор-1----yalafhttpclient-isvpnconnected) для деталей.

Reversed-семантика: `[needle containsString:iface_name]`, где needle тянется из const-NSArray.

---

## Детектор №2 — `VPNConnectionCheckerImpl` (Swift)

`sub_1037CFD4C` (~824 bytes) — Swift-implementation `YXFintechFoundation.VPNConnectionCheckerImpl`. Под капотом стандартный pattern: `CFNetworkCopySystemProxySettings()` → bridge to `[String: Any]` → `__SCOPED__.allKeys` → substring-match через хелпер.

DI-инжект через property — название не локализовано, но скорее всего `vpnChecker` или `vpnConnectionChecker`.

---

## Детектор №3 — `sub_1063F7788` (~780 bytes)

Дополнительный consumer `CFNetworkCopySystemProxySettings`. Вероятно — обёртка над теми же данными для другого слоя (например, для Sentry/телеметрии или для checkout-flow EatsAccountManager).

---

## UI / реакция

В отличие от 2GIS / Кинопоиска, **dedicated VPN-classes** (вроде `VPNAlertVC`, `VPNBlockedWindow`) **не найдены**. Реакция, вероятно, реализована inline в основных view-controller'ах, гейтится через `EatsSDKExperiments.VPNCheckConfig` (если эксперимент включён — показывать blocker, иначе нет).

3 analytics-события (`Init/Showen/Updated`) указывают на полноценный stateful VPN-blocker (показан → состояние обновилось → закрыт).

---

## Trampoline `j__CFNetworkCopySystemProxySettings` @ `0x10615BB98`

4 байта, прямой `B` (jump) к импорту. Это — оптимизация компилятора: какой-то Swift-код часто дёргает `CFNetworkCopySystemProxySettings` и компилятор сделал thunk вместо in-place call. Не отдельный детектор.

---

## Обход существующим `VPNHide`-твиком

Хук `CFNetworkCopySystemProxySettings` вырезает VPN-ключи из `__SCOPED__` → все 3 детектора получают пустой `__SCOPED__`:

| Детектор | Эффект |
|---|---|
| `-[YALAFHTTPClient isVPNConnected]` | пустой allKeys → block ничего не находит → `NO` |
| `VPNConnectionCheckerImpl` | пустой allKeys → ранний return false |
| `sub_1063F7788` | то же |

Для активации добавить в [`tweaks/VPNHide/Filter.plist`](../../tweaks/VPNHide/Filter.plist):

```
{ Filter = { Bundles = ( …, "com.appkode.foodfox" ); }; }
```

Bundle ID legacy: `com.appkode.foodfox` (AppKode — разработчик, FoodFox — название проекта до поглощения Яндексом).

---

## Сравнение

| | MyMTS | МФ | CDEK | DNS | ЦППК | Urent | Гос | бил | 2GIS | Налог | Rost | В&Т | Amediateka | YM | Кинопоиск | **Я.Еда** |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Лок. детекторов | 2 | 1 | 2 | 1 | 1 | 3 | 5 | 2 | 3 | 0 | 1 | 1 | 2 | 2 | 3 | **3** |
| AppsFlyer-style | ✅ | — | ✅ | — | ❌ | ✅ | — | ✅ | ✅ | — | ✅ | ❌ | ✅ | ❌ | ✅ | ❌ |
| YAL (Yandex AppLib) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | — | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ |
| MobileAdsCore (SPB TV) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | — | ❌ | ❌ | ✅ | ❌ | ✅ | ❌ |
| Свой Swift checker | ❌ | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | — | ❌ | ✅ | ❌ | ✅ | ❌ | **✅** (`YXFintechFoundation`) |
| Server-side | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | — | ❌ | ❌ | ✅ | ❌ | ✅ | ❌ |
| Detector в финтех-модуле | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | — | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ **(уникально)** |
| Remote-config struct | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ | — | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ |
| Опечатка `Showen` в analytics | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | — | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| Покрытие VPNHide | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ (лок.) | n/a | ✅ | ✅ | ✅ (лок.) | ✅ | ✅ (лок.) | ✅ |

Я.Еда — **третье** приложение в выборке с YAL-Obj-C-детектором (после Маркета и Кинопоиска), и единственное, где главный Swift-checker лежит в **`YXFintechFoundation`** — общем финтех-фундаменте Яндекса. Это намекает, что тот же checker используется в Я.Такси, Я.Маркет, Я.Доставка и других сервисах Яндекса с финтех-функционалом, и Яндекс централизованно мониторит VPN на уровне платёжной инфраструктуры (вероятно, для compliance / antifraud).

Опечатка `VpnBlockingShowenAnalyticsEvent` (вместо `Shown`) ушла в продакшен и осталась там — характерный признак, что аналитика была написана быстро, ревью не словило, а переименовать в реляционных таблицах метрик уже не дёшево.

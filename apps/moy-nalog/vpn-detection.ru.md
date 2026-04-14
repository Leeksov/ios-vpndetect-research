[🇬🇧 English version](vpn-detection.md)

# Мой налог — детектирование VPN / Proxy

**Бинарник:** `selfemployed` v4.7.1 (arm64, Obj-C + Swift)
**Способ анализа:** IDA Pro / Hex-Rays.

---

## TL;DR

**Приложение не детектит VPN**.

Полностью отсутствует весь стек проверок, встречавшийся в других разобранных приложениях:

- Нет импорта `CFNetworkCopySystemProxySettings`
- Нет импорта `nw_path_uses_interface_type` / `nw_interface_get_type`
- Нет импорта `CFNetworkCopyProxiesForURL`
- Нет импорта `SCDynamicStoreCopyProxies` / `DNSServiceQueryRecord`
- Нет ни одной Swift/Obj-C строки вида `isVPN*`, `vpn*`, `isProxy`, `VpnChecker`, `VPNDetector`, `VPNMonitoring` и т.п.
- Нет строк с русскими «VPN», «впн», «Включён VPN» и т.д.
- Нет строки `__SCOPED__`.

Все попадания по regex'у `VPN|vpn|proxy|ipsec` — **ложные**, из системных библиотек, слинкованных в бинарь:

| Попадание | Источник |
|---|---|
| `(MPLS-labeled VPN)`, `ipsecEndSystem`, `ipsecTunnel`, `ipsecUser`, `ipsec3`, `ipsec4`, `ipsec Internet Key Exchange` | OpenSSL/BoringSSL X.509 policy OID названия (статическая часть displayable-name таблицы). |
| `http_proxy`, `all_proxy`, `NO_PROXY`, `SOCKS-PROXY`, `HAPROXY`, `Proxy-Connection`, `Proxy-authenticate`, `CONNECT to proxy`, `Excessive user name length for proxy auth` | libcurl — внутренние строки для чтения `http_proxy`/`HTTPS_PROXY`/`NO_PROXY` env-переменных и CONNECT-туннелей. |
| `isAppDelegateProxyEnabled`, `App Delegate Proxy is disabled`, `proxyOriginalDelegate`, `createAppDelegateProxy` | Firebase/FirebaseMessaging — AppDelegate swizzling. |
| `ProxyFaceReporter`, `ProxyReporter`, `ProxyFeedbackReporter`, `initFromCreatedFaceSession:withCreatedProxyReporter:` | VisionLabs / LUNA ID — биометрическое распознавание лица (используется для идентификации самозанятого). |
| `com.huawei.hms.push.proxy`, `hmsPushProxyDev`, `/rest/proxy/v1/apply`, `/rest/proxy/v1/cancel` | Huawei Push SDK — только для HMS-устройств, к VPN не относится. |
| `isSessionScoped`, `sessionScoped`, `ItemScopedCustomParameterLimitReached` | Firebase Analytics — event filter scoping. |
| `ScopedRecognizerHandle` | C++ шаблон face recognizer. |

## Импорты

| Символ | Статус | Где используется |
|---|---|---|
| `_getifaddrs` | ✅ | единственный caller — `sub_10070AE0C`: утилита чтения IP-адресов в строку через `inet_ntop` (libcurl-style). **Не VPN.** |
| `_sysctl` / `_sysctlbyname` | ✅ | uptime / hw model (аналитика). |
| `_getenv` | ✅ | env SDK / libcurl proxy-env чтение. |
| `_dlopen` / `_dlsym` | ✅ | dynamic loading, не VPN. |
| `_if_nametoindex` | ✅ | вспомогательный (libcurl). |
| `_CFNetworkCopySystemProxySettings` | ❌ | **не импортируется** |
| `_nw_path_uses_interface_type` | ❌ | **не импортируется** |
| `_nw_interface_get_type` | ❌ | **не импортируется** |
| `_CFNetworkCopyProxiesForURL` | ❌ | **не импортируется** |
| `_SCDynamicStoreCopyProxies` | ❌ | **не импортируется** |
| `_DNSServiceQueryRecord` | ❌ | **не импортируется** |

---

## Обход

**Не нужен.** Приложение работает через VPN и прокси как есть, ничего не проверяет, ничего не блокирует, никаких снекбаров о VPN не показывает.

В `Filter.plist` твика `VPNHide` добавлять `com.gnivts.selfemployed` нет смысла — хукать там нечего.

---

## Контекст

Мой налог — приложение ФНС для самозанятых. Работает с налоговым API, биометрией (VisionLabs для проверки личности при регистрации), платежами. Логично, что команда ФНС **не считает VPN угрозой** — это не маркетинговая аналитика, а госуслуга, завязанная на ИНН и биометрию. Санкционная блокировка через IP-геолокацию тоже не имеет смысла, приложение работает только для резидентов РФ, идентифицированных по паспорту.

Сравнение с другими разобранными:

| App | Детекторы |
|---|---|
| MyMTS | 2 |
| МФ | 1 |
| CDEK | 2 |
| DNS-SHOP | 1 |
| ЦППК | 1 |
| Urent | 3 |
| Госуслуги | 5 |
| билайн | 2 |
| 2GIS | 3 + server-side |
| **Мой налог** | **0** |

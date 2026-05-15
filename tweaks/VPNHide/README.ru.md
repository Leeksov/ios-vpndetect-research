[🇬🇧 English version](README.md)

# VPNHide

Универсальный Theos-твик, скрывающий активный VPN/Proxy от iOS-приложения. Низкоуровневый bypass через [fishhook](https://github.com/facebook/fishhook) — перепривязка импортов Mach-O, без Logos-хуков на Obj-C/Swift-методы.

## Что хукается

| Символ | Что делает хук |
|---|---|
| `CFNetworkCopySystemProxySettings` | Удаляет из `__SCOPED__` ключи-интерфейсы, содержащие `utun/tun/tap/ipsec/ppp/wg`. Также сбрасывает top-level `HTTPEnable`, `HTTPSEnable`, `SOCKSEnable`, `HTTPProxy`, `HTTPSProxy`, `ProxyAutoConfig*` и аналогичные флаги. |
| `CFNetworkCopyProxiesForURL` | Безусловно возвращает `[{ kCFProxyTypeKey: kCFProxyTypeNone }]` — one-entry массив, будто резолвинг прокси для URL показал «direct connection». |
| `nw_path_uses_interface_type` | Для `nw_interface_type_other` (0) всегда возвращает `false`. Для остальных типов — проксирует оригинал. |
| `nw_interface_get_type` | Если оригинал вернул `.other` и имя интерфейса (через `nw_interface_get_name` из `dlsym`) матчится по VPN-префиксу — возвращает `.wifi` вместо `.other`. Покрывает Swift-код, делающий `path.availableInterfaces.map(\.type)` вместо `path.usesInterfaceType(_:)`. |
| `getifaddrs` | Отфильтровывает VPN-интерфейсы из linked-list, возвращаемого libc. |
| `-[NSURLSession dataTaskWithRequest:completionHandler:]` | ObjC-свизл. Перехватывает запросы, URL которых содержит `mobileproxy.passport.yandex.net/tmgrdfrend/checkvpn`, и закрывает их синтетическим `NSURLErrorNotConnectedToInternet` — проба не доходит до сети, вердикт не возвращается. См. [Yandex Passport checkvpn](#yandex-passport-checkvpn-server-side-проба). |

Перепривязка — в `__attribute__((constructor))` + повторно на каждом `_dyld_register_func_for_add_image`. Это покрывает фреймворки, подгружаемые лениво через `dlopen` после старта процесса (и `libswiftNetwork.dylib` — Swift-overlay для `Network.framework`, вызывающий `nw_interface_get_type` из своих wrapper'ов).

## Когда применим

- Детект через `CFNetworkCopySystemProxySettings.__SCOPED__` + сравнение имён интерфейсов с `tun`/`ipsec`/`ppp`/… (классический AppsFlyer-style).
- Детект через `CFNetworkCopySystemProxySettings` → прямое чтение `HTTPProxy`/`HTTPSProxy`/`SOCKSProxy` ключей (Гос-услуги-style).
- Детект через `CFNetworkCopyProxiesForURL` per-URL с проверкой `kCFProxyHostNameKey` (Гос-услуги).
- Детект через `NWPathMonitor` + `NWPath.usesInterfaceType(.other)` (MyMTS).
- Детект через `NWPath.availableInterfaces.map(\.type).contains(.other)` — Swift enum-сравнение (ЦППК `NetworkMonitor`).
- Любой детект на базе `getifaddrs` / `if_nameindex`-обхода.
- Yandex Passport **server-side** проверка через `mobileproxy.passport.yandex.net/tmgrdfrend/checkvpn` — обходится убийством самого запроса (см. ниже).

## Yandex Passport checkvpn (server-side проба)

Ряд приложений Яндекса (Почта, Метро, Ключ, Кинопоиск, Яндекс Go / Такси, Карты/Пробки, Переводчик, Маркет Blue, Расписания, IoT) тащит общий Passport SDK, который на старте / обновлении токена дёргает:

```
GET https://mobileproxy.passport.yandex.net/tmgrdfrend/checkvpn
```

Это **server-side**-детектор: вердикт («клиент пришёл с VPN/прокси-egress?») считается на стороне Яндекса по исходному IP запроса и возвращается в теле ответа. Приложение потом гейтит фичи / рисует баннер / пишет телеметрию на основе того, что прилетело. Классические хуки по именам интерфейсов и proxy-settings (всё остальное в этом твике) сюда не подходят — логика детекта живёт не на устройстве.

Bypass — **убить пробу на клиенте**: свизлим `-[NSURLSession dataTaskWithRequest:completionHandler:]`, матчим URL подстрокой, в completion handler синтезируем `NSURLErrorNotConnectedToInternet`. Приложение воспринимает это как обычный сетевой сбой и продолжает работу без вердикта. Работает, потому что SDK к ошибке этого эндпоинта толерантен (иначе нельзя — на флаки-мобильной сети он регулярно валится сам).

Преднастроенные бандлы в [`Filter.plist`](Filter.plist): `ru.yandex.mail`, `ru.yandex.mobile.metro`, `ru.yandex.mobile.kluch`, `ru.kinopoisk`, `ru.yandex.ytaxi`, `ru.yandex.traffic`, `ru.yandex.mobile.translate`, `ru.yandex.blue.market`, `ru.yandex.rasp`, `com.yandex.iot`.

## Когда **не** поможет

- Server-side детект по IP-адресу *кроме* Yandex'овского `checkvpn`-эндпоинта.
- Чтение routing table через `sysctl(net.route.0)` — не хукается (при необходимости добавить отдельный хук).
- DNS-cross-check через `DNSServiceQueryRecord` — не хукается.
- Детекторы, читающие дескрипторы сокетов и проверяющие flags интерфейса напрямую через `ioctl(SIOCGIFFLAGS)`.
- Детекторы на уровне Swift NWPathMonitor, которые сверяют `NWInterface.name` (строку) с VPN-префиксами — тут имя интерфейса настоящее, и мы его не подменяем. Пока в разобранных приложениях такого не встречено.

## Сборка

```sh
cd tweaks/VPNHide
git submodule add https://github.com/facebook/fishhook.git fishhook
make package install
```

Переменные окружения: `THEOS`, `THEOS_DEVICE_IP`. Для релиза — `FINALPACKAGE=1 make package`.

## Настройка под приложение

[`Filter.plist`](Filter.plist) содержит список bundle ID, для которых твик активируется. По умолчанию там все разобранные приложения с детектом. Добавьте или уберите нужные bundle ID — полная таблица приложений в репе: [`../../README.md`](../../README.ru.md).

## Проверка

1. Поднять VPN (OpenVPN / WireGuard / IKEv2 — любой, создающий `utun*`).
2. Запустить целевое приложение.
3. Проверить, что триггеры детекта (снекбары, feature-gates, поле `is_vpn_enabled` в телеметрии) не срабатывают.

Пример per-app разбора, из которого эти хуки выводились — [`apps/mymts/vpn-detection.md`](../../apps/mymts/vpn-detection.ru.md).

## Ограничения

- Charles/Proxyman сами поднимают прокси-интерфейс — использовать только в паре с твиком, иначе хук пропустит настоящие прокси-настройки, которые вы сами выставили.
- Не подменяет DNS, не устраняет IP-утечки.

# Яндекс Маркет

| Поле | Значение |
|---|---|
| Display name | Маркет |
| Bundle ID | `ru.yandex.blue.market` |
| CFBundleExecutable | `Beru` |
| Версия | 2026.11.1 |
| Min iOS | 15.0 |
| Архитектуры | arm64 |
| Размер бинарника | 139 MB |

## Пути

- IPA: `/Users/leeksov/Downloads/AyuGram Desktop/_Яндекс Маркет_v2026.11.1-AppAssassin.ipa`
- .app: `/Users/leeksov/Downloads/AyuGram Desktop/_extracted/Яндекс Маркет/Payload/Beru.app/`
- Бинарник: `/Users/leeksov/Downloads/AyuGram Desktop/_extracted/Яндекс Маркет/Payload/Beru.app/Beru`

CFBundleExecutable — `Beru` (legacy-имя от прежнего названия Беру.ру).

## Заметки по бинарнику

- Без AppsFlyer SDK (нет `+[AppsFlyerUtils isVPNConnected]`). Свои реализации.
- Два дублирующих VPN-детектора: Obj-C `-[YALAFHTTPClient isVPNConnected]` (Yandex AppLib) и Swift `MarketProtocols.VPNCheckerServiceImpl`.
- Уникальная reversed-семантика в Obj-C-детекторе: `[needle containsString:iface]` (needle содержит iface), а не наоборот.
- DI-property `vpnCheckerService` (как у Госуслуг / Beeline / 2GIS / Amediateka).
- Bundle ID и executable — legacy `Beru` (название проекта до поглощения Яндексом).

## Разобранные темы

| Тема | Файл |
|---|---|
| Детектирование VPN / Proxy | [vpn-detection.md](vpn-detection.md) |

## Связанные твики

- [`tweaks/VPNHide/`](../../tweaks/VPNHide/) — покрывает оба детектора (`__SCOPED__` чистится → пустой allKeys); для активации добавить `ru.yandex.blue.market` в `Filter.plist`.

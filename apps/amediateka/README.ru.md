[🇬🇧 English version](README.md)

# Amediateka

| Поле | Значение |
|---|---|
| Display name | Amediateka |
| Bundle ID | `com.spbtv.ag.tv.Amedia` |
| CFBundleExecutable | `Amediateka` |
| Версия | 4.54.0 |
| Min iOS | 15.0 |
| Архитектуры | arm64 |
| Размер бинарника | 55 MB |

## Пути

- IPA: `/Users/leeksov/Downloads/AyuGram Desktop/_Amediateka — сер…_v4.54.0-AppAssassin.ipa`
- .app: `/Users/leeksov/Downloads/AyuGram Desktop/_extracted/amediateka/Payload/Amediateka.app/`
- Бинарник (для IDA): [`../../binaries/amediateka`](../../binaries/amediateka)

## Заметки по бинарнику

- VPN-detector живёт в **shared-SDK `MobileAdsCore`** (SPB TV common framework), главное приложение подключается через DI (`vpnStatusChecker`).
- Тристейт-результат `0/1/2` (no/yes/unknown) — как у Госуслуг.
- **Server-side check**: бекенд возвращает HTTP 403 + code `"Vpn"`, парсится в Swift-error `ShortApiError403Vpn`.
- Геоблок-инфраструктура отдельно (`{{WAS_GEOBLOCKED}}`, `isGeoBlocked`).

## Разобранные темы

| Тема | Файл |
|---|---|
| Детектирование VPN / Proxy | [vpn-detection.md](vpn-detection.md) |

## Связанные твики

- [`tweaks/VPNHide/`](../../tweaks/VPNHide/) — покрывает локальную часть; server-side `403 Vpn` остаётся (но не критично, контент лицензирован только для РФ). Для активации добавить `com.spbtv.ag.tv.Amedia` в `Filter.plist`.

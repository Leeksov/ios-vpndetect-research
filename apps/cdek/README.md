# CDEK

| Поле | Значение |
|---|---|
| Display name | CDEK |
| Bundle ID | `com.cdek.cdekapp` |
| CFBundleExecutable | `CDEK` |
| Версия | 5.9.0 |
| Min iOS | 15.1 |
| Архитектуры | arm64 |
| Размер бинарника | 17 MB |

## Пути

- IPA: `/Users/leeksov/Downloads/AyuGram Desktop/_CDEK_v5.9.0-AppAssassin.ipa`
- .app: `/Users/leeksov/Downloads/AyuGram Desktop/_extracted/CDEK/Payload/CDEK.app/`
- Бинарник: `/Users/leeksov/Downloads/AyuGram Desktop/_extracted/CDEK/Payload/CDEK.app/CDEK`

## Заметки по бинарнику

- React Native приложение (reanimated, margelo/nitro, worklets, RNSVG).
- Нативная сторона — Swift + Obj-C (AppsFlyer SDK, Sentry, Mindbox, Firebase GoogleUtilities).
- VPN-детект реализован как native-модуль RN: CocoaPods-пакет `VpnDetect` (`_TtC9VpnDetect15VpnDetectModule`, JS-API `isVpnConnected`).

## Разобранные темы

| Тема | Файл |
|---|---|
| Детектирование VPN / Proxy | [vpn-detection.md](vpn-detection.md) |

## Связанные твики

- [`tweaks/VPNHide/`](../../tweaks/VPNHide/) — покрывает CDEK-овский детект; для активации добавить `com.cdek.cdekapp` в `Filter.plist`.

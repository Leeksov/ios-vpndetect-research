[🇬🇧 English version](README.md)

# Расписание ЦППК (Расписание и билеты)

| Поле | Значение |
|---|---|
| Display name | Расписание ЦППК |
| Bundle ID | `ru.central-ppk.Timetable` |
| CFBundleExecutable | `Timetable PROD` |
| Версия | 2.7 |
| Min iOS | 15.0 |
| Архитектуры | arm64 |
| Размер бинарника | 10 MB |

## Пути

- IPA: `/Users/leeksov/Downloads/AyuGram Desktop/_Расписание и билеты_v2.7-AppAssassin.ipa`
- .app: `/Users/leeksov/Downloads/AyuGram Desktop/_extracted/Расписание и билеты/Payload/Timetable PROD.app/`
- Бинарник: `/Users/leeksov/Downloads/AyuGram Desktop/_extracted/Расписание и билеты/Payload/Timetable PROD.app/Timetable PROD`

Внимание: имя бинарника содержит пробел — цитируйте пути при работе из shell.

## Разобранные темы

| Тема | Файл |
|---|---|
| Детектирование VPN / Proxy | [vpn-detection.md](vpn-detection.md) |

## Связанные твики

- [`tweaks/VPNHide/`](../../tweaks/VPNHide/) — покрывается хуком `nw_interface_get_type`, добавленным специально под этот кейс (перепривязывается в GOT `libswiftNetwork.dylib`). Для активации добавить `ru.central-ppk.Timetable` в `Filter.plist`.

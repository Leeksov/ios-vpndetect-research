[🇬🇧 English version](README.md)

# Urent

| Поле | Значение |
|---|---|
| Display name | Urent |
| Bundle ID | `ru.urentbike.app` |
| CFBundleExecutable | `Urent` |
| Версия | 1.94.1 |
| Min iOS | 16.0 |
| Архитектуры | arm64 |
| Размер бинарника | 67 MB |

## Пути

- IPA: `/Users/leeksov/Downloads/AyuGram Desktop/_Urent_v1.94.1-AppAssassin.ipa`
- .app: `/Users/leeksov/Downloads/AyuGram Desktop/_extracted/Urent/Payload/Urent.app/`
- Бинарник: `/Users/leeksov/Downloads/AyuGram Desktop/_extracted/Urent/Payload/Urent.app/Urent`

## Разобранные темы

| Тема | Файл |
|---|---|
| Детектирование VPN / Proxy | [vpn-detection.md](vpn-detection.md) |

## Связанные твики

- [`tweaks/VPNHide/`](../../tweaks/VPNHide/) — покрывает Urent (3 дублирующих детектора на `__SCOPED__`); для активации добавить `ru.urentbike.app` в `Filter.plist`.

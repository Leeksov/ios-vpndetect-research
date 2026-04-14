[🇬🇧 English version](README.md)

# Rostic's (бывш. KFC Russia)

| Поле | Значение |
|---|---|
| Display name | Rostic's |
| Bundle ID | `ru.yum.KFC-Russia` |
| CFBundleExecutable | `kfc` |
| Версия | 10.29.0 |
| Min iOS | 16.0 |
| Архитектуры | arm64 |
| Размер бинарника | 65 MB |

## Пути

- IPA: `/Users/leeksov/Downloads/AyuGram Desktop/_Rostic's__Еда_доставка,_акции_v10_29_0_AppAssassin.ipa`
- .app: `/Users/leeksov/Downloads/AyuGram Desktop/_extracted/rostics/Payload/kfc.app/`
- Бинарник (для IDA): [`../../binaries/rostics`](../../binaries/rostics)

Bundle ID и имя executable — legacy KFC-эпохи (`ru.yum.KFC-Russia` / `kfc`), ребренд в Rostic's произошёл только на UI-уровне.

## Разобранные темы

| Тема | Файл |
|---|---|
| Детектирование VPN / Proxy | [vpn-detection.md](vpn-detection.md) |

## Связанные твики

- [`tweaks/VPNHide/`](../../tweaks/VPNHide/) — покрывает Rostic's (один AppsFlyer-детектор); для активации добавить `ru.yum.KFC-Russia` в `Filter.plist`.

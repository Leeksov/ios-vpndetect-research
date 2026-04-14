# Вкусно — и точка

| Поле | Значение |
|---|---|
| Display name | Вкусно— и точка |
| Bundle ID | `com.mcdonaldsru.mcd` |
| CFBundleExecutable | `mcd-ios` |
| Версия | 13.2.0 |
| Min iOS | 15.6 |
| Архитектуры | arm64 |
| Размер бинарника | 54 MB |

## Пути

- IPA: `/Users/leeksov/Downloads/AyuGram Desktop/_Вкусно — и точка_v13.2.0-AppAssassin.ipa`
- .app: `/Users/leeksov/Downloads/AyuGram Desktop/_extracted/vkusno-i-tochka/Payload/mcd-ios.app/`
- Бинарник (для IDA): [`../../binaries/vkusno-i-tochka`](../../binaries/vkusno-i-tochka)

Bundle ID и executable — legacy McDonald's-эпохи (`com.mcdonaldsru.mcd` / `mcd-ios`), ребренд в «Вкусно — и точка» только на уровне UI.

## Разобранные темы

| Тема | Файл |
|---|---|
| Детектирование VPN / Proxy | [vpn-detection.md](vpn-detection.md) |

## Связанные твики

- [`tweaks/VPNHide/`](../../tweaks/VPNHide/) — покрывает В&Т (один Swift-checker, без AppsFlyer-дубля); для активации добавить `com.mcdonaldsru.mcd` в `Filter.plist`.

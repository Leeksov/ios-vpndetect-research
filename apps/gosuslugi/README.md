# Госуслуги

| Поле | Значение |
|---|---|
| Display name | Gosuslugi |
| Bundle ID | `com.minsvyaz.gosuslugi` |
| CFBundleExecutable | `Gosuslugi` |
| Версия | 25.3.0 |
| Min iOS | 14.0 |
| Архитектуры | arm64 |
| Размер бинарника | 131 MB |

## Пути

- IPA: `/Users/leeksov/Downloads/AyuGram Desktop/_Госуслуги_v25.3.0-AppAssassin.ipa`
- .app: `/Users/leeksov/Downloads/AyuGram Desktop/_extracted/Госуслуги/Payload/Gosuslugi.app/`
- Бинарник: `/Users/leeksov/Downloads/AyuGram Desktop/_extracted/Госуслуги/Payload/Gosuslugi.app/Gosuslugi`

## Заметки по бинарнику

- Двойная реализация фреймворков: `GUNetwork.VPNCheckService` + самостоятельный `VPNCheckService` (с DI `VPNCheckAssembly`, `VPNCheckServiceStrings`, `VPNSnackbarMessage`).
- `vpnProtocolsKeysIdentifiers` — список подстрок VPN-интерфейсов, **externally supplied** (remote config / plist / DI). Уникальная черта среди разобранных приложений.
- Трёхзначная аналитика `^(vpn_on)|(vpn_off)|(vpn_unknown)$`.
- Debug-флаг `debugDoNotShowVPNSnackbar` для разработчиков.

## Разобранные темы

| Тема | Файл |
|---|---|
| Детектирование VPN / Proxy | [vpn-detection.md](vpn-detection.md) |

## Связанные твики

- [`tweaks/VPNHide/`](../../tweaks/VPNHide/) — покрывает все 5 детекторов (в т.ч. `CFNetworkCopyProxiesForURL` per-URL). `com.minsvyaz.gosuslugi` уже в `Filter.plist`.

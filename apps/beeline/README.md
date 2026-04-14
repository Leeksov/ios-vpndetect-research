# билайн (My Beeline)

| Поле | Значение |
|---|---|
| Display name | билайн |
| Bundle ID | `ru.beeline.mobile` |
| CFBundleExecutable | `MyBeeline` |
| Версия | 5.36.0 |
| Min iOS | 16.0 |
| Архитектуры | arm64 |
| Размер бинарника | 100 MB |

## Пути

- IPA: `/Users/leeksov/Downloads/AyuGram Desktop/_билайн_v5.36.0-AppAssassin.ipa`
- .app: `/Users/leeksov/Downloads/AyuGram Desktop/_extracted/билайн/Payload/MyBeeline.app/`
- Бинарник: `/Users/leeksov/Downloads/AyuGram Desktop/_extracted/билайн/Payload/MyBeeline.app/MyBeeline`

## Заметки по бинарнику

- Детектор VPN вынесен в отдельный Swift-framework `MBVpnDetector` с DI-архитектурой (`ProxySettingsProvider` protocol + `SystemProxySettingsProvider` impl).
- Список VPN-паттернов — Swift-property `vpnProtocols`, вероятно remote-configurable (по симметрии с Госуслугами).
- UI-плашка gate'ится remote feature-flag'ом (описание «Регулирует предупреждение об активном VPN» @ `0x104338e00`).
- В бинарник попали debug-комменты с тикетами (`PRFL-9677: Добавить уведомление о включенном VPN`).

## Разобранные темы

| Тема | Файл |
|---|---|
| Детектирование VPN / Proxy | [vpn-detection.md](vpn-detection.md) |

## Связанные твики

- [`tweaks/VPNHide/`](../../tweaks/VPNHide/) — покрывает MyBeeline детект; для активации добавить `ru.beeline.mobile` в `Filter.plist`.

[🇬🇧 English version](README.md)

# Мой МТС

| Поле | Значение |
|---|---|
| Display name | Мой МТС |
| Bundle ID | `ru.mts.mymts` |
| CFBundleExecutable | `MtsServiceRu` |
| Версия | — (бинарник без Info.plist) |
| Min iOS | — |
| Архитектуры | arm64 |
| Размер бинарника | 32 MB |

## Пути

- Бинарник: [`../../MtsServiceRu`](../../MtsServiceRu)
- IDA-база: `MtsServiceRu.i64` (там же, рядом: `.id0`/`.id1`/`.id2`/`.nam`/`.til`)
- IPA: _нет_ — в репо лежит только извлечённый исполняемый файл, без .app-бандла.

## Заметки по бинарнику

- Основной swift-модуль: `MtsServiceRu`.
- Общие фреймворки: `MyMtsKit`, `GeoWidgetSDK`, `SPMProxy`.
- Сторонняя аналитика: AppsFlyer, AppMetrica (Yandex), OpenTelemetry.
- Swift-код активно использует `NWPathMonitor` / `Combine`-пайплайны (`CurrentValueSubject`) — почти вся реактивщина, связанная с состоянием сети, идёт через `GeoWidgetSDK`.
- UI-снекбары и gate'ы фич завязаны на Swift-протоколы `MyMtsKit.VpnDetectorListener` и `MyMtsKit.FeedbackMessageVpnDetectorListener`.
- Feature-flags реализованы через `*ConditionParam`-классы в `MtsServiceRu` (например, `VpnEnabledConditionParam`, `MtsAnalyticsExperimentsConditionParam`).
- Обфускации нет; Swift-метаданные читаемы, Obj-C-селекторы не скрыты.

## Разобранные темы

| Тема | Файл |
|---|---|
| Детектирование VPN / Proxy | [vpn-detection.md](vpn-detection.md) |

## Связанные твики

- [`tweaks/VPNHide/`](../../tweaks/VPNHide/) — скрытие VPN от приложения.

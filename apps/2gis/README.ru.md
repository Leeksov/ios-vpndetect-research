[🇬🇧 English version](README.md)

# 2GIS

| Поле | Значение |
|---|---|
| Display name | 2GIS |
| Bundle ID | `ru.doublegis.grymmobile` |
| CFBundleExecutable | `ru.doublegis.grymmobile` |
| Версия | 7.21.7 |
| Min iOS | 16.0 |
| Архитектуры | arm64 |
| Размер бинарника | 183 MB |

## Пути

- IPA: `/Users/leeksov/Downloads/AyuGram Desktop/_2GIS_v7.21.7-AppAssassin.ipa`
- .app: `/Users/leeksov/Downloads/AyuGram Desktop/_extracted/2GIS/Payload/ru.doublegis.grymmobile.app/`
- Бинарник: `/Users/leeksov/Downloads/AyuGram Desktop/_extracted/2GIS/Payload/ru.doublegis.grymmobile.app/ru.doublegis.grymmobile`

## Заметки по бинарнику

- Архитектура с 4 отдельными фреймворками под VPN-детект: `VNVPNCheckerAPI`, `VNVPNCheckerAPIInterfaces`, `VNVPNCheckerUI`, `VNCarPlay`.
- **Server-side** детект через `/v1/vpn-detection-free` (HTTP 451 = блок).
- Full-screen UI-блок через отдельный `UIWindow` (`VPNBlockedWindow`), плюс отдельный CarPlay-overlay с preservation маршрута.
- `String.hasPrefix` (не `contains`) + `lowercased()` — строже, чем у прочих приложений.
- Debug-символы из Jenkins CI слиты в релиз: `/Users/user/jenkins/agent/workspace/release-v4ios/...`.

## Разобранные темы

| Тема | Файл |
|---|---|
| Детектирование VPN / Proxy | [vpn-detection.md](vpn-detection.md) |

## Связанные твики

- [`tweaks/VPNHide/`](../../tweaks/VPNHide/) — покрывает локальные детекторы (3 шт); server-side check сам не сработает, т.к. локальный triger заглушён. Для активации добавить `ru.doublegis.grymmobile` в `Filter.plist`.

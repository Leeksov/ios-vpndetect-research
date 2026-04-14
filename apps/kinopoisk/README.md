# Кинопоиск

| Поле | Значение |
|---|---|
| Display name | Кинопоиск |
| Bundle ID | `ru.kinopoisk` |
| CFBundleExecutable | `Kinopoisk` |
| Версия | 8.41.3 |
| Min iOS | 17.0 |
| Архитектуры | arm64 |
| Размер бинарника | 165 MB |

## Пути

- IPA: `/Users/leeksov/Downloads/AyuGram Desktop/_Кинопоиск_v8.41.3-AppAssassin.ipa`
- .app: `/Users/leeksov/Downloads/AyuGram Desktop/_extracted/kinopoisk/Payload/Kinopoisk.app/`
- Бинарник (для IDA): [`../../binaries/kinopoisk`](../../binaries/kinopoisk)

## Заметки по бинарнику

- **3 локальных VPN-детектора + server-side `/tmgrdfrend/checkvpn`** (третий разобранный кейс с server-check после 2GIS и Amediateka).
- Переиспользует **сразу два shared-SDK** с другими разобранными приложениями:
  - `MobileAdsCore.MACVpnStatusCheckerImpl` (общий с **Amediateka**)
  - Yandex AppLib `YAL*` (общий с **Я.Маркетом**)
- **`YALVPNConnect*`** — это **собственный Yandex anti-blocking прокси** (НЕ детектор пользовательского VPN), управляющий региональным содержимым. Полная Obj-C подсистема (`YALVPNConnectManager`, `YALVPNConfig`, `YALVPNConfigApp`, `YALVPNConnectProductLocation`).
- Full-screen blocker UI с 6 analytics-событиями (`vpn_blocker_show/hide/reload/close/settings/openurl`).
- Feature-flag `ios_block_vpn` для server-side kill switch.
- UI-текст «У вас включен VPN или в вашей стране доступен не весь каталог Кинопоиска» — Кинопоиск осознанно не различает VPN от region-availability в сообщении.

## Разобранные темы

| Тема | Файл |
|---|---|
| Детектирование VPN / Proxy | [vpn-detection.md](vpn-detection.md) |

## Связанные твики

- [`tweaks/VPNHide/`](../../tweaks/VPNHide/) — покрывает 3 локальных детектора; server-side `/checkvpn` остаётся, но при заглушённой локалке скорее всего не дёргается. Для активации добавить `ru.kinopoisk` в `Filter.plist`.

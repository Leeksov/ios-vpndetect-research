[🇬🇧 English version](README.md)

# Яндекс Еда

| Поле | Значение |
|---|---|
| Display name | YandexEats |
| Bundle ID | `com.appkode.foodfox` |
| CFBundleExecutable | `YandexEats` |
| Версия | 8.102.1 |
| Min iOS | 16.0 |
| Архитектуры | arm64 |
| Размер бинарника | 221 MB |

## Пути

- IPA: `/Users/leeksov/Downloads/AyuGram Desktop/_Yandex Eats_v8.102.1-AppAssassin.ipa`
- .app: `/Users/leeksov/Downloads/AyuGram Desktop/_extracted/yandex-eats/Payload/YandexEats.app/`
- Бинарник (для IDA): [`../../binaries/yandex-eats`](../../binaries/yandex-eats)

Bundle ID — `com.appkode.foodfox` (AppKode — разработчик, FoodFox — проект до поглощения Яндексом).

## Заметки по бинарнику

- 3 локальных VPN-детектора, **без** AppsFlyer SDK и **без** `MobileAdsCore`.
- Главный Swift-checker лежит в **`YXFintechFoundation`** — общем финтех-фундаменте Яндекса (по-видимому, шарится между Я.Маркет, Я.Такси, Я.Доставка и др.). Уникальная позиция детектора — на уровне платёжной инфраструктуры, не general networking.
- `EatsSDKExperiments.VPNCheckConfig` — Codable-структура для remote-config (вкл./выкл. детектора через A/B).
- 3 analytics-события: `VpnBlockingInit`, `VpnBlockingShowen` (sic, опечатка `Showen`), `VpnBlockingUpdated`.
- Использует Yandex AppLib `YAL` (общий с Я.Маркет и Кинопоиском).

## Разобранные темы

| Тема | Файл |
|---|---|
| Детектирование VPN / Proxy | [vpn-detection.md](vpn-detection.md) |

## Связанные твики

- [`tweaks/VPNHide/`](../../tweaks/VPNHide/) — покрывает все 3 детектора (`__SCOPED__` чистится); для активации добавить `com.appkode.foodfox` в `Filter.plist`.

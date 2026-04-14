[🇷🇺 Русская версия](README.ru.md)

# Расписание ЦППК (Расписание и билеты)

| Field | Value |
|---|---|
| Display name | Расписание ЦППК |
| Bundle ID | `ru.central-ppk.Timetable` |
| CFBundleExecutable | `Timetable PROD` |
| Version | 2.7 |
| Min iOS | 15.0 |
| Architectures | arm64 |
| Binary size | 10 MB |

## Paths

- IPA: `/Users/leeksov/Downloads/AyuGram Desktop/_Расписание и билеты_v2.7-AppAssassin.ipa`
- .app: `/Users/leeksov/Downloads/AyuGram Desktop/_extracted/Расписание и билеты/Payload/Timetable PROD.app/`
- Binary: `/Users/leeksov/Downloads/AyuGram Desktop/_extracted/Расписание и билеты/Payload/Timetable PROD.app/Timetable PROD`

Note: the binary name contains a space — quote paths when working from shell.

## Topics analysed

| Topic | File |
|---|---|
| VPN / Proxy detection | [vpn-detection.md](vpn-detection.md) |

## Related tweaks

- [`tweaks/VPNHide/`](../../tweaks/VPNHide/) — covered by the `nw_interface_get_type` hook added specifically for this case (rebinds in `libswiftNetwork.dylib` GOT). Add `ru.central-ppk.Timetable` to `Filter.plist`.

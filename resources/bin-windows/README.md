# Движок обхода для Windows (zapret2)

Здесь лежат готовые бинарники движка `winws2.exe` — то же, что для Linux
лежит в `../bin-linux/`. Приложение запускает движок как процесс и передаёт
ему аргументы; перехват пакетов движок делает сам через WinDivert, поэтому
отдельного бэкенда перехвата в Rust-коде не требуется.

## Что откуда

| | |
|---|---|
| Источник | https://github.com/bol-van/zapret2, релиз **v1.0.6** |
| Архив | `zapret2-v1.0.6.zip`, https://github.com/bol-van/zapret2/releases/download/v1.0.6/zapret2-v1.0.6.zip |
| Взято | `binaries/windows-x86_64/*`, `binaries/windows-x86/*`, `docs/LICENSE.txt` |
| Лицензия | MIT, `Copyright (c) 2016-2026 bol-van` — см. `LICENSE-zapret2.txt` |
| Проверка | SHA-256 каждого файла сверен с `sha256sum.txt` того же релиза |

Состав (x86_64; в `x86/` — то же для 32-битной системы):

| Файл | Роль |
|---|---|
| `winws2.exe` | движок обхода (zapret2) |
| `WinDivert.dll`, `WinDivert64.sys` | перехват пакетов (WinDivert 2.2.2, LGPLv3/GPLv2) |
| `cygwin1.dll` | рантайм, с которым собран движок |
| `ip2net.exe`, `mdig.exe`, `killall.exe` | вспомогательные утилиты zapret2 |

Скрипты стратегий (`lua/`) и фильтры WinDivert (`windivert.filter/`) берутся
из общих ресурсов репозитория — дублировать их здесь не нужно.

## Как обновлять

1. Скачать архив нужного релиза с https://github.com/bol-van/zapret2/releases
   и `sha256sum.txt` к нему.
2. Сверить SHA-256 всех файлов из `binaries/windows-*` со списком релиза.
3. Заменить файлы здесь, обновить версию в этой таблице.

Требуются права администратора: WinDivert ставит драйвер, движок без прав не
запустится.

# План: полный порт winws2/nfqws2 (zapret2) на Rust — Windows, Linux, Android

Статус: план (2026-10-21). Источники фактов: github.com/bol-van/zapret2
(лицензия docs/LICENSE.txt — MIT, Copyright (c) 2016-2026 bol-van);
живая установка Zapret в /home/kalinov/Faugus/default/drive_c/Zapret/Dev
(winws2.exe, lua/, bin/, presets/, windivert.filter/, каталоги sqlite).

## Почему это возможно

1. **Лицензия MIT** — портирование и перелицензирование кода законны;
   обязательства — сохранить копирайт в файлах порта.
2. **Одно ядро, два перехвата**: winws2 и nfqws2 собираются из одного
   nfq2/nfqws.c. Платформенное — только способ получения пакетов:
   WinDivert (Windows), NFQUEUE (Linux/Android), ipfw/pf (BSD).
3. **Стратегии на Lua, а не в C** — вся логика дурения DPI вынесена в
   .lua-скрипты (zapret-lib/antidpi/obfs/auto…). Их можно исполнять как
   есть из Rust через mlua (Lua 5.4) — совместимость с community-пресетами
   и стратегиями сохраняется без переписывания сотен тысяч строк.
4. У нас уже есть: парсер пресетов (primecore-profile), runner/диагностика
   (primecore-ws), привилегии Linux (primecore-privilege), шифрованный DNS
   (primecore-dnswire), каталоги фейков (primecore-fakes), списки
   (primecore-lists), файловая база (primecore-files).

## Оценка объёма (по данным GitHub)

* C-код ≈ 865 КБ (~30 тыс. строк), из них nfqws.c 94 КБ;
* Lua ≈ 224 КБ (исполняются как есть через mlua, не переписываются);
* порядок работ: от чистой логики к платформенным дверям.

## Этапы

### Этап 0 — инвентаризация (идёт, агент aj-14)
Точная таблица модулей C (файл → строки → роль), что годится для
golden-тестов, какие системные вызовы где используются.

### Этап 1 — чистая логика пакетов (крейт primecore-packet)
Перенос с parity-тестами: dissect (IP/IPv6/TCP/UDP/ICMP), reconstruct,
checksums (crc16, ip/tcp/udp/icmp6), kavl/uthash-структуры → BTreeMap/двоичное
дерево, hostlist/ipset-фильтры (частично уже есть в primecore-lists).
Golden-тесты: эталоны с python-порта и живые пакеты из логов winws2.

### Этап 2 — протоколы и conntrack (primecore-protocol)
protocol.c (распознавание TLS/QUIC/HTTP/DPI-сигнатур), conntrack.c
(отслеживание соединений), gzip/zlib-пути, таймеры. Всё чистое — без ОС.

### Этап 3 — Lua-конвейер (primecore-lua-bridge)
mlua (Lua 5.4, vendored) + регистрация функций nfqws2: dissect_*,
reconstruct_*, rawsend-заглушки через трейт, константы (ICMP/IP/TCP/TH_*,
VERDICT_*), execution_plan. Существующие .lua работают без правок —
это критическое требование совместимости (иначе community-стратегии мертвы).

### Этап 4 — движок desync (primecore-desync)
desync.c: механизмы fake/multisplit/fakedsplit/hostfakesplit/tcpseg/oob/
syndata как C-примитивы, на которые опираются lua-скрипты; pools, packet_queue.

### Этап 5 — платформенные бэкенды перехвата
* Linux/Android: NFQUEUE через чистый netlink (rtnetlink nfqueue) или ffi
  libnetfilter_queue; правила nftables/iptables генерирует слой запуска
  (использует primecore-privilege). Android = Linux-путь + root (Magisk).
* Windows: WinDivert через windivert-sys/windivert-трейт (DLL как у
  оригинала); фильтры --wf-* и --wf-raw-part (язык фильтров windivert).
* Общий трейт перехвата: `PacketSource` (забрать пакет + метаданные) и
  `PacketSink` (вернуть вердикт/модифицированный пакет) — ядро не знает ОС.

### Этап 6 — CLI-совместимость (bin/winws2-rs)
Парсер аргументов, совместимый с nfqws2/winws2 (те же флаги, включая
--wf-*, --qnum, --fwmark, --lua-desync, --blob, --hostlist/--ipset),
режимы сервиса Windows (win.c) и systemd — по надобности.

### Этап 7 — интеграция с PrimeProxy
primecore-ws запускает бинарь как процесс (как сейчас) ИЛИ движок
линкуется как библиотека в сервер; лог-анализатор (primecore-log-analyzer)
уже читает debug-лог формата winws2 — пригодится сразу.

## Риски и честные ограничения

* nfqws.c 94 КБ — крупнейший файл; переносить срезами с golden-тестами,
  не одним куском.
* Пара rawsend/raw_packet на Linux требует raw-сокетов и CAP_NET_RAW —
  это работа для primecore-privilege (демон privd уже есть).
* Windows-сборка с WinDivert требует драйвер-подпись — как у оригинала,
  DLL поставляется рядом; в CI без Windows-железа проверяем компиляцией.
* BSD (dvtws2) — вне первого объёма: пользователи на BSD могут остаться
  на оригинале; ядро после этапа 4 позволит бэкенд позже.
* Сборки Android: NDK cross-compile, NFQUEUE доступен с root; без root
  zapret2 в принципе не работает (как и оригинал).

## Что уже даёт живая установка (не ждать этапов)

* golden-файлы: presets/winws1_builtin (307), winws2_builtin (136) —
  вход для парсера пресетов; bin/*.bin — фейковые пакеты для detect-тестов
  (уже используется в primecore-fakes); windivert.filter/*.txt — корпус
  фильтров WinDivert; lua/*.lua — корпус для mlua-конвейера;
  system/fakes_catalog.sqlite3, hosts_catalog.sqlite3 — настоящие базы.
* docs/manual.md из репозитория — эталон семантики флагов для CLI.

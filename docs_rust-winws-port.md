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

## Инвентаризация aj-14 (фактическая)

Метод: Sourcegraph по живому индексу репозитория (клона в среде не было);
размеры — нижние границы, перепроверить wc -l после клонирования.

* **Лицензия**: docs/LICENSE.txt — MIT, «Copyright (c) 2016-2026 bol-van».
* **Сборка**: один набор исходников → три бинаря (nfqws2/dvtws2/winws2);
  tpws в zapret2 нет. make-цели: all (Linux), systemd, android, bsd.
* **C-ядро nfq2/ ≈ 20–25 тыс. строк**:

| Файл | ≥ строк | Роль |
|---|---|---|
| lua.c | 4700 | весь Lua-API: push/parse диссектов, reconstruct_*, rawsend-обёртки, блобы, таймеры |
| nfqws.c | 3170 | main (стр. 2240), getopt_long_only, 90+ опций (IDX_*), профили, NFQUEUE-callback |
| darkmagic.c | 2345 | платформенный I/O, proto_dissect_l3l4, rawsend, WinDivert OVERLAPPED, nl80211, COM |
| desync.c | 2242 | оркестрация: dp_match/dp_find, play_prolog, вызов lua-стратегий, ipcache, replay |
| protocol.c | 1248 | TLS-SNI, HTTP, **QUIC Initial decrypt** (HKDF, salts draft-22/23/29/q50/t50/t51/v1/v2), DNS, posmarker-DSL |
| pools.c | 1165 | uthash/kavl-пулы: hostlist/ipset-коллекции, ipcache IP↔hostname |
| helpers.c | 765 | хелперы, hex, маски |
| conntrack.c | 344 | conntrack + TCP-реассемблинг (в conntrack.h), Lua-ссылки в треке |
| ipset.c / hostlist.c | 330 | reload, поиск |
| params.c | 400 | логирование, профили |
| sec.c | 117 | seccomp (Linux only) |
| packet_queue.c | 88 | очередь delayed/replay |
| checksum.c, timer.c, gzip.c, filter.c, random.c | ~100 | мелкие |
| crypto/ | ~4k | SHA-2, AES, GCM/CTR, HKDF, HMAC — заменяются крейтами |
| andr/ | small | netlink/getifaddrs-шимы Android |

* **Платформенные слои**: Linux — NFQUEUE через **libnetfilter_queue**
  (-lnetfilter_queue -lnfnetlink -lmnl), не ручной netlink; Android — то же
  + шимы и -llog; BSD — divert-сокеты; Windows — **WinDivert** (библиотеки
  вкоммичены), собрано под **Cygwin**; Windows-сервис — win.c.
  epoll/kqueue нигде нет — цикл блокирующий recv.
* **Lua**: LuaJIT 2.1 по умолчанию (5.1 API), фолбэк lua5.x; ~4.5–5 тыс.
  строк в 6 файлах: zapret-lib (1421), zapret-antidpi (1300 — ВСЕ стратегии),
  zapret-tests (961), zapret-auto (530 — оркестраторы circular/stopif),
  zapret-obfs (411 — wgobfs/udp2icmp/ippxor/synhide), zapret-pcap (45).
  Архитектура: C сам НЕ влияет на трафик — только диссект/состояние/реконструк
  отдаются Lua, который решает всё.
* **Golden-инструментарий готов в самом репо**: zapret-tests.lua — селфтесты
  C-функций (dissect, csum, aes, aes-gcm, aes-ctr, hkdf, hash, gzip, bin,
  time, ipstr, resolve, ifaddrs, rawsend, timer, random) с зашитыми
  входами-выходами — идеальные parity-тесты ядра без сети;
  zapret-pcap.lua пишет живой трафик в pcap — корпус для дифф-тестов
  диссектора. Pcap-фикстур в репо нет.
* **CLI**: getopt_long_only + таблица ~90+ опций; конфиг через argv '@'/'$'
  + wordexp. Портить на clap.
* **Топ-сложные**: lua.c (4.7k) → nfqws.c → darkmagic.c → desync.c →
  protocol.c → pools.c.

## Уточнение этапов по инвентаризации

* Этап 1 (dissect/checksum) расширяется: proto_dissect_l3l4 живёт в
  darkmagic.c — вычленять именно оттуда; struct dissect (darkmagic.h).
* Этап 2 (protocol) подтверждён: QUIC-decrypt на готовых крейтах
  (aes-gcm/hkdf/sha2), salt-таблицы переносим дословно.
* Этап 3: Lua — **LuaJIT-режим mlua** (5.1 API совместимость), стратегии
  как есть; parity — прогон zapret-tests.lua над Rust-ядром.
* Этап 5: NFQUEUE — FFI к libnetfilter_queue (bindgen) вместо ручного
  netlink; WinDivert — windivert-sys; Android — тот же NFQUEUE + шимы
  andr/ + seccomp не переносить (sec.c — Linux only, на Android опционально).
* Крипто: SHA-2/AES/GCM/CTR/HKDF/HMAC — крейты (sha2, aes, aes-gcm,
  hkdf, hmac), parity через zapret-tests.lua.

## Следующий шаг (срез 1 порта)

1. Клонировать zapret2 локально, снять точный wc -l по модулям aj-14.
2. Крейт primecore-packet: dissect (из darkmagic.c proto_dissect_l3l4 +
   struct dissect), checksums, packet_queue — с parity-тестами, снятыми
   из lua/zapret-tests.lua (входы-выходы зашиты в самом скрипте).
3. Параллельно: golden-корпус пресетов из живой установки
   (winws1_builtin 307 / winws2_builtin 136 файлов) прогонять через
   primecore-profile-парсер — готовый набросанный вход до этапа 1.

nfqws2 — бинарники zapret2 v1.0.6 (MIT, bol-van)
Скопированы из релиза: github.com/bol-van/zapret2, тарбол zapret2-v1.0.6.tar.gz,
каталог binaries/. Все ELF статически слинкованы (musl), внешние библиотеки
не требуются. Версия подтверждена запуском: "github version v1.0.6, lua_compat_ver 6".

Состав каждого каталога <арх>:
  nfqws2  — ядро обхода (NFQUEUE, Lua-движок стратегий)
  mdig    — массовый DNS-резолвер (hostlist-auto, авто-списки)
  ip2net  — группировка IP в подсети (оптимизация списков)

Архитектуры: linux-x86_64, linux-x86, linux-arm64, linux-arm, linux-riscv64.
Полный набор (mips, ppc, lexra и др.) — в релизе zapret2.

Лицензия: MIT, см. docs/LICENSE.txt (Copyright 2016-2026 bol-van).
Примечание апстрима: бинари только в релизах, из исходников сборка описана
в docs/compile репозитория zapret2.

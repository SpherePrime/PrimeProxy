# Порядок переноса (continuation guide, не редактировать без нужды)

Осталось (diagnostics, по порядку): path_trace.py, filter_place.py, filter_habits.py, sections.py, engine.py.
Потом прочие пакеты: dns core (server_check, plans, dns_providers, commands), presets, orchestra, hostlist, block_check, engine Реестра.

path_trace.py:
- Hop(ttl, kind, address, rtt_ms), RouteTrace(target, hops, reached, supported), FilterFacts, FilterVerdict.
- Коды: FILTER_FOUND, NO_CONTROL, NOT_STATEFUL, NOT_ON_PATH, UNSURE, NO_DISTANCE, AT_TARGET.
- Транспорт — замыкания по образцу quic_probe.rs и reach.rs; HOP_* брать из icmp.rs.

sections.py — после path_trace; собрать чистые judge_* из готовых rust-модулей, транспорт и Run-статы — замыканиями.

engine.py — последним (Run/Stop/потоки;CbPhase и др. уже в run_context.rs).

Если при генерации файла замечены чужие символы (китайские глифы, обрывки) — НЕ коммитить, перегенерировать
начисто: известный дефект записи длинных блоков. Каждую правку проверять чтением файла.

Перед коммитом: cargo fmt --all; cargo clippy -p primecore-diagnostics --all-targets --all-features -- -D warnings;
cargo test -p primecore-diagnostics. Золотые тесты сверять с python-эталоном до правок кода.

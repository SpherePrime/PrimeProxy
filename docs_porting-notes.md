# Порядок переноса (continuation guide, не редактировать без нужды)

Осталось (diagnostics, по порядку): engine.py. sections.py перенесён целиком: чистые judge_* (dns_finding_parts, dns/speed/crowd_problems, emit_*, find_filter_place, check_filter_habits, name_speed_report, check_name_speed_report, check_crowd, check_speed, check_network, ask_outside, finish_dns_servers, tcp_reset_seen, dns_place_verdict); run-обёртки (environment_lines, zapret_status, routed_adapters, tools_line, download, upload, check_ipv6, clock_skew, check_system, live_services, check_subnets, check_udp_burst, check_name_speed, start_registry, _dns_provider) остаются в engine-этапе — они держат Run.
Потом прочие пакеты: dns core (server_check, plans, dns_providers, commands), presets, orchestra, hostlist, block_check, engine Реестра.

path_trace.py:
- Hop(ttl, kind, address, rtt_ms), RouteTrace(target, hops, reached, supported), FilterFacts, FilterVerdict.
- Коды: FILTER_FOUND, NO_CONTROL, NOT_STATEFUL, NOT_ON_PATH, UNSURE, NO_DISTANCE, AT_TARGET.
- Транспорт — замыкания по образцу quic_probe.rs и reach.rs; HOP_* брать из icmp.rs.

sections.py — перенесён (commit 0a5b542). Данные движка — замыканиями: pair_of(method, ip, host, name, ttl), connects(ip, ttl), owner_of, traced(ip), dns_ask; HabitSend для habits; resting/rests — &dyn Fn(f64). ask_outside возвращает список (сервис, сайт, ответ) — движок сам правит probe.outside (в python — мутация).

engine.py — последним (Run/Stop/потоки;CbPhase и др. уже в run_context.rs).
Перед ним — два пласта-подготовки:
1) report_text.py-сборщики отчётных словарей (target_report, section_lines/section_report, service_status, service_roads, service_tags, services_report, voice_report, freeze_report, telegram_report, system_report, STEP_TITLES) — чистые, тест золотом;
2) run_context.py-машина (Steps, Live, Lane, Run: пул, дедлайн, «Стоп», note_reference/reference_report, later/start_stages, wait/close) — std::thread + mpsc; Future заменён handle-каналами; задачи возвращают Result<T, Box<dyn Error>>; Stopped — отдельная ошибка движка.

Если при генерации файла замечены чужие символы (китайские глифы, обрывки) — НЕ коммитить, перегенерировать
начисто: известный дефект записи длинных блоков. Каждую правку проверять чтением файла.

Перед коммитом: cargo fmt --all; cargo clippy -p primecore-diagnostics --all-targets --all-features -- -D warnings;
cargo test -p primecore-diagnostics. Золотые тесты сверять с python-эталоном до правок кода.

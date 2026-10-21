# Порядок переноса (continuation guide, не редактировать без нужды)

diagnostics перенесены ЦЕЛИКОМ, включая engine.py (Run/Lane/Live/Steps, run_probes/recheck_failed, run_blockcheck/run_dns_check/check_site), сетевой транспорт без TLS — net_transport.rs (TCP/STUN/UDP-серии + планировщики + транспорты под EngineIo; golden STUN/шапки + живые локальные тесты) — и TLS/HTTPS-слой: chrome_https.rs дополнен транспортом ChromeConnection/chrome_get на rustls (заголовки WINDOWS_HEADERS, HTTP/1.1 keep-alive, ошибки → коды libcurl, decode_body: gzip/deflate; golden `_classify`/`_cert_problem` против python, 23 случая, + живые локальные тесты — tests/chrome_https_tests.rs). Отпечаток приветствия rustls браузерный не повторяет (python — curl_cffi/BoringSSL): осознанное различие, выводы опираются только на KIND_*/STAGE_*/body_cut. Провайдер шифрования — ring, выбирается явно (иначе rustls падает при неоднозначности ring/aws-lc-rs; ring проще для Windows-сборки). Дымовой тест tests/engine_smoke.rs гоняет полный прогон на подставном транспорте; живой сбор — tests/net_transport_tests.rs на локальных сокетах. Осталось за cert_owner/clock_skew/network_check/freeze-транспортом поверх chrome_get, volume/cause и protocol_probe-транспортом — замыкания EngineIo ждут их. QUIC-слой готов: quic_initial.rs (AES-128/GCM/HKDF руками, golden против python с подменой os.urandom — пакет целиком для 5 имён) + quic_probe::quic_hello (UDP с отменой) + net_transport::quic_collect_with/quic_transport (python collect с параллельными посылками через Run); живые тесты на подставном QUIC-сервере — tests/quic_probe_tests.rs. OS-слой Windows — платформенный (SystemReader-трейт с NullSystemReader для не-Windows). Было: sections.py перенесён целиком: чистые judge_* (dns_finding_parts, dns/speed/crowd_problems, emit_*, find_filter_place, check_filter_habits, name_speed_report, check_name_speed_report, check_crowd, check_speed, check_network, ask_outside, finish_dns_servers, tcp_reset_seen, dns_place_verdict); run-обёртки (environment_lines, zapret_status, routed_adapters, tools_line, download, upload, check_ipv6, clock_skew, check_system, live_services, check_subnets, check_udp_burst, check_name_speed, start_registry, _dns_provider) остаются в engine-этапе — они держат Run.
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

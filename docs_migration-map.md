# Карта переезда Python → Rust

Здесь перечислено, что уже переехало, что переехало с оговоркой и что
осталось в основной программе.

## 1. Переехало (primecore-*, тесты на живых фикстурах)

| Python | Rust | Особенности |
|---|---|---|
| `src/updater/versions.py` | `primecore-versions` | только ASCII-цифры через точку; `version_key` → Vec<u64> |
| `src/primebypass_update/manifest.py` + `signed.py` | `primecore-manifest` | сериализация байт-в-байт с production (sort_keys+indent+\\n); `PRODUCT="primebypass"`, LEGACY `"zapret-gui"` — данные прошлого |
| `src/primebypass_update/bsdiff.py` | `primecore-patch` | ванильный контракт: `out[new++] = old[old] + diff; old += copy + seek;` diff/extra — MultiBzDecoder |
| `src/hosts/hosts.py` (чистая логика) | `primecore-hosts` | маркеры блока `primebypass:hosts`; LEGACY `primeproxy:`/`zapretgui:`; MAX-маркеры всех эпох; Telegram-блок без конца |
| `src/primebypass_update/release/*` (каналы, Telegram, resolver, зеркала) | `primecore-release` | гонка через std::thread+mpsc, руки передаются замыканиями |
| маршрутизатор HTTP | `primecore-server` | axum; ручки версий/hosts/патча/манифеста; `/api/check` — живой Forgejo |

Имена, которые не переименовываются (данные сервера и прошлого):

* `git.zapret.moe`, репозиторий `zapretdiscordyoutube/zapretgui` — адрес
  живых выпусков;
* `Zapret2Setup*.exe`, `Zapret2Setup_DEV_21_1_7_181.exe` — установщики,
  уже разосланные подписанными релизами;
* ключи `gui-2026a`/`gui-reserve-1` — идентификаторы ключей внутри
  манифестов;
* каналы Telegram `zapretnetdiscordyoutube`/`zapretguidev`;
* LEGACY-маркеры hosts и LEGACY_PRODUCT `"zapret-gui"`;
* имена payload-файлов внутри манифеста (`lua/zapret-*.lua` и др.) —
  серверные пути, меняются только на сервере.

## 2. Осталось в основной программе (осознанно, не переносится)

* PyQt6-интерфейс, сплэш, трей (Python door);
* командные утилиты Windows (`icacls`,
  `runas`, AI-клиенты) — директ OS-код;
* каталог сервисов/IP-профилей (`proxy_domains`, `adobe_domains`);
* проверка посредников (`relay_check`), IPv6-зонд (ctypes/socket);
* конфиг сборки (`_build_secrets.py`: UPDATE_SERVERS, ключи).

## 3. Роли дверей

| дверь | интерактив | ядро |
|---|---|---|
| Now (Python) | PyQt6 | та же логика в Python |
| Electron (next/app-shell) | Vite React UI | sidecar primecore-server |
| Linux/Docker (next/docker) | без окна, HTTP | primecore-server |
| Android (next/android) | WebView (та же Vite-сборка) | UniFFI из тех же крейтов |

## 4. Ограничения текущей заготовки

* `/api/patch/apply` принимает old+patch (base64) — подкачивание
  больших файлов через HTTP не оптимизировано (меняется на потоковые
  endpoints при переносе пользователя в Electron);
* зеркала/opt-out сервера (`VPS_SERVERS`) сейчас читаются из env
  `PRIMEBYPASS_MIRROR_SERVERS`; в билде — заменить на compile-time
  конфиг сборки;
* `primecore-server` пока не поднимает ни спуска всех
  файлов-изменений, ни скачивания установщика: только проверку и
  манифесты;
* `/api/dns/server_check` — живой прогон вкладки «DNS-серверы» по HTTP
  (готово); `/api/dns/domain_lookup` отвечает 501 — живой сборщик
  LookupIo ещё не подключён;
* интерфейс: каркас next/app-shell (Electron + Vite React, страница
  «Настройка DNS» 1:1 по python-текстам) и next/android (Capacitor,
  та же dist-сборка); Windows-секции страницы скрыты до платформенного
  слоя;
* привилегии Linux: крейт primecore-privilege — sudo/pkexec один раз
  при первом запуске, демон privd держит права, дальше сокет без
  пароля (docs_linux-privileges.md).

## Перенесено в Rust (готово)

| Python-эталон | Rust-крейт / модуль | Паритет |
|---|---|---|
| settings/mode.py + core/paths.py | primecore-mode | golden (7) |
| settings/normalize.py (скаляры) | primecore-settings/src/normalize.rs | golden (10) |
| settings/schema.py + folders/defaults.py | primecore-settings/src/schema.rs | golden canonical |
| settings/normalize.py (секции) | primecore-settings/src/app_settings.rs | golden (4: default/noisy/garbage/empty) |
| settings/store.py (ядро sqlite: прагмы, схема, секции, ревизия) | primecore-settings/src/store.rs | кросс-язык: py→rust и rust→py, fresh-init |
| utils/dns_wire.py (кодек: encode/parse/reverse/failure_text/forged_denial + UDP/TCP-транспорт + query_server) | primecore-dnswire | golden (9) + mock-тесты UDP/TCP (10); mock-DNS против живого python не гоняли; DoT (rustls) и DoH (reqwest) — только компиляция, живая сеть недоступна |

| utils/socket_cancel.py | primecore-socketcancel | «Стоп» без unsafe: poll-отрезки вместо закрытия сокета из потока; отзыв до узла в пределах отрезка 200 мс |

| utils/net_failure.py | primecore-netfailure | errno/winerror-таблицы; classify по классам — по io::ErrorKind; золотые errno Linux |

| profile/models.py (структуры, логические ключи) + profile/winws2.py (парсер --lua-desync) | primecore-profile | golden (3) |
| profile/winws1.py + profile/parser.py (разбор пресетов: шапка/preamble/профили/хвост, match-корзины, подписи, ключи персистентности, оглавление) | primecore-profile | golden_parser (2); outlines сравнены поиндексно |
| profile/strategy_shape.py (форма стратегии winws2: составная/ветки/payload-scopes, значок пакетов) | primecore-profile/src/strategy_shape.rs | golden_shape (1, 8 кейсов); используется serializer-ом |
| profile/strategy_visuals.py (значок стратегии: ключи способов, метка, описание, простые слова) | primecore-profile/src/strategy_visuals.rs | внутри golden_catalog (3 теста: 8 визуалов + подписи) |
| profile/strategy_catalog.py (каталоги на диске: разбор файлов, фильтры профиля/веток, кэш, подпись дерева) | primecore-profile/src/strategy_catalog.rs | golden_catalog (3): alpha 4 записи + beta отбросы, визуалы из 8 примеров |
| profile/strategy_state.py (отметки/избранное/открытая группа/группировка/миграция ключей в settings базе) | primecore-profile/src/strategy_state.rs | golden_state (1, 19 операций python построчно + итоговая секция)
| profile/strategy_list/facts.py (сведения о стратегиях: series/source/family_key/plain_label/payload_badge/search_text) | primecore-profile/src/strategy_facts.rs | внутри golden_plan (facts сравнены с python целиком)
| profile/strategy_list/plan.py (build_plan: группы/подзаголовки/сортировugg/priority, twins, очереди recommended/full/catalog, family_scores, next_to_try/try_progress/try_stage, бейджи/подписи/подсказки) | primecore-profile/src/strategy_plan.rs | golden_plan (4 теста: facts-паритет, бейджи/подписи, очереди, 10 сценариев build_plan + tab_count/try_stage/next_to_try); весь workspace — 147 тестов green |
| profile/strategy_list/rows.py (visible_rows: заголовки групп/секции/стратегии, twin-наборы, default_open_group) | primecore-profile/src/strategy_plan.rs (та же секция) | golden_rows (3 теста: 5 раскрывающих случаев + shown-подписи + default_open) |
| profile/strategy_list/knowledge.py (объяснение шагов стратегии простыми словами: StepNote/StrategyStep, функции/защиты/блобы/положения, explain_strategy) | primecore-profile/src/strategy_knowledge.rs | golden_knowledge (4 теста: 22 набора аргументов × обычный/udp, все защиты разом, position_words, методы плиток) |
| profile/serializer.py (serialize_preset + with_enabled/strategy_lines/whole/ready/user_match/deleted/duplicated/moved/raw_text/append_profile_from_template, копии имён, границы) | primecore-profile/src/serializer.rs | golden_serializer (3 теста, 29 шагов золота: операции + ошибки + winws1); весь workspace — 138 тестов green |
| profile/match_filters.py (l7_transport, каталог из match-строк, метки протокола/портов, filter_values, voice/http80) | primecore-profile/src/match_filters.rs | golden_match_filters (3 теста) |
| profile/winws2_transport.py (OutRangeSettings, payload-имена, normalize/parse/validate out-range) | primecore-profile/src/winws2_transport.rs | golden_winws2_transport (3 теста) |
| profile/editable_settings.py (читаемые настройки профиля: тип/значение/роль/диапазоны; with_editable_profile_settings: правка фильтра и диапазонов до первой --lua-desync; canonical через parse_out_range_expression; new_profile_insert_index; списки из сервисных исключений) | primecore-profile/src/editable_settings.rs | golden_editable (7 тестов: чтение/диапазоны, normalize/file_reference, исходный пресет, 2 правки+вставки, роль exclude, 5 сообщений об ошибках); с подсветкой ошибок python (byte-for-byte строки). Весь workspace — 167 тестов green |
| pathlib.PureWindowsPath (имя/родитель/суффиксы/stem, разбор диск/UNC/корень) + lists/core/layered_files.py (проверка слоёв base/user/final, безопасные имена файлов Windows) | primecore-lists/src/{winpath.rs,layered.rs} | golden_winpath (28 случаев python построчно: имя/родитель/суффиксы/stem);полный полный слой списков (reconcile/снимки владения) переносится позже |
| profile/filter_switch.py (кандидат/разрешение hostlist↔ipset: paired-значения ipset-all↔other, exclude-пару переключать нельзя; проверка файлов списков; запрет дублей match-сигнатур в пресете близнецов) | primecore-profile/src/filter_switch.rs | golden_filter_switch (4 теста: кандидаты/разрешения 4 профилей, дубли plain+twin, доступные типы, 11 спец-случаев); Весь workspace — 173 теста green |
| profile/stock_names.py (прежние стоковые имена → нынешние, показу ByCasefold) + profile/list_interpreter.py (строки списка профилей: пресет+шаблоны, объединение по логическим ключам, выбор источника группы, показ имени по-нынешнему, user-ключи шаблонов) | primecore-profile/src/{stock_names.rs,list_interpreter.rs} | golden_list_interpreter (6 сценариев: plain/dedup/templates_only/dup_enabled/user_template/fallback); Весь workspace — 174 теста green |
| profile/derived_cache.py (ядро профиля из текста и каталогов: стратегия по identity/composite, вид списка, подпись совпадений, доступные виды фильтров; LRU 512 с отпечатком папки lists (TTL 0.5 с) и PresetSourcesCache по ревизии) | primecore-profile/src/derived_cache.rs | golden_derived_cache (ядра 10 сценариев: простое/своё/none/составное/winws1/исключения по имени/сырой текст; LRU-вытеснение limit=2, переименование на том же сыром тексте, TTL отпечатка списков, sources пресета); Весь workspace — 175 тестов green |
| profile/strategy_usage.py (частоты готовых стратегий в готовых пресетах: по сервису/каталогу, _CatalogIndex на словарях, load по подписи дерева) | primecore-profile/src/strategy_usage.rs | golden_strategy_usage (winws2/winws1 подсчёты, places-сортировки, for_profile с каталогом, неоднозначные/multi/composite-индексы, load: кэш + пересчёт после удаления файла); Весь workspace — 176 тестов green |
| profile/conditions_text.py (условия профиля словами: фраза по диапазону -d8/a/x, range_hint, match_label, conditions_summary шапки) | primecore-profile/src/conditions_text.rs | golden_conditions_text (18 range_phrase, 11 range_hint, 4 сводки шапки tcp/udp/без условий/http); Весь workspace — 177 тестов green |
| profile/identity.py (sidecar-реестр uid ↔ последнее имя/сигнатура: normalize_registry, resolve_profile_identities 4 правила в порядке силы, генерация uuid4-подобного uid; порядок реестра — порядок вставки) | primecore-profile/src/identity.rs | golden_identity (9 сценариев: exact/renamed/edit_match/new/empty_pair/two_same_sig/clash/mixed/cleanup + нормализация мусорного реестра); Весь workspace — 178 тестов green |

| diagnostics/verdict.py (перечни Level/ReachState/DnsState/Verdict/PingAnsi, judgements: приговор, нагрузка, протоколы, DNS-сигнатуры, статусы отсылки, гистерезис) | primecore-diagnostics/src/verdict.rs | verdict_golden (34 сценария), goldый ping-ANSI; Default через ReachState::Unknown |
| diagnostics/{subnet_catalog,subnet_whitelist,cert_owner,quic_probe,ipv6_check,outside_check,telegram_check,volume_probe,udp_burst,protocol_probe,windows_dns_query,block_cause,run_context(.probe),system_state(чист.),problems,report_text(базa)} | primecore-diagnostics | проблемный класт: 42 теста green + golden_collect_problems |
| diagnostics/problems.py (collect_problems: полный join вердиктов/проб/системых/Telegram, 22 сценария python — byte-for-byte) | primecore-diagnostics/src/problems.rs + tests/problems_golden.rs | golden_collect_problems (22 scenario, burst+reference riêng) |

### Перенесено в Rust — diagnostics (кластер целиком, продолжение)

| Python-эталон | Rust-модуль | Паритет |
|---|---|---|
| diagnostics/{history,compare,report_contract,report_upgrade,self_check,rule_passports,limits,levels,block_kind,address_kinds,icmp,services} | primecore-diagnostics/src/*.rs | свои тесты, зелёные |
| diagnostics/{cert_owner,ip_owner,my_network,dns_reference,chrome_https,browser_hello,tls_probe,reach,net_access} | primecore-diagnostics/src/*.rs | замыкания-транспорты; сеть — живьём не гонялась |
| diagnostics/{quic_probe,udp_burst,volume_probe,upload_probe,protocol_probe,block_cause,block_kind} | primecore-diagnostics/src/*.rs | транспорта не требуют или замыкания |
| diagnostics/{freeze_check,voice_check,telegram_check,ipv6_check,crowd_probe,speed_check,name_speed,system_state,registry,outside_check} | primecore-diagnostics/src/*.rs | чистая часть; Run-обёртки в engine-этапе |
| diagnostics/{dns_place,path_trace,filter_habits,filter_place} | primecore-diagnostics/src/{dns_place,path_trace,filter_habits,filter_place}.rs | TtlAsk/PairOf/HabitSend — замыкания; cuts-as-set дедуп; Counter-ничьи — stable sort |
| diagnostics/sections.py (чистая часть: dns_finding_parts, finish_dns_servers, dns/speed/crowd_problems, emit_freeze/telegram/system/network/voice, dns_place_verdict, find_filter_place, check_filter_habits, name_speed_report/check_name_speed_report, check_crowd, check_speed, check_network, ask_outside, tcp_reset_seen) | primecore-diagnostics/src/sections.rs (commit 0a5b542) | 10 тестов; данные движка идут замыканиями: pair_of(method,ip,host,name,ttl), connects(ip,ttl), owner_of, traced, dns_ask; ask_outside возвращает список (сервис,сайт,ответ) — движок сам правит probe.outside |

Критичные мосты sections.rs (использовать при переносе engine.py):

* `finish_dns_servers(waited: Result<Value, String>, emit)` — вместо `run.wait`;
* `Problem.parts: Option<Value>` — title/servers/note из находок DNS;
* советы Zapret в speed/crowd_problems зависят от `zapret_running == Some(false)` → `start_zapret`;
* `find_filter_place` — данные от движка только замыканиями (`PairOf`, `connects`, `OwnerOf`, `traced`, `TtlAsk`);
* `check_filter_habits`: break внутри habits; spare-blocked merge; resting/rests — `&dyn Fn(f64)`;
* `name_speed_report`: `known(SERVER_HOST)` до скачиваний; `fetches(ip, name)`;
* `dedup`/`round_fps` — банк-округление (`report_text::py_round0`);
* `check_crowd` — отложенный замер left-vs-`CROWD_RESERVE_S`;
* `check_speed` — строки и имена только при `collected && services`;
* `ask_outside` возвращает список `(сервис, сайт, ответ)`; правка `probe.outside` — на движке.

| report_text.py-сборщики отчётных словарей (target_report, section_report, service_status, service_roads, service_tags, services_report, voice/freeze/telegram/system_report, step_title) | primecore-diagnostics/src/report_text.rs + tests/report_golden.rs (10148db) | golden_report_builders: 7 сценариев python byte-for-byte; round(x,1) — верное округление точного значения (format+parse), не масштабный трюк |
| run_context.py-машина (Steps, Live, Lane, Run: пул, дедлайн, «Стоп», note_reference/reference_report, later/start_stages, wait/close) | primecore-diagnostics/src/run_context.rs (a4b447a) | 10 тестов; Future — Handle с каналом и Any-упаковкой; TaskError {Stopped, Cancelled, Failed}; python-текст RuntimeError пула сохранён |
| engine.py (merge_dns_answers, service_verdict, with_section_problems, add_name_speed, has_spoofing, fresh_live_data; _discover_googlevideo, _probe_target/_probe_host, _start_quic/_start_protocols, _refine_cause, _check_volume; _run_probes, _recheck_failed; _announce; run_blockcheck, check_site, run_dns_check) | primecore-diagnostics/src/engine.rs (02fd524, далее) | чистые функции — тесты; оркестрация — дымовой тест tests/engine_smoke.rs на подставном транспорте (полный прогон без сети и без взаимных блокировок); транспорт и несобранные collect'ы — замыканиями EngineIo |

Сетевой транспорт — net_transport.rs (собран и протестирован):

* TCP: `tcp_connect` (исходы Connected/Refused/TimedOut/Unreachable/Cancelled), поверх него — python-контракты `telegram_connect` ((соединился, мс)/(None,None)), `subnet_reachable` (соединение или RST = дошёл), `self_check_now` (тревога только при «установившемся»);
* STUN (RFC 5389): `build_stun_request` (20 случайных байт — никаких данных о пользователе), `parse_stun_response` (+XOR/MAPPED, IPv4/IPv6) — golden против python; `test_stun` с повторами и бюджетом, коды те же (OK/TIMEOUT/RESET/UNREACHABLE/PARSE_ERR/DNS_ERR/CANCELLED);
* UDP-серия: `send_burst` — 30 запросов с одного сокета, ответ по номеру транзакции; заморозка видна обрывом ответов;
* планировщики на машине прогона: `check_voice` (STUN_TARGETS из voice_check), `check_bursts` (серверы разом, серии по очереди), `check_telegram` (повтор после паузы), `collect_groups` (залп в net_lane + повтор закрытых);
* готовые транспорты под поля EngineIo: `voice_transport`, `burst_transport`, `telegram_transport`, `subnets_transport`, `system_transport(reader)`; `SystemReader` — трейт Windows-чтений (реестр/WMI), `NullSystemReader` — поведение python на не-Windows; `collect_facts` повторяет `sys.platform != "win32"`-ветку;
* чистые форматтеры sections: `environment_lines(servers, provider_of)` (строка Windows — у платформенного слоя) и `tools_line(other, in_path, kind_of)` — golden против python (monkeypatch net_access/bypass_tools);
* тесты: tests/net_transport_tests.rs — 23 (golden STUN/шапка + живые TCP/UDP против локальных подставных серверов, включая имитацию заморозки UDP и переподключение Telegram).

TLS/HTTPS-слой — chrome_https.rs (транспорт собран и протестирован):

* классификация исхода `_classify`/`_cert_problem` — дословный порт, golden против python (18 сценариев classify + 5 cert_problem: коды libcurl, вид сбоя системы, что успело прийти; cancelled перекрывает всё, кроме полного ответа);
* транспорт `ChromeConnection`/`chrome_get` на rustls (в python — curl_cffi chrome150): те же заголовки WINDOWS_HEADERS, IP задаётся явно (SNI и Host — имя сайта), HTTP/1.1 keep-alive, отменяемость между отрезками 0.2 с, лимиты как у libcurl (timeout на подключение/рукопожатие, read_timeout на замирание — `body_cut`, timeout+60 на весь запрос);
* отображение ошибок rustls/ОС в коды libcurl: обрыв чтения → E_RECV(56), тишина → E_TIMEOUT(28)/E_GOT_NOTHING(52), недокачанное тело → E_PARTIAL_FILE(18), проверка сертификата → E_PEER_VERIFY(60) с текстами словами libcurl (от них cert_problem узнаёт причину), прочий рукопожатийный сбой → E_SSL_CONNECT(35), сбой записи → E_WRITE_ERROR(23);
* распаковка при decode_body: gzip/deflate (flate2); br/zstd в Rust остаются сжатыми — различие с python отмечено (нужно только разовое чтение страницы движком, исходы проб не зависят);
* отпечаток приветствия rustls браузерный не повторяет (python даёт это через curl_cffi/BoringSSL) — осознанное различие: выводы опираются только на KIND_*/STAGE_*/body_cut;
* провайдер шифрования — ring, выбирается явно (в графе бывает включён и aws-lc-rs, тогда rustls сам не выбирает; ring не требует cmake/NASM при сборке под Windows);
* корни сертификатов — webpki-roots (аналог certifi: и BoringSSL, и rustls хранилище Windows не читают);
* тесты: tests/chrome_https_tests.rs — golden 23 случая + живые локальные (полный ответ, обрыв «хватит», chunked + keep-alive, замирание тела → body_cut, обрыв тела, ответа нет, «Стоп» посреди тела, отказ соединения, тишина рукопожатия → timeout, самодельный сертификат → cert).

QUIC-слой — quic_initial.rs + quic_probe.rs (собран и протестирован):

* `quic_initial.rs` — дословный порт `utils/quic_initial.py`: свой AES-128 (S-блок вычисляется, как в python), AES-128-GCM, HMAC-SHA256 без внешних зависимостей, ключи Initial по RFC 9001 (соль + HKDF-метки), приветствие TLS 1.3 с SNI (ASCII — как есть, как у python `encode("idna")`; не-ASCII — punycode через idna) и защита заголовка; `is_reply_to` — любой ответ на наше соединение;
* golden против python с подменой `os.urandom` (пакет целиком для 5 имён, включая punycode, ключи, GCM, распознавание ответа) — tests/quic_initial_tests.rs + tests/quic_initial_golden.json;
* `quic_probe::quic_hello` — UDP-отправка пакета Initial с отменой между отрезками 0.2 с; `net_transport::quic_collect_with` — python `collect`: настоящее имя, при молчании параллельно постороннее и без имени (через машину прогона), затем настоящее имя ещё раз; `quic_transport()` — готовое замыкание QuicCollect;
* живые тесты на подставном QUIC-сервере (локальный UDP): ответ услышан, тишина, «Стоп», «блокируется по имени» (настоящее имя молчит дважды, постороннее проходит), полная тишина — не блокировка.

Приватность (как в python): пробы шлют только сами запросы — SYN без данных, STUN из случайных байт, DNS-вопрос об имени сервера; ответы выбрасываются, ничего не сохраняется и не уходит на серверы проекта. Единственная передача данных — необязательная «Сверить с сервером в Нидерландах» (ask_outside, по галочке, только имена неоткрывшихся сайтов).

Причины и дороги — блок завершён (транспорты поверх rustls и Chrome-соединений):

* `block_cause.rs` — транспорт: `NoVerify` (verifier без проверки — python `CERT_NONE`), `hello_config(version)` (ANY/TLS12/TLS13, ALPN http/1.1, ring), `tls_hello`/`tls_stream` (TcpStream + `complete_io` с 0.2 с-отрезками; `tls_stream` отдаёт установленное соединение — им пользуется cert_owner), `hello_failure` (классификация rustls::Error по тексту → ALERT/GARBAGE/ERROR/RESET), `http_probe`+`parse_http_facts` (порт 80: статус, Location, распознавание заглушки), `later_hello` (отложенная проба), `collect` — пробы через машину прогона (`run.submit`/`run.wait`) с шагом STAGGER_S; `HelloResult::with_ms`;
* `protocol_probe.rs` — `timed_http`, `collect`/`collect_with_port`: TLS 1.2, TLS 1.3 и порт 80 по тому же адресу, пробы по очереди с шагом;
* `volume_probe.rs` — `download`/`collect`/`collect_with_port`: запросы подряд по одному Chrome-соединению (`ChromeConnection::request` с `enough`-замыканием), счёт байт на проводе, reconnected → счёт по прежнему соединению кончился; оценка раннего выхода после ESTIMATE_AFTER;
* `cert_reader.rs` — дословный порт `utils/cert_reader.py`: ручной DER-парсер (`item`/`items` — BER-длина 1–4 байта), `text` (BMPString 0x1E → UTF-16 BE с заменами), `name` (CN/O по OID 550403/55040a), `alt_names` (OID 551d11, DNS-тег 0x82, дедуп с сохранением порядка), `read_names(der)`; юнит-тесты на настоящих rcgen-сертификатах (subject/O/SAN/издатель, битые и обрезанные DER);
* `cert_owner.rs` — транспорт `collect`/`collect_with_port`: TLS без проверки к ip:443 (`tls_stream` ANY), DER из `peer_certificates()[0]`, поверх — `read_names`; `CertCollect` возвращает `Option<CertNames>` (None — получить не удалось, как у python);
* `engine.rs` — типы `ProtocolsCollect`/`CauseCollect`/`VolumeCollect`/`CertCollect` обновлены; call sites (start_protocols, refine_cause, check_volume) передают `run`/`ping` как в python;
* `net_transport.rs` — фабрики `cause_transport()`, `protocols_transport()`, `volume_transport()`, `cert_transport()`, `chrome_get_transport(cancel)` (общий на прогон `chrome_get`), `clock_skew_transport` (python `sections.clock_skew`: DoH-адреса www.google.com → `/generate_204` → заголовок `Date`; `http_date_timestamp` — свой разбор RFC 1123 с проверкой дня по длине месяца, эталоны против python `parsedate_to_datetime`), `network_transport` (python `sections.check_network`: /cdn-cgi/trace по 1.1.1.1/1.0.0.1, владелец сети шифрованным вопросом к эталону, `my_network::local_address` — UDP-сокет без пакетов), `freeze_transport` (python `check_freeze`+`sections.download`: 64 КБ с FREEZE_READ_TIMEOUT, кэш адресов на прогон, опциональная отправка); `system_transport(reader, clock_skew)` — расхождение часов приходит замыканием;
* тесты: tests/block_cause_tests.rs (11 живых: локальный rustls-сервер с rcgen-сертификатом, RESET/GARBAGE/CONNECT/TIMEOUT/CANCELLED, pin TLS 1.2/1.3, collect с пингом, protocol_probe три дороги), юнит-тесты volume_probe (объём по одному соединению, закрытие сервером = reset по коду 52, «Стоп», повтор при замирании в окне), юнит-тесты cert_reader/cert_owner (живой TLS-сервер: имена читаются без проверки; refused → None), юнит-тесты net_transport (разбор Date против python, високосные 2000/2024 против 1900).

Приватность (как в python): пробы шлют только сами запросы — SYN без данных, STUN из случайных байт, DNS-вопрос об имени сервера; ответы выбрасываются, ничего не сохраняется и не уходит на серверы проекта. Единственная передача данных — необязательная «Сверить с сервером в Нидерландах» (ask_outside, по галочке, только имена неоткрывшихся сайтов).

Начат пакет dns → новый крейт primecore-dns (срез 1, чистая логика; UI dns/ui в Rust не переносится — PyQt6 остаётся в Python-части):

* `local_proxy_catalog.rs` — режимы движка dnscrypt-proxy (MODE_*, Upstream), списки штампов DNSCrypt/relays/ODoH дословно из python, `doh_stamp` (base64url, IDNA-имя, props DNSSEC) — golden против python doh_stamp (3 штампа байт-в-байт), `doh_upstreams`/`servers`/`relays`/`routes` (Quad9 не анонимизируется, посредник другого владельца);
* `providers.rs` — DNS_PROVIDERS встроенным JSON с сохранённым порядком (preserve_order), iter/network_providers (режимы выброшены), is_encrypted_only, proxy_mode_for (Windows 10 → через движок), proxy_upstreams, find_provider_by_address, doh_templates, catalog_problems (адрес/уникальность/DoH-https/dot/статус — проверка проходит на живом списке), OUTDATED_DNS_ADDRESS_REPLACEMENTS; свой валидатор IPv6 (группы, «::», IPv4-хвост) — батарея против python ip_address (18 случаев);
* `custom_servers.rs` — правила «Своего DNS»: parse_doh_template (https-only, плейсхолдер {?dns}, IPv6 в скобках, имя из цифр = недописанный IP), split_addresses/split_pasted, read_form (имя из DoH-хоста или первого адреса, ошибки с полем), upsert/remove/duplicate (уникальность названий case-insensitive), addresses/clipboard_text, build_dns_providers_with_custom, custom_doh_templates; записи — serde_json Value, как у python-словарей;
* `adapters.rs` — DnsAdapter/RawInterface/InternetRoute/StaticDns (типы winapi.py без самих вызовов) + is_dns_adapter (признаки hardware/connector/filter, интернет-индексы) + build_dns_adapters с сортировкой «интернет, подключённые, имя»;
* `state.rs` — LineCheck/DnsState/DnsCommandResult/CustomServerResult;
* проверки линии: `interception.rs` (канарейка 192.0.2.53), `reachability.rs` (check_servers: IPv4, IPv6 только без IPv4; UDP+TCP+DoH; doh_closed; is_local), `latency.rs` (лучшая из попыток, дедуп серверов), `answering.rs` (whoami.akamai.net → владелец Cymru шифрованным путём → канарейка; short_owner «CLOUDFLARENET - Cloudflare, Inc., US» → «Cloudflare») — транспорты замыканиями над primecore_dnswire, живой тест канарейки (TEST-NET-1 не маршрутизируется).

34 теста крейта. Далее в dns: server_check.py (1095) + server_check_plans/verdict, domain_lookup.py (1422) + plans, dns_providers-commands (commands.py 495), doh_lookup.py, page_plans/page_workers, local_proxy.py+config+windows, winapi-слой, address_migration, line_check (нужен settings-слой), dns_check_plans, workers-сшивка. Осталось: block_check (4340), presets (8310), orchestra (5923). В freeze_transport отправка пока не подключена (нужен транспорт http2_post/utils.http2_post.py).

| telegram_proxy (14 565 строк: MTProxy-прокси, socks5/wss, fake-tls/obfs/aes-ctr, key-clusters, route-catalog, dc-map, cloudflare, config-настройки, hosts, logger, diagnostics, manager, runtime) | primecore-telegram | 260 тестов green (чистая логика; сетевые действия — замыкания/трейты); clippy чист |
| привилегии Linux (sudo/pkexec один раз → демон privd → unix-сокет) | primecore-privilege (lib.rs, client.rs, bin/privd.rs) | docs_linux-privileges.md; живой прогон демона не гонялся |
| log (чистая часть): log_kinds (fnmatch-совместимый glob с диапазонами), cleanup_old_logs (лимиты 50/20/10/200), crash (формат отчёта и имя файла) | primecore-log | 8 тестов, значения сверены с python; qt/stdio-слой остаётся у вызывающего |
| winws_log_analyzer (чистая часть): parser (конечный автомат: преамбула → пакетные блоки, head/tail-хранение 200/200k), models, filters | primecore-log-analyzer | 10 тестов, синтетический эталонный лог сверён с python-парсером байт-в-байт; qt-воркер и чтение файла — у вызывающего |
| utils/http2_post.py (один POST по HTTP/2: приветствие, HPACK-заголовки без словаря, чтение кадров; read_status чистый) | primecore-http2 | 12 тестов: статусы (готовые/текст/сжатые/словарь), обмен над UnixStream-pair против python-тестов 1:1; сокет — трейт Http2Socket |
| utils/probe_gate.py (шлюз проб: пропуск на прогон по кнопке, одна фоновая проверка за раз, интервалы из настроек) | primecore-diagnostics/src/probe_gate.rs | 7 тестов (python test_probe_gate.py портирован; глобальное состояние — Mutex, user_run — страж с Drop) |
| utils/circular_strategy_numbering.py (перенумерация :strategy=N после circular/circular_quality; сброс на --new/--payload-группах) | primecore-orchestra/src/numbering.rs (начало крейта) | 8 тестов, эталоны сняты с python; re.split с lookaround реализован вручную |
| config/urls.py (адреса документации, статьи онбординга) + config/telegram_links.py (пары tg:///https://, метки start) | primecore-config | 5 тестов; winreg/webbrowser — у вызывающего |
| utils/atomic_text.py (atomic_write_text с повторами os.replace; decode_preset_bytes UTF-8-BOM/cp1251 — эвристика не-ASCII) | primecore-files | 8 тестов во временной папке + golden-декод против python; cp1251-таблица снята с кодека python |
| winws_runtime (срез 1): health/winws_output, windivert_diagnostics (17 Win32-кодов), winws_exit_diagnosis + silent_exit_probe (трейт SystemProbes), spawn_failure, runner_base + preset_runner_support + constants (PresetRunnerStateMachine, list2cmdline MS C runtime, LaunchPlan, трейт ProcessSpawner) | primecore-ws | 59 тестов; runner_zapret2/zapret1, engine, restart, commands, launch — в работе (срез 2) |
| folders (чистая часть): classify_* (токены по границе слова, lookbehind с кириллицей), normalize_folder_state + FolderLibraryStore, resolve_folder_order + plan_* + build_folder_rows | primecore-folders (defaults — уже были в primecore-settings/src/schema.rs) | 34 теста (порт test_folders_library 21 + test_folders_ordering_plan 8 + 3 краевых); ~30 краевых случаев сверены с живым python; RLock — у вызывающего |
| utils/net_resolve.py (резолв с жёстким дедлайном, кэш TTL 30/5, limit 512, connect_tcp с ограничением обеих фаз) | primecore-net-resolve | 8 тестов с подставным резолвером (как monkeypatch getaddrinfo в python-тестах); демонический поток в Rust невозможен — залипший резолв доживает в фоне |

## Кроссплатформенность (winws2 vs nfqws2)

* `winws2` (Windows, WinDivert, `--wf-*`) и `nfqws2` (Linux, NFQUEUE,
  `--qnum`/`--fwmark`) — одна программа; Lua-стратегии и профили
  переносимы между системами, отличен только слой перехвата;
* пресет целиком в Linux не переносим (первые строки — `--wf-*`), в
  Linux-срезе запуска их надо вырезать и генерировать правила
  nftables/iptables — детали и следствия для порта: docs_platform-flags.md.

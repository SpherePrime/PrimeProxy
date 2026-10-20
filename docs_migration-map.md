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
  манифесты.

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

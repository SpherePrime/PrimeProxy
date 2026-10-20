use primecore_hosts::*;

fn line(s: &str) -> String {
    format!("{s}\n")
}

#[test]
fn parses_mapping_line() {
    let (ip, domains, comment) =
        parse_hosts_mapping_line("10.0.0.5 primebypass.site # последний").expect("строка");
    assert_eq!(ip, "10.0.0.5");
    assert_eq!(domains, vec!["primebypass.site".to_string()]);
    assert_eq!(comment, "последний");

    let (ip, domains, _) = parse_hosts_mapping_line("1.1.1.1  a.ru b.ru").expect("два имени");
    assert_eq!(ip, "1.1.1.1");
    assert_eq!(domains.len(), 2);

    assert!(parse_hosts_mapping_line("# только комментарий").is_none());
    assert!(parse_hosts_mapping_line("   \n").is_none());
    assert!(parse_hosts_mapping_line("10.0.0.1\n").is_none());
    assert!(parse_hosts_mapping_line("noip\n").is_none());
}

fn sample_block() -> String {
    let mut text = String::new();
    text.push_str(&line("# верх файла"));
    text.push_str(&line(MANAGED_HOSTS_BEGIN));
    text.push_str(&line(MANAGED_HOSTS_NOTICE));
    text.push_str(&line("10.0.0.5 one.site"));
    text.push_str(&line("10.0.0.6 two.site"));
    text.push_str(&line(MANAGED_HOSTS_END));
    text.push_str(&line("10.0.0.9 foreign.site"));
    text
}

#[test]
fn removes_managed_block_and_counts_entries() {
    let lines: Lines = sample_block().lines().map(str::to_string).collect();
    let (kept, removed) = remove_managed_hosts_block(&lines);
    assert_eq!(removed, 2);
    let joined = kept.join("");
    assert!(joined.contains("# верх файла"));
    assert!(joined.contains("10.0.0.9 foreign.site"));
    assert!(!joined.contains("one.site"));
    assert!(!joined.contains(MANAGED_HOSTS_BEGIN));
}

#[test]
fn removes_legacy_blocks_of_old_releases() {
    let markers: [(&str, &str); 3] = [
        (
            "# >>> primeproxy:hosts managed begin >>>",
            "# <<< primeproxy:hosts managed end <<<",
        ),
        (
            "# >>> zapretgui:hosts managed begin >>>",
            "# <<< zapretgui:hosts managed end <<<",
        ),
        (MANAGED_HOSTS_BEGIN, MANAGED_HOSTS_END),
    ];
    for (begin, end) in markers {
        let text = format!("{begin}\n10.0.0.5 one.site\n{end}\n");
        let lines: Lines = text.lines().map(str::to_string).collect();
        let (kept, removed) = remove_managed_hosts_block(&lines);
        assert_eq!(removed, 1, "{begin}");
        assert!(kept.join("").trim().is_empty(), "{begin}");
    }
}

#[test]
fn iterates_rows_of_block() {
    let lines: Lines = sample_block().lines().map(str::to_string).collect();
    let rows = iter_managed_hosts_block_rows(&lines);
    assert_eq!(
        rows,
        vec![
            ("one.site".to_string(), "10.0.0.5".to_string()),
            ("two.site".to_string(), "10.0.0.6".to_string())
        ]
    );
}

#[test]
fn inserts_block_before_foreign_mapping() {
    let mut lines: Lines = vec![
        line("# заголовок"),
        line(""),
        line("10.0.0.9 foreign.site"),
        line("# комментарий"),
    ];
    let rows: Rows = vec![
        ("one.site".to_string(), "10.0.0.5".to_string()),
        ("two.site".to_string(), "10.0.0.6".to_string()),
    ];
    insert_managed_hosts_block(&mut lines, &rows, None);
    let text = lines.join("");
    let begin = text.find(MANAGED_HOSTS_BEGIN).expect("блок вставлен");
    let mapping = text.find("10.0.0.9").expect("чужая строка осталась");
    assert!(begin < mapping, "блок перед чужими строками: {text:?}");
    assert!(text.contains("10.0.0.9 foreign.site"));
    assert!(text.contains(MANAGED_HOSTS_BEGIN));
    assert!(text.contains(MANAGED_HOSTS_END));
    // Разделительная пустая строка между блоком и старым содержимым.
    assert!(text.contains("10.0.0.\n\n10.0.0.9") || text.contains("<<<\n\n10.0.0.9"));
    assert!(
        text.contains(&format!("{MANAGED_HOSTS_END}\n\n10.0.0.9")),
        "между блоком и чужой строкой остаётся пустой разделитель: {text:?}"
    );
}

#[test]
fn insert_with_empty_rows_is_noop() {
    let mut lines: Lines = vec![line("10.0.0.9 foreign.site")];
    let before = lines.clone();
    insert_managed_hosts_block(&mut lines, &Rows::new(), None);
    assert_eq!(lines, before);
}

#[test]
fn russian_entry_counts() {
    assert_eq!(format_hosts_entries_count(1), "1 запись");
    assert_eq!(format_hosts_entries_count(2), "2 записи");
    assert_eq!(format_hosts_entries_count(5), "5 записей");
    assert_eq!(format_hosts_entries_count(11), "11 записей");
    assert_eq!(format_hosts_entries_count(21), "21 запись");
    assert_eq!(format_hosts_entries_count(22), "22 записи");
    assert_eq!(format_hosts_entries_count(25), "25 записей");
    assert_eq!(format_hosts_entries_count(100), "100 записей");
}

fn own_service_line() -> String {
    "10.0.0.5 one.site\n".to_string()
}

fn other_service_line() -> String {
    "10.0.0.7 nice.org\n".to_string()
}

fn max_block() -> (String, Vec<String>) {
    (
        "# MAX BLOCKED BY PRIMEBYPASS".to_string(),
        vec![line("10.0.0.1 max.site")],
    )
}

#[test]
fn drop_conflicts_removes_only_misleading_ip() {
    let text = format!(
        "{}{}10.0.0.8 one.site\n10.0.0.7 mixed.site nice.site\n",
        own_service_line(),
        other_service_line()
    );
    let lines: Lines = text.lines().map(str::to_string).collect();
    let wanted: Rows = vec![
        ("one.site".to_string(), "10.0.0.5".to_string()),
        ("nice.site".to_string(), "10.0.0.6".to_string()),
    ];
    let (kept, dropped) = drop_conflicting_foreign_rows(&lines, &wanted);
    assert_eq!(
        dropped,
        vec![
            "10.0.0.8 one.site".to_string(),
            "10.0.0.7 nice.site".to_string()
        ]
    );
    let joined = kept.join("");
    assert!(
        joined.contains("nice.org"),
        "случайная чужая строка не тронута"
    );
    assert!(
        !joined.contains("10.0.0.8 one.site"),
        "мешающая запись убрана"
    );
    assert!(
        joined.contains("10.0.0.7 mixed.site"),
        "строка на несколько имён сохраняет неизвестное имя"
    );
    assert!(
        !joined.contains("nice.site\n") || joined.contains("10.0.0.6 nice.site"),
        "конфликтное имя убрано из многоимённой строки"
    );
}

#[test]
fn drop_conflicts_keeps_line_when_ip_from_service_rows() {
    let lines: Lines = vec![line("10.0.0.5 one.site"), line("10.0.0.5 two.site")];
    let wanted: Rows = vec![
        ("one.site".to_string(), "10.0.0.5".to_string()),
        ("two.site".to_string(), "10.0.0.5".to_string()),
    ];
    let (kept, dropped) = drop_conflicting_foreign_rows(&lines, &wanted);
    assert_eq!(dropped, Vec::<String>::new());
    assert_eq!(kept.join(""), lines.join(""));
}

#[test]
fn other_blocks_are_skipped_with_own_end_marker() {
    let (_, mut block_lines) = max_block();
    block_lines.push(line(MANAGED_HOSTS_BEGIN));
    block_lines.push(line("10.0.0.5 one.site"));
    block_lines.push(line(MANAGED_HOSTS_END));
    block_lines.push(line("10.0.0.9 tg.site"));
    let wanted: Rows = vec![("one.site".to_string(), "10.0.0.5".to_string())];
    block_lines.push(line("10.0.0.8 one.site"));
    let (kept, dropped) = drop_conflicting_foreign_rows(&block_lines, &wanted);
    let joined = kept.join("");
    assert_eq!(dropped, vec!["10.0.0.8 one.site".to_string()]);
    assert!(joined.contains("max.site"), "чужой блок не тронут");
    assert!(joined.contains("one.site"), "наш блок не тронут");
}

#[test]
fn telegram_block_is_skipped_up_to_blank() {
    let mut lines = vec![
        line("# --- Telegram Proxy (auto-managed by PrimeBypass)"),
        line("10.0.0.2 tg.site"),
    ];
    lines.push(line(""));
    lines.push(line("10.0.0.9 tg.site"));
    let wanted: Rows = vec![("tg.site".to_string(), "10.0.0.2".to_string())];
    let (kept, dropped) = drop_conflicting_foreign_rows(&lines, &wanted);
    let joined = kept.join("");
    assert_eq!(dropped, vec!["10.0.0.9 tg.site".to_string()]);
    assert!(
        joined.contains("10.0.0.2 tg.site"),
        "блок Telegram не тронут"
    );
}

#[test]
fn filters_empty_dupes_and_ipv6() {
    let rows: Rows = vec![
        ("one.site".to_string(), "10.0.0.5".to_string()),
        (" ONE.SITE ".to_string(), " 10.0.0.5 ".to_string()),
        ("".to_string(), "10.0.0.6".to_string()),
        ("two.site".to_string(), "2620:0:2d0:200::7".to_string()),
        ("two.site".to_string(), "2620:0:2d0:200::7".to_string()),
        ("three.site".to_string(), "10.0.0.7".to_string()),
    ];
    let (desired, had) = filter_desired_hosts_rows(&rows, false);
    assert!(had);
    assert_eq!(
        desired,
        vec![
            ("one.site".to_string(), "10.0.0.5".to_string()),
            ("three.site".to_string(), "10.0.0.7".to_string())
        ]
    );
    let (desired_with_ipv6, had2) = filter_desired_hosts_rows(&rows, true);
    assert!(had2);
    assert_eq!(desired_with_ipv6.len(), 3);
    assert!(desired_with_ipv6
        .iter()
        .any(|(d, ip)| d.as_str() == "two.site" && ip.starts_with("2620:")));
}

#[test]
fn binary_rows_key_compare_is_domain_orderless_dot_aware() {
    let one: Rows = vec![
        ("one.site".to_string(), "10.0.0.5".to_string()),
        ("two.site".to_string(), "10.0.0.6".to_string()),
    ];
    let two: Rows = vec![
        ("two.site".to_string(), "10.0.0.6".to_string()),
        ("one.site".to_string(), "10.0.0.5".to_string()),
    ];
    assert_eq!(hosts_rows_key(&one), hosts_rows_key(&two));
    let three: Rows = vec![
        ("one.site".to_string(), "10.0.0.9".to_string()),
        ("two.site".to_string(), "10.0.0.6".to_string()),
    ];
    assert_ne!(hosts_rows_key(&one), hosts_rows_key(&three));
}

fn block_rows_of(text: &str) -> Rows {
    let lines: Lines = text.lines().map(str::to_string).collect();
    iter_managed_hosts_block_rows(&lines)
}

#[test]
fn decide_refresh_all_zones() {
    let block = format!(
        "{}10.0.0.5 one.site\n{}",
        line(MANAGED_HOSTS_BEGIN),
        line(MANAGED_HOSTS_END)
    );
    let block_rows = block_rows_of(&block);

    assert!(block_rows.len() == 1);
    let (should, reason) = decide_applied_selection_refresh(&Rows::new(), true, true, Vec::new);
    assert!(!should);
    assert!(reason.contains("блока"), "{reason}");
    let (should, reason) = decide_applied_selection_refresh(&block_rows, false, true, Vec::new);
    assert!(!should);
    assert!(reason.contains("выбор"), "{reason}");
    let desired: Rows = vec![("one.site".to_string(), "10.0.0.5".to_string())];
    let (should, reason) =
        decide_applied_selection_refresh(&block_rows, true, true, || desired.clone());
    assert!(!should);
    assert!(reason.contains("актуальны"), "{reason}");
    let stale: Rows = vec![("one.site".to_string(), "10.0.0.6".to_string())];
    let (should, reason) =
        decide_applied_selection_refresh(&block_rows, true, true, || stale.clone());
    assert!(should, "новые адреса требуют перезаписи");
    assert!(reason.contains("устарели"), "{reason}");
}

#[test]
fn ipv6_block_not_dropped_when_ipv6_down() {
    let block = format!(
        "{BEGIN}{IP}5{END}",
        BEGIN = line(MANAGED_HOSTS_BEGIN),
        IP = "",
        END = ""
    );
    let _ = &block;
    let text = format!(
        "{}10.0.0.5 one.site\n2620:0:2d0:200::7 one.site\n{}",
        line(MANAGED_HOSTS_BEGIN),
        line(MANAGED_HOSTS_END)
    );
    let block_rows = block_rows_of(&text);
    let (should, reason) = decide_applied_selection_refresh(&block_rows, true, false, || {
        vec![("one.site".to_string(), "10.0.0.5".to_string())]
    });
    assert!(!should, "IPv6 ещё поднялся — не переписываем блок");
    assert!(reason.contains("IPv6 сейчас недоступен"), "{reason}");
    let (should, _) = decide_applied_selection_refresh(&block_rows, true, true, || {
        vec![("one.site".to_string(), "10.0.0.5".to_string())]
    });
    assert!(
        should,
        "IPv6 доступен — сверить разница адресов ведёт к записи"
    );
}

#[test]
fn ipv6_detection_matches_expected() {
    assert!(is_ipv6_address("2620:0:2d0:200::7"));
    assert!(!is_ipv6_address("10.0.0.5"));
    assert!(!is_ipv6_address("not-an-ip"));
}

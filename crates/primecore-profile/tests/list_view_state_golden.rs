use primecore_profile::display_items::ProfileDisplayItem;
use primecore_profile::list_view_state::{
    profile_group_counter_tooltip, profile_group_tooltip, profile_name_inside_group,
    profile_row_tooltip, profile_state_tooltip, profile_strategy_tooltip, row_for_profile,
};

#[test]
fn view_state_tooltips_golden() {
    assert_eq!(
        profile_group_tooltip("YouTube", 2, 5),
        "Группа «YouTube»: профили одного сайта или сервиса.\nВключено 2 из 5. Нажмите на шапку, чтобы свернуть или развернуть группу."
    );
    assert_eq!(
        profile_group_counter_tooltip(2, 5),
        "Включено 2 из 5 профилей группы.\nКаждое деление полоски — один профиль, в том же порядке, что строки ниже. Закрашенное деление — профиль включён.\nВключать все профили не нужно: в пресете уже включено то, что обычно требуется. Если сайт не открывается, сначала смените стратегию у включённого профиля."
    );
    assert_eq!(
        profile_state_tooltip(true, false, true),
        "Кольцо: профиль есть в пресете, но выключен. В файле это записано через --skip."
    );
    assert_eq!(
        profile_name_inside_group("Видео (googlevideo.com)", "YouTube"),
        "Видео (googlevideo.com)"
    );

    let item = ProfileDisplayItem {
        order: 0,
        key: "k".to_string(),
        persistent_key: "p".to_string(),
        profile_index: 0,
        match_lines: vec!["--filter-tcp=80".to_string()],
        display_name: "YouTube XSS".to_string(),
        list_type: "hostlist".to_string(),
        group_name: "YouTube".to_string(),
        strategy_name: "Стратегия A".to_string(),
        rating: "work".to_string(),
        favorite: true,
        in_preset: true,
        enabled: true,
        user_profile_id: String::new(),
        group: "youtube".to_string(),
        strategy_id: "s1".to_string(),
        ..ProfileDisplayItem::default()
    };
    assert_eq!(
        profile_row_tooltip(&item),
        "TCP/HTTP • TCP 80 • hostlist\nTCP/HTTP — незашифрованный HTTP-трафик (порт 80).\nHostlist — обход действует только для доменов из списка этого профиля.\nСтратегия обхода: Стратегия A."
    );
    assert_eq!(
        profile_strategy_tooltip(true, true, "Стратегия A", "work", true),
        "Стратегия обхода: Стратегия A.\nЕсли сайт не открывается, нажмите на профиль и попробуйте другую стратегию.\nЗвезда: стратегия у вас в избранном.\nГалочка: вы отметили, что эта стратегия работает."
    );
    let row = row_for_profile(&item, "simple:youtube:YT");
    assert_eq!(row["description"], "TCP/HTTP | порты: TCP 80");
    assert_eq!(row["icon_name"], "simple:youtube:YT");
    assert_eq!(row["icon_in_header"], true);
    assert_eq!(row["tile_name"], "YouTube XSS");

    let quiet = ProfileDisplayItem {
        order: 0,
        key: "k2".to_string(),
        persistent_key: "p2".to_string(),
        profile_index: 1,
        match_lines: Vec::new(),
        display_name: "YouTube XSS".to_string(),
        list_type: String::new(),
        group_name: "YouTube".to_string(),
        strategy_name: String::new(),
        rating: String::new(),
        favorite: false,
        in_preset: false,
        enabled: false,
        user_profile_id: String::new(),
        group: "youtube".to_string(),
        strategy_id: String::new(),
        ..ProfileDisplayItem::default()
    };
    let quiet_row = row_for_profile(&quiet, "");
    assert_eq!(
        quiet_row["tooltip"],
        "TCP\nTCP — обычные соединения с сайтами и сервисами (TLS/HTTP).\nПрофиля ещё нет в пресете. Включать его не обязательно: нажмите на него и выберите готовую стратегию, только если этот сайт у вас не открывается."
    );
    assert_eq!(quiet_row["icon_color"], "#888888");
    assert_eq!(quiet_row["icon_name"], "simple:youtube:YT");
}

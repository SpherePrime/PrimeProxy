//! Порт zapretgui/tests/test_folders_library.py.

use serde_json::{json, Value};

use primecore_folders::{
    build_folder_rows, classify_preset_folder, classify_profile_folder, default_preset_folders,
    default_profile_folders, normalize_folder_state, FolderLibraryStore, COMMON_FOLDER_KEY,
    PINNED_FOLDER_KEY,
};

fn ordered_names(state: &Value) -> Vec<String> {
    let folders = state["folders"].as_object().expect("folders");
    let mut entries: Vec<(i64, String)> = folders
        .values()
        .map(|folder| {
            (
                folder["order"].as_i64().expect("order"),
                folder["name"].as_str().expect("name").to_string(),
            )
        })
        .collect();
    entries.sort_by_key(|(order, _name)| *order);
    entries.into_iter().map(|(_order, name)| name).collect()
}

#[test]
fn default_preset_folders_have_strict_order() {
    let state = default_preset_folders("winws2");

    assert_eq!(
        ordered_names(&state),
        [
            "ALL TCP & UDP",
            "Общие",
            "1.10.3",
            "1.10.0",
            "1.9.9",
            "Game filter",
            "Circular"
        ]
    );
    assert_eq!(state["folders"][COMMON_FOLDER_KEY]["system"], json!(true));
}

#[test]
fn winws1_default_preset_folders_have_flowseal_version_groups() {
    let state = default_preset_folders("winws1");

    assert_eq!(
        ordered_names(&state),
        [
            "Все сайты",
            "1.10.3",
            "1.10.0",
            "1.9.9a",
            "ALT",
            "Игры",
            "YouTube",
            "Discord",
            "Провайдеры",
            "Bolvan",
            "Fake TLS",
            "Split / MD5 / TTL",
            "Общие",
        ]
    );
    assert_eq!(state["folders"][COMMON_FOLDER_KEY]["system"], json!(true));
}

#[test]
fn default_profile_folders_have_common_and_all_sites_at_the_end() {
    let state = default_profile_folders();

    assert_eq!(
        ordered_names(&state),
        [
            "YouTube",
            "Discord",
            "Голосовые звонки (Discord, Telegram)",
            "GitHub",
            "Telegram",
            "WhatsApp",
            "Мессенджеры",
            "Соцсети",
            "Игры",
            "Roblox",
            "Amazon",
            "Хостеры",
            "Сайты",
            "ZapretKVN",
            "Общие",
            "Все сайты",
        ]
    );
    assert_eq!(state["folders"][COMMON_FOLDER_KEY]["system"], json!(true));
}

#[test]
fn preset_default_folder_is_classified_from_known_name() {
    assert_eq!(
        classify_preset_folder("ALL TCP & UDP v3_2.txt", "winws2"),
        "all-tcp-udp"
    );
    assert_eq!(
        classify_preset_folder("Default (circular).txt", "winws2"),
        "circular"
    );
    assert_eq!(
        classify_preset_folder("general EXP 1.10.0 (game filter).txt", "winws2"),
        "1-10-0"
    );
    assert_eq!(
        classify_preset_folder("general EXP 1.10.3 (game filter).txt", "winws2"),
        "1-10-3"
    );
    assert_eq!(
        classify_preset_folder("general ALT13 1.10.3 (game filter).txt", "winws2"),
        "1-10-3"
    );
    assert_eq!(
        classify_preset_folder("general ALT10 1.9.9 (game filter).txt", "winws2"),
        "1-9-9"
    );
    assert_eq!(
        classify_preset_folder("Preset X (game filter).txt", "winws2"),
        "game-filter"
    );
    assert_eq!(
        classify_preset_folder("Unknown custom.txt", "winws2"),
        COMMON_FOLDER_KEY
    );
}

#[test]
fn winws1_199a_preset_wins_over_alt_and_game_filter() {
    assert_eq!(
        classify_preset_folder("general ALT10 1.9.9a (game filter).txt", "winws1"),
        "1-9-9a"
    );
}

#[test]
fn winws1_1100_preset_wins_over_exp_and_game_filter() {
    assert_eq!(
        classify_preset_folder("general EXP 1.10.0 (game filter).txt", "winws1"),
        "1-10-0"
    );
}

#[test]
fn winws1_1103_preset_wins_over_alt_exp_game_filter_and_all_sites() {
    for name in [
        "general 1.10.3 (game filter).txt",
        "general ALT1 1.10.3 (game filter).txt",
        "general ALT13 1.10.3 (game filter).txt",
        "general EXP 1.10.3 (game filter).txt",
        "general FAKE TLS AUTO ALT3 1.10.3 (game filter).txt",
        "general SIMPLE FAKE ALT2 1.10.3 (game filter).txt",
        "allsites 1.10.3.txt",
    ] {
        assert_eq!(classify_preset_folder(name, "winws1"), "1-10-3", "{name}");
    }
    assert_eq!(
        classify_preset_folder("general ALT12 1.9.9a (game filter).txt", "winws1"),
        "1-9-9a"
    );
}

#[test]
fn shared_voice_profile_gets_its_own_folder_not_discord() {
    // STUN — общий протокол звонков: профиль чинит голос и в Discord, и в
    // Telegram, поэтому слово discord в том же фильтре его в Discord не тянет.
    assert_eq!(
        classify_profile_folder("Голосовые звонки/чаты --filter-l7=stun,discord"),
        "voice"
    );
    assert_eq!(
        classify_profile_folder("Voice --filter-l7=wireguard,stun,discord"),
        "voice"
    );
    assert_eq!(classify_profile_folder("Звонки --filter-l7=stun"), "voice");
    // Профили самого Discord остаются в Discord.
    assert_eq!(
        classify_profile_folder(
            "Discord UDP (обычно не нужно) --filter-udp=443-65535 --filter-l7=discord"
        ),
        "discord"
    );
    assert_eq!(
        classify_profile_folder("discord.media (voice RTC) --filter-tcp=443"),
        "discord"
    );
    // Слово stun в имени списка — не фильтр звонков.
    assert_eq!(
        classify_profile_folder("Discord --hostlist=lists/discord-stun.txt"),
        "discord"
    );

    let folders = default_profile_folders()["folders"]
        .as_object()
        .expect("folders")
        .clone();
    assert_eq!(
        folders["voice"]["name"],
        json!("Голосовые звонки (Discord, Telegram)")
    );
    assert_eq!(
        folders["voice"]["order"].as_i64().expect("order"),
        folders["discord"]["order"].as_i64().expect("order") + 1
    );
}

#[test]
fn profile_default_folder_is_classified_from_profile_text() {
    assert_eq!(
        classify_profile_folder("YouTube Russia CDN --hostlist=youtube.txt"),
        "youtube"
    );
    assert_eq!(
        classify_profile_folder("i.ytimg.com (превью роликов) --hostlist=lists/i.ytimg.txt"),
        "youtube"
    );
    assert_eq!(
        classify_profile_folder("Discord Updates --hostlist=discord.txt"),
        "discord"
    );
    assert_eq!(
        classify_profile_folder("vencord.dev --hostlist=lists/vencord.txt"),
        "discord"
    );
    assert_eq!(
        classify_profile_folder("GitHub --hostlist=lists/github.txt"),
        "github"
    );
    assert_eq!(
        classify_profile_folder("githubusercontent.com --hostlist=lists/githubusercontent.txt"),
        "github"
    );
    assert_eq!(
        classify_profile_folder("Telegram --hostlist=telegram.txt"),
        "telegram"
    );
    assert_eq!(
        classify_profile_folder("MTProto --filter-l7=mtproto"),
        "telegram"
    );
    assert_eq!(
        classify_profile_folder("WhatsApp --hostlist=lists/whatsapp.txt"),
        "whatsapp"
    );
    assert_eq!(
        classify_profile_folder("static.whatsapp.net --hostlist=lists/static-whatsapp.txt"),
        "whatsapp"
    );
    assert_eq!(
        classify_profile_folder("WhatsApp UDP wide --ipset=lists/ipset-whatsapp.txt"),
        "whatsapp"
    );
    assert_eq!(
        classify_profile_folder("Viber --hostlist=lists/viber.txt"),
        "messengers"
    );
    assert_eq!(
        classify_profile_folder("Signal --hostlist=lists/signal.txt"),
        "messengers"
    );
    assert_eq!(
        classify_profile_folder("Facebook --hostlist=facebook.txt"),
        "social"
    );
    assert_eq!(classify_profile_folder("Valorant game filter"), "games");
    assert_eq!(
        classify_profile_folder("itch.io --hostlist=lists/itch.txt"),
        "games"
    );
    assert_eq!(
        classify_profile_folder("roblox --ipset=lists/ipset-roblox.txt"),
        "roblox"
    );
    assert_eq!(
        classify_profile_folder("tr.rbxcdn.com --hostlist=lists/tr-rbxcdn-com.txt"),
        "roblox"
    );
    assert_eq!(
        classify_profile_folder("Tanki X --hostlist=lists/tankix.txt"),
        "games"
    );
    assert_eq!(
        classify_profile_folder("EpicGames & Fortnite --hostlist=lists/epicgames-fortnite.txt"),
        "games"
    );
    assert_eq!(
        classify_profile_folder("Ubisoft --hostlist=lists/ubisoft.txt"),
        "games"
    );
    assert_eq!(
        classify_profile_folder("lol-ru --ipset=lists/ipset-lol-ru.txt"),
        "games"
    );
    assert_eq!(
        classify_profile_folder("cloudflare --ipset=lists/ipset-cloudflare.txt"),
        "hosters"
    );
    assert_eq!(
        classify_profile_folder("amazon --ipset=lists/ipset-amazon.txt"),
        "amazon"
    );
    assert_eq!(
        classify_profile_folder("cloudfront.net --hostlist=lists/cloudfront.txt"),
        "amazon"
    );
    assert_eq!(
        classify_profile_folder("akamai --ipset=lists/ipset-akamai.txt"),
        "hosters"
    );
    assert_eq!(
        classify_profile_folder("datacamp --ipset=lists/ipset-datacamp.txt"),
        "hosters"
    );
    assert_eq!(
        classify_profile_folder("digitalocean --ipset=lists/ipset-digitalocean.txt"),
        "hosters"
    );
    assert_eq!(
        classify_profile_folder("fastly --ipset=lists/ipset-fastly.txt"),
        "hosters"
    );
    assert_eq!(
        classify_profile_folder("frantech --ipset=lists/ipset-frantech.txt"),
        "hosters"
    );
    assert_eq!(
        classify_profile_folder("novoserve --ipset=lists/ipset-novoserve.txt"),
        "hosters"
    );
    assert_eq!(
        classify_profile_folder("worldstream --ipset=lists/ipset-worldstream.txt"),
        "hosters"
    );
    assert_eq!(
        classify_profile_folder("ovh --ipset=lists/ipset-ovh.txt"),
        "hosters"
    );
    assert_eq!(
        classify_profile_folder("railway --ipset=lists/ipset-railway.txt"),
        "hosters"
    );
    assert_eq!(
        classify_profile_folder("hetzner --ipset=lists/ipset-hetzner.txt"),
        "hosters"
    );
    assert_eq!(
        classify_profile_folder("Google TCP --ipset=lists/ipset-google.txt"),
        "hosters"
    );
    assert_eq!(
        classify_profile_folder("Google Cloud --ipset=lists/ipset-usa-google.txt"),
        "hosters"
    );
    assert_eq!(
        classify_profile_folder("timeweb --ipset=lists/ipset-timeweb.txt"),
        "zapretkvn"
    );
    assert_eq!(
        classify_profile_folder("zapretkvn --ipset=lists/ipset-zapretkvn.txt"),
        "zapretkvn"
    );
    assert_eq!(
        classify_profile_folder("--filter-tcp=80,443 --hostlist-exclude=ru.txt"),
        "all-sites"
    );
    assert_eq!(classify_profile_folder("rutracker.org"), "sites");
}

#[test]
fn profile_folder_normalization_merges_new_default_folders() {
    let old_state = json!({
        "folders": {
            "youtube": {"name": "YouTube", "order": 0},
            "discord": {"name": "Discord", "order": 1},
            "messengers": {"name": "Мессенджеры", "order": 2},
            "social": {"name": "Соцсети", "order": 3},
            "games": {"name": "Игры", "order": 4},
            "sites": {"name": "Сайты", "order": 5},
            "common": {"name": "Общие", "order": 6, "system": true},
            "all-sites": {"name": "Все сайты", "order": 7},
        },
        "items": {},
    });

    let normalized = normalize_folder_state(&old_state, &default_profile_folders());

    assert_eq!(
        ordered_names(&normalized),
        [
            "YouTube",
            "Discord",
            "Голосовые звонки (Discord, Telegram)",
            "GitHub",
            "Telegram",
            "WhatsApp",
            "Мессенджеры",
            "Соцсети",
            "Игры",
            "Roblox",
            "Amazon",
            "Хостеры",
            "Сайты",
            "ZapretKVN",
            "Общие",
            "Все сайты",
        ]
    );
}

fn live_items(entries: &[(&str, &str, i64)]) -> Vec<Value> {
    entries
        .iter()
        .map(|(key, name, rating)| json!({"key": key, "name": name, "rating": rating}))
        .collect()
}

#[test]
fn manual_order_wins_over_rating_then_name() {
    let mut state = default_preset_folders("winws2");
    state["items"] = json!({
        "manual-second.txt": {"folder_key": COMMON_FOLDER_KEY, "order": 1, "rating": 10},
        "manual-first.txt": {"folder_key": COMMON_FOLDER_KEY, "order": 0, "rating": 0},
        "rated.txt": {"folder_key": COMMON_FOLDER_KEY, "order": Value::Null, "rating": 9},
        "alpha.txt": {"folder_key": COMMON_FOLDER_KEY, "order": Value::Null, "rating": 0},
    });
    let rows = build_folder_rows(
        &state,
        &live_items(&[
            ("alpha.txt", "Alpha", 0),
            ("rated.txt", "Rated", 9),
            ("manual-second.txt", "Manual Second", 10),
            ("manual-first.txt", "Manual First", 0),
        ]),
        false,
        "",
    );

    let item_keys: Vec<&str> = rows
        .iter()
        .filter(|row| row["kind"] == json!("item"))
        .map(|row| row["key"].as_str().expect("key"))
        .collect();
    assert_eq!(
        item_keys,
        [
            "manual-first.txt",
            "manual-second.txt",
            "rated.txt",
            "alpha.txt"
        ]
    );
}

#[test]
fn pinned_items_are_rendered_in_service_folder_above_regular_folders() {
    let mut state = default_preset_folders("winws2");
    state["items"] = json!({
        "regular.txt": {"folder_key": COMMON_FOLDER_KEY, "order": Value::Null, "rating": 0},
        "pinned.txt": {"folder_key": COMMON_FOLDER_KEY, "order": Value::Null, "rating": 0, "pinned": true},
    });

    let rows = build_folder_rows(
        &state,
        &[
            json!({"key": "regular.txt", "name": "Regular", "rating": 0}),
            json!({"key": "pinned.txt", "name": "Pinned", "rating": 0, "pinned": true}),
        ],
        true,
        "",
    );

    assert_eq!(rows[0]["kind"], json!("folder"));
    assert_eq!(rows[0]["key"], json!(PINNED_FOLDER_KEY));
    assert_eq!(rows[1]["kind"], json!("item"));
    assert_eq!(rows[1]["key"], json!("pinned.txt"));
}

#[test]
fn collapsed_pinned_service_folder_hides_pinned_items() {
    let mut state = default_preset_folders("winws2");
    state["folders"][PINNED_FOLDER_KEY] =
        json!({"name": "Закрепленные", "order": 0, "collapsed": true, "system": true});
    state["items"] = json!({
        "pinned.txt": {"folder_key": COMMON_FOLDER_KEY, "order": Value::Null, "rating": 0, "pinned": true},
    });

    let rows = build_folder_rows(
        &state,
        &[json!({"key": "pinned.txt", "name": "Pinned", "rating": 0, "pinned": true})],
        true,
        "",
    );

    assert_eq!(rows[0]["kind"], json!("folder"));
    assert_eq!(rows[0]["key"], json!(PINNED_FOLDER_KEY));
    assert!(!rows
        .iter()
        .any(|row| row["kind"] == json!("item") && row["key"] == json!("pinned.txt")));
}

#[test]
fn folder_rename_and_move_skip_unchanged_values() {
    let default_state = default_preset_folders("winws2");
    let mut store = FolderLibraryStore::new(&default_state, None);
    let folder_key = store.create_folder_after("Моя папка", COMMON_FOLDER_KEY);
    let current_order = store.to_dict()["folders"][folder_key.as_str()]["order"]
        .as_i64()
        .expect("order");

    assert!(!store.rename_folder(&folder_key, "Моя   папка"));
    assert!(!store.move_folder(&folder_key, current_order));
}

#[test]
fn item_metadata_setters_skip_unchanged_values() {
    let mut state = default_preset_folders("winws2");
    state["items"] = json!({
        "custom.txt": {
            "folder_key": COMMON_FOLDER_KEY,
            "order": 2,
            "rating": 7,
            "pinned": true,
        }
    });
    let mut store = FolderLibraryStore::new(&state, None);

    assert!(!store.set_item_folder("custom.txt", COMMON_FOLDER_KEY));
    assert!(!store.set_item_order("custom.txt", Some(2)));
    assert!(!store.set_item_rating("custom.txt", 7));
    assert!(!store.set_item_pinned("custom.txt", true));
}

#[test]
fn default_item_metadata_does_not_create_empty_item() {
    let default_state = default_preset_folders("winws2");
    let mut store = FolderLibraryStore::new(&default_state, None);

    assert!(!store.set_item_folder("custom.txt", COMMON_FOLDER_KEY));
    assert!(!store.set_item_order("custom.txt", None));
    assert!(!store.set_item_rating("custom.txt", 0));
    assert!(!store.set_item_pinned("custom.txt", false));
    assert_eq!(store.to_dict()["items"], json!({}));
}

#[test]
fn delete_folder_moves_items_to_common() {
    let default_state = default_preset_folders("winws2");
    let mut store = FolderLibraryStore::new(&default_state, None);
    let folder_key = store.create_folder("Игры");
    assert!(store.set_item_folder("custom.txt", &folder_key));

    assert!(store.delete_folder(&folder_key));

    let state = store.to_dict();
    assert!(state["folders"]
        .as_object()
        .expect("folders")
        .get(&folder_key)
        .is_none());
    assert_eq!(
        state["items"]["custom.txt"]["folder_key"],
        json!(COMMON_FOLDER_KEY)
    );
}

#[test]
fn common_folder_cannot_be_deleted_but_can_move() {
    let default_state = default_preset_folders("winws2");
    let mut store = FolderLibraryStore::new(&default_state, None);

    assert!(!store.delete_folder(COMMON_FOLDER_KEY));
    assert!(store.move_folder(COMMON_FOLDER_KEY, 3));
    assert_eq!(
        store.to_dict()["folders"][COMMON_FOLDER_KEY]["order"],
        json!(3)
    );
}

#[test]
fn create_folder_after_common_places_user_folder_next_to_common() {
    let default_state = default_preset_folders("winws2");
    let mut store = FolderLibraryStore::new(&default_state, None);

    let folder_key = store.create_folder_after("Моя папка", COMMON_FOLDER_KEY);

    assert_eq!(folder_key, "моя-папка");
    assert_eq!(
        ordered_names(&store.to_dict()),
        [
            "ALL TCP & UDP",
            "Общие",
            "Моя папка",
            "1.10.3",
            "1.10.0",
            "1.9.9",
            "Game filter",
            "Circular"
        ]
    );
}

#[test]
fn system_folder_cannot_be_renamed() {
    let default_state = default_preset_folders("winws2");
    let mut store = FolderLibraryStore::new(&default_state, None);

    assert!(!store.rename_folder(COMMON_FOLDER_KEY, "Другое имя"));
    assert_eq!(
        store.to_dict()["folders"][COMMON_FOLDER_KEY]["name"],
        json!("Общие")
    );
}

#[test]
fn move_folder_by_step_swaps_visible_order() {
    let default_state = default_preset_folders("winws2");
    let mut store = FolderLibraryStore::new(&default_state, None);
    let folder_key = store.create_folder_after("Моя папка", COMMON_FOLDER_KEY);

    assert!(store.move_folder_by_step(&folder_key, 1));

    assert_eq!(
        ordered_names(&store.to_dict()),
        [
            "ALL TCP & UDP",
            "Общие",
            "1.10.3",
            "Моя папка",
            "1.10.0",
            "1.9.9",
            "Game filter",
            "Circular"
        ]
    );
}

// Сверено с python: normalize_folder_state на «мусорных» значениях.
#[test]
fn normalize_tolerates_garbage_values() {
    let default_state = default_preset_folders("winws2");
    let state = json!({
        "items": {
            "a": {"order": "5", "rating": "7", "pinned": 1, "folder_key": Value::Null},
            "b": {"order": -3},
            "c": {"rating": true},
            "d": {"order": 3.9},
            "e": {"order": -0.5},
            "f": {"pinned": "", "order": ""},
            "g": {"folder_key": 5},
        },
        "folders": {"x": {"name": "X", "order": "3"}, "y": {"name": "Y", "order": "5.5"}},
    });

    let normalized = normalize_folder_state(&state, &default_state);
    let items = &normalized["items"];
    assert_eq!(
        items["a"],
        json!({"folder_key": COMMON_FOLDER_KEY, "order": 5, "rating": 7, "pinned": true})
    );
    assert_eq!(items["b"]["order"], json!(0));
    assert_eq!(
        items["c"],
        json!({"folder_key": COMMON_FOLDER_KEY, "order": Value::Null, "rating": 1})
    );
    assert_eq!(items["d"]["order"], json!(3));
    assert_eq!(items["e"]["order"], json!(0));
    assert_eq!(
        items["f"],
        json!({"folder_key": COMMON_FOLDER_KEY, "order": Value::Null, "rating": 0})
    );
    assert_eq!(items["g"]["folder_key"], json!(COMMON_FOLDER_KEY));
    // Порядки «x» (3) и «y» (дефолт) сдвигаются вставками дефолтных папок —
    // значения сверены с python.
    assert_eq!(normalized["folders"]["x"]["order"], json!(10));
    assert_eq!(normalized["folders"]["y"]["order"], json!(8));
}

#[test]
fn create_folder_generates_unique_clean_keys() {
    let default_state = default_preset_folders("winws1");
    let mut store = FolderLibraryStore::new(&default_state, None);

    let first = store.create_folder("Игры");
    let second = store.create_folder("Игры");
    assert_eq!(first, "игры");
    assert_eq!(second, "игры-2");
    assert_eq!(store.create_folder("   "), "новая-папка");
    assert_eq!(store.create_folder(&"x".repeat(100)).len(), 80);
    assert_eq!(
        store.to_dict()["folders"]["новая-папка"]["name"],
        json!("Новая папка")
    );
}

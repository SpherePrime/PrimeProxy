use primecore_profile::user_profiles::{
    create_user_profile, delete_user_profile, load_user_profile_templates, update_user_profile,
    validate_user_profile_filter, AppPaths,
};

fn temp_root(tag: &str) -> std::path::PathBuf {
    let base = std::env::temp_dir().join(format!(
        "primeup-{tag}-{}-{}",
        std::process::id(),
        primecore_profile::identity::generate_profile_uid(),
    ));
    std::fs::create_dir_all(&base).unwrap();
    base
}

fn read(root: &std::path::Path, rest: &str) -> Option<String> {
    std::fs::read_to_string(root.join(rest)).ok()
}

#[test]
fn user_profiles_crud_golden() {
    // python-сценарий: создать youtube-moi → переименовать → удалить,
    // файлы слоёв и итог тасуются и удаляются вслед.
    let root = temp_root("crud");
    let paths = AppPaths {
        user_root: root.clone(),
    };
    let profile_id = create_user_profile(&paths, "YouTube мой", "tcp", "443").unwrap();
    assert_eq!(profile_id, "youtube-moi");
    assert_eq!(
        read(&root, "lists/user/youtube-moi.txt"),
        Some("www.example.com\n".to_string())
    );
    assert_eq!(
        read(&root, "lists/user/ipset-youtube-moi.txt")
            .unwrap_or_default()
            .trim(),
        "123.123.123.123"
    );
    assert!(root.join("lists/youtube-moi.txt").is_file());
    assert!(root.join("lists/ipset-youtube-moi.txt").is_file());

    let (old_row, new_row): (
        std::collections::BTreeMap<String, String>,
        std::collections::BTreeMap<String, String>,
    ) = {
        use serde_json::{Map, Value};
        let (old, new) =
            update_user_profile(&paths, &profile_id, "Дискорд мой", "udp", "50000,50002").unwrap();
        let as_map = |row: Map<String, Value>| {
            row.iter()
                .map(|(key, value)| (key.clone(), value.as_str().unwrap_or_default().to_string()))
                .collect::<std::collections::BTreeMap<_, _>>()
        };
        (as_map(old), as_map(new))
    };
    assert_eq!(old_row.get("hostlist").unwrap(), "lists/youtube-moi.txt");
    assert_eq!(new_row.get("name").unwrap(), "Дискорд мой");
    assert_eq!(new_row.get("ports").unwrap(), "50000,50002");
    assert!(read(&root, "lists/user/youtube-moi.txt").is_none());
    assert!(read(&root, "lists/user/diskord-moi.txt").is_some());
    assert!(root.join("lists/ipset-diskord-moi.txt").is_file());

    let deleted = delete_user_profile(&paths, &profile_id).unwrap();
    let deleted_name = deleted
        .get("name")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    assert_eq!(deleted_name, "Дискорд мой");
    assert!(read(&root, "lists/user/diskord-moi.txt").is_none());
    assert!(read(&root, "lists/diskord-moi.txt").is_none());

    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn user_profiles_validation_golden() {
    assert_eq!(validate_user_profile_filter("tcp", "1-65535"), None);
    // python: "stun discord" → "stundiscord" без пробела — проходит.
    assert_eq!(validate_user_profile_filter("l7", "stun discord"), None);
    assert_eq!(
        validate_user_profile_filter("tcp", "~100-50").as_deref(),
        Some("Начало диапазона портов не должно быть больше конца.")
    );
    assert_eq!(validate_user_profile_filter("udp", "*"), None);
    assert_eq!(
        validate_user_profile_filter("tcp", "0").as_deref(),
        Some("Порт должен быть от 1 до 65535.")
    );
    assert_eq!(
        validate_user_profile_filter("tcp", "").as_deref(),
        Some("Значение фильтра profile не должно быть пустым")
    );
}

#[test]
fn user_profiles_duplicates_golden() {
    let root = temp_root("dup");
    let paths = AppPaths {
        user_root: root.clone(),
    };
    let first = create_user_profile(&paths, "Каналы", "tcp", "80").unwrap();
    assert_eq!(first, "kanaly");
    let duplicate = create_user_profile(&paths, "каналы", "tcp", "81");
    assert_eq!(
        duplicate.unwrap_err(),
        "Пользовательский profile с таким названием уже есть"
    );
    let second = create_user_profile(&paths, "Каналы 2", "tcp", "82").unwrap();
    assert_eq!(second, "kanaly-2");
    load_user_profile_templates(&paths, "winws2");
    std::fs::remove_dir_all(&root).ok();
}

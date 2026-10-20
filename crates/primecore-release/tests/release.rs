use primecore_release::*;
use serde_json::json;
use serde_json::Value;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

fn value_ok(release: &str) -> Result<serde_json::Value, String> {
    Ok(json!({"version": release}))
}

fn err_ok(error: &str) -> Result<serde_json::Value, String> {
    Err(error.to_string())
}

fn const_fetch(outcome: Result<serde_json::Value, String>) -> FetchSource {
    Arc::new(move || outcome.clone())
}

#[test]
fn channels_normalize() {
    assert_eq!(normalize_update_channel("dev"), CHANNEL_DEV);
    assert_eq!(normalize_update_channel(" DEV "), CHANNEL_DEV);
    assert_eq!(normalize_update_channel(""), CHANNEL_STABLE);
    assert_eq!(normalize_update_channel("nightly"), CHANNEL_STABLE);
    assert!(is_dev_update_channel("dev"));
    assert!(!is_dev_update_channel("stable"));
    assert_eq!(
        get_channel_installer_name("dev"),
        "PrimeBypassSetup_DEV.exe"
    );
    assert_eq!(get_channel_installer_name("stable"), "PrimeBypassSetup.exe");
}

#[test]
fn dev_asset_names_include_legacy() {
    assert!(is_dev_release_asset_name(
        "PrimeBypassSetup_DEV_21_1_5_78.exe"
    ));
    assert!(is_dev_release_asset_name("Zapret2Setup_DEV_21_1_5_78.exe"));
    assert!(is_dev_release_asset_name(
        "PrimeProxySetup_DEV_21_1_5_67.exe"
    ));
    assert!(is_dev_release_asset_name("installer_DEV.exe"));
    assert!(!is_dev_release_asset_name("PrimeBypassSetup.exe"));
    assert!(!is_dev_release_asset_name("PrimeProxySetup.exe"));
}

#[test]
fn telegram_version_uses_installer_names_only() {
    let html = "дата 16.09.2026 ip 10.7.8.9\r\nPrimeProxySetup_DEV_21_1_5_78.exe потом";
    assert_eq!(
        version_from_telegram_html(html),
        Some("21.1.5.78".to_string())
    );

    let html = "Zapret2Setup_20_1_1_2.exe и позже PrimeBypassSetup_DEV_22_0_0_1.exe!";
    assert_eq!(
        version_from_telegram_html(html),
        Some("22.0.0.1".to_string())
    );

    assert_eq!(
        version_from_telegram_html("просто числа 21_1_5_78.exe"),
        None
    );
    assert!(telegram_source_name("dev").contains("zapretguidev"));
    assert!(telegram_source_name("stable").contains("zapretnetdiscordyoutube"));
}

#[test]
fn sha256_normalizes() {
    assert_eq!(
        normalize_sha256(
            &"  A6A52B4D3D9F7C0D89F1DFEBD1446DEB69B5E9D1E7FBC0FA3F5AA2DBBA1B7F90 ".to_uppercase()
        )
        .len(),
        64
    );
    assert_eq!(normalize_sha256("abcd"), "");
    assert_eq!(normalize_sha256(&"g".repeat(64)), "");
    assert_eq!(normalize_sha256(""), "");
    let ok = normalize_sha256(&"a".repeat(64));
    assert_eq!(ok, "a".repeat(64));
}

fn mirror_release() -> serde_json::Value {
    let sha = "c".repeat(64);
    json!({
        "version": "21.1.5.80",
        "update_url": "https://mirror.primebypass.su:9440/download/PrimeBypassSetup.exe",
        "file_name": "PrimeBypassSetup.exe",
        "file_size": 1000,
        "sha256": sha,
        "verify_ssl": false,
    })
}

#[test]
fn metadata_contract_accepts_valid_and_permissive_ftp() {
    let release = mirror_release();
    let metadata = ReleaseArtifactMetadata::from_mapping(&release).expect("валидная запись");
    assert_eq!(metadata.version, "21.1.5.80");
    assert_eq!(metadata.file_name, "PrimeBypassSetup.exe");
    assert_eq!(metadata.file_size, 1000);
    assert_eq!(metadata.sha256.len(), 64);
    assert!(!metadata.verify_ssl);
    assert!(is_installable_release(&release));
    let metadata_http = ReleaseArtifactMetadata::from_mapping(&json!({
        "version": "21.1.5.80",
        "update_url": "http://mirror.primebypass.su:9080/download/PrimeBypassSetup.exe",
        "file_name": "PrimeBypassSetup.exe",
        "file_size": 1000,
        "sha256": metadata.sha256,
    }))
    .expect("HTTP тоже допустим");
    assert!(
        metadata_http.verify_ssl,
        "по умолчанию проверяем сертификат"
    );
}

#[test]
fn metadata_contract_rejects_broken() {
    for (name, release) in [
        (
            "нет версии",
            json!({"update_url": "https://host.ru/x.exe", "file_name": "x.exe", "file_size": 1, "sha256": "a".repeat(64)}),
        ),
        (
            "пустой sha",
            json!({"version": "21.1.5.80", "update_url": "https://host.ru/x.exe", "file_name": "x.exe", "file_size": 1}),
        ),
        (
            "короткий sha",
            json!({"version": "21.1.5.80", "update_url": "https://host.ru/x.exe", "file_name": "x.exe", "file_size": 1, "sha256": "abc"}),
        ),
        (
            "нулевой размер",
            json!({"version": "21.1.5.80", "update_url": "https://host.ru/x.exe", "file_name": "x.exe", "file_size": 0, "sha256": "a".repeat(64)}),
        ),
        (
            "нет размера",
            json!({"version": "21.1.5.80", "update_url": "https://host.ru/x.exe", "file_name": "x.exe", "sha256": "a".repeat(64)}),
        ),
        (
            "имя не совпало",
            json!({"version": "21.1.5.80", "update_url": "https://host.ru/x.exe", "file_name": "y.exe", "file_size": 1, "sha256": "a".repeat(64)}),
        ),
        (
            "без имени файла",
            json!({"version": "21.1.5.80", "update_url": "https://host.ru/x.exe", "file_size": 1, "sha256": "a".repeat(64)}),
        ),
        (
            "query в url",
            json!({"version": "21.1.5.80", "update_url": "https://host.ru/x.exe?do", "file_name": "x.exe", "file_size": 1, "sha256": "a".repeat(64)}),
        ),
        (
            "логин в url",
            json!({"version": "21.1.5.80", "update_url": "https://user@host.ru/x.exe", "file_name": "x.exe", "file_size": 1, "sha256": "a".repeat(64)}),
        ),
        (
            "не http-схема",
            json!({"version": "21.1.5.80", "update_url": "ftp://host.ru/x.exe", "file_name": "x.exe", "file_size": 1, "sha256": "a".repeat(64)}),
        ),
        (
            "https без пути",
            json!({"version": "21.1.5.80", "update_url": "https://host.ru", "file_name": "x.exe", "file_size": 1, "sha256": "a".repeat(64)}),
        ),
    ] {
        let outcome = ReleaseArtifactMetadata::from_mapping(&release);
        assert!(outcome.is_err(), "{name}: запись прошла: {:?}", release);
        assert!(!is_installable_release(&release), "{name}");
    }
}

#[test]
fn trusted_url_rules() {
    let prefix = FORGEJO_RELEASE_DOWNLOAD_PREFIX;
    let base = format!("https://{FORGEJO_HOST}{prefix}21.1.5.80/PrimeBypassSetup.exe");
    assert!(trusted_release_asset_url(
        &base,
        "21.1.5.80",
        "PrimeBypassSetup.exe"
    ));
    assert!(!trusted_release_asset_url(
        &format!("http://{FORGEJO_HOST}{prefix}21.1.5.80/PrimeBypassSetup.exe"),
        "21.1.5.80",
        "PrimeBypassSetup.exe"
    ));
    assert!(!trusted_release_asset_url(
        &format!("https://evil.example{prefix}21.1.5.80/PrimeBypassSetup.exe"),
        "21.1.5.80",
        "PrimeBypassSetup.exe"
    ));
    assert!(!trusted_release_asset_url(
        &format!("https://{FORGEJO_HOST}:443{prefix}21.1.5.80/PrimeBypassSetup.exe"),
        "21.1.5.80",
        "PrimeBypassSetup.exe"
    ));
    assert!(!trusted_release_asset_url(
        &format!("https://{FORGEJO_HOST}{prefix}21.1.5.80/PrimeBypassSetup.exe?mirror"),
        "21.1.5.80",
        "PrimeBypassSetup.exe"
    ));
    let traversal = format!("https://{FORGEJO_HOST}{prefix}21.1.5.80/sub/PrimeBypassSetup.exe");
    assert!(!trusted_release_asset_url(
        &traversal,
        "21.1.5.80",
        "PrimeBypassSetup.exe"
    ));
    assert!(trusted_release_asset_url(
        &format!("https://{FORGEJO_HOST}{prefix}21_1_5%2E80/PrimeBypassSetup.exe"),
        "21_1_5.80",
        "PrimeBypassSetup.exe"
    ));
    assert!(release_page_url("21_1_5.80").contains("tag/21_1_5.80"));
}

#[test]
fn sidecar_parsing() {
    let name = "PrimeBypassSetup.exe";
    let sum = "a".repeat(64);
    let text = format!("{sum}  {name}\n");
    assert_eq!(
        parse_sha256_sidecar(&text, name).expect("валидная строка"),
        sum
    );
    assert_eq!(
        parse_sha256_sidecar(&format!("{sum}  other.exe"), name),
        Err("Некорректный файл контрольной суммы выпуска".to_string())
    );
    assert_eq!(
        parse_sha256_sidecar(&format!("{name}{}", "0".repeat(23)), name),
        Err("Некорректный файл контрольной суммы выпуска".to_string())
    );
}

#[test]
fn channel_matches_by_prerelease_and_name() {
    assert!(matches_channel(true, "PrimeBypassSetup.exe", CHANNEL_DEV));
    assert!(!matches_channel(
        true,
        "PrimeBypassSetup.exe",
        CHANNEL_STABLE
    ));
    assert!(matches_channel(
        false,
        "PrimeBypassSetup_DEV_1_0_0_0.exe",
        CHANNEL_DEV
    ));
    assert!(!matches_channel(
        false,
        "PrimeBypassSetup_DEV_1_0_0_0.exe",
        CHANNEL_STABLE
    ));
    assert!(matches_channel(
        false,
        "PrimeBypassSetup.exe",
        CHANNEL_STABLE
    ));
}

fn forgejo_release(prerelease: bool) -> serde_json::Value {
    json!({
        "tag_name": "21.1.5.80",
        "prerelease": prerelease,
        "draft": false,
        "name": "PrimeBypass 21.1.5.80",
        "body": "заметки",
        "published_at": "2026-10-18T10:00:00+00:00",
        "assets": [
            {"name": "PrimeBypassSetup.exe", "size": 1213137,
             "browser_download_url": format!("https://{}/zapretdiscordyoutube/zapretgui/releases/download/21.1.5.80/PrimeBypassSetup.exe", FORGEJO_HOST)},
            {"name": "PrimeBypassSetup.exe.sha256", "size": 90,
             "browser_download_url": format!("https://{}/zapretdiscordyoutube/zapretgui/releases/download/21.1.5.80/PrimeBypassSetup.exe.sha256", FORGEJO_HOST)},
            {"name": "update-manifest.json", "size": 1213122,
             "browser_download_url": format!("https://{}/zapretdiscordyoutube/zapretgui/releases/download/21.1.5.80/update-manifest.json", FORGEJO_HOST)},
            {"name": "update-manifest.json.sig", "size": 90,
             "browser_download_url": format!("https://{}/zapretdiscordyoutube/zapretgui/releases/download/21.1.5.80/update-manifest.json.sig", FORGEJO_HOST)},
        ],
    })
}

#[test]
fn forgejo_candidate_collects_signed_assets() {
    let release = forgejo_release(false);
    let candidate = forgejo_candidate(&release, CHANNEL_STABLE).expect("стабильный кандидат");
    assert_eq!(
        candidate.get("version").and_then(Value::as_str),
        Some("21.1.5.80")
    );
    assert_eq!(
        candidate.get("file_name").and_then(Value::as_str),
        Some("PrimeBypassSetup.exe")
    );
    assert!(candidate
        .get("manifest_url")
        .and_then(Value::as_str)
        .expect("манифест найден")
        .ends_with("21.1.5.80/update-manifest.json"));
    assert!(candidate
        .get("signature_url")
        .and_then(Value::as_str)
        .expect("подпись найдена")
        .ends_with("21.1.5.80/update-manifest.json.sig"));
    assert_eq!(
        candidate.get("release_url").and_then(Value::as_str),
        Some(release_page_url("21.1.5.80").as_str())
    );

    assert!(forgejo_candidate(&forgejo_release(true), CHANNEL_DEV).is_some());
    assert!(forgejo_candidate(&forgejo_release(true), CHANNEL_STABLE).is_none());
    let mut draft = forgejo_release(false);
    draft["draft"] = json!(true);
    assert!(forgejo_candidate(&draft, CHANNEL_DEV).is_none());
    let mut no_sidecar = forgejo_release(false);
    no_sidecar["assets"] = json!([
        {"name": "PrimeBypassSetup.exe", "size": 1,
         "browser_download_url": format!("https://{}/zapretdiscordyoutube/zapretgui/releases/download/21.1.5.80/PrimeBypassSetup.exe", FORGEJO_HOST)},
    ]);
    assert!(forgejo_candidate(&no_sidecar, CHANNEL_STABLE).is_none());
}

#[test]
fn release_list_selects_candidates_in_order() {
    let payload = json!([
        {"tag_name": "bogus", "draft": false, "assets": []},
        forgejo_release(false),
        {"tag_name": "20.9.9.1", "draft": false, "prerelease": true, "assets": []},
    ]);
    let candidates = candidates_from_release_list(&payload, CHANNEL_STABLE).expect("список");
    assert_eq!(candidates.len(), 1);
    assert_eq!(
        history_entry(&candidates[0])
            .get("version")
            .and_then(Value::as_str),
        Some("21.1.5.80")
    );
    assert!(candidates_from_release_list(&json!({"oops": false}), CHANNEL_STABLE).is_none());
}

fn all_versions_bundle() -> serde_json::Value {
    json!({
        "stable": {
            "version": "21.1.5.80",
            "file_name": "PrimeBypassSetup.exe",
            "file_size": 1213137,
            "sha256": "a".repeat(64),
            "release_notes": "заметки",
            "date": "2026-10-18",
            "manifest": true,
        },
        "dev": {
            "version": "21.1.5.81",
            "file_name": "PrimeBypassSetup_DEV.exe",
            "file_size": 1213137,
            "sha256": "b".repeat(64),
        },
    })
}

#[test]
fn mirror_release_built_from_versions() {
    let data = all_versions_bundle();
    let release = release_from_versions(
        &data,
        CHANNEL_STABLE,
        "https://mirror.primebypass.su:9440",
        false,
        "mirror (HTTPS)",
    )
    .expect("выпуск собран");
    assert_eq!(
        release.get("version").and_then(Value::as_str),
        Some("21.1.5.80")
    );
    assert_eq!(
        release.get("name").and_then(Value::as_str),
        Some("PrimeBypass 21.1.5.80 (stable)")
    );
    assert_eq!(
        release.get("source").and_then(Value::as_str),
        Some("mirror (HTTPS)")
    );
    let update_url = release
        .get("update_url")
        .and_then(Value::as_str)
        .expect("ссылка");
    assert_eq!(
        update_url,
        "https://mirror.primebypass.su:9440/download/PrimeBypassSetup.exe"
    );
    let manifest_url = release
        .get("manifest_url")
        .and_then(Value::as_str)
        .expect("манифест есть при manifest:true");
    assert!(manifest_url.ends_with("PrimeBypassSetup.exe.update-manifest.json"));
    assert!(release
        .get("signature_url")
        .and_then(Value::as_str)
        .unwrap_or("")
        .ends_with("PrimeBypassSetup.exe.update-manifest.json.sig"));

    // Становится ошибкой: нет канала, нет sha, битая версия.
    assert_eq!(
        release_from_versions(&json!({}), CHANNEL_STABLE, "https://host", false, "м"),
        Err("в ответе нет канала stable".to_string())
    );
    let mut disabled = all_versions_bundle();
    disabled["stable"]["sha256"] = json!("x");
    assert!(release_from_versions(&disabled, CHANNEL_STABLE, "https://host", false, "м").is_err());
    disabled["stable"]["sha256"] = json!("a".repeat(64));
    disabled["stable"]["version"] = json!("б sâu");
    assert!(release_from_versions(&disabled, CHANNEL_STABLE, "https://host", false, "м").is_err());
}

#[test]
fn mirror_download_addresses() {
    let server = json!({
        "name": "обозреватель",
        "host": "mirror.primebypass.su",
        "https_port": 9440,
        "http_port": 9080,
    });
    let download = mirror_download(&server, "PrimeBypassSetup.exe", false);
    assert_eq!(download.name, "обозреватель");
    assert_eq!(
        download.https_url,
        "https://mirror.primebypass.su:9440/download/PrimeBypassSetup.exe"
    );
    assert_eq!(
        download.http_url,
        "http://mirror.primebypass.su:9080/download/PrimeBypassSetup.exe"
    );
    assert!(!download.verify_ssl);
}

#[test]
fn forgejo_success_skips_mirrors() {
    let mirrors_asked = Arc::new(AtomicBool::new(false));
    let asked = Arc::clone(&mirrors_asked);
    let fetch_mirrors: FetchSource = Arc::new(move || {
        asked.store(true, Ordering::SeqCst);
        Ok(json!({}))
    });
    let lookup = lookup_latest_release(
        CHANNEL_DEV,
        const_fetch(value_ok("21.1.5.80")),
        fetch_mirrors,
        MIRROR_FALLBACK_DELAY_SECONDS,
        FORGEJO_DEADLINE_SECONDS,
        MIRRORS_DEADLINE_SECONDS,
    );
    assert!(lookup.ok(), "{:?}", lookup.error);
    assert_eq!(
        lookup
            .release
            .and_then(|r| r.get("version").and_then(Value::as_str).map(str::to_string)),
        Some("21.1.5.80".to_string())
    );
    assert!(
        !mirrors_asked.load(Ordering::SeqCst),
        "зеркала не должны стартовать"
    );
}

#[test]
fn both_failures_report_both_reasons() {
    let lookup = lookup_latest_release(
        CHANNEL_STABLE,
        const_fetch(err_ok("сервер закрыт")),
        const_fetch(err_ok("зеркала молчат")),
        0.01,
        0.05,
        0.05,
    );
    assert!(!lookup.ok());
    assert!(
        lookup.error.contains("Не удалось узнать новейшую версию"),
        "текст новичка или новичка: {}",
        lookup.error
    );
    assert!(
        lookup.error.contains("Forgejo: сервер закрыт"),
        "{}",
        lookup.error
    );
    assert!(
        lookup.error.contains("Зеркала: зеркала молчат"),
        "{}",
        lookup.error
    );
}

#[test]
fn mirror_wins_when_forgejo_dead() {
    let lookup = lookup_latest_release(
        CHANNEL_STABLE,
        const_fetch(err_ok("сервер закрыт")),
        const_fetch(value_ok("21.1.5.80")),
        0.01,
        0.1,
        0.5,
    );
    assert!(lookup.ok(), "{}", lookup.error);
    assert_eq!(
        lookup
            .release
            .unwrap()
            .get("version")
            .and_then(Value::as_str),
        Some("21.1.5.80")
    );
}

#[test]
fn forgejo_timeout_reported_as_no_answer() {
    let late_forgejo: FetchSource = Arc::new(|| {
        thread::sleep(Duration::from_millis(150));
        value_ok("21.1.5.80")
    });
    let lookup = lookup_latest_release(
        CHANNEL_STABLE,
        late_forgejo,
        const_fetch(err_ok("зеркала молчат")),
        0.01,
        0.05,
        0.05,
    );
    assert!(!lookup.ok());
    assert!(
        lookup.error.contains("нет ответа за отведённое время"),
        "{}",
        lookup.error
    );
}

#[test]
fn first_good_answer_wins_the_race() {
    // Магия похожа на зеркало: ответы приходят по-разному; успех — тот,
    // что пришёл первым, если Forgejo живой, но тормознул.
    let slow_forgejo: FetchSource = Arc::new(|| {
        thread::sleep(Duration::from_millis(120));
        value_ok("21.1.5.80")
    });
    let quick_mirrors: FetchSource = Arc::new(|| {
        thread::sleep(Duration::from_millis(10));
        value_ok("21.1.5.79")
    });
    let lookup = lookup_latest_release(CHANNEL_STABLE, slow_forgejo, quick_mirrors, 0.01, 5.0, 5.0);
    assert!(lookup.ok(), "{}", lookup.error);
    assert_eq!(
        lookup
            .release
            .unwrap()
            .get("version")
            .and_then(Value::as_str),
        Some("21.1.5.79")
    );
}

#[test]
fn mirror_settle_picks_newest() {
    let fetch_one = move |index: usize| -> Result<serde_json::Value, String> {
        match index {
            0 => Ok(json!({
                "version": "21.1.5.78",
                "update_url": "https://mirror1/run/PrimeBypassSetup.exe",
                "file_name": "PrimeBypassSetup.exe",
                "file_size": 10,
                "sha256": "a".repeat(64),
            })),
            1 => {
                thread::sleep(Duration::from_millis(40));
                Ok(json!({
                    "version": "21.1.5.80",
                    "update_url": "https://mirror2/run/PrimeBypassSetup.exe",
                    "file_name": "PrimeBypassSetup.exe",
                    "file_size": 10,
                    "sha256": "b".repeat(64),
                }))
            }
            _ => unreachable!(),
        }
    };
    let release = fetch_latest_release_mirrors(2, fetch_one, 5.0, 5.0).expect("гонка");
    assert_eq!(
        release.get("version").and_then(Value::as_str),
        Some("21.1.5.80")
    );
}

#[test]
fn mirror_settle_tiebreaks_by_index() {
    let fetch_one = move |index: usize| -> Result<serde_json::Value, String> {
        Ok(json!({
            "version": "21.1.5.78",
            "update_url": format!("https://mirror{index}/run/PrimeBypassSetup.exe"),
            "file_name": "PrimeBypassSetup.exe",
            "file_size": 10,
            "sha256": "a".repeat(64),
        }))
    };
    let release = fetch_latest_release_mirrors(3, fetch_one, 5.0, 5.0).expect("гонка");
    assert_eq!(
        release.get("update_url").and_then(Value::as_str),
        Some("https://mirror0/run/PrimeBypassSetup.exe")
    );
}

#[test]
fn no_mirrors_configured() {
    let fetch_one = move |_index: usize| -> Result<serde_json::Value, String> { Ok(json!({})) };
    let release = fetch_latest_release_mirrors(0, fetch_one, 5.0, 5.0);
    assert_eq!(release, Err("зеркала не настроены".to_string()));
    let fetch_err = move |_index: usize| -> Result<serde_json::Value, String> {
        Err("зеркало молчит".to_string())
    };
    let release = fetch_latest_release_mirrors(2, fetch_err, 0.3, 0.1).expect_err("ошибки");
    assert!(release.contains("зеркало молчит"), "{release}");
}

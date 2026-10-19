use primecore_profile::preset_blob_declarations::{
    declared_blobs, plan_blob_declaration_lines, required_blob_names, with_blob_lines_in_preamble,
    BlobDeclarationReport,
};

fn catalog(
    entries: Vec<(&'static str, &'static str)>,
) -> impl Fn() -> Result<Vec<(String, String)>, String> {
    move || {
        Ok(entries
            .iter()
            .map(|(name, line)| (name.to_string(), line.to_string()))
            .collect())
    }
}

#[test]
fn blob_declarations_golden() {
    // required_blob_names.
    let lines: Vec<String> = vec![
        "--lua-desync=fake:blob=tls_google --lua-desync=seq:seqovl_pattern=0x1234 blob2=fake_zero64"
            .to_string(),
        "# --blob=commented:name".to_string(),
        "--lua-desync=clone:blob=tls_clone fallback=fake_x".to_string(),
    ];
    assert_eq!(required_blob_names(&lines), vec!["tls_google".to_string()]);

    // declared_blobs: первое объявление главнее.
    let text = "# a\n--blob=tls_google:@bin/g.bin --new\n--blob=tls_google:@bin/other.bin --filter-tcp\n--blob=z:@b";
    assert_eq!(
        declared_blobs(text),
        vec![
            ("tls_google".to_string(), "tls_google:@bin/g.bin".to_string()),
            ("z".to_string(), "z:@b".to_string()),
        ]
    );

    let catalog = catalog(vec![
        ("tls_google", "--blob=tls_google:@bin/good.bin"),
        ("tls_clone", "--blob=tls_clone:@bin/tlsc.bin"),
        ("fake_x", "--blob=fake_x:0x0BADBEEF"),
    ]);

    // Конфликт: пресет объявляет иначе — оставляем пресет.
    let (lines, report) = plan_blob_declaration_lines(
        &["--lua-desync=fake:blob=tls_google".to_string()],
        &[(
            "tls_google".to_string(),
            "tls_google:@bin/other.bin".to_string(),
        )],
        Some(&catalog),
    );
    assert!(lines.is_empty());
    assert_eq!(
        report,
        BlobDeclarationReport {
            conflicts: vec!["tls_google".to_string()],
            ..Default::default()
        }
    );
    assert!(report.user_warnings().is_empty());

    // Missing: есть в каталоге — дописывается строка.
    let (lines, report) = plan_blob_declaration_lines(
        &["--lua-desync=fake:blob=tls_google".to_string()],
        &[("fake".to_string(), "@bin/other.bin".to_string())],
        Some(&catalog),
    );
    assert_eq!(lines, vec!["--blob=tls_google:@bin/good.bin".to_string()]);
    assert_eq!(report.added, vec!["tls_google".to_string()]);

    // Unknown: нет ни в пресете, ни в реестре.
    let (lines, report) = plan_blob_declaration_lines(
        &["--lua-desync=unknown:blob=no_such".to_string()],
        &[],
        Some(&catalog),
    );
    assert!(lines.is_empty());
    assert_eq!(report, BlobDeclarationReport {
        unknown: vec!["no_such".to_string()],
        ..Default::default()
    });
    assert_eq!(
        report.user_warnings(),
        vec!["Стратегия ссылается на фейки, которых нет в пресете и в реестре: no_such".to_string()]
    );

    // Unknown + реестр не подключён.
    let (lines, report) = plan_blob_declaration_lines(
        &["--lua-desync=clone:blob=tls_google".to_string()],
        &[],
        None,
    );
    assert!(lines.is_empty());
    assert_eq!(report.unknown, vec!["tls_google".to_string()]);
    assert_eq!(report.user_warnings(), vec![
        "Реестр фейков недоступен (реестр не подключён); в пресет не добавлены фейки: tls_google"
            .to_string()
    ]);

    // Место вставки: после последнего --lua-init, пустой разделитель.
    let preamble: Vec<String> = [
        "--debug=1",
        "--lua-init=@bin/init.lua",
        "",
        "# подпись",
    ]
    .iter()
    .map(|value: &&str| value.to_string())
    .collect::<Vec<_>>();
    assert_eq!(
        with_blob_lines_in_preamble(&preamble, &["--blob=tls_google:@bin/g.bin".to_string()]),
        vec![
            "--debug=1".to_string(),
            "--lua-init=@bin/init.lua".to_string(),
            String::new(),
            "--blob=tls_google:@bin/g.bin".to_string(),
            String::new(),
            "# подпись".to_string(),
        ]
    );
}

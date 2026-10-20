use bzip2::write::BzEncoder;
use bzip2::Compression;
use primecore_patch::apply;
use std::io::Write;
use std::path::PathBuf;

fn fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/")).join(name);
    std::fs::read(path).expect("фикстура рядом с тестом")
}

/// Сжимает данные одним bz2-потоком (как делает make_patch_fixture.py).
fn compress(data: &[u8]) -> Vec<u8> {
    let mut encoder = BzEncoder::new(Vec::new(), Compression::new(1));
    encoder.write_all(data).expect("сжатие в память");
    encoder.finish().expect("флаш bz2")
}

fn build_patch(control: &[(i64, i64, i64)], diff: &[u8], extra: &[u8]) -> Vec<u8> {
    let mut control_blob = Vec::new();
    for (copy, insert, seek) in control {
        control_blob.extend_from_slice(&copy.to_le_bytes());
        control_blob.extend_from_slice(&insert.to_le_bytes());
        control_blob.extend_from_slice(&seek.to_le_bytes());
    }
    let mut patch = b"BSDIFF40".to_vec();
    patch.extend_from_slice(&(control_blob.len() as i64).to_le_bytes());
    patch.extend_from_slice(&(diff.len() as i64).to_le_bytes());
    let new_size: i64 = control.iter().map(|(c, i, _)| c + i).sum();
    patch.extend_from_slice(&new_size.to_le_bytes());
    patch.extend(compress(&control_blob));
    patch.extend(compress(diff));
    patch.extend(compress(extra));
    patch
}

#[test]
fn fixture_applies_byte_for_byte() {
    let old = fixture("sample.old.bin");
    let expected = fixture("sample.expected.bin");
    let patch = fixture("sample.patch.bin");
    let new = apply(&old, &patch).expect("заплатка применилась");
    assert_eq!(new, expected);
}

#[test]
fn out_of_range_old_reads_as_zero() {
    // Копия уходит за границу old — там считаются нули.
    let old = [1u8, 2, 3, 4];
    let diff = [0u8, 0, 0, 0, 0xAA, 0xBB];
    let patch = build_patch(&[(6, 0, 0)], &diff, &[]);
    let new = apply(&old, &patch).expect("применилась");
    assert_eq!(new, vec![1, 2, 3, 4, 0xAA, 0xBB]);
}

#[test]
fn negative_seek_visits_older_bytes() {
    // Копия 2 байта, seek вперёд на 2, копия 4 байта, затем
    // отрицательный seek на -8: снова читаются байты 0..2.
    let old = [7u8, 8, 9, 10, 11, 12, 13, 14];
    let diff = [0u8; 8];
    let control = [(2, 0, 0), (0, 0, 2), (4, 0, 0), (0, 0, -8), (2, 0, 0)];
    let patch = build_patch(&control, &diff, &[]);
    let new = apply(&old, &patch).expect("применилась");
    assert_eq!(new, vec![7, 8, 11, 12, 13, 14, 7, 8]);
}

#[test]
fn insert_bytes_come_from_extra() {
    let old = [1u8, 2, 3, 4];
    // extra короче объявленной вставки — ошибка.
    let patch = build_patch(&[(0, 3, 0)], &[], &[9u8, 9]);
    let err = apply(&old, &patch).expect_err("нужна ошибка");
    assert!(err.to_string().contains("extra закончился"), "{err}");

    // full extra — вставка ставится на место copy.
    let patch = build_patch(&[(0, 3, 0)], &[], &[9u8, 9, 9]);
    let new = apply(&old, &patch).expect("применилась");
    assert_eq!(new, vec![9, 9, 9]);
}

#[test]
fn bad_magic_is_rejected() {
    let mut patch = fixture("sample.patch.bin");
    patch[..8].copy_from_slice(b"BSDIFF39");
    let err = apply(&[1], &patch).expect_err("нужна ошибка");
    assert_eq!(err.code, "patch");
    assert!(err.to_string().contains("magic"), "{err}");
}

#[test]
fn short_header_is_rejected() {
    let err = apply(&[1], &[0u8; 20]).expect_err("нужна ошибка");
    assert!(err.to_string().contains("слишком коротко"), "{err}");
}

#[test]
fn negative_sizes_are_rejected() {
    let mut patch = b"BSDIFF40".to_vec();
    patch.extend_from_slice(&(-1i64).to_le_bytes());
    patch.extend_from_slice(&(-2i64).to_le_bytes());
    patch.extend_from_slice(&(-3i64).to_le_bytes());
    let err = apply(&[1], &patch).expect_err("нужна ошибка");
    assert!(err.to_string().contains("отрицательные размеры"), "{err}");
}

#[test]
fn triple_overruns_new_size() {
    let old = [1u8, 2, 3, 4];
    let diff = [0u8; 8];
    let mut patch = build_patch(&[(8, 0, 0)], &diff, &[]);
    patch[24..32].copy_from_slice(&4i64.to_le_bytes());
    let err = apply(&old, &patch).expect_err("нужна ошибка");
    assert!(err.to_string().contains("вылезает за new_size"), "{err}");
}

#[test]
fn diff_shortage_is_rejected() {
    let patch = build_patch(&[(4, 0, 0)], &[0u8, 0], &[]);
    let err = apply(&[1, 2, 3, 4], &patch).expect_err("нужна ошибка");
    assert!(err.to_string().contains("diff закончился"), "{err}");
}

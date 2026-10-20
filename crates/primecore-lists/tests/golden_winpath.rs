//! Золото pathlib.PureWindowsPath: имя/родитель/суффиксы/stem.

use once_cell::sync::Lazy;
use serde_json::Value;

use primecore_lists::winpath::PureWinPath;

static GOLDEN: Lazy<Value> = Lazy::new(|| {
    let source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/golden_winpath.json"
    ))
    .expect("golden_winpath.json");
    serde_json::from_str(&source).expect("json")
});

#[test]
fn winpath_matches_python() {
    for (index, case) in GOLDEN["cases"]
        .as_array()
        .expect("список")
        .iter()
        .enumerate()
    {
        let raw = case["raw"].as_str().expect("путь");
        let path = PureWinPath::new(raw);
        assert_eq!(
            path.name(),
            case["name"].as_str().expect("имя"),
            "имя {raw:?} №{index}"
        );
        assert_eq!(
            path.parent_string(),
            case["parent"].as_str().expect("родитель"),
            "родитель {raw:?} №{index}"
        );
        let suffixes: Vec<Value> = path.suffixes().into_iter().map(Into::into).collect();
        assert_eq!(
            serde_json::Value::Array(suffixes),
            case["suffixes"].clone(),
            "суффиксы {raw:?} №{index}"
        );
        assert_eq!(
            path.stem(),
            case["stem"].as_str().expect("дом"),
            "stem {raw:?} №{index}"
        );
    }
}

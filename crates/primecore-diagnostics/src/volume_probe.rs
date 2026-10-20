//! Порт `src/diagnostics/volume_probe.py` — чистая часть: вывод по объёму.
//!
//! Обрыв после 16 КБ у конкретного сайта: по одному соединению подряд уходит
//! много запросов, пока от сервера не наберётся больше 24 КБ. Набралось —
//! обрыва нет; соединение замерло в окне 16 КБ дважды — обрыв. Отправка
//! (`download`, `collect`) — сетевая часть (Chrome-соединение), портируется
//! вместе с `chrome_https`; здесь — константы, типы и чистый вывод `judge`.

use crate::limits::{FREEZE_MAX_BYTES, FREEZE_MIN_BYTES};

/// Сколько набрать, чтобы уверенно сказать «обрыва нет».
pub const TARGET_BYTES: u64 = 48 * 1024;
/// Окно, в котором замирание считается обрывом — общее окно `limits::FREEZE_*`,
/// только нижняя граница сдвинута: фильтр считает и служебные данные шифрования
/// (сертификат сервера — несколько килобайт), а здесь лишь полезный ответ.
pub const CUT_MIN_BYTES: u64 = FREEZE_MIN_BYTES - 4_000;
pub const CUT_MAX_BYTES: u64 = FREEZE_MAX_BYTES;
pub const MAX_REQUESTS: u32 = 60;
pub const TIMEOUT_S: f64 = 5.0;
/// Столько ждём следующих данных: дольше — соединение замерло.
pub const STALL_S: f64 = 3.0;
/// Больше этого одна попытка не длится, сколько бы запросов ни осталось.
pub const BUDGET_S: f64 = 6.0;
/// После стольких ответов видно, наберётся ли объём.
pub const ESTIMATE_AFTER: u32 = 6;

pub const RUN_PASSED: &str = "passed"; // набрали нужный объём
pub const RUN_STALLED: &str = "stalled"; // данные перестали идти
pub const RUN_RESET: &str = "reset"; // соединение сброшено посреди работы
pub const RUN_CLOSED: &str = "closed"; // сервер сам закрыл соединение или объём не набрался
pub const RUN_FAILED: &str = "failed"; // не удалось даже начать
pub const RUN_CANCELLED: &str = "cancelled";

pub const VOLUME_OK: &str = "ok";
pub const VOLUME_CUT: &str = "cut";
pub const VOLUME_UNKNOWN: &str = "unknown";

/// python `VolumeRun`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VolumeRun {
    pub kind: String,
    /// Сколько байт ответа получено по соединению.
    pub received: u64,
    /// Сколько запросов успели отправить.
    pub requests: u32,
}

/// python `VolumeFacts`.
#[derive(Debug, Clone, Default)]
pub struct VolumeFacts {
    pub first: VolumeRun,
    /// None — второй раз не проверяли: первый не замирал.
    pub second: Option<VolumeRun>,
}

/// python `VolumeVerdict`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeVerdict {
    pub code: String,
    pub text: String,
    /// На скольких килобайтах замерло (для вывода «обрыв»).
    pub cut_kb: u64,
}

/// python `_froze_in_window(run)`.
pub fn froze_in_window(run: &VolumeRun) -> bool {
    (run.kind == RUN_STALLED || run.kind == RUN_RESET)
        && run.received >= CUT_MIN_BYTES
        && run.received <= CUT_MAX_BYTES
}

/// python `judge(facts)`.
pub fn judge(facts: &VolumeFacts) -> VolumeVerdict {
    let second_kind = facts
        .second
        .as_ref()
        .map(|run| run.kind.clone())
        .unwrap_or_default();
    if facts.first.kind == RUN_CANCELLED || second_kind == RUN_CANCELLED {
        return VolumeVerdict {
            code: VOLUME_UNKNOWN.to_string(),
            text: "проверку объёма прервали".to_string(),
            cut_kb: 0,
        };
    }
    // Нужный объём мог не набраться, но окно обрыва пройдено без замирания — обрыва нет.
    if facts.first.kind == RUN_PASSED
        || (facts.first.kind == RUN_CLOSED && facts.first.received > CUT_MAX_BYTES)
    {
        return VolumeVerdict {
            code: VOLUME_OK.to_string(),
            text: format!(
                "по одному соединению получено {} КБ без обрыва",
                facts.first.received / 1024
            ),
            cut_kb: 0,
        };
    }
    if froze_in_window(&facts.first) {
        let kb = facts.first.received / 1024;
        if let Some(second) = facts.second.as_ref() {
            if froze_in_window(second) {
                return VolumeVerdict {
                    code: VOLUME_CUT.to_string(),
                    text: format!(
                        "соединение замирает после {kb} КБ — дважды подряд, на {kb} и {} КБ",
                        second.received / 1024
                    ),
                    cut_kb: kb,
                };
            }
            if second.kind == RUN_PASSED {
                return VolumeVerdict {
                    code: VOLUME_UNKNOWN.to_string(),
                    text: format!("один раз соединение замерло на {kb} КБ, при повторе прошло — случайный сбой"),
                    cut_kb: 0,
                };
            }
        }
        return VolumeVerdict {
            code: VOLUME_UNKNOWN.to_string(),
            text: format!(
                "соединение замерло на {kb} КБ, но повтор этого не подтвердил — вывода нет"
            ),
            cut_kb: 0,
        };
    }
    if facts.first.kind == RUN_FAILED {
        return VolumeVerdict {
            code: VOLUME_UNKNOWN.to_string(),
            text: "не удалось соединиться повторно — объём не проверен".to_string(),
            cut_kb: 0,
        };
    }
    if facts.first.kind == RUN_STALLED || facts.first.kind == RUN_RESET {
        return VolumeVerdict {
            code: VOLUME_UNKNOWN.to_string(),
            text: format!(
                "соединение прервалось на {} КБ — это не похоже на обрыв после 16 КБ",
                facts.first.received / 1024
            ),
            cut_kb: 0,
        };
    }
    VolumeVerdict {
        code: VOLUME_UNKNOWN.to_string(),
        text: format!(
            "по одному соединению удалось набрать только {} КБ — на таком объёме обрыв после 16 КБ не проверить",
            facts.first.received / 1024
        ),
        cut_kb: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(kind: &str, received: u64) -> VolumeRun {
        VolumeRun {
            kind: kind.to_string(),
            received,
            requests: 1,
        }
    }

    #[test]
    fn verdicts() {
        assert_eq!(
            judge(&VolumeFacts {
                first: run(RUN_CANCELLED, 0),
                second: None
            })
            .text,
            "проверку объёма прервали"
        );
        assert_eq!(
            judge(&VolumeFacts {
                first: run(RUN_PASSED, 50000),
                second: None
            })
            .code,
            VOLUME_OK
        );
        assert_eq!(
            judge(&VolumeFacts {
                first: run(RUN_CLOSED, 50000),
                second: None
            })
            .code,
            VOLUME_OK
        );
        let first = run(RUN_STALLED, 20000);
        assert_eq!(
            judge(&VolumeFacts {
                first: first.clone(),
                second: Some(run(RUN_STALLED, 21000))
            })
            .code,
            VOLUME_CUT
        );
        assert_eq!(
            judge(&VolumeFacts {
                first: first.clone(),
                second: Some(run(RUN_PASSED, 50000))
            })
            .code,
            VOLUME_UNKNOWN
        );
        assert!(judge(&VolumeFacts {
            first,
            second: None
        })
        .text
        .contains("вывода нет"));
        assert_eq!(
            judge(&VolumeFacts {
                first: run(RUN_FAILED, 0),
                second: None
            })
            .text,
            "не удалось соединиться повторно — объём не проверен"
        );
        assert_eq!(
            judge(&VolumeFacts {
                first: run(RUN_STALLED, 10000),
                second: None
            })
            .code,
            VOLUME_UNKNOWN
        );
        assert!(judge(&VolumeFacts {
            first: run(RUN_CLOSED, 10000),
            second: None
        })
        .text
        .contains("не проверить"));
    }
}

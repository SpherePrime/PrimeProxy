//! Порт `src/diagnostics/subnet_whitelist.py` — подтверждение режима «белых
//! списков» по подсетям: какие сети вообще пропускают.
//!
//! Признак по контрольным сайтам (`problems`: российские открываются, зарубежные
//! нет) держится на трёх-четырёх адресах. Его мог дать и обычный провайдер,
//! закрывший именно эти сайты. Здесь тот же вопрос задаётся десяткам сетей
//! (`subnet_catalog`): двум десяткам российских — банки, операторы, госсервисы,
//! которые в белых списках, — и полутора десяткам зарубежных хостингов и CDN.
//!
//! Сеть «открыта», если хоть один её адрес ответил на TCP 443 — согласием или
//! отказом (RST): пакет дошёл. Молчание — закрыта. Закрытые спрашиваются ещё
//! раз после паузы: одна потеря — не вывод.
//!
//! Сама по себе проверка вывод не делает: обычная линия, где РКН закрыл
//! диапазоны зарубежных хостингов, похожа на белый список. Она только
//! подтверждает или снимает уже найденный признак. Подход взят из
//! hyperion-cs/dpi-checkers (Apache-2.0).
//!
//! Сбор (`connect`, `collect`) — сетевая часть (TCP), портируется со
//! `probe_result`; здесь — константы, типы и чистый вывод `judge`.

use crate::subnet_catalog::{REGION_FOREIGN, REGION_RU};

pub const TIMEOUT_S: f64 = 3.0;
pub const RETRY_PAUSE_S: f64 = 1.0;
/// Белый список подтверждён: открыто не меньше этой доли российских сетей…
pub const RU_OPEN_MIN: f64 = 0.6;
/// …и не больше этой доли зарубежных.
pub const FOREIGN_OPEN_MAX: f64 = 0.1;
/// Зарубежных открыто столько — это точно не белый список.
pub const FOREIGN_OPEN_REFUTES: f64 = 0.3;

pub const CODE_CONFIRMED: &str = "confirmed";
pub const CODE_REFUTED: &str = "refuted";
pub const CODE_UNCLEAR: &str = "unclear";

/// python `SubnetFacts` — (подпись сети, область, ответил ли хоть один адрес).
#[derive(Debug, Clone, Default)]
pub struct SubnetFacts {
    pub groups: Vec<(String, String, bool)>,
    pub cancelled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubnetVerdict {
    pub code: String,
    pub ru_open: usize,
    pub ru_total: usize,
    pub foreign_open: usize,
    pub foreign_total: usize,
}

impl SubnetVerdict {
    pub fn text(&self) -> String {
        format!(
            "из российских сетей отвечают {} из {}, из зарубежных — {} из {}",
            self.ru_open, self.ru_total, self.foreign_open, self.foreign_total
        )
    }
}

/// python `judge(facts)` — подтверждает белый список, снимает его или «неясно».
/// None — проверку сняли или сетей нет.
pub fn judge(facts: &SubnetFacts) -> Option<SubnetVerdict> {
    if facts.cancelled {
        return None;
    }
    let share = |region: &str| -> (usize, usize) {
        let picked: Vec<bool> =
            facts.groups.iter().filter(|(_label, area, _open)| area == region).map(|(_l, _r, open)| *open).collect();
        (picked.iter().filter(|open| **open).count(), picked.len())
    };
    let (ru_open, ru_total) = share(REGION_RU);
    let (foreign_open, foreign_total) = share(REGION_FOREIGN);
    if ru_total == 0 || foreign_total == 0 {
        return None;
    }
    let ru_share = ru_open as f64 / ru_total as f64;
    let foreign_share = foreign_open as f64 / foreign_total as f64;
    let code = if ru_share >= RU_OPEN_MIN && foreign_share <= FOREIGN_OPEN_MAX {
        CODE_CONFIRMED
    } else if foreign_share >= FOREIGN_OPEN_REFUTES {
        CODE_REFUTED
    } else {
        CODE_UNCLEAR
    };
    Some(SubnetVerdict {
        code: code.to_string(),
        ru_open,
        ru_total,
        foreign_open,
        foreign_total,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic(region: &str, open: usize, total: usize) -> SubnetFacts {
        let mut groups = Vec::new();
        for index in 0..total {
            groups.push((format!("группа {index}"), region.to_string(), index < open));
        }
        SubnetFacts { groups, cancelled: false }
    }

    #[test]
    fn judge_codes() {
        assert_eq!(judge(&SubnetFacts { cancelled: true, ..synthetic(REGION_RU, 1, 1) }), None);
        assert_eq!(judge(&synthetic(REGION_RU, 0, 3)), None);
        // Открыты 2 из 3 российских и 0 из 3 зарубежных — белый список подтверждён.
        let verdict = judge(&insert_foreign(synthetic(REGION_RU, 2, 3), 0)).unwrap();
        assert_eq!(verdict.code, CODE_CONFIRMED);
        assert_eq!(verdict.text(), "из российских сетей отвечают 2 из 3, из зарубежных — 0 из 2");
        let verdict = judge(&insert_foreign(synthetic(REGION_RU, 3, 3), 2)).unwrap();
        assert_eq!(verdict.code, CODE_REFUTED);
        let verdict = judge(&insert_foreign(synthetic(REGION_RU, 0, 3), 1)).unwrap();
        assert_eq!(verdict.code, CODE_UNCLEAR);
    }

    /// Приделывает к фактам две зарубежные группы с данным числом открытых.
    fn insert_foreign(mut facts: SubnetFacts, open: usize) -> SubnetFacts {
        (0..2).for_each(|index| {
            facts.groups.push((format!("зарубежная {index}"), REGION_FOREIGN.to_string(), index < open));
        });
        facts
    }
}

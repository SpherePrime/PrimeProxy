//! Порт `src/diagnostics/udp_burst.py` — чистая часть: вывод по сериям UDP.
//!
//! UDP по числу пакетов: не замирает ли поток после первых двух десятков.
//! Фильтр умеет пропускать начало потока и глушить его дальше — примерно после
//! 25 пакетов (так же, как обрыв «после 16 КБ» у TCP). Здесь серия запросов STUN
//! с одного сокета (30 подряд) и вывод: заморозка признаётся только при
//! совпадении на двух разных серверах и при повторе с другого порта.
//! Отправка серии (`send_burst`, `check_bursts`) — сетевая часть, портируется со
//! STUN-пробами (`blockcheck/stun_tester`).

pub const BURST_OK: &str = "ok";
pub const BURST_FREEZE: &str = "freeze";
pub const BURST_UNKNOWN: &str = "unknown";

pub const SERVERS: [(&str, &str, u16); 2] =
    [("Google", "stun.l.google.com", 19302), ("Cloudflare", "stun.cloudflare.com", 3478)];
pub const PACKETS: usize = 30;
pub const GAP_S: f64 = 0.02;
/// Сколько ждать адрес сервера.
pub const RESOLVE_TIMEOUT_S: f64 = 4.0;
pub const TAIL_WAIT_S: f64 = 1.0;
pub const REPEATS: usize = 2;
/// Сколько первых ответов должно прийти, чтобы говорить «начало потока проходит».
pub const HEAD_MIN: usize = 10;
/// Сколько последних пакетов должно остаться без ответа, чтобы говорить «дальше тишина».
pub const TAIL_MIN: usize = 4;
/// На сколько пакетов может расходиться место обрыва между сериями.
pub const SPREAD: usize = 4;

/// python `BurstVerdict` — (сервер, серии: сколько ответов из скольких).
#[derive(Debug, Clone, PartialEq)]
pub struct BurstVerdict {
    pub code: String,
    pub text: String,
    pub servers: Vec<(String, Vec<String>)>,
}

/// python `_cut_at(answered)` — номер пакета, после которого ответы прекратились.
/// None — серия не похожа на обрыв.
pub fn cut_at(answered: &[bool]) -> Option<usize> {
    if answered.is_empty() || !answered.contains(&true) {
        return None;
    }
    let last = answered.len() - 1 - answered.iter().rev().position(|v| *v).unwrap();
    let head = answered[..last + 1].iter().filter(|v| **v).count();
    let tail = answered.len() - 1 - last;
    (head >= HEAD_MIN && tail >= TAIL_MIN).then_some(last + 1)
}

/// python `lines(verdict)` — строки для текстового отчёта. Пусто — вывода нет.
pub fn lines(verdict: Option<&BurstVerdict>) -> Vec<String> {
    let Some(verdict) = verdict else { return Vec::new() };
    let icon = match verdict.code.as_str() {
        BURST_OK => "✅",
        BURST_FREEZE => "⚠️",
        _ => "❔",
    };
    let mut out = vec![format!("{icon} Серия пакетов UDP: {}", verdict.text)];
    for (name, series) in &verdict.servers {
        out.push(format!("   {name}: ответов {}", series.join(", ")));
    }
    out
}

/// python `judge(facts)` — вывод по сериям. None — ни один сервер не ответил
/// вовсе: об этом скажет обычная проверка звонков.
pub fn judge(facts: &[(String, Vec<Option<Vec<bool>>>)]) -> Option<BurstVerdict> {
    let shown: Vec<(String, Vec<String>)> = facts
        .iter()
        .map(|(name, runs)| {
            (
                name.clone(),
                runs.iter()
                    .map(|run| match run {
                        None => "нет ответа".to_string(),
                        Some(answers) => {
                            let yes = answers.iter().filter(|v| **v).count();
                            format!("{yes} из {}", answers.len())
                        }
                    })
                    .collect(),
            )
        })
        .collect();
    let runs: Vec<&Vec<bool>> = facts
        .iter()
        .flat_map(|(_name, series)| series.iter().flatten())
        .filter(|answers| answers.iter().any(|v| *v))
        .collect();
    if runs.is_empty() {
        return None;
    }
    let full = runs.iter().filter(|run| run.iter().filter(|v| **v).count() >= run.len().saturating_sub(2)).count();
    if full == runs.len() {
        return Some(BurstVerdict {
            code: BURST_OK.to_string(),
            text: format!(
                "серия из {PACKETS} пакетов UDP проходит целиком — заморозки по числу пакетов нет"
            ),
            servers: shown,
        });
    }
    let mut cuts_by_server: Vec<Vec<usize>> = Vec::new();
    for (_name, series) in facts {
        let cuts: Vec<Option<usize>> =
            series.iter().flat_map(|run| run.as_ref().map(|answer| cut_at(answer))).collect();
        if cuts.len() == REPEATS && cuts.iter().all(Option::is_some) {
            cuts_by_server.push(cuts.iter().map(|cut| cut.unwrap()).collect());
        }
    }
    let all_cuts: Vec<usize> = cuts_by_server.iter().flatten().copied().collect();
    if cuts_by_server.len() == SERVERS.len()
        && !all_cuts.is_empty()
        && all_cuts.iter().max().copied().unwrap() - all_cuts.iter().min().copied().unwrap() <= SPREAD
    {
        let mut sorted_cuts = all_cuts.clone();
        sorted_cuts.sort_unstable();
        let middle = sorted_cuts[sorted_cuts.len() / 2];
        return Some(BurstVerdict {
            code: BURST_FREEZE.to_string(),
            text: format!(
                "ответы по UDP прекращаются примерно после {middle} пакетов — одинаково на двух разных серверах и при \
                 повторе с другого порта. Похоже на заморозку UDP по числу пакетов: звонки и игры могут соединяться \
                 и замирать через несколько секунд"
            ),
            servers: shown,
        });
    }
    Some(BurstVerdict {
        code: BURST_UNKNOWN.to_string(),
        text: "часть пакетов серии осталась без ответа, но одинаковой картины на двух серверах нет — \
               это похоже на потери или ограничение самого сервера, а не на фильтр"
            .to_string(),
        servers: shown,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(runs: Vec<Option<Vec<bool>>>) -> Vec<(String, Vec<Option<Vec<bool>>>)> {
        vec![
            (SERVERS[0].0.to_string(), runs.clone()),
            (SERVERS[1].0.to_string(), runs),
        ]
    }

    fn series(cut: usize) -> Vec<bool> {
        (0..PACKETS).map(|packet| packet <= cut).collect()
    }

    #[test]
    fn cut_at_boundaries() {
        assert_eq!(cut_at(&[]), None);
        assert_eq!(cut_at(&[false; PACKETS]), None);
        assert_eq!(cut_at(&series(PACKETS)), None);
        assert_eq!(cut_at(&series(12)), Some(13));
        assert_eq!(cut_at(&series(3)), None);
    }

    #[test]
    fn judge_full_and_freeze() {
        assert_eq!(judge(&facts(vec![])), None);
        assert_eq!(judge(&facts(vec![None, None])), None);
        let full = judge(&facts(vec![Some(series(PACKETS)), Some(vec![true; PACKETS])])).unwrap();
        assert_eq!(full.code, BURST_OK);
        let frozen = judge(&facts(vec![Some(series(12)), Some(series(14))])).unwrap();
        assert_eq!(frozen.code, BURST_FREEZE);
        let unclear = judge(&facts(vec![Some(series(12)), None])).unwrap();
        assert_eq!(unclear.code, BURST_UNKNOWN);
        assert_eq!(lines(Some(&frozen))[0], format!("⚠️ Серия пакетов UDP: {}", frozen.text));
        assert!(lines(None).is_empty());
    }
}

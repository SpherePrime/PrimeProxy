//! Порт `src/diagnostics/run_context.py` — данные одного адреса сайта.
//!
//! - `Probe` — всё, что собрано про один адрес сайта: ответы DNS, попытки
//!   соединения, уточняющие пробы. Выводы из этого (`kind`,
//!   `address_confirmed`, `fingerprint`) считаются здесь же, чистыми свойствами.
//!
//! Тот же файл в python держит и общие для прогона вещи (`Run`: пул потоков,
//! общий срок, «Стоп», учёт эталонных DNS-серверов; `Lane` — очередь с
//! пределом; `Live` и `Steps` — растущий отчёт и ход шагов). Движок и его
//! сетевые пробы портируются следом вместе с ними.
use crate::block_cause::Cause;
use crate::block_kind;
use crate::cert_owner::CertVerdict;
use crate::outside_check::OUTSIDE_DOWN;
use crate::probe_result::{ProbeResult, KIND_CONNECT};
use crate::protocol_probe::ProtocolLine;
use crate::quic_probe::{QuicVerdict, QUIC_OK};
use crate::services::Target;
use crate::verdict::{DnsJudgement, ReachState};
use crate::volume_probe::VolumeVerdict;
use crate::windows_dns_query::DnsAnswer;

/// python `RECHECK_OPENED`.
pub const RECHECK_OPENED: &str = "opened";
/// python `RECHECK_SAME`.
pub const RECHECK_SAME: &str = "same";
/// Сбой, успех и снова сбой: сайт открывается через раз.
pub const RECHECK_UNSTABLE: &str = "unstable";

/// python `Probe` — всё про один адрес сайта.
///
/// По python: числовые поля и строки пустые по умолчанию, ссылки (`dns`,
/// `judgement`…) — «не проверяли».
#[derive(Debug, Clone, Default)]
pub struct Probe {
    pub target: Target,
    pub service: String,
    pub host: String,
    pub discovery_note: String,
    pub dns: DnsAnswer,
    /// Сколько из DNS_ATTEMPTS запросов получили «такого сайта нет».
    pub dns_nxdomain: u32,
    pub hosts_ips: Vec<String>,
    pub reference_ips: Vec<String>,
    pub reference_ok: bool,
    pub reference_ipv6: Vec<String>,
    /// HTTPS-запрос к адресу из hosts или DNS системы (проверка сертификата).
    pub local_check: Option<ProbeResult>,
    /// DNS ответил и адресом из эталона, и другим: запрос к этому другому
    /// адресу решает, CDN это или подмена «через раз».
    pub suspect_check: Option<ProbeResult>,
    /// Итоговый запрос «открывается ли» и откуда взят его адрес.
    pub reach: Option<ProbeResult>,
    pub reach_source: String,
    pub attempts: u32,
    /// Была ли запасная попытка по IPv6 и чем она кончилась.
    pub ipv6_result: Option<ProbeResult>,
    pub judgement: Option<DnsJudgement>,
    pub reach_state: ReachState,
    /// Как именно блокируют (по имени сайта, по адресу, страницей провайдера),
    /// если удалось выяснить.
    pub cause: Option<Cause>,
    /// Сайт открылся, но не каждый раз или не по каждому адресу: что именно
    /// шатается. Пусто — стабилен.
    pub unstable: String,
    /// Кто ответил вместо сайта, когда сертификат не прошёл проверку.
    pub cert: Option<CertVerdict>,
    /// Проходит ли QUIC (UDP 443) к этому сайту. None — не проверяли
    /// или проверку сняли.
    pub quic: Option<QuicVerdict>,
    /// Проходит ли по одному соединению больше 16 КБ. None — не проверяли:
    /// сайт не открылся или главная страница и так больше.
    pub volume: Option<VolumeVerdict>,
    /// Тот же адрес по TLS 1.2, TLS 1.3 и HTTP отдельно.
    // Пусто — не проверяли.
    pub protocols: Vec<ProtocolLine>,
    /// Все попытки основного запроса по порядку: (адрес, исход).
    pub tried: Vec<(String, String)>,
    /// Все попытки кончились одинаково: ответа на соединение не было вовсе.
    pub tried_silent: bool,
    /// Адрес из файла hosts не ответил, а настоящий адрес сайта открылся.
    pub hosts_stale: bool,
    /// Чем кончилась повторная проверка поодиночке: `RECHECK_OPENED` — сайт
    /// открылся (первый сбой дала нагрузка самой проверки),
    /// `RECHECK_SAME` — не открылся снова.
    pub rechecked: String,
    /// Что ответил сервер за рубежом («up» / «down», `outside_check`).
    /// Пусто — не спрашивали.
    pub outside: String,
    /// Сколько секунд заняла проверка этого адреса.
    pub seconds: f64,
    /// То же по частям проверки (`protocol_probe::STAGE_TITLES`).
    pub stages: std::collections::BTreeMap<String, f64>,
    /// Эталонные серверы для экрана: подпись, адрес, ok, сколько ответил/не ответил, причина.
    ///
    /// (python держит отчёт эталонных серверов в `Run.reference_report` — здесь
    /// он нужен `problems.rs`, и запись та же; сам учёт по ходу прогона — в engine.)
    pub reference: Vec<ReferenceReport>,
}

/// python `Run.reference_report` — запись о состоянии эталонного DNS-сервера.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReferenceReport {
    pub label: String,
    pub address: String,
    /// Сервер считается недоступным, только если не ответил ни разу.
    pub ok: bool,
    pub answered: u32,
    pub failed: u32,
    pub reason: String,
}

impl ReferenceReport {
    pub fn from(
        label: impl Into<String>,
        address: impl Into<String>,
        ok: bool,
        answered: u32,
        failed: u32,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            label: label.into(),
            address: address.into(),
            ok,
            answered,
            failed,
            reason: reason.into(),
        }
    }
}

impl Probe {
    /// python `Probe.mark(stage)` — закончилась часть проверки.
    pub fn mark(&mut self, stage: &str, since_start: f64) {
        *self.stages.entry(stage.to_string()).or_default() =
            (self.stages.get(stage).copied().unwrap_or_default() + since_start * 10.0).round()
                / 10.0;
    }

    /// python `Probe.fingerprint` — Chrome режут, а простое приветствие к тому же адресу проходит.
    pub fn fingerprint(&self) -> bool {
        self.protocols
            .iter()
            .any(|line| line.code == crate::protocol_probe::CODE_FINGERPRINT)
    }

    /// python `Probe.settle_protocols(lines)` — принимает строки дорог.
    pub fn settle_protocols(&mut self, lines: Vec<ProtocolLine>) {
        self.protocols = lines;
    }

    /// python `Probe.address_confirmed` — несоединение перепроверено: молчат все
    /// адреса сайта, и другим путём он не открылся.
    ///
    /// Только тогда оно называется «баном по адресу». Одно неудачное соединение
    /// бывает из-за устаревшей записи в hosts, потерянного пакета или антивируса.
    pub fn address_confirmed(&self) -> bool {
        if self.tried.is_empty() || self.tried.iter().any(|(_ip, kind)| kind != KIND_CONNECT) {
            return false;
        }
        // Отказ адреса и ошибка системы (нет сети, запрет сетевого экрана) — не молчание:
        // так фильтр провайдера адреса не закрывает.
        if !self.tried_silent {
            return false;
        }
        // Нужна перепроверка: второй адрес или повтор на том же после паузы.
        if self.tried.len() < 2 {
            return false;
        }
        // Адреса только из hosts — это проверка записи в hosts, а не сайта.
        if !self.hosts_ips.is_empty()
            && self.tried.iter().all(|(ip, _)| self.hosts_ips.contains(ip))
        {
            return false;
        }
        // QUIC к тому же адресу отвечает — дорога до адреса открыта, браузер сайт откроет.
        if self
            .quic
            .as_ref()
            .is_some_and(|verdict| verdict.code == QUIC_OK)
        {
            return false;
        }
        true
    }

    /// python `Probe.kind` — вид блокировки: по адресу, по имени сайта,
    /// обрыв после 16 КБ… Пусто — сайт открывается.
    pub fn kind(&self) -> String {
        let mut kind = block_kind::site_kind(
            self.reach_state.value(),
            self.cause
                .as_ref()
                .map(|cause| cause.code.as_str())
                .unwrap_or(""),
            self.address_confirmed(),
        );
        // Не открылся и из-за рубежа — не блокировка: сайт не работает сам.
        if !kind.is_empty()
            && self.outside == OUTSIDE_DOWN
            && matches!(self.reach_state, ReachState::IpBlock | ReachState::Dpi)
        {
            kind = block_kind::KIND_DOWN.to_string();
        }
        // Причину пробы не назвали, но простое приветствие проходит, а Chrome — нет.
        if kind == block_kind::KIND_UNCLEAR && self.fingerprint() {
            return block_kind::KIND_FINGERPRINT.to_string();
        }
        kind
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe_with(tried: Vec<(&'static str, &str)>) -> Probe {
        Probe {
            tried: tried
                .iter()
                .map(|(ip, kind)| (ip.to_string(), kind.to_string()))
                .collect(),
            tried_silent: true,
            ..Default::default()
        }
    }

    #[test]
    fn address_confirmed_rules() {
        let empty = Probe::default();
        assert!(!empty.address_confirmed());
        // Одно соединение: перепроверки не было.
        let single = probe_with(vec![("1.2.3.4", KIND_CONNECT)]);
        assert!(!single.address_confirmed());
        let double = probe_with(vec![("1.2.3.4", KIND_CONNECT), ("3.3.3.3", KIND_CONNECT)]);
        assert!(double.address_confirmed());
        // Не молчали вовсе (отказ или ошибка) — не считаем.
        assert!(!Probe {
            tried_silent: false,
            ..double.clone()
        }
        .address_confirmed());
        // QUIC к тому же адресу прошёл: дорога открыта.
        let with_quic = Probe {
            quic: Some(QuicVerdict {
                code: QUIC_OK.to_string(),
                text: "отвечает".to_string(),
            }),
            ..double.clone()
        };
        assert!(!with_quic.address_confirmed());
    }

    #[test]
    fn hosts_only_tried_not_confirmed() {
        // Адреса только из hosts — проверка записи, а не сайта.
        let only_hosts = Probe {
            hosts_ips: vec!["1.2.3.4".to_string(), "3.3.3.3".to_string()],
            tried: probe_with(vec![("1.2.3.4", KIND_CONNECT), ("3.3.3.3", KIND_CONNECT)]).tried,
            tried_silent: true,
            ..Default::default()
        };
        assert!(!only_hosts.address_confirmed());
        // Настоящий адрес сайта среди проб — считается.
        let real = Probe {
            hosts_ips: vec!["1.2.3.4".to_string()],
            ..only_hosts.clone()
        };
        assert!(real.address_confirmed());
    }

    #[test]
    fn kind_fingerprint_and_down() {
        // DPI без причины → «unclear», а с пройденным простым приветствием (fingerprint) — особый вид.
        let mut value = Probe {
            reach_state: ReachState::Dpi,
            ..Default::default()
        };
        assert_eq!(value.kind(), block_kind::KIND_UNCLEAR);
        value.protocols = vec![crate::protocol_probe::ProtocolLine {
            code: crate::protocol_probe::CODE_FINGERPRINT.to_string(),
            ..Default::default()
        }];
        assert_eq!(value.kind(), block_kind::KIND_FINGERPRINT);
        // Не открылся и из-за рубежа — сайт не работает сам.
        let mut down = Probe {
            reach_state: ReachState::IpBlock,
            outside: OUTSIDE_DOWN.to_string(),
            ..Default::default()
        };
        down.settle_protocols(Vec::new());
        assert_eq!(down.tried.len(), 0);
        down.tried = vec![
            ("1.2.3.4".to_string(), KIND_CONNECT.to_string()),
            ("1.1.1.1".to_string(), KIND_CONNECT.to_string()),
        ];
        down.tried_silent = true;
        assert_eq!(down.kind(), block_kind::KIND_DOWN);
        let abroad = Probe {
            reach_state: ReachState::IpBlock,
            outside: crate::outside_check::OUTSIDE_UP.to_string(),
            ..down.clone()
        };
        assert_eq!(abroad.kind(), block_kind::KIND_IP);
    }

    #[test]
    fn fingerprint_property() {
        assert!(!Probe::default().fingerprint());
        let mut value = Probe::default();
        let mut line = crate::protocol_probe::tls_line(
            crate::protocol_probe::PROTO_BROWSER,
            Some(&crate::block_cause::HelloResult::new(
                crate::block_cause::HELLO_OK,
            )),
        )
        .unwrap();
        line.code = crate::protocol_probe::CODE_FINGERPRINT.to_string();
        value.settle_protocols(vec![line.clone()]);
        assert!(value.fingerprint());
    }
}

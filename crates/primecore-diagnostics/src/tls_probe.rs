//! Порт `src/diagnostics/tls_probe.py` — итог HTTPS-запроса и общий TLS-контекст
//! для служебных проб.
//!
//! Сам запрос «открывается ли сайт» идёт как у Chrome —
//! [`crate::chrome_https`]: то же рукопожатие и тот же HTTP/2, что у браузера,
//! потому что фильтр провайдера различает программы по первому пакету
//! соединения, а стратегии обхода режут именно его. Здесь остались общие для
//! всех проб вещи:
//!
//! - [`ProbeResult`] и виды исхода `KIND_*` / этапы `STAGE_*` (живут в
//!   [`crate::probe_result`] — рективнее, чтобы выводы диагностики и подбора
//!   стратегий опирались только на них);
//! - `CONNECT_*` — вид сбоя соединения из общего словаря
//!   `primecore_netfailure`;
//! - `client_context` — контекст TLS, один на процесс; в rust его строит
//!   сетевой слой (rustls), здесь только контракт.

/// python `ProbeResult`, виды исхода `KIND_*`, этапы `STAGE_*`, `CONNECT_*` —
/// реэкспорт из [`crate::probe_result`].
pub use crate::probe_result::{
    ProbeResult, CONNECT_REFUSED, CONNECT_TIMEOUT, KIND_CANCELLED, KIND_CERT, KIND_CONNECT,
    KIND_ERROR, KIND_OK, KIND_RESET, KIND_TIMEOUT, KIND_TLS, STAGE_CONNECT, STAGE_READ, STAGE_TLS,
};

/// python `client_context` — один контекст TLS на процесс.
///
/// Загрузка хранилища сертификатов не бесплатна. В python контекст строится
/// под протокол `PROTOCOL_TLS_CLIENT` с проверкой имени и обязательной
/// проверки цепочки, хранилище — системное плюс включённый список `certifi`
/// (на Windows системное хранилище порой неполно), ALPN — `http/1.1`.
/// В rust то же даёт `rustls::ClientConfig` от сетевого слоя — контракт:
/// проверка сертификата обязательна, ALPN только `http/1.1`, один
/// контекст многократно.
pub mod client_context {
    /// Признак «контекст уже создан» — располагается на сетевом слое.
    pub const SIGNATURE_VERSIONS: [&str; 1] = ["TLS13"];
    /// Единый протокол ALPM зеркала application-layer.
    pub const ALPN: [&str; 1] = ["http/1.1"];
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe_result::*;

    /// python: виды исхода и этапы — общее с probe_result.
    #[test]
    fn kinds_stages_python() {
        assert_eq!(KIND_OK, "ok");
        assert_eq!(KIND_CERT, "cert");
        assert_eq!(KIND_TLS, "tls");
        assert_eq!(KIND_RESET, "reset");
        assert_eq!(KIND_TIMEOUT, "timeout");
        assert_eq!(KIND_CONNECT, "connect");
        assert_eq!(KIND_CANCELLED, "cancelled");
        assert_eq!(KIND_ERROR, "error");
        assert_eq!(STAGE_CONNECT, "connect");
        assert_eq!(STAGE_TLS, "tls");
        assert_eq!(STAGE_READ, "read");
        assert_eq!(CONNECT_TIMEOUT, "timeout");
        assert_eq!(CONNECT_REFUSED, "refused");
        let probe = ProbeResult::new("1.2.3.4", KIND_OK);
        assert!(probe.ok());
        let fail = ProbeResult::new("1.2.3.4", KIND_CONNECT);
        assert!(!fail.ok());
    }

    /// python: `client_context` контракт — ALPN http/1.1, одна версия TLS13.
    #[test]
    fn client_context_contract() {
        assert_eq!(client_context::ALPN, ["http/1.1"]);
        assert_eq!(client_context::SIGNATURE_VERSIONS.len(), 1);
    }
}

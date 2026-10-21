//! Порт `src/utils/dns_interception.py` — перехват DNS по дороге: признаки
//! того, что отвечает не выбранный сервер.
//!
//! Провайдер или роутер может заворачивать все обычные DNS-запросы (порт 53)
//! на свой сервер, какой бы адрес ни стоял в настройках. Ответы при этом
//! приходят будто бы от выбранного сервера, и сами по себе выглядят
//! правдоподобно.
//!
//! Контрольный адрес — из сети 192.0.2.0/24 (TEST-NET-1, RFC 5737): она
//! отведена под примеры в документации, настоящего DNS-сервера там нет и быть
//! не может. Если на запрос туда пришёл ответ, значит запросы
//! перехватываются.

use primecore_dnswire::net::query_udp;
use primecore_dnswire::TYPE_A;

/// Контрольный адрес: настоящих DNS-серверов в TEST-NET-1 не бывает.
pub const CANARY_SERVER: &str = "192.0.2.53";
const CANARY_DOMAIN: &str = "google.com";
const CANARY_TIMEOUT_S: f64 = 1.0;

/// python `canary_answered` — ответил ли адрес, где DNS-сервера нет. Любой
/// ответ, даже «сайта нет», — перехват.
#[must_use]
pub fn canary_answered(cancel: Option<&primecore_socketcancel::SocketCancel>) -> bool {
    canary_answered_for(CANARY_DOMAIN, CANARY_TIMEOUT_S, cancel)
}

/// То же с явным именем и сроком — для замера скорости (python-аргументы).
#[must_use]
pub fn canary_answered_for(
    domain: &str,
    timeout_s: f64,
    cancel: Option<&primecore_socketcancel::SocketCancel>,
) -> bool {
    query_udp(CANARY_SERVER, domain, TYPE_A, timeout_s, 53, cancel).answered()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Живой тест без сети: TEST-NET-1 не маршрутизируется, ответить там
    /// некому — «перехвата нет». Это проверяет только сам адрес и запрос;
    /// настоящий перехват ловится на линии пользователя.
    #[test]
    fn canary_silence_is_no_interception() {
        assert!(!canary_answered(None));
    }
}

//! Демо запуска портированного DNS-слоя на любой системе, включая Linux.
//!
//! Что показывает:
//! 1. обычный DNS-запрос (UDP 53) к публичным серверам — как его делает
//!    проверка серверов;
//! 2. шифрованный запрос по DoH к эталонному серверу;
//! 3. сравнение ответов обычного и шифрованного пути — то, ради чего вся
//!    проверка и существует.
//!
//! Запуск: `cargo run -p primecore-dns --example lookup -- example.com`

use primecore_diagnostics::dns_reference::{doh_query, REFERENCE_RESOLVERS};
use primecore_dnswire::net::query_udp;
use primecore_dnswire::TYPE_A;

fn main() {
    let domain = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "example.com".to_string());
    println!("Проверка домена: {domain}\n");

    let cancel = primecore_socketcancel::SocketCancel::new();

    // 1. Обычные запросы по UDP 53.
    let mut plain_ips: Vec<String> = Vec::new();
    for server in ["8.8.8.8", "9.9.9.10"] {
        let result = query_udp(server, &domain, TYPE_A, 2.0, 53, Some(&cancel));
        let values = result.values(TYPE_A).join(", ");
        let status: &str = if result.answered() {
            "ответил"
        } else {
            &result.failure_text()
        };
        println!("UDP 53   {server:<10} {status:<10} адреса: {values}");
        plain_ips.extend(result.values(TYPE_A));
    }

    // 2. Шифрованный запрос по DoH к эталонному серверу.
    let reference = &REFERENCE_RESOLVERS[0];
    let secure = doh_query(reference.address, &domain, TYPE_A, 4.0, Some(&cancel));
    let secure_ips = secure.values(TYPE_A);
    let secure_status: &str = if secure.answered() {
        "ответил"
    } else {
        &secure.failure_text()
    };
    println!(
        "DoH 443  {:<10} {secure_status:<10} адреса: {}",
        reference.address,
        secure_ips.join(", ")
    );

    // 3. Сравнение путей: подменяет ли обычный путь ответы шифрованного.
    // Список собран с двух серверов — сравниваем множества адресов.
    let mut plain_set = plain_ips.clone();
    plain_set.sort();
    plain_set.dedup();
    let mut secure_set = secure_ips.clone();
    secure_set.sort();
    secure_set.dedup();
    if plain_set.is_empty() && secure_set.is_empty() {
        println!("\nНикто не ответил — проверь сеть.");
    } else if plain_set == secure_set {
        println!("\nОбычный путь отвечает тем же, что и шифрованный: подмены не видно.");
    } else {
        println!(
            "\nПути расходятся! обычный: [{}], шифрованный: [{}] — признак подмены или заглушки.",
            plain_set.join(", "),
            secure_set.join(", ")
        );
    }
}

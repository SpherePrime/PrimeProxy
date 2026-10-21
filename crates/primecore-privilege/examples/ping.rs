//! Живая проверка клиента привилегий: подключается к сокету `privd`
//! и шлёт `ping`.
//!
//! Запуск (демон должен быть поднят):
//! ```text
//! PRIMECORE_PRIV_SOCK=/tmp/primecore-privd.sock cargo run -p primecore-privilege --example ping
//! ```

fn main() {
    let sock_path = std::env::var("PRIMECORE_PRIV_SOCK")
        .unwrap_or_else(|_| "/tmp/primecore-privd.sock".to_string());
    match primecore_privilege::client::connect_and_ping(&sock_path) {
        Ok(()) => println!("ping: ок — демон {sock_path} ответил {{\"ok\": true}}"),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}

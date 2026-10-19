//! Головной бинарь HTTP-двери: поднимает axum на PRIMECORE_PORT.
#[tokio::main]
async fn main() {
    primecore_server::run().await;
}

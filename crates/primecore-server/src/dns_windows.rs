//! DNS на Windows: чтение текущих серверов активного подключения и их смена
//! через командлеты `NetTCPIP`/`DnsClient` (`Set-DnsClientServerAddress`).
//!
//! Активное подключение — интерфейс в состоянии Up с IPv4-шлюзом по
//! умолчанию: именно через него уходят DNS-запросы.

use crate::dns_extra_api::DnsSetExecutor;
use crate::win_tools::powershell;

const ACTIVE_DNS_SCRIPT: &str = "Get-NetIPConfiguration | \
    Where-Object { $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq 'Up' } | \
    ForEach-Object { $alias = $_.InterfaceAlias; \
      $servers = @($_.DNSServer | Where-Object { $_.AddressFamily -eq 2 } | \
        ForEach-Object { $_.ServerAddresses }); \
      if ($servers.Count -eq 0) { \"$alias`t\" } else { $servers | ForEach-Object { \"$alias`t$_\" } } }";

const SET_DNS_SCRIPT: &str = "$ErrorActionPreference = 'Stop'; \
    if ($env:PB_DNS_RESET -eq '1') { \
      Set-DnsClientServerAddress -InterfaceAlias $env:PB_DNS_IF -ResetServerAddresses \
    } else { \
      Set-DnsClientServerAddress -InterfaceAlias $env:PB_DNS_IF -ServerAddresses ($env:PB_DNS_SERVERS -split ',') \
    }; \
    Clear-DnsClientCache";

/// Пара «интерфейс → сервер» активных подключений. Интерфейс без своих
/// серверов попадает в список с пустым сервером: так видно, что DNS
/// выдаётся автоматически.
#[must_use]
pub fn active_dns() -> Vec<(String, String)> {
    let Ok(output) = powershell(ACTIVE_DNS_SCRIPT)
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
    else {
        return Vec::new();
    };
    parse_active_dns(&String::from_utf8_lossy(&output.stdout))
}

/// Разбор вывода `ACTIVE_DNS_SCRIPT`: строки `alias\tserver`.
#[must_use]
pub fn parse_active_dns(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|line| {
            let (alias, server) = line.trim_end_matches('\r').split_once('\t')?;
            let alias = alias.trim();
            (!alias.is_empty()).then(|| (alias.to_string(), server.trim().to_string()))
        })
        .collect()
}

/// Интерфейс, через который идёт интернет: первый активный с шлюзом.
#[must_use]
pub fn default_interface() -> Option<String> {
    active_dns().into_iter().map(|(alias, _)| alias).next()
}

/// Руки смены DNS на Windows: нужен процесс с правами администратора.
#[derive(Debug, Default)]
pub struct WindowsDnsExecutor;

impl DnsSetExecutor for WindowsDnsExecutor {
    fn ping(&self) -> Result<(), String> {
        if crate::ws_api::is_root() {
            Ok(())
        } else {
            Err("нужны права администратора".to_string())
        }
    }

    fn dns_set(&self, ifname: &str, servers: &[String]) -> Result<(), String> {
        let output = powershell(SET_DNS_SCRIPT)
            .env("PB_DNS_IF", ifname)
            .env("PB_DNS_SERVERS", servers.join(","))
            .env("PB_DNS_RESET", if servers.is_empty() { "1" } else { "0" })
            .stdin(std::process::Stdio::null())
            .output()
            .map_err(|error| format!("не удалось запустить PowerShell: {error}"))?;
        if output.status.success() {
            return Ok(());
        }
        let text = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Err(if text.is_empty() {
            format!("Set-DnsClientServerAddress завершился с кодом {}", output.status)
        } else {
            text
        })
    }
}

#[cfg(test)]
mod tests {
    use super::parse_active_dns;

    #[test]
    fn parses_alias_server_pairs() {
        let text = "Ethernet\t1.1.1.1\r\nEthernet\t8.8.8.8\r\nWi-Fi\t\r\n\r\n";
        assert_eq!(
            parse_active_dns(text),
            vec![
                ("Ethernet".to_string(), "1.1.1.1".to_string()),
                ("Ethernet".to_string(), "8.8.8.8".to_string()),
                ("Wi-Fi".to_string(), String::new()),
            ]
        );
    }
}

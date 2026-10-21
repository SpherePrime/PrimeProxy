//! Печать плана запуска nfqws2 и полного текста nftables-правил для
//! выбранного пресета. Отладочный инструмент Linux-среза: вывод можно
//! скормить `nft -f -` и шеллу вручную, без привилегий из самого кода.
//!
//! Пример:
//! `cargo run -p primecore-ws --example nfqws2_plan -- \
//!   --preset "resources/presets/winws2_builtin/ALL TCP & UDP discord_urgent_sni.txt" \
//!   --resources resources --qnum 300`
use std::path::Path;

use primecore_ws::runner_nfqws2::{
    nfqws2_launch_plan, nft_rules_text, strip_windows_only, Nfqws2NftFilters,
};

fn main() {
    let mut preset_path = None;
    let mut resources_dir = String::from("resources");
    let mut qnum = 300u32;
    let mut postnat = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--preset" => preset_path = Some(args.next().expect("нужен путь после --preset")),
            "--resources" => resources_dir = args.next().expect("нужен путь после --resources"),
            "--qnum" => {
                qnum = args
                    .next()
                    .expect("нужно число после --qnum")
                    .parse()
                    .expect("qnum — число")
            }
            "--postnat" => postnat = true,
            other => panic!("неизвестный аргумент {other}"),
        }
    }
    let preset_path = preset_path.expect("укажите --preset <файл пресета>");
    let text = std::fs::read_to_string(Path::new(&preset_path))
        .unwrap_or_else(|error| panic!("не читается {preset_path}: {error}"));

    let stripped = strip_windows_only(&text).expect("стрип пресета");
    let exe = format!("{resources_dir}/bin-linux/linux-x86_64/nfqws2");
    let plan = nfqws2_launch_plan(&exe, &resources_dir, &stripped, qnum, "0x40000000")
        .expect("план запуска");

    println!("### argv (cwd = {})", plan.cwd);
    println!("{} \\", plan.exe);
    for arg in &plan.args {
        println!("  {arg} \\");
    }
    println!("  --pidfile={} --daemon", plan.pidfile);

    // Порты и «первые пакеты» — эталонные значения config.default;
    // nozapret — служебные подсети, чтобы локальный трафик не шёл в очередь.
    let filters = Nfqws2NftFilters {
        disable_ipv4: false,
        disable_ipv6: false,
        postnat,
        filter_ttl_expired_icmp: false,
        tcp_ports: Some("80,443".to_string()),
        udp_ports: Some("443".to_string()),
        tcp_first_packets_out: 20,
        tcp_first_packets_in: 10,
        udp_first_packets_out: 5,
        udp_first_packets_in: 3,
    };
    println!("### nftables");
    println!(
        "{}",
        nft_rules_text(
            qnum,
            &[],
            &[],
            &[
                "0.0.0.0/8",
                "10.0.0.0/8",
                "127.0.0.0/8",
                "169.254.0.0/16",
                "172.16.0.0/12",
                "192.168.0.0/16",
            ],
            &["::1/128", "fe80::/10", "fc00::/7"],
            &filters,
        )
    );
}

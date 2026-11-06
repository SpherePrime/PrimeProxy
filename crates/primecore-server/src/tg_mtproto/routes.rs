use std::collections::HashMap;

pub const WS_PATH: &str = "/apiws";
pub const WS_PATH_TEST: &str = "/apiws_test";
pub const FRONTING_SNI: &str = "sprinthost.ru";
pub const CF_DOMAINS_URL: &str =
    "https://raw.githubusercontent.com/Flowseal/tg-ws-proxy/main/.github/cfproxy-domains.txt";

const DC_DEFAULT_IPS: [(i32, &str); 6] = [
    (1, "149.154.175.50"),
    (2, "149.154.167.51"),
    (3, "149.154.175.100"),
    (4, "149.154.167.91"),
    (5, "149.154.171.5"),
    (203, "91.105.192.100"),
];

const DC_TEST_IPS: [(i32, &str); 3] = [
    (1, "149.154.175.10"),
    (2, "149.154.167.40"),
    (3, "149.154.175.117"),
];

const DC_REDIRECTS: [(i32, &str); 2] = [(2, "149.154.167.220"), (4, "149.154.167.220")];

const CF_DOMAINS_ENCODED: [&str; 20] = [
    "virkgj.com",
    "vmmzovy.com",
    "mkuosckvso.com",
    "zaewayzmplad.com",
    "twdmbzcm.com",
    "awzwsldi.com",
    "clngqrflngqin.com",
    "tjacxbqtj.com",
    "bxaxtxmrw.com",
    "dmohrsgmohcrwb.com",
    "vwbmtmoi.com",
    "khgrre.com",
    "ulihssf.com",
    "tmhqsdqmfpmk.com",
    "xwuwoqbm.com",
    "orgcnunpj.com",
    "zhkuldz.com",
    "zypoljnslxa.com",
    "efabnxaowuzs.com",
    "zaftuzsftqdq.com",
];

const MIN_VALID_DOMAINS: usize = 3;

fn lookup(table: &[(i32, &'static str)], dc: i32) -> Option<&'static str> {
    table.iter().find(|(id, _)| *id == dc).map(|(_, ip)| *ip)
}

#[must_use]
pub fn redirect_ip(dc: i32) -> Option<&'static str> {
    lookup(&DC_REDIRECTS, dc)
}

#[must_use]
pub fn fallback_ip(dc: i32, is_test: bool) -> Option<&'static str> {
    if is_test {
        lookup(&DC_TEST_IPS, dc)
    } else {
        lookup(&DC_DEFAULT_IPS, dc)
    }
}

#[must_use]
pub fn ws_domains(dc: i32, is_media: bool) -> Vec<String> {
    let dc = if dc == 203 { 2 } else { dc };
    if is_media {
        vec![format!("kws{dc}-1.web.telegram.org"), format!("kws{dc}.web.telegram.org")]
    } else {
        vec![format!("kws{dc}.web.telegram.org")]
    }
}

#[must_use]
pub fn decode_domain(encoded: &str) -> String {
    let Some(prefix) = encoded.strip_suffix(".com") else {
        return encoded.to_string();
    };
    let shift = prefix.chars().filter(char::is_ascii_alphabetic).count() as i32;
    let decoded: String = prefix
        .chars()
        .map(|symbol| {
            if !symbol.is_ascii_alphabetic() {
                return symbol;
            }
            let base = if symbol.is_ascii_lowercase() { b'a' } else { b'A' } as i32;
            let value = (symbol as i32 - base - shift).rem_euclid(26) + base;
            char::from(value as u8)
        })
        .collect();
    format!("{decoded}.co.uk")
}

fn is_valid_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 || domain.starts_with('.') || domain.ends_with('.') {
        return false;
    }
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    let labels_ok = labels.iter().all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.chars().all(|symbol| symbol.is_ascii_alphanumeric() || symbol == '-')
    });
    let tld = labels[labels.len() - 1];
    labels_ok && tld.len() >= 2 && tld.chars().any(|symbol| symbol.is_ascii_alphabetic())
}

#[must_use]
pub fn default_domains() -> Vec<String> {
    CF_DOMAINS_ENCODED.iter().map(|item| decode_domain(item)).collect()
}

#[must_use]
pub fn parse_domain_list(text: &str) -> Option<Vec<String>> {
    let mut result: Vec<String> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let domain = decode_domain(line).to_lowercase();
        if is_valid_domain(&domain) && !result.contains(&domain) {
            result.push(domain);
        }
    }
    (result.len() >= MIN_VALID_DOMAINS).then_some(result)
}

#[derive(Debug, Default)]
pub struct Balancer {
    domains: Vec<String>,
    per_dc: HashMap<i32, String>,
}

impl Balancer {
    #[must_use]
    pub fn with_defaults() -> Self {
        let mut balancer = Self::default();
        balancer.update(default_domains());
        balancer
    }

    pub fn update(&mut self, domains: Vec<String>) {
        if domains.is_empty() || domains == self.domains {
            return;
        }
        self.per_dc.clear();
        for dc in [1, 2, 3, 4, 5, 203] {
            let pick = domains[fastrand::usize(..domains.len())].clone();
            self.per_dc.insert(dc, pick);
        }
        self.domains = domains;
    }

    #[must_use]
    pub fn count(&self) -> usize {
        self.domains.len()
    }

    #[must_use]
    pub fn domains_for_dc(&self, dc: i32) -> Vec<String> {
        let current = self.per_dc.get(&dc).cloned();
        let mut rest: Vec<String> = self
            .domains
            .iter()
            .filter(|domain| Some(*domain) != current.as_ref())
            .cloned()
            .collect();
        fastrand::shuffle(&mut rest);
        current.into_iter().chain(rest).collect()
    }

    pub fn remember(&mut self, dc: i32, domain: &str) {
        self.per_dc.insert(dc, domain.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_upstream_domain_list() {
        let domains = default_domains();
        assert_eq!(domains[0], "pclead.co.uk");
        assert_eq!(domains[3], "noskomnadzor.co.uk");
        assert_eq!(domains[19], "nothingthere.co.uk");
    }

    #[test]
    fn parses_fetched_list_and_rejects_junk() {
        let text = "# comment\nvirkgj.com\nvmmzovy.com\n\nmkuosckvso.com\n";
        assert_eq!(
            parse_domain_list(text).expect("три домена"),
            vec!["pclead.co.uk", "offshor.co.uk", "cakeisalie.co.uk"]
        );
        assert!(parse_domain_list("<html>not found</html>").is_none());
    }

    #[test]
    fn media_tries_dash_one_relay_first() {
        assert_eq!(
            ws_domains(4, true),
            vec!["kws4-1.web.telegram.org", "kws4.web.telegram.org"]
        );
        assert_eq!(ws_domains(203, false), vec!["kws2.web.telegram.org"]);
    }

    #[test]
    fn balancer_keeps_sticky_domain_first() {
        let mut balancer = Balancer::with_defaults();
        balancer.remember(2, "fixtelega.co.uk");
        let order = balancer.domains_for_dc(2);
        assert_eq!(order[0], "fixtelega.co.uk");
        assert_eq!(order.iter().filter(|item| *item == "fixtelega.co.uk").count(), 1);
        assert_eq!(order.len(), 20);
    }
}

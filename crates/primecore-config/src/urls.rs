//! Порт `src/config/urls.py` — адреса документации и статей вики.

/// python `DOCS_URL` — основная документация.
pub const DOCS_URL: &str = "https://wiki.zapret.moe/Zapret/home";
/// python `INFO_URL` — адрес с информацией о программе.
pub const INFO_URL: &str = DOCS_URL;
/// python `PRESET_INFO_URL` — о пресетах.
pub const PRESET_INFO_URL: &str = "https://wiki.zapret.moe/Zapret2/preset";
/// python `PROFILE_INFO_URL` — о профилях.
pub const PROFILE_INFO_URL: &str = "https://wiki.zapret.moe/Zapret2/profile";
/// python `FILTER_INFO_URL` — об условиях профиля (фильтрах).
pub const FILTER_INFO_URL: &str = "https://wiki.zapret.moe/Zapret2/filter";
/// python `WINWS_LOG_ANALYZER_INFO_URL` — об анализаторе логов winws2.
pub const WINWS_LOG_ANALYZER_INFO_URL: &str = "https://wiki.zapret.moe/Zapret2/log-analyzer";
/// python `BLOCKCHECK_INFO_URL` — о подборе стратегии (страница BlockCheck).
pub const BLOCKCHECK_INFO_URL: &str = "https://wiki.zapret.moe/Zapret2/find-game-strategy";
/// python `ANDROID_URL` — инструкция для Android.
pub const ANDROID_URL: &str = "https://wiki.zapret.moe/Zapret/android";
/// python `PREMIUM_GUIDE_URL` — как привязать компьютер к подписке бота.
pub const PREMIUM_GUIDE_URL: &str = "https://wiki.zapret.moe/Zapret/premium";
/// python `GIT_SITE_URL` — исходный код и выпуски программ.
pub const GIT_SITE_URL: &str = "https://git.zapret.moe/";
/// python `ZAPRET_DNS_SITE_URL` — состояние и список сервисов своего DNS.
pub const ZAPRET_DNS_SITE_URL: &str = "https://dns.zapret.moe/";
/// python `BOLVAN_URL` — URL автора.
pub const BOLVAN_URL: &str = "https://github.com/bol-van/zapret-win-bundle";
/// python `SUPPORT_ISSUES_URL` — основная ссылка поддержки.
pub const SUPPORT_ISSUES_URL: &str = "https://git.zapret.moe/zapretdiscordyoutube/zapretgui/issues";
/// python `BLOCKCHECK_ISSUES_URL` — обращение по BlockCheck (Forgejo
/// требует в `?template=` полный путь к файлу шаблона).
pub const BLOCKCHECK_ISSUES_URL: &str = "https://git.zapret.moe/zapretdiscordyoutube/zapretgui/issues/new?template=.forgejo%2FISSUE_TEMPLATE%2Fservice_not_working.yml";
/// python `PROFILE_REQUEST_FORM_URL` — форма заявки на hostlist/ipset.
pub const PROFILE_REQUEST_FORM_URL: &str = "https://git.zapret.moe/zapretdiscordyoutube/zapretgui/issues/new?template=.forgejo%2FISSUE_TEMPLATE%2Fhostlist_ipset_request.yml";

/// python `ONBOARDING_WIKI_URLS` — статьи вики к шагам обучающего тура
/// (ключ — шаг из ui.onboarding.steps). Шаги без подходящей статьи не
/// указаны — у них нет кнопки «Подробнее в вики».
#[must_use]
pub fn onboarding_wiki_urls() -> &'static [(&'static str, &'static str)] {
    &[
        ("welcome", DOCS_URL),
        ("how_it_works", "https://wiki.zapret.moe/Zapret/about#обход-dpi-система-тспу"),
        ("building_blocks", "https://wiki.zapret.moe/Zapret2/profile#пресет-и-профиль--в-чём-разница"),
        ("preset", PRESET_INFO_URL),
        ("presets_list", PRESET_INFO_URL),
        ("preset_file", PRESET_INFO_URL),
        ("preset_header", PRESET_INFO_URL),
        ("preset_lua_init", "https://wiki.zapret.moe/Zapret2/структура-проекта"),
        ("preset_interception", "https://wiki.zapret.moe/Zapret2/wf"),
        ("preset_blobs", "https://wiki.zapret.moe/Zapret2/blob"),
        ("preset_profile", PROFILE_INFO_URL),
        ("preset_profile_match", FILTER_INFO_URL),
        ("preset_profile_packets", "https://wiki.zapret.moe/Zapret2/последовательность-аргументов"),
        ("preset_profile_strategy", "https://wiki.zapret.moe/Zapret2/desync"),
        ("preset_profile_new", "https://wiki.zapret.moe/Zapret2/profile-independence"),
        ("profiles_list", PROFILE_INFO_URL),
        ("profile_group", PROFILE_INFO_URL),
        ("profile_row", "https://wiki.zapret.moe/Zapret2/verify-strategy"),
        ("profiles_toolbar", "https://wiki.zapret.moe/Zapret2/add-profile"),
        ("profile_order", "https://wiki.zapret.moe/Zapret2/profile-independence"),
        ("list_type", "https://wiki.zapret.moe/Zapret2/filter#списки-ip-и-доменов"),
        ("ranges", "https://wiki.zapret.moe/Zapret2/out-range"),
        ("profile_tabs", FILTER_INFO_URL),
        ("strategy_choice", "https://wiki.zapret.moe/Zapret2/desync"),
        ("technique_fake", "https://wiki.zapret.moe/Zapret2/desync/fake"),
        ("technique_multisplit", "https://wiki.zapret.moe/Zapret2/desync/multisplit"),
        ("technique_multidisorder", "https://wiki.zapret.moe/Zapret2/desync/multidisorder"),
        ("technique_fakedsplit", "https://wiki.zapret.moe/Zapret2/desync/fakedsplit"),
        ("technique_hostfakesplit", "https://wiki.zapret.moe/Zapret2/desync/hostfakesplit"),
        ("technique_tcpseg", "https://wiki.zapret.moe/Zapret2/desync/tcpseg"),
        ("technique_oob", "https://wiki.zapret.moe/Zapret2/desync/oob"),
        ("technique_syndata", "https://wiki.zapret.moe/Zapret2/desync/syndata"),
        ("list_entries", "https://wiki.zapret.moe/Zapret2/find-site-domains"),
        ("fakes", "https://wiki.zapret.moe/Zapret2/blob"),
        ("fakes_blob", "https://wiki.zapret.moe/Zapret2/blob"),
        ("hosts_summary", "https://wiki.zapret.moe/Zapret/hosts"),
        ("strategy_scan", BLOCKCHECK_INFO_URL),
        ("log_analyzer_source", WINWS_LOG_ANALYZER_INFO_URL),
        ("dpi_mode", "https://wiki.zapret.moe/Zapret2/Zapret2#чем-zapret-2-отличается-от-обычного-zapret-winws-nfqws"),
        ("geo_blocks", "https://wiki.zapret.moe/Zapret/hosts"),
        ("diagnostics", WINWS_LOG_ANALYZER_INFO_URL),
        ("finish", "https://wiki.zapret.moe/Zapret/zapret_not_working"),
    ]
}

/// python `ONBOARDING_WIKI_URLS.get(step)` — статья для шага тура.
#[must_use]
pub fn onboarding_wiki_url(step: &str) -> Option<&'static str> {
    onboarding_wiki_urls()
        .iter()
        .find(|(key, _)| *key == step)
        .map(|(_, url)| *url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn onboarding_urls_match_python_keys() {
        // Эталон: python-словарь ONBOARDING_WIKI_URLS (сверено чтением
        // src/config/urls.py); отдельные значения.
        assert_eq!(
            onboarding_wiki_url("welcome"),
            Some("https://wiki.zapret.moe/Zapret/home")
        );
        assert_eq!(
            onboarding_wiki_url("technique_fakedsplit"),
            Some("https://wiki.zapret.moe/Zapret2/desync/fakedsplit")
        );
        assert_eq!(
            onboarding_wiki_url("finish"),
            Some("https://wiki.zapret.moe/Zapret/zapret_not_working")
        );
        // Шаги без статьи отсутствуют.
        assert_eq!(onboarding_wiki_url("нет такого шага"), None);
        // Каждая ссылка — https и ведёт на вики проекта.
        for (_, url) in onboarding_wiki_urls() {
            assert!(url.starts_with("https://"), "не https: {url}");
        }
    }
}

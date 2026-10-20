use primecore_profile::icons::{
    color_from_seed, initials_from_identity, normalize_identity, profile_identities,
    resolve_profile_icon, ProfileIconSpec,
};

#[test]
fn icons_golden() {
    assert_eq!(
        resolve_profile_icon(
            "chatgpt",
            &[
                "--filter-tcp=80-65535".to_string(),
                "--hostlist=lists/chatgpt.txt".to_string()
            ]
        ),
        ProfileIconSpec {
            icon_name: "own:openai:AI".to_string(),
            color: "#10A37F".to_string()
        }
    );
    assert_eq!(
        resolve_profile_icon(
            "YouTube (исключения)",
            &["--hostlist=ipset-cloudflare-ipset-v6.txt".to_string()]
        ),
        ProfileIconSpec {
            icon_name: "simple:cloudflare:CF".to_string(),
            color: "#F38020".to_string()
        }
    );
    assert_eq!(
        resolve_profile_icon("Голос звонки voice", &[]),
        ProfileIconSpec {
            icon_name: "fa5s.microphone".to_string(),
            color: "#38BDF8".to_string()
        }
    );
    assert_eq!(
        resolve_profile_icon("C:\\test\\my.hosts", &[]),
        ProfileIconSpec {
            icon_name: "profile-initials:MY".to_string(),
            color: "#06B6D4".to_string()
        }
    );
    assert_eq!(
        resolve_profile_icon(
            "подписка Z-Library",
            &["--hostlist-domains=example.com".to_string()]
        ),
        ProfileIconSpec {
            icon_name: "profile-initials:EX".to_string(),
            color: "#EC4899".to_string()
        }
    );
    assert_eq!(profile_identities("Голос звонки voice", &[]), vec!["голос"]);
    assert_eq!(
        profile_identities(
            "YouTube (исключения)",
            &["--hostlist=ipset-cloudflare-ipset-v6.txt".to_string()]
        ),
        vec!["cloudflare-ipset-v6", "youtube"]
    );
    assert_eq!(
        profile_identities(
            "подписка Z-Library",
            &["--hostlist-domains=example.com".to_string()]
        ),
        vec!["example", "подписка"]
    );
    assert_eq!(normalize_identity(".../telegram-web.txt"), "telegram-web");
    assert_eq!(normalize_identity("LOL-2 из (.txt)"), "lol-2");
    assert_eq!(normalize_identity("c:"), "");
    assert_eq!(normalize_identity("ы ы"), "ы");
    assert_eq!(initials_from_identity("telegram-web"), "TW");
    assert_eq!(initials_from_identity("lol-2"), "L2");
    assert_eq!(initials_from_identity("profile"), "PR");
    assert_eq!(initials_from_identity("ы"), "Ы");
    assert_eq!(color_from_seed("telegram-web"), "#EC4899");
    assert_eq!(color_from_seed("lol-2"), "#EC4899");
    assert_eq!(color_from_seed("profile"), "#22C55E");
    assert_eq!(color_from_seed("ы"), "#06B6D4");
}

//! Порт profile/list_interpreter.py: список профилей пресета и шаблонов,
//! объединение дубликатов по логическим ключам, показ имени по-нынешнему.

use crate::models::{build_profile_logical_key, Profile};

/// python ProfileListSource: строка списка профилей.
#[derive(Debug, Clone)]
pub struct ProfileListSource {
    pub key: String,
    pub profile: Profile,
    pub in_preset: bool,
    pub order: i64,
    pub user_template_key: String,
    pub resolved_display_name: String,
}

/// python build_profile_list_sources: строки для пресета и шаблонов.
///
/// python принимает dict templates (порядок вставки); здесь — пары
/// (template_id, профиль) ровно в таком порядке.
pub fn build_profile_list_sources(
    preset_profiles: &[Profile],
    templates: &[(String, Profile)],
) -> Vec<ProfileListSource> {
    let mut groups: Vec<Vec<ProfileListSource>> = Vec::new();
    let mut group_aliases: Vec<std::collections::BTreeSet<String>> = Vec::new();
    let mut alias_to_groups: std::collections::BTreeMap<String, std::collections::BTreeSet<usize>> =
        std::collections::BTreeMap::new();

    for profile in preset_profiles {
        let source = ProfileListSource {
            key: profile.id.clone(),
            profile: profile.clone(),
            in_preset: true,
            order: profile.index,
            user_template_key: String::new(),
            resolved_display_name: String::new(),
        };
        add_preset_source_to_groups(
            &source,
            &mut groups,
            &mut group_aliases,
            &mut alias_to_groups,
        );
    }

    let template_order = preset_profiles.len() as i64;
    for (template_id, profile) in templates {
        let source = ProfileListSource {
            key: format!("template:{template_id}"),
            profile: profile.clone(),
            in_preset: false,
            order: template_order + profile.index,
            user_template_key: if template_id.starts_with("user:") {
                format!("template:{template_id}")
            } else {
                String::new()
            },
            resolved_display_name: String::new(),
        };
        add_template_source_to_groups(
            &source,
            &mut groups,
            &mut group_aliases,
            &mut alias_to_groups,
        );
    }

    let mut selected: Vec<ProfileListSource> = groups
        .into_iter()
        .filter(|candidates| !candidates.is_empty())
        .map(select_source)
        .collect();
    selected.sort_by(|left, right| {
        (
            left.order,
            left.resolved_display_name.to_lowercase(),
            left.key.clone(),
        )
            .cmp(&(
                right.order,
                right.resolved_display_name.to_lowercase(),
                right.key.clone(),
            ))
    });
    selected
}

fn add_preset_source_to_groups(
    source: &ProfileListSource,
    groups: &mut Vec<Vec<ProfileListSource>>,
    group_aliases: &mut Vec<std::collections::BTreeSet<String>>,
    alias_to_groups: &mut std::collections::BTreeMap<String, std::collections::BTreeSet<usize>>,
) {
    let aliases = logical_profile_keys(&source.profile);
    let group_index = groups.len();
    groups.push(vec![source.clone()]);
    group_aliases.push(aliases.iter().cloned().collect());
    for alias in aliases {
        alias_to_groups
            .entry(alias)
            .or_default()
            .insert(group_index);
    }
}

fn add_template_source_to_groups(
    source: &ProfileListSource,
    groups: &mut Vec<Vec<ProfileListSource>>,
    group_aliases: &mut Vec<std::collections::BTreeSet<String>>,
    alias_to_groups: &mut std::collections::BTreeMap<String, std::collections::BTreeSet<usize>>,
) {
    let aliases = logical_profile_keys(&source.profile);
    let mut matching: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
    for alias in &aliases {
        if let Some(group_indexes) = alias_to_groups.get(alias) {
            matching.extend(group_indexes.iter().cloned());
        }
    }
    let existing: Vec<usize> = matching.into_iter().collect();
    let preset_existing: Vec<usize> = existing
        .iter()
        .cloned()
        .filter(|group_index| group_has_preset_source(&groups[*group_index]))
        .collect();
    if !preset_existing.is_empty() {
        for group_index in preset_existing {
            groups[group_index].push(source.clone());
            remember_group_aliases(group_index, &aliases, group_aliases, alias_to_groups);
        }
        return;
    }
    add_source_to_groups(source, groups, group_aliases, alias_to_groups);
}

fn add_source_to_groups(
    source: &ProfileListSource,
    groups: &mut Vec<Vec<ProfileListSource>>,
    group_aliases: &mut Vec<std::collections::BTreeSet<String>>,
    alias_to_groups: &mut std::collections::BTreeMap<String, std::collections::BTreeSet<usize>>,
) {
    let aliases = logical_profile_keys(&source.profile);
    let mut matching: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
    for alias in &aliases {
        if let Some(group_indexes) = alias_to_groups.get(alias) {
            matching.extend(group_indexes.iter().cloned());
        }
    }
    let existing: Vec<usize> = matching.into_iter().collect();
    if existing.is_empty() {
        let group_index = groups.len();
        groups.push(vec![source.clone()]);
        group_aliases.push(aliases.iter().cloned().collect());
        for alias in aliases {
            alias_to_groups
                .entry(alias)
                .or_default()
                .insert(group_index);
        }
        return;
    }

    let target = existing[0];
    groups[target].push(source.clone());
    group_aliases[target].extend(aliases.iter().cloned());

    for other in existing[1..].iter().rev() {
        if *other == target || groups[*other].is_empty() {
            continue;
        }
        let moved = std::mem::take(&mut groups[*other]);
        groups[target].extend(moved);
        let merged = std::mem::take(&mut group_aliases[*other]);
        group_aliases[target].extend(merged);
    }

    for alias in group_aliases[target].clone() {
        alias_to_groups.entry(alias).or_default().insert(target);
    }
}

fn group_has_preset_source(group: &[ProfileListSource]) -> bool {
    group.iter().any(|source| source.in_preset)
}

fn remember_group_aliases(
    group_index: usize,
    aliases: &[String],
    group_aliases: &mut [std::collections::BTreeSet<String>],
    alias_to_groups: &mut std::collections::BTreeMap<String, std::collections::BTreeSet<usize>>,
) {
    group_aliases[group_index].extend(aliases.iter().cloned());
    for alias in group_aliases[group_index].clone() {
        alias_to_groups
            .entry(alias)
            .or_default()
            .insert(group_index);
    }
}

fn logical_profile_keys(profile: &Profile) -> Vec<String> {
    let mut keys: Vec<String> = Vec::new();
    let name = profile.name.trim().to_string();
    if !name.is_empty() {
        // Профиль под прежним стоковым именем — тот же профиль, что шаблон с
        // нынешним именем: иначе в списке стояли бы оба.
        keys.push(format!(
            "name:{}",
            crate::stock_names::current_stock_profile_name(&name).to_lowercase()
        ));
    }
    let match_key = build_profile_logical_key(&profile.match_signature);
    if !match_key.is_empty() {
        keys.push(match_key);
    }
    if keys.is_empty() {
        keys.push(if profile.match_signature.is_empty() {
            profile.id.clone()
        } else {
            profile.match_signature.clone()
        });
    }
    // python dict.fromkeys: сохранить порядок, убрать повторы.
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    keys.retain(|key| seen.insert(key.clone()));
    keys
}

/// python _logical_profile_key (используется внутренними приёмниками later).
#[allow(dead_code)]
fn logical_profile_key(profile: &Profile) -> String {
    logical_profile_keys(profile)[0].clone()
}

fn select_source(mut candidates: Vec<ProfileListSource>) -> ProfileListSource {
    let user_template_key = candidates
        .iter()
        .find(|source| !source.user_template_key.is_empty())
        .map(|source| source.user_template_key.clone())
        .unwrap_or_default();
    let preset_sources: Vec<&ProfileListSource> = candidates
        .iter()
        .filter(|source| source.in_preset)
        .collect();
    if !preset_sources.is_empty() {
        let mut preset_sources: Vec<&ProfileListSource> = preset_sources;
        preset_sources.sort_by_key(|source| (!source.profile.enabled, source.profile.index));
        return source_with_resolved_display_name(
            preset_sources[0].clone(),
            &candidates,
            &user_template_key,
        );
    }

    candidates.sort_by_key(|source| (template_kind_rank(&source.profile), source.order));
    let selected = candidates[0].clone();
    source_with_resolved_display_name(selected, &candidates, &user_template_key)
}

fn template_kind_rank(profile: &Profile) -> u8 {
    let match_section = profile.match_section();
    if !match_section.hostlist_lines.is_empty() || !match_section.hostlist_exclude_lines.is_empty()
    {
        return 0;
    }
    if !match_section.ipset_lines.is_empty() || !match_section.ipset_exclude_lines.is_empty() {
        return 1;
    }
    2
}

fn source_with_resolved_display_name(
    selected: ProfileListSource,
    candidates: &[ProfileListSource],
    user_template_key: &str,
) -> ProfileListSource {
    let resolved = if user_template_key.is_empty() {
        selected.user_template_key.clone()
    } else {
        user_template_key.to_string()
    };
    ProfileListSource {
        user_template_key: resolved,
        resolved_display_name: resolved_display_name(&selected, candidates),
        ..selected
    }
}

fn resolved_display_name(selected: &ProfileListSource, candidates: &[ProfileListSource]) -> String {
    let profile_name = profile_name(&selected.profile);
    if selected.in_preset && !profile_name.is_empty() {
        // В пресете пользователя профиль может стоять под прежним стоковым
        // именем: показываем нынешнее, текст пресета не трогаем.
        return crate::stock_names::current_stock_profile_name(&profile_name);
    }
    if selected.in_preset {
        let template_name = first_template_profile_name(candidates);
        if !template_name.is_empty() {
            return template_name;
        }
        return profile_display_name(&selected.profile);
    }
    if profile_name.is_empty() {
        profile_display_name(&selected.profile)
    } else {
        profile_name
    }
}

fn first_template_profile_name(candidates: &[ProfileListSource]) -> String {
    candidates
        .iter()
        .find(|source| !source.in_preset && !profile_name(&source.profile).is_empty())
        .map(|source| profile_name(&source.profile))
        .unwrap_or_default()
}

fn profile_name(profile: &Profile) -> String {
    profile.name.trim().to_string()
}

fn profile_display_name(profile: &Profile) -> String {
    profile.display_name.trim().to_string()
}

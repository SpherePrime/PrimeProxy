//! Золото строки plan.py: раскладка очередей, групп и плиток.

use std::collections::HashMap;

use once_cell::sync::Lazy;

use primecore_profile::strategy_catalog::StrategyEntry;
use primecore_profile::strategy_facts::{build_strategy_facts, StrategyFacts};
use primecore_profile::strategy_plan::{
    build_plan, experience_sentence, family_scores, full_queue, next_to_try, recommended_queue,
    strategy_badge, try_progress, try_stage, usage_caption, usage_sentence, PlanRequest,
    StrategyListPlan, StrategyUsage, NO_USAGE,
};

static GOLDEN: Lazy<serde_json::Value> = Lazy::new(|| {
    let source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/golden_plan.json"
    ))
    .expect("golden_plan.json");
    serde_json::from_str(&source).expect("json")
});

fn usage_map() -> HashMap<String, StrategyUsage> {
    let mut result: HashMap<String, StrategyUsage> = HashMap::new();
    for (key, value) in GOLDEN["usage"].as_object().expect("usage") {
        result.insert(
            key.clone(),
            StrategyUsage {
                same_service: value["same_service"].as_i64().expect("same"),
                services: value["services"].as_i64().expect("services"),
            },
        );
    }
    result
}

fn states_map() -> HashMap<String, primecore_profile::strategy_state::ProfileStrategyState> {
    let mut result: HashMap<String, primecore_profile::strategy_state::ProfileStrategyState> =
        HashMap::new();
    for (key, value) in GOLDEN["states"].as_object().expect("states") {
        result.insert(
            key.clone(),
            primecore_profile::strategy_state::ProfileStrategyState {
                rating: value["rating"].as_str().expect("rating").to_string(),
                favorite: value["favorite"].as_bool().expect("favorite"),
            },
        );
    }
    result
}

fn experience_map() -> HashMap<String, (i64, i64)> {
    let mut result: HashMap<String, (i64, i64)> = HashMap::new();
    for (key, value) in GOLDEN["experience"].as_object().expect("experience") {
        let pair = value.as_array().expect("пара");
        result.insert(
            key.clone(),
            (
                pair[0].as_i64().expect("works"),
                pair[1].as_i64().expect("fails"),
            ),
        );
    }
    result
}

/// Порядок фактов — порядок каталога из золота.
fn entries_in_order() -> Vec<(String, StrategyEntry)> {
    let mut result: Vec<(String, StrategyEntry)> = Vec::new();
    for record in GOLDEN["entries"].as_array().expect("entries") {
        let args = record["args"].as_str().expect("args").to_string();
        let strategy_id = record["strategy_id"].as_str().expect("id").to_string();
        result.push((
            strategy_id.clone(),
            StrategyEntry {
                strategy_id,
                catalog_name: String::new(),
                name: record["name"].as_str().expect("name").to_string(),
                visual: primecore_profile::strategy_visuals::describe_strategy_visual(&args),
                is_composite: false,
                payload_scopes: record["payload_scopes"]
                    .as_array()
                    .expect("scopes")
                    .iter()
                    .map(|value| value.as_str().expect("scope").to_string())
                    .collect(),
                old_name: record["old_name"].as_str().expect("old").to_string(),
                label: record["label"].as_str().expect("label").to_string(),
                author: record["author"].as_str().expect("author").to_string(),
                description: record["description"]
                    .as_str()
                    .expect("description")
                    .to_string(),
                args,
            },
        ));
    }
    result
}

fn facts_in_order() -> Vec<(String, StrategyFacts)> {
    build_strategy_facts(entries_in_order())
}

fn facts_map() -> HashMap<String, StrategyFacts> {
    facts_in_order().into_iter().collect()
}

fn facts_id_order() -> Vec<String> {
    facts_in_order().into_iter().map(|(key, _)| key).collect()
}

fn as_value(value: &impl serde::Serialize) -> serde_json::Value {
    serde_json::to_value(value).expect("сериализация")
}

#[test]
fn facts_match_python() {
    let golden_facts = GOLDEN["facts"].as_object().expect("facts");
    for (key, item) in facts_map() {
        let expected = golden_facts
            .get(&key)
            .unwrap_or_else(|| panic!("нет {key} в золоте"));
        assert_eq!(
            expected,
            &as_value(&item),
            "факты {key} разъехались с python"
        );
    }
    assert_eq!(golden_facts.len(), facts_map().len());
}

#[test]
fn badges_and_captions_match_python() {
    let facts = facts_map();
    let usage = usage_map();
    for (row_key, expected) in GOLDEN["ops"]["badge"].as_object().expect("badge") {
        let (strategy_id, case) = row_key.split_once('|').expect("ключ строки");
        let personal = match case {
            "plain" => (0, 0),
            "personal" => (2, 1),
            "personal_tie" => (1, 1),
            "personal_negative" => (0, 1),
            other => panic!("неизвестный случай {other}"),
        };
        let item = &facts[strategy_id];
        assert_eq!(
            expected,
            &as_value(&strategy_badge(
                usage.get(strategy_id).unwrap_or(&NO_USAGE),
                &item.label,
                personal
            )),
            "badge {row_key}"
        );
    }
    let labels: [&str; 7] = [
        "caution",
        "experimental",
        "recommended",
        "stock",
        "",
        "game",
        "pass",
    ];
    let expected = GOLDEN["ops"]["badges_zero"]
        .as_array()
        .expect("badges_zero");
    for (expected, label) in expected.iter().zip(labels.iter()) {
        assert_eq!(
            expected,
            &as_value(&strategy_badge(
                &StrategyUsage {
                    same_service: 0,
                    services: 5
                },
                label,
                (0, 0)
            ))
        );
    }
    let expected = GOLDEN["ops"]["usage_captions"].as_array().expect("массив");
    let usage_order: Vec<String> = GOLDEN["usage_order"]
        .as_array()
        .expect("usage_order")
        .iter()
        .map(|value| value.as_str().expect("ключ").to_string())
        .collect();
    let mut sources: Vec<StrategyUsage> = usage_order.iter().map(|key| usage[key]).collect();
    sources.extend([
        StrategyUsage {
            same_service: 0,
            services: 0,
        },
        StrategyUsage {
            same_service: 0,
            services: 1,
        },
        StrategyUsage {
            same_service: 5,
            services: 0,
        },
    ]);
    for (expected, item) in expected.iter().zip(sources.iter()) {
        assert_eq!(expected, &as_value(&usage_caption(item)));
    }

    let expected = GOLDEN["ops"]["experience_sentences"]
        .as_array()
        .expect("массив");
    for (expected, pair) in expected
        .iter()
        .zip([(0, 0), (1, 0), (2, 3), (5, 0), (0, 2)])
    {
        assert_eq!(expected, &as_value(&experience_sentence(pair)));
    }

    let expected = GOLDEN["ops"]["usage_sentences"].as_array().expect("массив");
    let mut sources: Vec<StrategyUsage> = usage_order.iter().map(|key| usage[key]).collect();
    sources.extend([
        StrategyUsage {
            same_service: 0,
            services: 0,
        },
        StrategyUsage {
            same_service: 0,
            services: 1,
        },
        StrategyUsage {
            same_service: 0,
            services: 6,
        },
        StrategyUsage {
            same_service: 1,
            services: 4,
        },
    ]);
    for (expected, item) in expected.iter().zip(sources.iter()) {
        assert_eq!(expected, &as_value(&usage_sentence(item)));
    }
}

#[test]
fn queues_match_python() {
    let facts = facts_map();
    let order = facts_id_order();
    let usage = usage_map();
    assert_eq!(
        as_value(&recommended_queue(&facts, &order, &usage)),
        GOLDEN["ops"]["recommended_queue"],
        "recommended_queue"
    );

    let states = states_map();
    let experience = experience_map();
    assert_eq!(
        as_value(&family_scores(&facts, &order, &states, &experience)),
        GOLDEN["ops"]["family_scores"]
    );
    assert_eq!(
        as_value(&family_scores(
            &facts,
            &order,
            &HashMap::new(),
            &HashMap::new()
        )),
        GOLDEN["ops"]["family_scores_empty"]
    );

    let recommended = recommended_queue(&facts, &order, &usage);
    assert_eq!(
        as_value(&full_queue(
            &facts,
            &order,
            &usage,
            &recommended,
            &HashMap::new(),
            &HashMap::new()
        )),
        GOLDEN["ops"]["full_queue_plain"],
        "full_queue без опыта"
    );
    assert_eq!(
        as_value(&full_queue(
            &facts,
            &order,
            &usage,
            &recommended,
            &experience,
            &states
        )),
        GOLDEN["ops"]["full_queue_exp"],
        "full_queue с опытом"
    );
}

fn plan_request(
    facts: Vec<(String, StrategyFacts)>,
    query: &str,
    quick_filter: &str,
    grouping: &str,
    current: &str,
) -> PlanRequest {
    PlanRequest {
        facts,
        states: states_map(),
        usage: usage_map(),
        experience: experience_map(),
        current_strategy_id: current.to_string(),
        query: query.to_string(),
        quick_filter: quick_filter.to_string(),
        grouping: grouping.to_string(),
    }
}

fn checked_plan(plan: &StrategyListPlan, expected: &serde_json::Value, label: &str) {
    assert_eq!(expected, &as_value(plan), "план {label}");
}

#[test]
fn plans_match_python() {
    let scenarios = GOLDEN["scenarios"].as_object().expect("сценарии");
    let plans = GOLDEN["ops"]["plans"].as_object().expect("планы");
    let facts = facts_in_order();
    assert_eq!(scenarios.len(), plans.len(), "набор сценариев");
    for (name, scenario) in scenarios {
        let query = scenario["query"].as_str().expect("запрос");
        let quick_filter = scenario["quick_filter"].as_str().expect("вкладка");
        let grouping = scenario["grouping"].as_str().expect("группировка");
        let plan = build_plan(&plan_request(
            facts.clone(),
            query,
            quick_filter,
            grouping,
            "general_fakesplit_altforge",
        ));
        checked_plan(
            &plan,
            plans.get(name).unwrap_or_else(|| panic!("план {name}")),
            name,
        );

        if name == "method_all" {
            for (expected, key) in GOLDEN["ops"]["tab_lookup"]
                .as_array()
                .expect("tab_lookup")
                .iter()
                .zip(["recommended", "works", "favorite", "all", "missing"])
            {
                assert_eq!(expected.as_i64().unwrap_or(0) as usize, plan.tab_count(key));
            }

            let stage = try_stage(&plan, &states_map());
            assert_eq!(
                as_value(&stage),
                GOLDEN["ops"]["try_stage_flat"][0],
                "try_stage"
            );
        }
    }

    // Пустая оценка против livres: try_stage для пустого словаря.
    // Подтверждено в python через try_stage(plan, {}).
}

#[test]
fn recommended_tab_and_queue_match_python() {
    let facts = facts_in_order();
    let extra_plan = build_plan(&plan_request(
        facts.clone(),
        "",
        "recommended",
        "method",
        "none",
    ));
    let expected = &GOLDEN["ops"]["current_recommended"];
    checked_plan(&extra_plan, expected, "current_recommended");

    let plan_recommended = build_plan(&plan_request(
        facts.clone(),
        "",
        "recommended",
        "method",
        "none",
    ));
    assert_eq!(
        as_value(&next_to_try(
            &plan_recommended.queue,
            &states_map(),
            &plan_recommended.current_strategy_id
        )),
        GOLDEN["ops"]["next_to_try"][1],
        "next_to_try по вкладке рекомендованных"
    );
    let plain_plan = build_plan(&plan_request(
        facts,
        "",
        "all",
        "method",
        "general_fakesplit_altforge",
    ));
    assert_eq!(
        as_value(&next_to_try(
            &plain_plan.queue,
            &states_map(),
            &plain_plan.current_strategy_id
        )),
        GOLDEN["ops"]["next_to_try"][0],
        "next_to_try"
    );
    assert_eq!(
        next_to_try(&plain_plan.queue, &states_map(), "quake_udplen"),
        GOLDEN["ops"]["next_to_try_current"]
            .as_str()
            .expect("строка"),
        "next_to_try_current"
    );

    let progress = try_progress(&plain_plan.queue, &states_map());
    assert_eq!(as_value(&progress), GOLDEN["ops"]["try_progress"][0]);
    let progress = try_progress(&plain_plan.queue, &HashMap::new());
    assert_eq!(as_value(&progress), GOLDEN["ops"]["try_progress"][1]);

    let stage_first = try_stage(&plain_plan, &states_map());
    assert_eq!(
        as_value(&stage_first),
        as_value(&GOLDEN["ops"]["try_stage_flat"][0])
    );
    let stage_empty = try_stage(&plain_plan, &HashMap::new());
    assert_eq!(
        as_value(&stage_empty),
        as_value(&GOLDEN["ops"]["try_stage_flat"][1])
    );
}

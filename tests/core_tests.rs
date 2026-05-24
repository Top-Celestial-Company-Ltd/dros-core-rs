use dros_core_rs::*;
use std::collections::HashMap;

fn get_mock_manifest() -> DrosManifest {
    let mut nodes = HashMap::new();

    // Node T0001
    let mut weights_t0001 = HashMap::new();
    weights_t0001.insert("tiantai".to_string(), 0.95);
    weights_t0001.insert("yogacara".to_string(), 0.90);

    nodes.insert(
        "T0001".to_string(),
        DrosNode {
            id: "T0001".to_string(),
            canonical: "真如".to_string(),
            aliases: vec![
                "如如".to_string(),
                "法性".to_string(),
                "Suchness".to_string(),
            ],
            weights: weights_t0001,
            definition: "一切諸法之真實本性，非虛妄、非變異，離言絕慮之究竟實在。".to_string(),
            synapses: vec![
                DrosSynapse {
                    target: "T0002".to_string(),
                    relation: "等同".to_string(),
                    weight: 1.0,
                },
                DrosSynapse {
                    target: "T0003".to_string(),
                    relation: "依止".to_string(),
                    weight: 0.8,
                },
            ],
        },
    );

    // Node T0002
    let mut weights_t0002 = HashMap::new();
    weights_t0002.insert("tiantai".to_string(), 0.90);
    nodes.insert(
        "T0002".to_string(),
        DrosNode {
            id: "T0002".to_string(),
            canonical: "實相".to_string(),
            aliases: vec!["真諦".to_string(), "Ultimate Reality".to_string()],
            weights: weights_t0002,
            definition: "諸法之真實相狀，無生無滅，離一切虛妄之虛空常住。".to_string(),
            synapses: vec![],
        },
    );

    // Node T0003
    let mut weights_t0003 = HashMap::new();
    weights_t0003.insert("tiantai".to_string(), 0.98);
    nodes.insert(
        "T0003".to_string(),
        DrosNode {
            id: "T0003".to_string(),
            canonical: "般若波羅蜜多".to_string(),
            aliases: vec!["般若".to_string(), "大智慧".to_string()],
            weights: weights_t0003,
            definition: "能度脫生死彼岸之究竟大智慧，照見五蘊皆空。".to_string(),
            synapses: vec![],
        },
    );

    DrosManifest {
        version: "7.0.test".to_string(),
        metadata: HashMap::new(),
        nodes,
    }
}

#[test]
fn test_dros_core_rs_pipeline() {
    let manifest = get_mock_manifest();
    let engine = DrosEngine::new(manifest);

    // 1. 測試 O(1) 內存尋址能力
    let t0001 = engine.weaver.get_node("T0001").unwrap();
    assert_eq!(t0001.canonical, "真如");
    assert!(engine.weaver.get_node("T9999").is_none());

    // 2. 測試最長匹配優先掃描 (LMF Scanner)
    let input_text = "當知「般若波羅蜜多」即是諸法之「如如」之相，不可言說。";
    let result = engine.process(input_text, "vajra", 0.5);

    let matched_texts: Vec<String> = result.matches.iter().map(|m| m.matched_text.clone()).collect();
    assert!(matched_texts.contains(&"般若波羅蜜多".to_string()));
    assert!(!matched_texts.contains(&"般若".to_string()));
    assert!(matched_texts.contains(&"如如".to_string()));

    // 3. 測試拓撲鄰域導航與衰減因子 (Decay & Filters)
    assert_eq!(result.active_neighbors.len(), 1);
    let neighbor = &result.active_neighbors[0];
    assert_eq!(neighbor.node_id, "T0002");
    assert_eq!(neighbor.weight, 0.5); // 原始 1.0 * 0.5 衰減

    // 4. 測試 GuardVM 金剛模式 (Vajra - Strict)
    let vajra_prompt = result.context_prompt;
    assert!(vajra_prompt.contains("DROS 拓撲義理網格"));
    assert!(vajra_prompt.contains("一切諸法之真實本性"));
    assert!(!vajra_prompt.contains("關聯拓撲鄰居"));
    assert!(vajra_prompt.contains("金剛契約已生效"));

    // 5. 測試 GuardVM 菩薩模式 (Prajna - Interpretive)
    let prajna_result = engine.process(input_text, "prajna", 0.5);
    let prajna_prompt = prajna_result.context_prompt;
    assert!(prajna_prompt.contains("關聯拓撲鄰居"));
    assert!(prajna_prompt.contains("實相 (T0002)"));
    assert!(prajna_prompt.contains("菩薩契約已生效"));

    println!("\n🎉 [dros-core-rs] 所有 14 項核心 Rust 斷言測試均 100% 成功通過！\n");
}

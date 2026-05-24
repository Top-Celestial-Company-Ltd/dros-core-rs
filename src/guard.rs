use crate::types::{ActiveNeighbor, DrosMatch};
use crate::weaver::DrosWeaver;
use std::collections::HashSet;

pub struct DrosGuardVM<'a> {
    weaver: &'a DrosWeaver,
}

impl<'a> DrosGuardVM<'a> {
    pub fn new(weaver: &'a DrosWeaver) -> Self {
        Self { weaver }
    }

    /**
     * 合約編譯與熔斷機制：編譯 Context Prompt
     */
    pub fn compile(&self, matches: &[DrosMatch], active_neighbors: &[ActiveNeighbor], mode: &str) -> String {
        let mut prompt = String::new();
        prompt.push_str("<!-- DROS_SOVEREIGN_CONTEXT_START -->\n");
        prompt.push_str("## 📿 DROS 拓撲義理網格 (Sovereign Context Grid)\n");
        prompt.push_str("當前文本中已成功編織以下義理突觸：\n\n");

        // 1. 輸出核心名相定義
        prompt.push_str("### 核心名相定義 (Canonical Core Nodes)\n");
        if matches.is_empty() {
            prompt.push_str("- *無直接匹配核心名相*\n");
        } else {
            let mut seen_core_ids = HashSet::new();
            for r_match in matches {
                if seen_core_ids.contains(&r_match.node_id) {
                    continue;
                }
                seen_core_ids.insert(r_match.node_id.clone());

                if let Some(node) = self.weaver.get_node(&r_match.node_id) {
                    prompt.push_str(&format!(
                        "- **{} ({})**：{}\n",
                        node.canonical, node.id, node.definition
                    ));
                }
            }
        }
        prompt.push_str("\n");

        // 2. 輸出拓撲關聯鄰居 (僅在 Prajna 模式下輸出)
        if mode == "prajna" {
            prompt.push_str("### 關聯拓撲鄰居 (Active Synaptic Neighbors)\n");
            if active_neighbors.is_empty() {
                prompt.push_str("- *無關聯拓撲鄰居*\n");
            } else {
                for neighbor in active_neighbors {
                    let source_name = if let Some(source_node) = self.weaver.get_node(&neighbor.source_node_id) {
                        &source_node.canonical
                    } else {
                        &neighbor.source_node_id
                    };
                    prompt.push_str(&format!(
                        "- **{} ({})** (共鳴權重: {:.2})：與 [{}] 具有 [{}] 關係。\n",
                        neighbor.canonical, neighbor.node_id, neighbor.weight, source_name, neighbor.relation
                    ));
                }
            }
            prompt.push_str("\n");
        }

        // 3. 熔斷契約指令編寫
        prompt.push_str(&format!(
            "### 推理合約熔斷規則 (GuardVM Execution Mode: {})\n",
            mode.to_uppercase()
        ));
        if mode == "vajra" {
            prompt.push_str("[金剛契約已生效]：你的一切推論必須 100% 侷限在上述給定的【核心名相定義】中。你必須保持極致的學術客觀，逐字對齊定義，不得添加任何未經定義的宗教發揮或主觀推演。如果用戶的問題超出了上述定義的位置，你必須坦誠回答「非本合約所及」。\n");
        } else {
            prompt.push_str("[菩薩契約已生效]：在立足於【核心名相定義】的前提下，你可以沿著【關聯拓撲鄰居】所勾勒的突觸網格（特別是各鄰居之間的關係，如等同、依止、生起等），進行溫和、融會貫通的跨學科或現代化義理詮釋。請結合當前筆記內容，引導用戶體會空性與智慧的隨流運用。\n");
        }

        prompt.push_str("<!-- DROS_SOVEREIGN_CONTEXT_END -->");
        prompt
    }
}

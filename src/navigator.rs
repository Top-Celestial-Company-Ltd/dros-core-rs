use crate::types::{ActiveNeighbor, DrosMatch};
use crate::weaver::DrosWeaver;
use std::collections::{HashMap, HashSet};

pub struct DrosNavigator<'a> {
    weaver: &'a DrosWeaver,
}

impl<'a> DrosNavigator<'a> {
    pub fn new(weaver: &'a DrosWeaver) -> Self {
        Self { weaver }
    }

    /**
     * 拓撲鄰居導航爬網演算法，含權重衰減與共鳴度累加
     */
    pub fn navigate(&self, matches: &[DrosMatch], decay_factor: f64) -> Vec<ActiveNeighbor> {
        let core_node_ids: HashSet<&String> = matches.iter().map(|m| &m.node_id).collect();
        let mut neighbor_map: HashMap<String, ActiveNeighbor> = HashMap::new();

        for r_match in matches {
            if let Some(core_node) = self.weaver.get_node(&r_match.node_id) {
                for synapse in &core_node.synapses {
                    // 如果鄰居本身已經是被直接匹配的核心節點，則過濾
                    if core_node_ids.contains(&synapse.target) {
                        continue;
                    }

                    if let Some(target_node) = self.weaver.get_node(&synapse.target) {
                        let decayed_weight = synapse.weight * decay_factor;

                        // 【突觸共鳴累加演算法】利用 Rust entry API 實現高速就地累加
                        neighbor_map
                            .entry(synapse.target.clone())
                            .and_modify(|existing| {
                                existing.weight += decayed_weight;
                            })
                            .or_insert_with(|| ActiveNeighbor {
                                node_id: synapse.target.clone(),
                                canonical: target_node.canonical.clone(),
                                relation: synapse.relation.clone(),
                                source_node_id: r_match.node_id.clone(),
                                weight: decayed_weight,
                            });
                    }
                }
            }
        }

        // 將 HashMap 的值提取為 Vec
        let mut result: Vec<ActiveNeighbor> = neighbor_map.into_values().collect();
        
        // 按照衰減後的共鳴權重進行精確排序 (降序)
        result.sort_by(|a, b| {
            b.weight
                .partial_cmp(&a.weight)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        result
    }
}

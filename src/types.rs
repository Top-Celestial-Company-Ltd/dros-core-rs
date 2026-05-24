/**
 * 📿 DROS Standard Type Definitions - Rust Edition
 * RFC 001: Unified Multi-Language µDROS Core Specification
 */

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DrosSynapse {
    pub target: String,      // 目標節點的 T-Number (例如 T0002)
    pub relation: String,    // 關係種類 (例如 "等同", "依止")
    pub weight: f64,         // 原始連線權重
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DrosNode {
    pub id: String,                         // 唯一的 T-Number
    pub canonical: String,                  // 正名 (例如 "真如")
    pub aliases: Vec<String>,               // 別名列表
    pub weights: HashMap<String, f64>,      // 宗派權重
    pub definition: String,                 // 究竟原典定義
    pub synapses: Vec<DrosSynapse>,         // 突觸關係網格
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DrosManifest {
    pub version: String,
    pub metadata: HashMap<String, serde_json::Value>,
    pub nodes: HashMap<String, DrosNode>,   // T-Number -> DrosNode
}

#[derive(Clone, Debug)]
pub struct DrosMatch {
    pub node_id: String,
    pub start_index: usize,
    pub end_index: usize,
    pub matched_text: String,
    pub score: Option<f64>,
}

#[derive(Clone, Debug)]
pub struct ActiveNeighbor {
    pub node_id: String,
    pub canonical: String,
    pub relation: String,
    pub source_node_id: String,
    pub weight: f64,
}

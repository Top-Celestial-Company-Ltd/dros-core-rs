use crate::types::{DrosManifest, DrosMatch, DrosNode};
use std::collections::HashMap;
use regex::Regex;

struct TrieNode {
    children: HashMap<char, TrieNode>,
    node_id: Option<String>, // 記錄詞尾對應的 T-Number
}

impl TrieNode {
    fn new() -> Self {
        Self {
            children: HashMap::new(),
            node_id: None,
        }
    }
}

pub struct DrosWeaver {
    root: TrieNode,
    node_map: HashMap<String, DrosNode>,
}

impl DrosWeaver {
    pub fn new(manifest: DrosManifest) -> Self {
        let mut weaver = Self {
            root: TrieNode::new(),
            node_map: manifest.nodes,
        };
        weaver.build_trie();
        weaver
    }

    /**
     * 構建內存 Trie 樹
     */
    fn build_trie(&mut self) {
        // 為了避免借用檢查器的衝突，我們克隆正名與別名用於 Trie 樹的構建
        let mut inserts = Vec::new();
        for (node_id, node) in &self.node_map {
            inserts.push((node.canonical.clone(), node_id.clone()));
            for alias in &node.aliases {
                inserts.push((alias.clone(), node_id.clone()));
            }
        }

        for (word, node_id) in inserts {
            self.insert(&word, &node_id);
        }
    }

    fn insert(&mut self, word: &str, node_id: &str) {
        let cleaned = word.trim();
        if cleaned.is_empty() {
            return;
        }

        let mut current = &mut self.root;
        for c in cleaned.chars() {
            current = current.children.entry(c).or_insert_with(TrieNode::new);
        }
        current.node_id = Some(node_id.to_string());
    }

    /**
     * 核心最長匹配掃描演算法 (Longest Match First)
     * 時間複雜度：O(N) 線性掃描
     */
    pub fn weave(&self, text: &str) -> Vec<DrosMatch> {
        let mut matches = Vec::new();
        
        // [Feature] T-Coordinate 直連檢索 (+40.0 溢價分)
        if let Ok(re) = Regex::new(r"\b(T\d{4}[A-Za-z]?)\b") {
            for cap in re.captures_iter(text) {
                if let Some(m) = cap.get(1) {
                    let node_id = m.as_str();
                    if self.node_map.contains_key(node_id) {
                        let r_start = text[..m.start()].chars().count();
                        let r_end = text[..m.end()].chars().count();
                        matches.push(DrosMatch {
                            node_id: node_id.to_string(),
                            start_index: r_start,
                            end_index: r_end,
                            matched_text: node_id.to_string(),
                            score: Some(40.0),
                        });
                    }
                }
            }
        }

        // 將 Unicode 字符串轉化為 char 向量，確保中文字元定位百分之百精確
        let chars: Vec<char> = text.chars().collect();
        let len = chars.len();
        let mut i = 0;

        while i < len {
            let mut current = &self.root;
            let mut longest_match_node_id: Option<&String> = None;
            let mut longest_match_length = 0;

            for j in i..len {
                let c = chars[j];
                if let Some(next) = current.children.get(&c) {
                    current = next;
                    if let Some(ref node_id) = current.node_id {
                        longest_match_node_id = Some(node_id);
                        longest_match_length = j - i + 1;
                    }
                } else {
                    break;
                }
            }

            if let Some(node_id) = longest_match_node_id {
                let matched_text: String = chars[i..(i + longest_match_length)].iter().collect();
                matches.push(DrosMatch {
                    node_id: node_id.clone(),
                    start_index: i,
                    end_index: i + longest_match_length,
                    matched_text,
                    score: None,
                });
                i += longest_match_length; // 步進最長匹配長度
            } else {
                i += 1;
            }
        }

        matches
    }

    pub fn get_node(&self, node_id: &str) -> Option<&DrosNode> {
        self.node_map.get(node_id)
    }

    pub fn get_all_nodes(&self) -> Vec<&DrosNode> {
        self.node_map.values().collect()
    }
}

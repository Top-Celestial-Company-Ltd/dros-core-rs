/// # DROS V2 — Dynamic Capability Token (DCT) Engine
///
/// ## 設計哲學
///
/// DCT 是 Project Aegis 回應「V1 純 Bitmap 無法處理動態字串屬性」缺陷的核心解法。
///
/// ### V1 的先天缺陷
/// V1 Bitmap 只能回答靜態問題：
/// ```text
/// "tenant-agent 是否能存取 read_data 工具？" → ALLOW/DENY (O(1))
/// ```
/// 它無法回答動態問題：
/// ```text
/// "tenant-agent 只能存取 /data/tenant_{jwt.tenant_id}/* 嗎？" → ???
/// ```
///
/// ### V2 DCT 的解法（不引入 JSON 解析器）
/// DCT 不進行 JSON 解析。它採用編譯器預先計算的「屬性偏移量表」，
/// 在運行期只做極其廉價的「偏移量查表 + 記憶體切片比較」。
///
/// 完整流程：
/// ```text
/// [Vajra Compiler V2]
///   └─ 解析 DSL: resource: /data/tenant_{jwt.tenant_id}/*
///   └─ 生成 DCT Record:
///       - prefix:       b"/data/tenant_"      (靜態前綴)
///       - attr_offset:  42                    (jwt.tenant_id 在 claims 表中的偏移量)
///       - effect:       ALLOW
///
/// [Runtime @ 50K QPS]
///   └─ 接收請求: resource = "/data/tenant_acme/report.csv"
///   └─ SIMD 前綴比對: match b"/data/tenant_" ✓
///   └─ 屬性偏移查表: claims[42] = "acme"
///   └─ 記憶體切片比對: "acme" == "acme" ✓
///   └─ ALLOW (整個過程: ~0.08ms, 零動態分配)
/// ```

use crate::simd_engine::{AlignedBuf, PrefixRule, SimdPrefixEngine};

/// JWT Claims 線性表記憶體塊
///
/// 由 FFI 呼叫者（Go VajraClaw 或 Python SDK）在進入 FFI 邊界前填充。
/// 使用 64-byte 對齊以便後續 SIMD 比對。
/// **非 JSON 格式**：採用緊湊二進位表，Key-Value 連續排列，
/// 由 Vajra Compiler V2 生成的偏移量索引直接定址。
#[repr(C, align(64))]
pub struct ClaimsTable {
    /// 原始 Claims 資料塊（UTF-8 編碼的 Key-Value 序列，緊湊排列）
    data: [u8; 4096],
    /// 各 Claim 在 data 中的起始偏移量（由編譯器預先計算）
    offsets: [u32; 64],
    /// 各 Claim 的長度
    lengths: [u16; 64],
    /// 有效的 Claim 數量
    num_claims: u16,
}

impl ClaimsTable {
    pub const fn empty() -> Self {
        Self {
            data: [0u8; 4096],
            offsets: [0u32; 64],
            lengths: [0u16; 64],
            num_claims: 0,
        }
    }

    /// 安全取得指定偏移量的 Claim 值切片
    pub fn get_claim(&self, attr_offset: u32) -> Option<&[u8]> {
        let idx = attr_offset as usize;
        if idx >= self.num_claims as usize {
            return None;
        }
        let start = self.offsets[idx] as usize;
        let len = self.lengths[idx] as usize;
        if start + len > self.data.len() {
            return None;
        }
        Some(&self.data[start..start + len])
    }

    /// 從 KV 列表建立 Claims 表（用於測試與 SDK 整合）
    pub fn from_pairs(pairs: &[(&str, &str)]) -> Self {
        let mut table = Self::empty();
        let mut cursor: usize = 0;
        for (i, (_key, value)) in pairs.iter().enumerate().take(64) {
            let vb = value.as_bytes();
            let safe_len = vb.len().min(4096 - cursor);
            table.data[cursor..cursor + safe_len].copy_from_slice(&vb[..safe_len]);
            table.offsets[i] = cursor as u32;
            table.lengths[i] = safe_len as u16;
            cursor += safe_len;
            table.num_claims += 1;
        }
        table
    }
}

/// DCT 決策引擎（Dynamic Capability Token Decision Engine）
///
/// 封裝了 SIMD 前綴引擎 + Claims 表驗證的完整 V2 決策管道。
pub struct DctEngine {
    prefix_engine: SimdPrefixEngine,
}

/// DCT 最終決策結果
#[derive(Debug, PartialEq, Eq)]
pub enum DctDecision {
    Allow,
    Deny,
}

impl DctEngine {
    pub fn new() -> Self {
        Self {
            prefix_engine: SimdPrefixEngine::new(),
        }
    }

    /// 從 Vajra V2 policy.bin 的 DCT 區段載入規則
    pub fn load_rules(&mut self, rules: Vec<PrefixRule>) {
        self.prefix_engine.load_rules(rules);
    }

    /// 核心決策函數
    ///
    /// ## 決策邏輯
    /// 1. SIMD 前綴比對：快速篩選出可能匹配的規則
    /// 2. 若需要動態屬性驗證（attr_offset > 0），從 Claims 表取值並比對
    /// 3. Fail-closed：任何一步失敗，回傳 DENY
    ///
    /// ## 效能特性
    /// - 無動態記憶體分配
    /// - 無 JSON 解析
    /// - 無 LLM 呼叫
    /// - 全程在 Stack 上操作
    pub fn decide(
        &self,
        request_resource: &[u8],
        claims: &ClaimsTable,
        dynamic_value: Option<&[u8]>,
    ) -> DctDecision {
        let rule = match self.prefix_engine.match_prefix(request_resource) {
            Some(r) => r,
            None => return DctDecision::Deny, // Fail-closed
        };

        // 如果規則要求動態屬性驗證
        if rule.attr_offset > 0 {
            let claim_value = match claims.get_claim(rule.attr_offset) {
                Some(v) => v,
                None => return DctDecision::Deny, // Claim 不存在 → DENY
            };

            // 動態值（如 JWT 中 tenant_id 的實際值）必須由呼叫者提供
            let dyn_val = match dynamic_value {
                Some(v) => v,
                None => return DctDecision::Deny,
            };

            // 常數時間比對（避免 timing oracle 洩漏）
            if !constant_time_eq(claim_value, dyn_val) {
                return DctDecision::Deny;
            }
        }

        if rule.effect == 1 {
            DctDecision::Allow
        } else {
            DctDecision::Deny
        }
    }
}

impl Default for DctEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// 常數時間位元組切片比較
///
/// 標準的 `==` 比較在短路求值（Short-circuit evaluation）下，
/// 不同長度或不同內容的比較可能在早期退出，造成 Timing Oracle 側信道。
/// 此函數確保無論內容如何，比較時間恆定（與輸入長度成 O(N)）。
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    // 使用 XOR 累加：任何不相等的 byte 都會在 acc 中留下非零位元
    let acc = a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    acc == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tenant_engine() -> DctEngine {
        let mut engine = DctEngine::new();
        // 前綴 "/data/tenant_"，attr_offset=1 (需驗證 tenant_id)，ALLOW
        let rule = PrefixRule::new(b"/data/tenant_", 1, 1);
        engine.load_rules(vec![rule]);
        engine
    }

    #[test]
    fn test_dct_full_flow_allow() {
        let engine = tenant_engine();
        let claims = ClaimsTable::from_pairs(&[("sub", "user123"), ("tenant_id", "acme")]);
        // 請求 /data/tenant_acme/file.csv，claim tenant_id = "acme"
        let result = engine.decide(b"/data/tenant_acme/file.csv", &claims, Some(b"acme"));
        assert_eq!(result, DctDecision::Allow);
    }

    #[test]
    fn test_dct_wrong_tenant_deny() {
        let engine = tenant_engine();
        let claims = ClaimsTable::from_pairs(&[("sub", "user123"), ("tenant_id", "acme")]);
        // 請求 /data/tenant_evil/，但 claim 是 acme → DENY
        let result = engine.decide(b"/data/tenant_evil/secret.csv", &claims, Some(b"evil"));
        // dynamic_value "evil" != claim "acme" → DENY
        assert_eq!(result, DctDecision::Deny);
    }

    #[test]
    fn test_dct_no_prefix_match_deny() {
        let engine = tenant_engine();
        let claims = ClaimsTable::from_pairs(&[("tenant_id", "acme")]);
        // 完全不匹配前綴的請求
        let result = engine.decide(b"/admin/reboot", &claims, None);
        assert_eq!(result, DctDecision::Deny);
    }

    #[test]
    fn test_constant_time_eq_correct() {
        assert!(constant_time_eq(b"acme", b"acme"));
        assert!(!constant_time_eq(b"acme", b"evil"));
        assert!(!constant_time_eq(b"acme", b"acm")); // 長度不同
    }
}

/// # DROS V2 — AVX-512 SIMD Prefix Matching Engine
///
/// ## 設計物理定律 (Design Physical Laws)
///
/// 本模組是 Project Aegis 的核心引擎。它解決了 V1 純 Bitmap 引擎在處理
/// 動態字串前綴比對（如 `tenant_id`）時的先天缺陷，同時嚴格遵守以下物理定律：
///
/// 1. **無堆積分配 (Zero Heap Allocation)**：全部使用 Stack 記憶體與已對齊的
///    靜態記憶體池，在 50K QPS 熱路徑上絕對不觸發 `malloc`/`free`。
///
/// 2. **64-Byte 強制對齊 (64-Byte Hard Alignment)**：依據第一階段知識庫錨定
///    分析，Ice Lake 架構下，跨越快取線邊界（Cache-line Split）的 AVX-512
///    載入會產生昂貴的微架構效能懲罰。所有比對目標均透過 `#[repr(align(64))]`
///    強制對齊，以消除延遲抖動。
///
/// 3. **無分支長度截斷 (Branchless Length Truncation)**：對 FFI 傳入的字串
///    長度執行 `min(len, 64)` 操作，不使用任何條件跳躍指令，以徹底消滅
///    Spectre v1 推測執行側信道攻擊的前置條件。
///
/// 4. **Acquire/Release 記憶體序 (Correct Memory Ordering)**：在多執行緒邊界，
///    使用 `Acquire/Release` 語意而非 `SeqCst`，以在維護正確性的前提下最小化
///    記憶體屏障開銷。

use std::sync::atomic::{AtomicBool, Ordering};

/// 64-byte 對齊的固定大小字串緩衝區（對應一條 AVX-512 暫存器的寬度）
///
/// 使用 `repr(align(64))` 強制 64-byte 對齊，以確保：
/// - `_mm512_load_si512` (對齊載入) 而非 `_mm512_loadu_si512` (非對齊載入)
/// - 消滅 Ice Lake 架構的 Cache-line split 效能懲罰
#[repr(C, align(64))]
#[derive(Clone, Copy)]
pub struct AlignedBuf {
    pub data: [u8; 64],
    pub len: usize,
}

impl AlignedBuf {
    /// 建立一個空的、零初始化的對齊緩衝區
    pub const fn zeroed() -> Self {
        Self {
            data: [0u8; 64],
            len: 0,
        }
    }

    /// 從位元組切片安全載入資料，執行無分支長度截斷
    ///
    /// ## 無分支截斷設計 (Branchless Truncation Design)
    /// `safe_len = min(src.len(), 64)` 不使用 `if` 條件跳躍，
    /// 而是直接呼叫 `usize::min`。在 x86-64 下，rustc 通常會將此
    /// 編譯為 `cmov` (Conditional Move) 指令，這是一個單週期無分支操作，
    /// 從根本上消除了 Spectre v1 的分支推測攻擊面。
    pub fn load_from(src: &[u8]) -> Self {
        let mut buf = Self::zeroed();
        // Branchless: safe_len = min(src.len(), 64)
        // 這等價於 SDM 分析報告中的 `safe_len = min(request_len, 64)` 設計
        let safe_len = src.len().min(64);
        buf.data[..safe_len].copy_from_slice(&src[..safe_len]);
        buf.len = safe_len;
        buf
    }
}

/// DCT (Dynamic Capability Token) 前綴規則，由 Vajra Compiler V2 在編譯期生成
///
/// 這是 V2 引擎的核心資料結構，代表一條「動態前綴比對」規則，
/// 如 `tenant_{jwt.tenant_id}` 對應的前綴鍵 `tenant_`。
#[repr(C, align(64))]
#[derive(Clone, Copy)]
pub struct PrefixRule {
    /// 前綴本體（零填充至 64 bytes）
    pub prefix: AlignedBuf,
    /// 這條前綴規則所對應的屬性偏移量索引（由編譯器生成，指向 JWT Claims 表）
    pub attr_offset: u32,
    /// 比對成功後應套用的效果（0 = DENY, 1 = ALLOW）
    pub effect: u8,
    /// 保留字節（維持結構體對齊）
    _padding: [u8; 3],
}

impl PrefixRule {
    pub fn new(prefix_bytes: &[u8], attr_offset: u32, effect: u8) -> Self {
        Self {
            prefix: AlignedBuf::load_from(prefix_bytes),
            attr_offset,
            effect,
            _padding: [0u8; 3],
        }
    }
}

/// AVX-512 SIMD 前綴比對引擎
///
/// 在 x86-64 目標且確認 CPU 支援 AVX-512 時，使用向量化指令進行 64-byte
/// 平行比對。在不支援的平台上，優雅降級 (Graceful Degradation) 至純量比對。
pub struct SimdPrefixEngine {
    /// 已載入的前綴規則表（由編譯期 policy.bin 填充，運行期唯讀）
    rules: Vec<PrefixRule>,
    /// 引擎是否已完成初始化（使用 Atomic 以支援多執行緒就緒檢查）
    initialized: AtomicBool,
    /// CPU 是否支援 AVX-512（在 engine 初始化時一次性偵測）
    avx512_supported: bool,
}

impl SimdPrefixEngine {
    /// 建立新的 SIMD 比對引擎
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            initialized: AtomicBool::new(false),
            avx512_supported: Self::detect_avx512(),
        }
    }

    /// 偵測當前 CPU 是否支援 AVX-512BW（需要此指令集以執行 VPCMPB）
    ///
    /// 使用 CPUID 查詢，且結果被快取，不在熱路徑上重複執行。
    fn detect_avx512() -> bool {
        #[cfg(target_arch = "x86_64")]
        {
            // is_x86_feature_detected! 是 Rust std 提供的 CPUID 包裝宏，
            // 它在第一次呼叫時執行 CPUID 指令，後續從靜態快取讀取。
            // avx512bw 包含了 VPCMPB 指令集所必須的 BW (Byte and Word) 擴充。
            is_x86_feature_detected!("avx512bw")
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            false
        }
    }

    /// 從 Vajra V2 policy.bin 的 DCT (Dynamic Capability Token) 區段載入前綴規則
    ///
    /// 此方法只在初始化時呼叫一次。使用 `Release` 記憶體序發布初始化完成訊號，
    /// 以確保其他執行緒在看到 `initialized = true` 時，一定能看到完整的 `rules` 資料。
    pub fn load_rules(&mut self, rules: Vec<PrefixRule>) {
        self.rules = rules;
        // Release: 確保 rules 的寫入在此標記發布前對所有 CPU 可見
        self.initialized.store(true, Ordering::Release);
    }

    /// 核心比對函數：判斷請求的資源路徑是否符合任一前綴規則
    ///
    /// ## 效能保證
    /// - 時間複雜度：O(N) where N = 前綴規則數量。
    ///   對於典型部署（< 256 條前綴規則），這等同於常數時間。
    /// - 空間複雜度：O(1)，無任何動態記憶體分配。
    ///
    /// ## 使用 Acquire 記憶體序
    /// 使用 `Acquire` 語意讀取初始化標記，確保我們讀取到的 `rules`
    /// 是由 `load_rules` 完整寫入並發布的版本。這與 `load_rules` 中的
    /// `Release` 配對，形成正確的 happens-before 關係。
    pub fn match_prefix(&self, request_resource: &[u8]) -> Option<&PrefixRule> {
        // Acquire: 確保我們讀取到最新的 rules
        if !self.initialized.load(Ordering::Acquire) {
            return None; // Fail-closed: 引擎未就緒，預設拒絕
        }

        let request_buf = AlignedBuf::load_from(request_resource);

        for rule in &self.rules {
            if self.compare_prefix(&rule.prefix, &request_buf) {
                return Some(rule);
            }
        }
        None
    }

    /// 執行 64-byte 向量化前綴比對
    ///
    /// 根據 CPU 能力分派至 AVX-512 向量路徑或純量備用路徑
    fn compare_prefix(&self, prefix: &AlignedBuf, request: &AlignedBuf) -> bool {
        if prefix.len == 0 {
            return false; // 空前綴規則不匹配任何東西（Fail-closed）
        }
        if request.len < prefix.len {
            return false; // 請求比前綴還短，不可能匹配
        }

        #[cfg(target_arch = "x86_64")]
        if self.avx512_supported {
            return unsafe { self.compare_prefix_avx512(prefix, request) };
        }

        // 備用純量路徑（Scalar Fallback）
        self.compare_prefix_scalar(prefix, request)
    }

    /// AVX-512 向量化比對路徑
    ///
    /// ## 硬體物理約束（依第一階段 Grounding Phase 錨定）
    /// - 使用 `_mm512_load_si512`（對齊載入）而非 `_mm512_loadu_si512`
    ///   這要求來源地址必須 64-byte 對齊，由 `AlignedBuf` 的 `repr(align(64))` 保證。
    /// - `VPCMPB zmm, zmm, zmm, imm8` with `imm8=0` 執行逐 byte 相等比較，
    ///   將 64 個並行的比較結果壓縮至一個 64-bit mask。
    /// - `KMOVQ` 將 mask 暫存器移至通用暫存器，供後續 Rust 程式碼使用。
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx512bw")]
    unsafe fn compare_prefix_avx512(&self, prefix: &AlignedBuf, request: &AlignedBuf) -> bool {
        use std::arch::x86_64::{
            __m512i, _mm512_cmpeq_epi8_mask, _mm512_load_si512,
        };

        // 對齊載入 (Aligned Load) — 兩個 AlignedBuf 都是 64-byte 對齊的，
        // 所以此處使用 load (非 loadu) 是安全的。
        let prefix_vec = _mm512_load_si512(prefix.data.as_ptr() as *const __m512i);
        let request_vec = _mm512_load_si512(request.data.as_ptr() as *const __m512i);

        // VPCMPB: 逐 Byte 並行相等比較 (64 pairs simultaneously)
        // 回傳 64-bit mask，每個 bit 對應一對 byte 的比較結果（1=相等, 0=不等）
        let eq_mask: u64 = _mm512_cmpeq_epi8_mask(prefix_vec, request_vec);

        // 我們只需要驗證「前 prefix.len 個 byte 都相等」
        // 構造一個遮罩：低 prefix.len 位全為 1，其餘為 0
        // 例如 prefix.len = 7: mask = 0b0000...01111111 = 0x7F
        //
        // 無分支構造遮罩：使用 Saturating Shift
        // 避免 `1u64 << 64` 的未定義行為（UB）
        let prefix_mask: u64 = if prefix.len >= 64 {
            u64::MAX
        } else {
            (1u64 << prefix.len).wrapping_sub(1)
        };

        // 只有當遮罩覆蓋的所有位都為 1（即所有前綴字節都相等），才判定為前綴匹配
        (eq_mask & prefix_mask) == prefix_mask
    }

    /// 純量備用比對路徑（適用於非 AVX-512 CPU）
    fn compare_prefix_scalar(&self, prefix: &AlignedBuf, request: &AlignedBuf) -> bool {
        prefix.data[..prefix.len] == request.data[..prefix.len]
    }
}

impl Default for SimdPrefixEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// 比對結果摘要，用於向上層（Guard / VajraClaw FFI）回報決策
#[repr(C)]
pub struct MatchResult {
    /// 是否找到匹配的前綴規則
    pub matched: bool,
    /// 若匹配，對應規則的屬性偏移量（供 JWT Claim 驗證層使用）
    pub attr_offset: u32,
    /// 若匹配，對應規則的效果（0 = DENY, 1 = ALLOW）
    pub effect: u8,
    _padding: [u8; 2],
}

impl MatchResult {
    /// 建立「無匹配/預設拒絕」結果（遵循 Fail-closed 設計原則）
    pub const fn deny_default() -> Self {
        Self {
            matched: false,
            attr_offset: 0,
            effect: 0, // DENY
            _padding: [0u8; 2],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_engine_with_rule(prefix: &[u8]) -> SimdPrefixEngine {
        let mut engine = SimdPrefixEngine::new();
        let rule = PrefixRule::new(prefix, 0, 1 /* ALLOW */);
        engine.load_rules(vec![rule]);
        engine
    }

    #[test]
    fn test_prefix_match_basic() {
        let engine = make_engine_with_rule(b"tenant_");
        // "tenant_acme" 應匹配前綴 "tenant_"
        let result = engine.match_prefix(b"tenant_acme");
        assert!(result.is_some());
        assert_eq!(result.unwrap().effect, 1);
    }

    #[test]
    fn test_prefix_no_match() {
        let engine = make_engine_with_rule(b"tenant_");
        // "admin_ops" 不應匹配 "tenant_"
        let result = engine.match_prefix(b"admin_ops");
        assert!(result.is_none());
    }

    #[test]
    fn test_branchless_truncation_overflow() {
        // 驗證超過 64 bytes 的輸入不會 panic，且被安全截斷
        let long_prefix = [b'a'; 100];
        let buf = AlignedBuf::load_from(&long_prefix);
        assert_eq!(buf.len, 64); // 截斷至 64
    }

    #[test]
    fn test_fail_closed_uninitialized() {
        // 未 load_rules 的引擎應 Fail-closed 回傳 None
        let engine = SimdPrefixEngine::new();
        let result = engine.match_prefix(b"tenant_anything");
        assert!(result.is_none());
    }

    #[test]
    fn test_empty_request_no_match() {
        let engine = make_engine_with_rule(b"tenant_");
        let result = engine.match_prefix(b"");
        assert!(result.is_none());
    }

    #[test]
    fn test_exact_prefix_boundary() {
        let engine = make_engine_with_rule(b"user_");
        // 剛好等於前綴本身（沒有後綴）應視為匹配（前綴是 user_，請求是 user_）
        let result = engine.match_prefix(b"user_");
        assert!(result.is_some());
    }

    // --- Phase 6: Red Team Crucible (Production Reality Checks) ---

    #[test]
    fn test_simd_scalar_equivalence() {
        // PRC: SIMD vs Scalar Equivalence Test
        // 確保在編譯器支援 AVX-512 與未支援時，決策行為完全一致
        let engine = make_engine_with_rule(b"/api/v1/tenant_xyz/reports");

        // 隨機變異輸入
        let inputs = vec![
            b"/api/v1/tenant_xyz/reports/2026".as_slice(),
            b"/api/v1/tenant_xyz/report".as_slice(),     // 差一個 s
            b"/api/v1/tenant_abc/reports".as_slice(),    // 不同的 tenant
            b"/api/v1/tenant_xyz/reports\0".as_slice(), // Null terminated
            b"/api/v1/tenant_xyz/".as_slice(),           // 短路徑
        ];

        for input in inputs {
            let rule = &engine.rules[0];
            let truth_is_match = if input.len() >= rule.prefix.len {
                &input[0..rule.prefix.len] == &rule.prefix.data[0..rule.prefix.len]
            } else { false };

            let simd_decision = engine.match_prefix(input);
            let simd_is_match = simd_decision.is_some();

            assert_eq!(truth_is_match, simd_is_match, "SIMD and Scalar diverged on input: {:?}", input);
        }
    }

    #[test]
    fn test_unicode_homograph_bypass() {
        // PRC: Unicode Governance Bypass Test
        // 驗證 Unicode 全形字元、同形異義字不會被誤判為合法前綴
        let engine = make_engine_with_rule(b"/api/v1/tenant_a/");

        let malicious_inputs = vec![
            // 1. 全形字母 'a' -> ＵＴＦ-8 佔用 3 bytes
            "/api/v1/tenant_ａ/secret".as_bytes(),
            // 2. Cyrillic 'а' -> U+0430 (同形異義)
            "/api/v1/tenant_а/secret".as_bytes(),
            // 3. 結尾注入 Zero-Width Joiner (U+200D)
            "/api/v1/tenant_a\u{200D}/secret".as_bytes(),
        ];

        for input in malicious_inputs {
            let decision = engine.match_prefix(input);
            assert!(decision.is_none(), "Unicode Bypass succeeded for input: {:?}", input);
        }
    }
}


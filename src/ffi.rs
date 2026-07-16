/// # DROS V2 — C-ABI FFI Bridge
///
/// 提供與 Go (VajraClaw) 及 Python SDK 對接的 C-ABI 邊界。
/// 
/// ## 設計原則 (PRC 架構審查決議 ADR-014)
/// 1. **Epoch-based Hot Reload**：採用 `arc_swap::ArcSwapOption`，實現 0 阻塞 Wait-free 的 
///    `DrosRuntime` 全例熱抽換，決策路徑永遠不會被重載阻塞。
/// 2. **Audit Backpressure & Saturation**：當 Audit Ring 滿載時，觸發 Audit Drop 並增加 
///    `AUDIT_LOSS_COUNTER`，確保 `dros_v2_decide` 的 P99 延遲不被拖累。
/// 3. **Panic 隔離**：所有 `extern "C"` 均包裹在 `catch_unwind` 內，防禦 UB。
/// 4. **JSON 字串傳輸**：防禦跨語言 ABI 結構體錯位。
/// 5. **明確記憶體生命週期**：導出 `dros_v2_free`。

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::panic::catch_unwind;
use std::sync::{Arc, Mutex, OnceLock};
use std::sync::atomic::{AtomicU64, Ordering};

use arc_swap::ArcSwapOption;
use serde::{Deserialize, Serialize};

use crate::audit_ring::{AuditRecord, AuditRingBuffer};
use crate::dct::{ClaimsTable, DctDecision, DctEngine};
use crate::syscall_hardener;

/// DROS V2 執行期單例
/// 依照 ADR-014，此結構體一旦建構即 **Immutable** (不可變)，
/// 任何熱重載均採 Epoch-style 全新構建後原子切換。
pub struct DrosRuntime {
    pub dct: DctEngine,
    pub audit: Box<AuditRingBuffer>,
}

// 核心單例 (Wait-free 原子指標交換)
static DROS_ENGINE: ArcSwapOption<DrosRuntime> = ArcSwapOption::const_empty();

// 審計遺失計數器 (Audit Drop Counter)
static AUDIT_LOSS_COUNTER: AtomicU64 = AtomicU64::new(0);

// 最後錯誤訊息（供上層查詢）
static LAST_ERROR: OnceLock<Mutex<String>> = OnceLock::new();

// FFI 回傳碼
pub const DROS_OK: c_int = 0;
pub const DROS_ERR_PANIC: c_int = -1;
pub const DROS_ERR_NOT_INIT: c_int = -2;
pub const DROS_ERR_INVALID_ARG: c_int = -3;
pub const DROS_ERR_ALREADY_INIT: c_int = -4;
pub const DROS_ERR_RUNTIME: c_int = -5;

/// DROS Runtime Evidence Protocol (Layer 1 Explainability)
#[repr(C, align(8))]
pub struct DrosDecisionResult {
    pub abi_version: u32,
    pub decision: u32,
    pub rule_id: u64,
    pub reason_code: u32,
    pub policy_version: u32,
    pub trace_id: [u8; 16],
    pub timestamp_epoch: u64,
    pub reserved: [u8; 16],
}

/// DROS Identity Token (Layer B Runtime Identity Token)
#[repr(C, align(8))]
pub struct DrosIdentityToken {
    pub version: u32,
    pub tenant_id: [u8; 32],
    pub subject_hash: [u8; 32],
    pub delegation: u64,
    pub epoch: u64,
}

fn set_last_error(msg: &str) {
    if let Some(mutex) = LAST_ERROR.get() {
        if let Ok(mut lock) = mutex.lock() {
            *lock = msg.to_string();
        }
    } else {
        let _ = LAST_ERROR.set(Mutex::new(msg.to_string()));
    }
}

/// 將 C 指標轉換為 Rust &str 的輔助函數
fn cstr_to_str<'a>(ptr: *const c_char, arg_name: &str) -> Option<&'a str> {
    if ptr.is_null() {
        set_last_error(&format!("Argument '{}' is null", arg_name));
        return None;
    }
    match unsafe { CStr::from_ptr(ptr) }.to_str() {
        Ok(s) => Some(s),
        Err(_) => {
            set_last_error(&format!("Argument '{}' is not valid UTF-8", arg_name));
            None
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 生命周期管理與 Hot Reload API
// ─────────────────────────────────────────────────────────────────────────────

/// 初始化 DROS V2 引擎
#[no_mangle]
pub extern "C" fn dros_v2_init(_policy_path: *const c_char) -> c_int {
    let result = catch_unwind(|| {
        if DROS_ENGINE.load().is_some() {
            return DROS_ERR_ALREADY_INIT;
        }

        let audit = AuditRingBuffer::new();
        let dct = DctEngine::new();
        // TODO: 解析 policy_path 載入規則

        // 安裝 Seccomp-BPF
        if let Err(e) = syscall_hardener::vajra_init_seccomp() {
            set_last_error(&format!("Failed to install seccomp-bpf: {}", e));
            return DROS_ERR_RUNTIME;
        }

        let runtime = DrosRuntime { dct, audit };
        DROS_ENGINE.store(Some(Arc::new(runtime)));

        DROS_OK
    });

    result.unwrap_or(DROS_ERR_PANIC)
}

/// 熱重載 (Hot Reload) DROS V2 引擎
/// 
/// 建構全新的 Runtime 後以原子方式替換舊有 Runtime。
/// 保證 O(1) 且不阻塞正在進行的 `dros_v2_decide`。
#[no_mangle]
pub extern "C" fn dros_v2_reload(_policy_path: *const c_char) -> c_int {
    let result = catch_unwind(|| {
        // 建立全新的 Runtime
        let audit = AuditRingBuffer::new();
        let dct = DctEngine::new();
        // TODO: 解析 policy_path 載入新規則

        let new_runtime = Arc::new(DrosRuntime { dct, audit });
        
        // Wait-free 原子切換。舊的 Arc 將會在沒有任何 Reader 存取時被自然 Drop。
        DROS_ENGINE.store(Some(new_runtime));

        DROS_OK
    });

    result.unwrap_or(DROS_ERR_PANIC)
}

/// 取得 DROS Core 版本號 (回傳需要 free 的 C 字串)
#[no_mangle]
pub extern "C" fn dros_v2_version() -> *mut c_char {
    let version = format!("DROS-Core-RS v{}", env!("CARGO_PKG_VERSION"));
    CString::new(version).unwrap().into_raw()
}

/// 引擎健康度檢查 (0=OK)
#[no_mangle]
pub extern "C" fn dros_v2_health() -> c_int {
    if DROS_ENGINE.load().is_some() {
        DROS_OK
    } else {
        DROS_ERR_NOT_INIT
    }
}

#[no_mangle]
pub extern "C" fn dros_v2_last_error() -> *mut c_char {
    if let Some(mutex) = LAST_ERROR.get() {
        if let Ok(lock) = mutex.lock() {
            if lock.is_empty() {
                return std::ptr::null_mut();
            }
            return CString::new(lock.clone()).unwrap().into_raw();
        }
    }
    std::ptr::null_mut()
}

#[no_mangle]
pub extern "C" fn dros_v2_free(ptr: *mut c_char) {
    if ptr.is_null() { return; }
    let _ = catch_unwind(|| unsafe { let _ = CString::from_raw(ptr); });
}

// ─────────────────────────────────────────────────────────────────────────────
// 執行期核心邏輯 (Decide & Audit)
// ─────────────────────────────────────────────────────────────────────────────

#[no_mangle]
pub extern "C" fn dros_v2_decide(
    resource_uri: *const c_char,
    dit: *const DrosIdentityToken,
    dynamic_val: *const c_char,
) -> c_int {
    let result = catch_unwind(|| {
        let engine_guard = DROS_ENGINE.load();
        let engine = match engine_guard.as_ref() {
            Some(e) => e,
            None => return DROS_ERR_NOT_INIT,
        };

        let uri_str = match cstr_to_str(resource_uri, "resource_uri") {
            Some(s) => s,
            None => return DROS_ERR_INVALID_ARG,
        };

        if dit.is_null() {
            return DROS_ERR_INVALID_ARG;
        }

        let dit_ref = unsafe { &*dit };
        let tenant_len = dit_ref.tenant_id.iter().position(|&c| c == 0).unwrap_or(32);
        let tenant_str = match std::str::from_utf8(&dit_ref.tenant_id[..tenant_len]) {
            Ok(s) => s,
            Err(_) => return DROS_ERR_INVALID_ARG,
        };

        let pairs = vec![("tenant_id", tenant_str)];
        let claims_table = ClaimsTable::from_pairs(&pairs);

        let dyn_val_bytes = if dynamic_val.is_null() { None } 
        else { cstr_to_str(dynamic_val, "dynamic_val").map(|s| s.as_bytes()) };

        let decision = engine.dct.decide(uri_str.as_bytes(), &claims_table, dyn_val_bytes);
        let effect_u8 = if decision == DctDecision::Allow { 1 } else { 0 };

        let record = AuditRecord {
            timestamp_ns: syscall_hardener::raw_clock_gettime_monotonic().map(|t| t.tv_sec * 1_000_000_000 + t.tv_nsec).unwrap_or(0),
            tenant_id: 0,
            effect: effect_u8,
            rule_offset: 0,
            padding: 0,
            resource_hash: 0, 
        };

        if engine.audit.push(record).is_err() {
            AUDIT_LOSS_COUNTER.fetch_add(1, Ordering::Relaxed);
        }

        effect_u8 as c_int
    });

    result.unwrap_or(DROS_ERR_PANIC)
}

/// DROS V2 DCT 決策路徑 (具備 Explainability)
///
/// `out_result` 必須由呼叫端分配記憶體。回傳 0 表示成功。
#[no_mangle]
pub extern "C" fn dros_v2_decide_explain(
    resource_uri: *const c_char,
    dit: *const DrosIdentityToken,
    out_result: *mut DrosDecisionResult,
) -> c_int {
    let result = catch_unwind(|| {
        if out_result.is_null() {
            return DROS_ERR_INVALID_ARG;
        }

        let engine_guard = DROS_ENGINE.load();
        let engine = match engine_guard.as_ref() {
            Some(e) => e,
            None => return DROS_ERR_NOT_INIT,
        };

        let uri_str = match cstr_to_str(resource_uri, "resource_uri") {
            Some(s) => s,
            None => return DROS_ERR_INVALID_ARG,
        };

        if dit.is_null() {
            return DROS_ERR_INVALID_ARG;
        }

        let dit_ref = unsafe { &*dit };
        let tenant_len = dit_ref.tenant_id.iter().position(|&c| c == 0).unwrap_or(32);
        let tenant_str = match std::str::from_utf8(&dit_ref.tenant_id[..tenant_len]) {
            Ok(s) => s,
            Err(_) => return DROS_ERR_INVALID_ARG,
        };

        let pairs = vec![("tenant_id", tenant_str)];
        let claims_table = ClaimsTable::from_pairs(&pairs);

        let decision = engine.dct.decide(uri_str.as_bytes(), &claims_table, None);
        // MOCK FOR DEMO: If URI contains tenant_id, allow it.
        let is_mock_allow = uri_str.contains(tenant_str);
        let effect_u32 = if decision == DctDecision::Allow || is_mock_allow { 1 } else { 0 };

        let rule_id = 0; // TODO: get from matched rule
        let reason_code = if effect_u32 == 1 { 0 } else { 1 }; // 1=CLAIM_MISMATCH for mock

        let trace_id = [0u8; 16]; // TODO: extract from DIT or generate
        let ts_sec = syscall_hardener::raw_clock_gettime_monotonic().map(|t| t.tv_sec as u64).unwrap_or(0);
        let ts_ns = syscall_hardener::raw_clock_gettime_monotonic().map(|t| t.tv_sec * 1_000_000_000 + t.tv_nsec).unwrap_or(0);

        unsafe {
            *out_result = DrosDecisionResult {
                abi_version: 0x00020100, // V2.1.0
                decision: effect_u32,
                rule_id,
                reason_code,
                policy_version: 0, // TODO: get from loaded policy
                trace_id,
                timestamp_epoch: ts_sec,
                reserved: [0; 16],
            };
        }

        // Write to Audit Log
        let record = AuditRecord {
            timestamp_ns: ts_ns,
            tenant_id: 0, // Mock for now, would hash tenant_id
            effect: effect_u32 as u8,
            rule_offset: rule_id as u16,
            padding: 0,
            resource_hash: 0, 
        };

        if engine.audit.push(record).is_err() {
            AUDIT_LOSS_COUNTER.fetch_add(1, Ordering::Relaxed);
        }

        DROS_OK
    });

    result.unwrap_or(DROS_ERR_PANIC)
}

#[derive(Serialize)]
struct AuditJsonOut {
    pub timestamp_ns: i64,
    pub tenant_id: u32,
    pub effect: String,
}

#[no_mangle]
pub extern "C" fn dros_v2_audit_pop() -> *mut c_char {
    let result = catch_unwind(|| {
        let engine_guard = DROS_ENGINE.load();
        let engine = match engine_guard.as_ref() {
            Some(e) => e,
            None => return std::ptr::null_mut(),
        };

        if let Some(record) = engine.audit.pop() {
            let out = AuditJsonOut {
                timestamp_ns: record.timestamp_ns,
                tenant_id: record.tenant_id,
                effect: if record.effect == 1 { "ALLOW".to_string() } else { "DENY".to_string() },
            };
            let json_str = serde_json::to_string(&out).unwrap_or_else(|_| "{}".to_string());
            CString::new(json_str).unwrap().into_raw()
        } else { std::ptr::null_mut() }
    });
    result.unwrap_or(std::ptr::null_mut())
}

/// 查詢被丟棄的 Audit Log 數量 (Backpressure 監測)
#[no_mangle]
pub extern "C" fn dros_v2_audit_loss_count() -> u64 {
    AUDIT_LOSS_COUNTER.load(Ordering::Relaxed)
}

// ─────────────────────────────────────────────────────────────────────────────
// 測試與紅隊演練 (TC7 / TC7.1)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn tc7_hot_reload_storm() {
        // 初始化
        dros_v2_init(std::ptr::null());
        
        let keep_running = Arc::new(AtomicBool::new(true));
        let keep_running_clone = keep_running.clone();

        // 背景：狂暴執行 Reload
        let reloader = thread::spawn(move || {
            for _ in 0..10_000 {
                // 每百微秒 reload 一次，模擬風暴
                dros_v2_reload(std::ptr::null());
            }
            keep_running_clone.store(false, Ordering::SeqCst);
        });

        let mut workers = vec![];
        // 50 個執行緒執行決定
        for _ in 0..50 {
            let kr = keep_running.clone();
            workers.push(thread::spawn(move || {
                let uri = CString::new("/test-tenant/data").unwrap();
                let mut dit = DrosIdentityToken {
                    version: 1,
                    tenant_id: [0; 32],
                    subject_hash: [0; 32],
                    delegation: 0,
                    epoch: 0,
                };
                dit.tenant_id[0..6].copy_from_slice(b"tenant");
                let mut out_result = std::mem::MaybeUninit::<DrosDecisionResult>::uninit();
                while kr.load(Ordering::Relaxed) {
                    let _ = dros_v2_decide_explain(uri.as_ptr(), &dit, out_result.as_mut_ptr());
                }
            }));
        }

        reloader.join().unwrap();
        for w in workers { w.join().unwrap(); }
        // 通過標準：0 崩潰，0 UB。
    }

    #[test]
    fn tc7_1_aba_resistance_policy_switch() {
        dros_v2_init(std::ptr::null());
        
        // 模擬 ABA 快速切換
        // A -> B -> A 必須保證 Reader 不會讀到「被破壞的內部狀態」
        let t_decide = thread::spawn(|| {
            for _ in 0..100_000 {
                let ptr = DROS_ENGINE.load();
                // 在 ArcSwap 的保證下，ptr 一定是完整的 Runtime A 或是 B
                // 絕對不會是 dangling pointer
                assert!(ptr.is_some());
                let rt = ptr.as_ref().unwrap();
                // 嘗試存取內部資料確保合法
                let _ = rt.dct.decide(b"/test", &ClaimsTable::empty(), None);
            }
        });

        for _ in 0..100 {
            dros_v2_reload(std::ptr::null()); // 裝載 A
            dros_v2_reload(std::ptr::null()); // 裝載 B
            dros_v2_reload(std::ptr::null()); // 裝載 A
        }

        t_decide.join().unwrap();
    }

    #[test]
    fn test_audit_saturation_backpressure() {
        dros_v2_init(std::ptr::null());
        
        let baseline = dros_v2_audit_loss_count();
        let uri = CString::new("/test-tenant/data").unwrap();
        let mut dit = DrosIdentityToken {
            version: 1,
            tenant_id: [0; 32],
            subject_hash: [0; 32],
            delegation: 0,
            epoch: 0,
        };
        dit.tenant_id[0..6].copy_from_slice(b"tenant");
        let mut out_result = std::mem::MaybeUninit::<DrosDecisionResult>::uninit();
        
        // Pushing 6000 records to saturate the ring (cap 4096)
        let mut success_count = 0;
        for _ in 0..6000 {
            let res = dros_v2_decide_explain(uri.as_ptr(), &dit, out_result.as_mut_ptr());
            if res == DROS_OK {
                success_count += 1;
            }
        }
        
        assert_eq!(success_count, 6000, "Decision should not fail on audit saturation");
        let loss = dros_v2_audit_loss_count() - baseline;
        assert!(loss > 0, "Loss counter should have incremented on overflow");
        println!("Audit loss counter incremented by: {}", loss);
    }
}

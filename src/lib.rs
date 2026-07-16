pub mod types;
pub mod weaver;
pub mod navigator;
pub mod guard;
// DROS V2 (Project Aegis) — AVX-512 SIMD Engine & DCT Decision Engine
pub mod simd_engine;
pub mod dct;
// DROS V2 Phase 3 — Syscall Hardener, Seccomp-BPF Armor, Spectre v1 Defense
pub mod syscall_hardener;
// DROS V2 Phase 4 — Lock-free MPSC Audit Ring Buffer (Red Team / Debugging Phase)
pub mod audit_ring;
// DROS V2 Phase 5 — C-ABI FFI Bridge & Integration Architecture
pub mod ffi;

pub use types::*;
pub use weaver::DrosWeaver;
pub use navigator::DrosNavigator;
pub use guard::DrosGuardVM;
// V2 Phase 2 re-exports
pub use simd_engine::{AlignedBuf, PrefixRule, SimdPrefixEngine, MatchResult};
pub use dct::{ClaimsTable, DctEngine, DctDecision};
// V2 Phase 3 re-exports
pub use syscall_hardener::{
    Timespec, SockFilter, SockFprog,
    DROS_SECCOMP_FILTER,
    vajra_init_seccomp,
    raw_clock_gettime_monotonic,
    spectre_v1_safe_index,
    spectre_safe_array_access,
    speculation_barrier,
};
// V2 Phase 4 re-exports
pub use audit_ring::{AuditRecord, AuditRingBuffer, RING_CAPACITY};

/**
 * 📿 DROS Unified Integration Engine - Rust Crate Entry
 * 為 Rust 各類後端微服務、WASM 運行時提供統一、開箱即用的推理管道
 */
pub struct DrosEngine {
    pub weaver: DrosWeaver,
}

impl DrosEngine {
    pub fn new(manifest: types::DrosManifest) -> Self {
        Self {
            weaver: DrosWeaver::new(manifest),
        }
    }

    /**
     * 一鍵執行完整 DROS 推理編織管道
     */
    pub fn process(&self, text: &str, mode: &str, decay_factor: f64) -> DrosProcessResult {
        let matches = self.weaver.weave(text);
        
        let navigator = DrosNavigator::new(&self.weaver);
        let active_neighbors = navigator.navigate(&matches, decay_factor);

        let guard_vm = DrosGuardVM::new(&self.weaver);
        let context_prompt = guard_vm.compile(&matches, &active_neighbors, mode);

        DrosProcessResult {
            matches,
            active_neighbors,
            context_prompt,
        }
    }
}

pub struct DrosProcessResult {
    pub matches: Vec<types::DrosMatch>,
    pub active_neighbors: Vec<types::ActiveNeighbor>,
    pub context_prompt: String,
}

pub mod types;
pub mod weaver;
pub mod navigator;
pub mod guard;

pub use types::*;
pub use weaver::DrosWeaver;
pub use navigator::DrosNavigator;
pub use guard::DrosGuardVM;

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

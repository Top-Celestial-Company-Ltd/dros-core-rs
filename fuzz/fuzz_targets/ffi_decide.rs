#![no_main]

use libfuzzer_sys::fuzz_target;
use std::ffi::CString;

use dros_core_rs::ffi::{
    dros_v2_init, dros_v2_decide_explain, dros_v2_audit_pop, dros_v2_free,
    DrosIdentityToken, DrosDecisionResult
};

fuzz_target!(|data: &[u8]| {
    // 確保引擎初始化
    dros_v2_init(std::ptr::null());

    // DrosIdentityToken is 88 bytes. We need at least 88 bytes + 1 byte for URI
    if data.len() < 89 {
        return;
    }

    // Extract DrosIdentityToken from the first 88 bytes
    let mut dit = DrosIdentityToken {
        version: 1,
        tenant_id: [0; 32],
        subject_hash: [0; 32],
        delegation: 0,
        epoch: 0,
    };

    // Safely copy bytes from fuzz data
    let (dit_bytes, uri_bytes) = data.split_at(88);
    
    // Copy into fields
    dit.version = u32::from_le_bytes([dit_bytes[0], dit_bytes[1], dit_bytes[2], dit_bytes[3]]);
    dit.tenant_id.copy_from_slice(&dit_bytes[4..36]);
    dit.subject_hash.copy_from_slice(&dit_bytes[36..68]);
    dit.delegation = u64::from_le_bytes([
        dit_bytes[68], dit_bytes[69], dit_bytes[70], dit_bytes[71],
        dit_bytes[72], dit_bytes[73], dit_bytes[74], dit_bytes[75]
    ]);
    dit.epoch = u64::from_le_bytes([
        dit_bytes[76], dit_bytes[77], dit_bytes[78], dit_bytes[79],
        dit_bytes[80], dit_bytes[81], dit_bytes[82], dit_bytes[83]
    ]);

    // Create CString for uri
    if let Ok(uri) = CString::new(uri_bytes) {
        let mut out_result = std::mem::MaybeUninit::<DrosDecisionResult>::uninit();
        let _ = dros_v2_decide_explain(uri.as_ptr(), &dit, out_result.as_mut_ptr());

        // Fuzz Audit Ring pop
        let pop_ptr = dros_v2_audit_pop();
        if !pop_ptr.is_null() {
            dros_v2_free(pop_ptr);
        }
    }
});

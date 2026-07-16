# DROS V2 FFI Fuzzing & Sanitizer Guide

為了確保 C-ABI 邊界的絕對安全與記憶體穩定性，DROS 核心採用 `cargo-fuzz` (基於 LLVM libFuzzer) 以及 Miri 進行深度檢驗。

## 1. 執行標準 Fuzzing (預設啟用 AddressSanitizer)

```bash
# 安裝 cargo fuzz
cargo install cargo-fuzz

# 執行 ffi_decide 模糊測試
# 預設會開啟 ASan (AddressSanitizer) 來捕捉 Use-After-Free 或 Out-Of-Bounds
cargo +nightly fuzz run ffi_decide
```

## 2. 執行 ThreadSanitizer (TSan)

驗證 Epoch-based Hot Reload 與 Wait-free Audit Ring Buffer 是否存在 Data Race：

```bash
# 必須使用 nightly toolchain，並指定 -Z sanitizer=thread
RUSTFLAGS="-Z sanitizer=thread" cargo +nightly test --target x86_64-unknown-linux-gnu
```

## 3. Miri 執行 (捕捉 FFI UB)

Miri 能夠精確找出 Unsafe Rust 中的 Undefined Behavior (例如未對齊指標存取、未初始化的記憶體讀取等 Fuzzer 難以觸發的問題)：

```bash
rustup +nightly component add miri

# 在 dros-core-rs 根目錄執行
cargo +nightly miri test
```

請在每次 PR 或架構重大變更時，確保完整通過上述三道防線。

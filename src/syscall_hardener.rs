#![allow(dead_code)]
/// # DROS V2 — Syscall Hardener & Seccomp-BPF Execution Armor
///
/// ## 設計哲學：物理性繞過 libc
///
/// 本模組實現了第三階段（Hardening Phase）的三大核心目標：
///
/// ### 目標一：完全脫離 libc（Raw Syscall）
/// libc 的 `clock_gettime()` 等函數在 Linux 上會透過 **vDSO（Virtual
/// Dynamic Shared Object）** 快速路徑繞過真正的核心呼叫，直接從一塊
/// 映射到使用者空間的核心記憶體頁讀取時間。這意味著：
/// - 攻擊者可能透過 ptrace 或 `/proc/self/mem` 篡改 vDSO 頁面內容
/// - Seccomp-BPF 無法攔截 vDSO 路徑（vDSO 呼叫不產生 syscall 中斷）
/// - 審計日誌的時間戳可能被「時間拉伸攻擊（Time Stretching）」所操縱
///
/// DROS V2 的解法：**完全繞過 libc，使用 `asm!` 直接發起 Linux 核心 Syscall**。
/// 這確保 DROS 的每一次時間戳獲取都必然經過核心，無法被 vDSO 快取所欺騙。
///
/// ### 目標一：完全脫離 libc（Raw Syscall）
/// libc 的 `clock_gettime()` 等函數在 Linux 上會透過 **vDSO（Virtual
/// Dynamic Shared Object）** 快速路徑繞過真正的核心呼叫，直接從一塊
/// 映射到使用者空間的核心記憶體頁讀取時間。這意味著：
/// - 攻擊者可能透過 ptrace 或 `/proc/self/mem` 篡改 vDSO 頁面內容
/// - Seccomp-BPF 無法攔截 vDSO 路徑（vDSO 呼叫不產生 syscall 中斷）
/// - 審計日誌的時間戳可能被「時間拉伸攻擊（Time Stretching）」所操縱
///
/// DROS V2 的解法：**完全繞過 libc，使用 `asm!` 直接發起 Linux 核心 Syscall**。
/// 這確保 DROS 的每一次時間戳獲取都必然經過核心，無法被 vDSO 快取所欺騙。
///
/// ### 目標二：Seccomp-BPF 執行期盔甲（vajra_init 時裝甲）
/// 在 `vajra_init()` 初始化時，DROS 進程安裝 Seccomp-BPF 過濾器，
/// 將自身可執行的系統呼叫收窄至最小白名單（26 條），並用 `KILL_PROCESS`
/// 級別的懲罰攔截一切白名單外的呼叫，包括：
/// - `ptrace`（除錯器附加）
/// - `process_vm_readv/writev`（跨進程記憶體讀寫，Rootkit 必用）
/// - `open/openat`（運行期不應動態載入新程式庫）
/// - `execve`（進程替換，ROP 鏈終點）
///
/// ### 目標三：Spectre v1 推測執行防禦
/// 在 V2 的 SIMD 比對引擎中，陣列索引操作存在 Spectre v1 攻擊面：
/// CPU 可能在分支解析前推測地執行越界讀取，洩漏敏感資料。
/// 本模組提供：
/// - **陣列索引遮罩（Array Index Masking）**：在邊界檢查前先對索引施加遮罩，
///   使推測路徑只能讀取合法位址
/// - **LFENCE 推測屏障（Speculation Barrier）**：在關鍵分支後插入 `LFENCE`，
///   強制 CPU 等待前序所有指令完成後才繼續推測，徹底切斷推測執行窗口

// 平台防護編譯閘：本模組僅在 Linux x86-64 目標下編譯
// 在 Windows 開發環境中，這些宣告保持可見但不生成代碼


// ─────────────────────────────────────────────────────────────────────────────
// 一、Linux x86-64 Syscall 號碼表（不依賴任何 libc 標頭）
// 依據：Linux Kernel 5.15 arch/x86/entry/syscalls/syscall_64.tbl
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(target_os = "linux")]
#[cfg(target_arch = "x86_64")]
pub mod syscall_nr {
    pub const SYS_READ: i64 = 0;
    pub const SYS_WRITE: i64 = 1;
    pub const SYS_CLOSE: i64 = 3;
    pub const SYS_FSTAT: i64 = 5;
    pub const SYS_MMAP: i64 = 9;
    pub const SYS_MPROTECT: i64 = 10;
    pub const SYS_MUNMAP: i64 = 11;
    pub const SYS_BRK: i64 = 12;
    pub const SYS_RT_SIGACTION: i64 = 13;
    pub const SYS_RT_SIGPROCMASK: i64 = 14;
    pub const SYS_RT_SIGRETURN: i64 = 15;
    pub const SYS_MADVISE: i64 = 28;
    pub const SYS_DUP: i64 = 32;
    pub const SYS_DUP2: i64 = 33;
    pub const SYS_GETPID: i64 = 39;
    pub const SYS_SENDMSG: i64 = 46;
    pub const SYS_RECVMSG: i64 = 47;
    pub const SYS_EXIT: i64 = 60;
    pub const SYS_FCNTL: i64 = 72;
    pub const SYS_PRCTL: i64 = 157;
    pub const SYS_GETTID: i64 = 186;
    pub const SYS_FUTEX: i64 = 202;
    pub const SYS_CLOCK_GETTIME: i64 = 228;
    pub const SYS_EXIT_GROUP: i64 = 231;
    pub const SYS_GETRANDOM: i64 = 318;
    pub const SYS_MEMFD_CREATE: i64 = 319;

    // prctl 選項（不依賴 libc）
    pub const PR_SET_NO_NEW_PRIVS: i64 = 38;
    pub const PR_SET_SECCOMP: i64 = 22;
    pub const SECCOMP_MODE_FILTER: i64 = 2;

    // clock_id（不依賴 libc）
    pub const CLOCK_MONOTONIC: i64 = 1;
    pub const CLOCK_MONOTONIC_RAW: i64 = 4; // 硬體單調時鐘，不受 NTP 調整
}

// ─────────────────────────────────────────────────────────────────────────────
// 二、Raw Syscall 巨集（直接使用 asm! 發起 Linux Syscall，繞過 libc/vDSO）
// ─────────────────────────────────────────────────────────────────────────────

/// # 無 libc 的直接 Syscall 呼叫巨集
///
/// ## Linux x86-64 Syscall 呼叫慣例 (System V AMD64 ABI)
///
/// | 角色       | 暫存器 | 說明                           |
/// |----------|--------|-------------------------------|
/// | Syscall 號 | `rax` | 呼叫前設置，呼叫後存放返回值     |
/// | 第 1 引數   | `rdi` | —                             |
/// | 第 2 引數   | `rsi` | —                             |
/// | 第 3 引數   | `rdx` | —                             |
/// | 第 4 引數   | `r10` | **注意：不是 `rcx`！**          |
/// | 第 5 引數   | `r8`  | —                             |
/// | 第 6 引數   | `r9`  | —                             |
/// | 返回值      | `rax` | 負值表示錯誤（`-errno`）        |
/// | 被破壞暫存器  | `rcx`, `r11` | Kernel 使用，呼叫後已更改 |
///
/// ## Clobber 清單說明
/// - `rcx`：Syscall 指令本身會將 rip 存入 rcx（用於 sysret 返回）
/// - `r11`：Syscall 指令本身會將 rflags 存入 r11
/// - `memory`：告知 rustc 這條 asm 可能讀寫任意記憶體（防止不正確的指令重排）
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
macro_rules! syscall {
    ($nr:expr) => {{
        let ret: i64;
        core::arch::asm!(
            "syscall",
            in("rax") $nr as i64,
            lateout("rax") ret,
            out("rcx") _,   // syscall 會修改 rcx（存 rip）
            out("r11") _,   // syscall 會修改 r11（存 rflags）
            options(nostack)
        );
        ret
    }};
    ($nr:expr, $a1:expr) => {{
        let ret: i64;
        core::arch::asm!(
            "syscall",
            in("rax") $nr as i64,
            in("rdi") $a1 as i64,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack)
        );
        ret
    }};
    ($nr:expr, $a1:expr, $a2:expr) => {{
        let ret: i64;
        core::arch::asm!(
            "syscall",
            in("rax") $nr as i64,
            in("rdi") $a1 as i64,
            in("rsi") $a2 as i64,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack)
        );
        ret
    }};
    ($nr:expr, $a1:expr, $a2:expr, $a3:expr) => {{
        let ret: i64;
        core::arch::asm!(
            "syscall",
            in("rax") $nr as i64,
            in("rdi") $a1 as i64,
            in("rsi") $a2 as i64,
            in("rdx") $a3 as i64,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack)
        );
        ret
    }};
    ($nr:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr) => {{
        let ret: i64;
        core::arch::asm!(
            "syscall",
            in("rax") $nr as i64,
            in("rdi") $a1 as i64,
            in("rsi") $a2 as i64,
            in("rdx") $a3 as i64,
            in("r10") $a4 as i64,  // 第 4 引數用 r10，不是 rcx！
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack)
        );
        ret
    }};
}

// ─────────────────────────────────────────────────────────────────────────────
// 三、直接 Syscall 函數（對外提供安全封裝）
// ─────────────────────────────────────────────────────────────────────────────

/// `timespec` 結構體（與 Linux Kernel 的 `struct timespec64` 佈局相容）
///
/// 使用 `repr(C)` 確保 Rust 不對欄位進行重排，
/// 保證與核心 ABI 的記憶體佈局完全一致。
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Timespec {
    pub tv_sec: i64,    // 秒（Unix epoch 起算）
    pub tv_nsec: i64,   // 奈秒（0..999_999_999）
}

/// 透過直接 Syscall 獲取 `CLOCK_MONOTONIC_RAW` 時鐘
///
/// ## 為什麼不用 libc 的 `clock_gettime`？
/// - libc 的實現在 Linux 下透過 **vDSO** 直接讀取核心共享記憶體頁，
///   不會觸發 `SYSCALL` 指令，也不會被 Seccomp-BPF 所攔截
/// - 惡意程式可能透過修改 vDSO 映射（在 `CLONE_NEWUSER` 沙箱中有可能），
///   向 DROS 返回偽造的時間戳
/// - `CLOCK_MONOTONIC_RAW`（id=4）是純硬體時鐘，不受 NTP 調整，
///   是 Merkle 審計樹中最可靠的時間源
///
/// ## 安全性注記
/// 此函數標記為 `unsafe`，因為它直接發起 syscall，
/// 呼叫者必須確保提供的指標有效且可寫。
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub fn raw_clock_gettime_monotonic() -> Result<Timespec, i64> {
    let mut ts = Timespec::default();
    let ret = unsafe {
        syscall!(
            syscall_nr::SYS_CLOCK_GETTIME,
            syscall_nr::CLOCK_MONOTONIC_RAW,
            &mut ts as *mut Timespec as i64
        )
    };
    if ret < 0 {
        Err(ret) // 負值即為 -errno
    } else {
        Ok(ts)
    }
}

/// 在非 Linux 平台的存根版本（允許編譯，但總是返回錯誤）
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
pub fn raw_clock_gettime_monotonic() -> Result<Timespec, i64> {
    Err(-38) // ENOSYS: 功能在此平台不可用
}

/// 透過直接 Syscall 建立匿名記憶體文件（`memfd_create`）
///
/// 對應 Kernel v5.15 的 `mm/shmem.c`。
/// 此函數不呼叫 libc 的 `memfd_create()`，
/// 直接透過 SYS_MEMFD_CREATE (319) 進行系統呼叫。
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub fn raw_memfd_create(name: &[u8], flags: u32) -> Result<i32, i64> {
    let ret = unsafe {
        syscall!(
            syscall_nr::SYS_MEMFD_CREATE,
            name.as_ptr() as i64,
            flags as i64
        )
    };
    if ret < 0 {
        Err(ret)
    } else {
        Ok(ret as i32)
    }
}

/// 透過直接 Syscall 寫入文件描述符
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub fn raw_write(fd: i32, buf: &[u8]) -> Result<usize, i64> {
    let ret = unsafe {
        syscall!(
            syscall_nr::SYS_WRITE,
            fd as i64,
            buf.as_ptr() as i64,
            buf.len() as i64
        )
    };
    if ret < 0 {
        Err(ret)
    } else {
        Ok(ret as usize)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 四、Seccomp-BPF 過濾器（執行期系統呼叫白名單鎖定）
// ─────────────────────────────────────────────────────────────────────────────

/// BPF 指令結構體（與 Linux `struct sock_filter` 完全相容）
///
/// ```c
/// struct sock_filter {
///     __u16  code;   // BPF 指令操作碼
///     __u8   jt;     // 條件為真時跳躍的指令數
///     __u8   jf;     // 條件為假時跳躍的指令數
///     __u32  k;      // 指令操作數（常數或偏移量）
/// };
/// ```
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

/// BPF 過濾器程式描述符（與 Linux `struct sock_fprog` 完全相容）
#[repr(C)]
pub struct SockFprog {
    pub len: u16,
    pub filter: *const SockFilter,
}

// BPF 指令碼常數（來自 Linux kernel uapi/linux/bpf_common.h）
const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

// Seccomp 返回動作常數（來自 linux/seccomp.h）
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;

// `seccomp_data.nr` 在 `seccomp_data` 結構體中的偏移量（位元組）
// struct seccomp_data { int nr; __u32 arch; __u64 instruction_pointer; ... }
const SECCOMP_DATA_NR_OFFSET: u32 = 0;

/// 構造 BPF `BPF_LD|BPF_W|BPF_ABS` 指令（從固定偏移量載入 32-bit word）
const fn bpf_stmt_ld_abs(offset: u32) -> SockFilter {
    SockFilter {
        code: BPF_LD | BPF_W | BPF_ABS,
        jt: 0,
        jf: 0,
        k: offset,
    }
}

/// 構造 BPF `BPF_JMP|BPF_JEQ|BPF_K` 指令（若等於 k 則跳躍 jt 條，否則跳躍 jf 條）
const fn bpf_stmt_jeq(k: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt,
        jf,
        k,
    }
}

/// 構造 BPF `BPF_RET|BPF_K` 指令（返回常數 k 作為 Seccomp 決策）
const fn bpf_stmt_ret(k: u32) -> SockFilter {
    SockFilter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k,
    }
}

/// DROS V2 執行期 Seccomp-BPF 白名單過濾器
///
/// ## BPF 程式邏輯（29 條指令）
///
/// ```text
/// [0]     LOAD  seccomp_data.nr          ; 載入當前系統呼叫號
/// [1..26] JEQ   <allowed_nr>, jt=N-k, jf=0  ; 若命中允許清單則跳至 ALLOW
/// [27]    RET   KILL_PROCESS              ; 預設殺死進程（任何不在白名單的呼叫）
/// [28]    RET   ALLOW                    ; 白名單通過
/// ```
///
/// ## 防禦的關鍵威脅
/// - `ptrace` (101)：除錯器附加，ROP 調試，記憶體探測
/// - `process_vm_readv` (310) / `process_vm_writev` (311)：跨進程讀寫
/// - `execve` (59) / `execveat` (322)：進程替換（ROP 鏈終點）
/// - `open` (2) / `openat` (257)：運行期動態庫載入
/// - `vsyscall` 頁面存取：由 MMU 而非 Seccomp 防禦（此 BPF 不覆蓋此面向）
///
/// ## 白名單設計原則
/// 每條允許的 Syscall 都必須有明確的業務理由。
/// 不確定的一律排除（Fail-closed 原則）。

// DROS V2 允許的 Syscall 數量（N）
// 注意：若修改允許清單，必須同步更新 jt 值！
// 跳躍公式：位於位置 k（1-indexed）的 JEQ 指令，jt = (N - k + 1)
// 其中 N = 白名單總數，ALLOW 在 [N+2]，KILL 在 [N+1]

// 以下是 26 條允許的 Syscall 及其 jt 值的完整計算：
// 位置 1 (read=0):          jt = 26+1-1 = 26
// 位置 2 (write=1):         jt = 26+1-2 = 25
// 位置 3 (close=3):         jt = 26+1-3 = 24
// 位置 4 (fstat=5):         jt = 26+1-4 = 23
// 位置 5 (mmap=9):          jt = 26+1-5 = 22
// 位置 6 (mprotect=10):     jt = 26+1-6 = 21
// 位置 7 (munmap=11):       jt = 26+1-7 = 20
// 位置 8 (brk=12):          jt = 26+1-8 = 19
// 位置 9 (rt_sigaction=13): jt = 26+1-9 = 18
// 位置 10 (rt_sigprocmask=14): jt = 26+1-10 = 17
// 位置 11 (rt_sigreturn=15): jt = 26+1-11 = 16
// 位置 12 (madvise=28):      jt = 26+1-12 = 15
// 位置 13 (dup=32):          jt = 26+1-13 = 14
// 位置 14 (dup2=33):         jt = 26+1-14 = 13
// 位置 15 (getpid=39):       jt = 26+1-15 = 12
// 位置 16 (sendmsg=46):      jt = 26+1-16 = 11
// 位置 17 (recvmsg=47):      jt = 26+1-17 = 10
// 位置 18 (exit=60):         jt = 26+1-18 = 9
// 位置 19 (fcntl=72):        jt = 26+1-19 = 8
// 位置 20 (prctl=157):       jt = 26+1-20 = 7
// 位置 21 (gettid=186):      jt = 26+1-21 = 6
// 位置 22 (futex=202):       jt = 26+1-22 = 5
// 位置 23 (clock_gettime=228): jt = 26+1-23 = 4
// 位置 24 (exit_group=231):  jt = 26+1-24 = 3
// 位置 25 (getrandom=318):   jt = 26+1-25 = 2
// 位置 26 (memfd_create=319): jt = 26+1-26 = 1
// 位置 27: KILL_PROCESS
// 位置 28: ALLOW

pub const DROS_SECCOMP_FILTER: [SockFilter; 29] = [
    // [0] 載入 syscall 號碼（seccomp_data.nr 在 offset 0）
    bpf_stmt_ld_abs(SECCOMP_DATA_NR_OFFSET),

    // [1..26] 白名單 JEQ 鏈（命中則跳至 ALLOW，否則繼續比對下一條）
    bpf_stmt_jeq(0,   26, 0), // read(0)
    bpf_stmt_jeq(1,   25, 0), // write(1)
    bpf_stmt_jeq(3,   24, 0), // close(3)
    bpf_stmt_jeq(5,   23, 0), // fstat(5)
    bpf_stmt_jeq(9,   22, 0), // mmap(9)
    bpf_stmt_jeq(10,  21, 0), // mprotect(10)
    bpf_stmt_jeq(11,  20, 0), // munmap(11)
    bpf_stmt_jeq(12,  19, 0), // brk(12)
    bpf_stmt_jeq(13,  18, 0), // rt_sigaction(13)
    bpf_stmt_jeq(14,  17, 0), // rt_sigprocmask(14)
    bpf_stmt_jeq(15,  16, 0), // rt_sigreturn(15)
    bpf_stmt_jeq(28,  15, 0), // madvise(28)
    bpf_stmt_jeq(32,  14, 0), // dup(32)
    bpf_stmt_jeq(33,  13, 0), // dup2(33)
    bpf_stmt_jeq(39,  12, 0), // getpid(39)
    bpf_stmt_jeq(46,  11, 0), // sendmsg(46)
    bpf_stmt_jeq(47,  10, 0), // recvmsg(47)
    bpf_stmt_jeq(60,   9, 0), // exit(60)
    bpf_stmt_jeq(72,   8, 0), // fcntl(72)
    bpf_stmt_jeq(157,  7, 0), // prctl(157)  ← 用於 Seccomp 自身安裝
    bpf_stmt_jeq(186,  6, 0), // gettid(186)
    bpf_stmt_jeq(202,  5, 0), // futex(202)  ← 互斥鎖實作
    bpf_stmt_jeq(228,  4, 0), // clock_gettime(228) ← 強制走核心路徑（非 vDSO）
    bpf_stmt_jeq(231,  3, 0), // exit_group(231)
    bpf_stmt_jeq(318,  2, 0), // getrandom(318)
    bpf_stmt_jeq(319,  1, 0), // memfd_create(319) ← DROS 記憶體池

    // [27] 預設：終止進程（任何不在白名單的呼叫）
    bpf_stmt_ret(SECCOMP_RET_KILL_PROCESS),

    // [28] 白名單通過：允許
    bpf_stmt_ret(SECCOMP_RET_ALLOW),
];

/// 在 `vajra_init()` 時安裝 Seccomp-BPF 執行期盔甲
///
/// ## 安裝步驟
/// 1. `prctl(PR_SET_NO_NEW_PRIVS, 1)`：禁止進程獲取新權限（Seccomp 安裝的前置條件）
/// 2. `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)`：安裝 BPF 過濾器
///
/// ## 安全警告
/// 此函數一旦成功執行，進程的 Syscall 能力將被**永久且不可逆地收窄**。
/// 必須確保在所有必要的初始化完成後才調用此函數。
///
/// ## 失敗處理（Fail-closed）
/// 若 Seccomp 安裝失敗（例如 Kernel 版本太舊），函數回傳 Err，
/// 呼叫者應視需要強制終止進程（不允許在無裝甲的情況下繼續運行）。
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub fn vajra_init_seccomp() -> Result<(), i64> {
    // 步驟 1：PR_SET_NO_NEW_PRIVS = 1
    // 這是安裝 Seccomp-BPF 的必要前置條件（Kernel 要求非特權進程必須先設置此標誌）
    let ret = unsafe {
        syscall!(
            syscall_nr::SYS_PRCTL,
            syscall_nr::PR_SET_NO_NEW_PRIVS,
            1i64,
            0i64,
            0i64
        )
    };
    if ret < 0 {
        return Err(ret);
    }

    // 步驟 2：安裝 BPF 過濾器
    let prog = SockFprog {
        len: DROS_SECCOMP_FILTER.len() as u16,
        filter: DROS_SECCOMP_FILTER.as_ptr(),
    };

    let ret = unsafe {
        syscall!(
            syscall_nr::SYS_PRCTL,
            syscall_nr::PR_SET_SECCOMP,
            syscall_nr::SECCOMP_MODE_FILTER,
            &prog as *const SockFprog as i64
        )
    };
    if ret < 0 {
        return Err(ret);
    }

    Ok(())
}

/// 非 Linux 平台的存根版本
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
pub fn vajra_init_seccomp() -> Result<(), i64> {
    // 在非 Linux 平台（如開發用 Windows）直接成功返回
    // 真實部署必須在 Linux 上執行
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// 五、Spectre v1 推測執行防禦工具組
// ─────────────────────────────────────────────────────────────────────────────

/// # Spectre v1 安全陣列索引遮罩
///
/// ## 攻擊原理
/// 在以下程式碼中，CPU 可能在 `if index < len` 的邊界檢查被確認前，
/// 推測地執行 `array[index]`，從而洩漏越界記憶體內容：
///
/// ```rust
/// if index < len {          // ← 推測執行：CPU 不等這個
///     let value = array[index]; // ← 越界存取已被推測執行！
///     secret_lookup[value];     // ← 透過 Cache timing 洩漏 value
/// }
/// ```
///
/// ## 防禦策略：陣列索引遮罩（Array Index Masking）
///
/// 在執行索引前，先計算一個遮罩：
/// - 若 `index < array_len`：遮罩 = `usize::MAX`（全部位元為 1），索引不變
/// - 若 `index >= array_len`：遮罩 = `0`（全部位元為 0），索引變為 0
///
/// 這樣即使在推測執行路徑上，存取的也只是 `array[0]`（合法位址），
/// 無法透過 Cache timing 洩漏任何越界資料。
///
/// ## 實作細節
/// 利用算術右移（Arithmetic Right Shift）將符號位傳播至所有位元位置：
/// - 若 `index >= array_len`：`index.wrapping_sub(array_len)` 的最高位（符號位）為 0
///   （因為 `usize` 是無符號，減法下溢 wrap 後高位可能不確定）
///
/// 更穩健的做法：直接比較並用 `isize` 的符號擴展：
/// ```
/// mask = (array_len - 1 - index) as isize >> (BITS - 1) → all-ones if index < len
/// ```
///
/// 這等價於：`mask = NOT(index >= array_len ? 0 : MAX)` 的 branchless 實現。
#[inline(always)]
pub fn spectre_v1_safe_index(index: usize, array_len: usize) -> usize {
    // 計算 (array_len - 1 - index)：
    // - 若 index < array_len：結果為正，算術右移後最高位為 0，mask = ...0000
    //   ← 等等這是錯的方向
    //
    // 正確算法（參考 CERT C Secure Coding STR30-C, CVE-2017-5753 mitigation）：
    //
    // mask = (index | (array_len - 1 - index)) >> (BITS - 1) 的取反
    // 或者更清晰的：
    //
    // let in_bounds = (index < array_len) as usize; // 0 or 1
    // let mask = in_bounds.wrapping_neg(); // if 1: 0xFFFF...FFFF; if 0: 0
    //
    // 這利用了 wrapping_neg(1) = 0xFFFF...FFFF 和 wrapping_neg(0) = 0 的特性

    let in_bounds = (index < array_len) as usize;
    // wrapping_neg(1) = 0xFFFF_FFFF_FFFF_FFFF (全 1 遮罩)
    // wrapping_neg(0) = 0x0000_0000_0000_0000 (全 0 遮罩)
    let mask = in_bounds.wrapping_neg();
    index & mask
}

/// # LFENCE 推測執行屏障（Speculation Barrier）
///
/// ## 用途
/// 在關鍵分支後插入 `LFENCE` 指令，強制 CPU 在繼續推測執行前，
/// 等待所有先前的記憶體讀取指令（`LOAD` 操作）完成。
///
/// 這有效地切斷了 Spectre 攻擊所需的「推測執行窗口」。
///
/// ## 使用場景
/// ```rust
/// if index < array_len {
///     speculation_barrier();  // ← 插入此處
///     // CPU 現在必須確認 index < array_len 才能繼續
///     let value = array[index];
/// }
/// ```
///
/// ## 效能影響
/// `LFENCE` 是一個輕量屏障，遠比 `MFENCE` 或 `CPUID` 廉價，
/// 但在高頻熱路徑上仍會造成約 15-30 個 CPU 週期的延遲。
/// 因此，建議僅在處理敏感資料的索引操作前使用，而非到處插入。
#[inline(always)]
pub fn speculation_barrier() {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "lfence",
            options(nostack, nomem, preserves_flags)
            // nostack: 不讀寫 rsp
            // nomem: 不需要 memory clobber（lfence 透過 CPU 微架構保證序列化，
            //        此處告知 rustc 本段 asm 不讀寫任何 Rust 變數）
            // preserves_flags: 不修改 EFLAGS
        );
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        // 在非 x86 平台，使用編譯器屏障（compiler fence）作為降級替代
        // 這只防止編譯器重排，無法防禦硬體推測執行
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

/// 帶 Spectre v1 防禦的安全陣列存取
///
/// 組合了索引遮罩和 LFENCE 屏障，提供最完整的 Spectre v1 防護。
///
/// ## 使用範例
/// ```rust
/// let prefix_rules: [PrefixRule; 256] = [...];
/// if let Some(value) = spectre_safe_array_access(&prefix_rules, untrusted_index) {
///     // 安全：即使在推測執行路徑上也不會越界
/// }
/// ```
#[inline(always)]
pub fn spectre_safe_array_access<T>(slice: &[T], index: usize) -> Option<&T> {
    let safe_idx = spectre_v1_safe_index(index, slice.len());
    // 在邊界確認之後，插入 LFENCE 切斷推測窗口
    speculation_barrier();
    if index < slice.len() {
        // SAFETY: safe_idx 已被遮罩至合法範圍，
        // 即使 CPU 在遮罩前推測執行，也只能存取 slice[0]
        Some(&slice[safe_idx])
    } else {
        None
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 六、BPF 過濾器結構驗證（編譯期斷言）
// ─────────────────────────────────────────────────────────────────────────────

/// 驗證 BPF 過濾器的結構完整性
///
/// 確保：
/// 1. 最後一條指令是 RET ALLOW（白名單通過）
/// 2. 倒數第二條指令是 RET KILL_PROCESS（預設拒絕）
/// 3. 第一條指令是 LOAD（載入 syscall 號）
pub const fn verify_bpf_filter_structure() -> bool {
    let filter = &DROS_SECCOMP_FILTER;
    let n = filter.len();

    // 第一條必須是 BPF_LD
    let first_ok = filter[0].code == (BPF_LD | BPF_W | BPF_ABS);
    // 倒數第二條必須是 KILL_PROCESS
    let kill_ok = filter[n - 2].k == SECCOMP_RET_KILL_PROCESS;
    // 最後一條必須是 ALLOW
    let allow_ok = filter[n - 1].k == SECCOMP_RET_ALLOW;

    first_ok && kill_ok && allow_ok
}

// 編譯期斷言：BPF 過濾器結構必須正確
const _: () = assert!(
    verify_bpf_filter_structure(),
    "DROS V2: BPF filter structure is invalid! Check ALLOW/KILL positions."
);

// ─────────────────────────────────────────────────────────────────────────────
// 七、單元測試
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spectre_v1_safe_index_in_bounds() {
        // 合法索引應通過遮罩後不變
        assert_eq!(spectre_v1_safe_index(3, 10), 3);
        assert_eq!(spectre_v1_safe_index(0, 1), 0);
        assert_eq!(spectre_v1_safe_index(9, 10), 9);
    }

    #[test]
    fn test_spectre_v1_safe_index_out_of_bounds() {
        // 越界索引應被遮罩為 0（合法位址）
        assert_eq!(spectre_v1_safe_index(10, 10), 0); // index == len
        assert_eq!(spectre_v1_safe_index(100, 10), 0); // 遠超出界
        assert_eq!(spectre_v1_safe_index(usize::MAX, 1), 0); // 極端情況
    }

    #[test]
    fn test_spectre_safe_array_access_valid() {
        let arr = [10u32, 20, 30, 40, 50];
        assert_eq!(spectre_safe_array_access(&arr, 2), Some(&30u32));
        assert_eq!(spectre_safe_array_access(&arr, 0), Some(&10u32));
        assert_eq!(spectre_safe_array_access(&arr, 4), Some(&50u32));
    }

    #[test]
    fn test_spectre_safe_array_access_oob() {
        let arr = [10u32, 20, 30];
        assert_eq!(spectre_safe_array_access(&arr, 3), None);
        assert_eq!(spectre_safe_array_access(&arr, 999), None);
    }

    #[test]
    fn test_bpf_filter_length() {
        // 1 (LOAD) + 26 (JEQ) + 2 (KILL + ALLOW) = 29
        assert_eq!(DROS_SECCOMP_FILTER.len(), 29);
    }

    #[test]
    fn test_bpf_filter_structure_valid() {
        assert!(verify_bpf_filter_structure());
    }

    #[test]
    fn test_bpf_filter_kill_is_penultimate() {
        let n = DROS_SECCOMP_FILTER.len();
        assert_eq!(DROS_SECCOMP_FILTER[n - 2].k, SECCOMP_RET_KILL_PROCESS);
    }

    #[test]
    fn test_bpf_filter_allow_is_last() {
        let n = DROS_SECCOMP_FILTER.len();
        assert_eq!(DROS_SECCOMP_FILTER[n - 1].k, SECCOMP_RET_ALLOW);
    }

    #[test]
    fn test_bpf_filter_read_is_allowed() {
        // read(0) 應該在白名單中
        let read_in_list = DROS_SECCOMP_FILTER[1..27].iter().any(|f| {
            f.code == (BPF_JMP | BPF_JEQ | BPF_K) && f.k == 0 // SYS_READ = 0
        });
        assert!(read_in_list, "SYS_READ must be in seccomp allowlist");
    }

    #[test]
    fn test_bpf_filter_execve_not_allowed() {
        // execve(59) 不應該在白名單中（防止 ROP 鏈終點）
        let execve_in_list = DROS_SECCOMP_FILTER[1..27].iter().any(|f| {
            f.code == (BPF_JMP | BPF_JEQ | BPF_K) && f.k == 59 // SYS_EXECVE = 59
        });
        assert!(!execve_in_list, "SYS_EXECVE must NOT be in seccomp allowlist");
    }

    #[test]
    fn test_bpf_filter_ptrace_not_allowed() {
        // ptrace(101) 不應在白名單
        let ptrace_in_list = DROS_SECCOMP_FILTER[1..27].iter().any(|f| {
            f.code == (BPF_JMP | BPF_JEQ | BPF_K) && f.k == 101 // SYS_PTRACE = 101
        });
        assert!(!ptrace_in_list, "SYS_PTRACE must NOT be in seccomp allowlist");
    }

    #[test]
    fn test_speculation_barrier_compiles() {
        // 確認屏障函數在目標平台可以編譯和執行
        speculation_barrier();
    }

    #[test]
    fn test_raw_clock_gettime_non_linux() {
        // 在非 Linux 平台，應回傳 Err(-38) (ENOSYS)
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        {
            let result = raw_clock_gettime_monotonic();
            assert!(result.is_err());
            assert_eq!(result.unwrap_err(), -38);
        }
    }
}

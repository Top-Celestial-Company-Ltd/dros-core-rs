/// # DROS V2 — Lock-free MPSC Audit Ring Buffer
///
/// ## 核心挑戰與防禦 (Red Team & Debugging Phase)
///
/// 在 50K QPS 的極高並發環境下，傳統的 `Mutex` 或 `RwLock` 會導致作業系統級別的
/// 執行緒上下文切換（Context Switch）與排程器介入，這會造成延遲的長尾效應（P99 Latency 飆升）。
/// 因此，DROS 的審計日誌系統必須採用 **Lock-free (無鎖)** 設計。
///
/// ### 挑戰一：ABA 問題 (The ABA Problem)
/// 若使用傳統的狀態機（如 `EMPTY -> WRITING -> FULL`）與 `CAS` 操作：
/// 1. 執行緒 A 讀取狀態為 `EMPTY`，準備寫入，但被作業系統中斷（Stall）。
/// 2. 執行緒 B 寫入資料（變 `FULL`），消費者讀取資料（變回 `EMPTY`）。
/// 3. 執行緒 A 甦醒，檢查狀態仍為 `EMPTY`，執行 `CAS` 成功，覆蓋了該槽位在下一輪的資料。
/// **防禦：** 本實作採用 **Monotonic Sequence Numbers (單調遞增序列號)**。
/// 每個槽位不紀錄狀態，而是紀錄「絕對代數（Generation）」。序列號永遠遞增，
/// 完美消除了 ABA 問題。
///
/// ### 挑戰二：偽共享效應 (False Sharing)
/// 在多核心 CPU 中，快取是以 Cache Line（通常為 64 Bytes）為單位載入的。
/// 若 `head`（被多個生產者頻繁更新）與 `tail`（被單一消費者頻繁更新）恰好位於
/// 同一個 Cache Line，生產者的每次 `CAS` 都會導致消費者 CPU 核心的快取失效，
/// 引發嚴重的 Cache Bouncing（快取震盪）。
/// **防禦：** 實作 `CachePadded<T>`，使用 `#[repr(align(64))]` 將 `head` 與 `tail`
/// 強制隔離在不同的 Cache Line。
///
/// ### 挑戰三：記憶體重排 (Memory Reordering)
/// 在 ARM 或 x86 的弱記憶體模型下，CPU 可能會將「寫入資料」與「更新索引」的指令重排，
/// 導致消費者讀到未完成的半殘資料（Data Race）。
/// **防禦：** 嚴格的 Acquire-Release 語意 (Memory Ordering)：
/// - 寫入資料後，使用 `Ordering::Release` 更新 `seq`。
/// - 讀取資料前，使用 `Ordering::Acquire` 載入 `seq`。

use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicUsize, Ordering};

/// 確保變數獨佔一個 64-byte Cache Line，防止 False Sharing
#[repr(C, align(64))]
pub struct CachePadded<T> {
    pub value: T,
}

/// 審計日誌紀錄（24 Bytes，無堆積記憶體指標）
#[derive(Clone, Copy, Default, Debug, PartialEq)]
#[repr(C)]
pub struct AuditRecord {
    pub timestamp_ns: i64,   // 發生時間（Monotonic Raw）
    pub tenant_id: u32,      // 租戶 ID
    pub effect: u8,          // 1 = ALLOW, 0 = DENY
    pub rule_offset: u16,    // 命中的 DCT 規則索引
    pub padding: u8,         // 補齊對齊
    pub resource_hash: u64,  // 請求資源的 64-bit Hash
}

/// 環形緩衝區的槽位 (Slot)
struct Slot {
    /// 槽位的絕對序列號，用於防禦 ABA 問題並標示所有權
    seq: AtomicUsize,
    /// 實際資料（使用 UnsafeCell 允許在多執行緒環境下突破內部可變性）
    data: UnsafeCell<AuditRecord>,
}

pub const RING_CAPACITY: usize = 4096;
const RING_MASK: usize = RING_CAPACITY - 1;

// 編譯期斷言：容量必須是 2 的次方，才能使用 Bitwise AND 取代 Modulo
const _: () = assert!((RING_CAPACITY & RING_MASK) == 0);

/// MPSC (Multi-Producer Single-Consumer) 無鎖環形緩衝區
/// 基於 Dmitry Vyukov 的 Bounded MPMC Queue 演算法簡化為 MPSC
pub struct AuditRingBuffer {
    buffer: Vec<Slot>,
    head: CachePadded<AtomicUsize>, // 生產者競爭的起點
    tail: CachePadded<AtomicUsize>, // 單一消費者讀取的起點
}

// 實作 Sync 與 Send，保證安全跨執行緒共享
unsafe impl Sync for AuditRingBuffer {}
unsafe impl Send for AuditRingBuffer {}

impl AuditRingBuffer {
    /// 初始化環形緩衝區
    ///
    /// ## 效能注記
    /// 這是 V2 執行期唯一會發生堆積配置（Heap Allocation）的地方。
    /// 必須在 `vajra_init()` 階段完成，執行期維持 Zero-Allocation。
    pub fn new() -> Box<Self> {
        let mut buffer = Vec::with_capacity(RING_CAPACITY);
        for i in 0..RING_CAPACITY {
            buffer.push(Slot {
                seq: AtomicUsize::new(i),
                data: UnsafeCell::new(AuditRecord::default()),
            });
        }

        Box::new(Self {
            buffer,
            head: CachePadded {
                value: AtomicUsize::new(0),
            },
            tail: CachePadded {
                value: AtomicUsize::new(0),
            },
        })
    }

    /// 生產者寫入（Wait-free / Lock-free）
    ///
    /// ## 流程
    /// 1. 取得 `head`。
    /// 2. 檢查槽位的 `seq` 是否等於 `head`（表示槽位已空出，準備迎接這世代的寫入）。
    /// 3. 若符合，使用 CAS 競爭 `head`。競爭成功則獲得該槽位專屬寫入權。
    /// 4. 寫入資料，並透過 Release 語意將 `seq` 推進為 `head + 1`，釋放給消費者。
    pub fn push(&self, record: AuditRecord) -> Result<(), &'static str> {
        let mut head = self.head.value.load(Ordering::Relaxed);
        
        loop {
            let slot = &self.buffer[head & RING_MASK];
            let seq = slot.seq.load(Ordering::Acquire);
            
            // 使用 isize 處理無號數溢位迴繞問題
            let diff = seq as isize - head as isize;

            if diff == 0 {
                // 槽位已空出，且世代正確 -> 嘗試 CAS 搶佔這個位子
                // 比較並交換：如果 self.head 的值還是 head，就更新為 head + 1
                match self.head.value.compare_exchange_weak(
                    head,
                    head + 1,
                    Ordering::Relaxed, // 搶佔只關乎順序，不需要同步資料
                    Ordering::Relaxed,
                ) {
                    Ok(_) => {
                        // 搶佔成功，此執行緒獨佔這個槽位
                        unsafe {
                            *slot.data.get() = record;
                        }
                        // 寫入完成，將狀態推給消費者 (Release 確保前面的寫入指令不被重排到這行之後)
                        slot.seq.store(head + 1, Ordering::Release);
                        return Ok(());
                    }
                    Err(actual_head) => {
                        // 搶佔失敗，head 已經被其他執行緒推動，更新本地 head 重試
                        head = actual_head;
                    }
                }
            } else if diff < 0 {
                // 生產者繞了一圈追上了消費者，佇列已滿
                // Fail-closed：在高安全場景，日誌不可丟失。
                return Err("Audit Ring Buffer Overflow: Consumer too slow!");
            } else {
                // 另一個生產者剛剛搶走這格並改了 seq，重新抓取 head
                head = self.head.value.load(Ordering::Relaxed);
            }
        }
    }

    /// 消費者讀取（Single Consumer）
    ///
    /// ## 流程
    /// 消費者唯一負責推動 `tail`。檢查槽位的 `seq` 是否為 `tail + 1`（表示生產者已完成寫入）。
    /// 讀出後將 `seq` 推至 `tail + RING_CAPACITY` 交還給下一世代的生產者。
    pub fn pop(&self) -> Option<AuditRecord> {
        let tail = self.tail.value.load(Ordering::Relaxed);
        let slot = &self.buffer[tail & RING_MASK];
        let seq = slot.seq.load(Ordering::Acquire);
        
        let diff = seq as isize - (tail + 1) as isize;

        if diff == 0 {
            // 資料已準備好
            let record = unsafe { *slot.data.get() };
            
            // 釋放槽位：推進 seq 讓生產者可以寫入下一世代的資料
            slot.seq.store(tail + RING_MASK + 1, Ordering::Release);
            
            // 推進消費者 tail
            self.tail.value.store(tail + 1, Ordering::Relaxed);
            
            Some(record)
        } else {
            // 佇列為空（diff < 0）
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::sync::Arc;

    #[test]
    fn test_single_thread_push_pop() {
        let ring = AuditRingBuffer::new();
        let record = AuditRecord { timestamp_ns: 123, tenant_id: 42, effect: 1, rule_offset: 0, padding: 0, resource_hash: 777 };
        
        assert_eq!(ring.pop(), None);
        assert!(ring.push(record).is_ok());
        
        let out = ring.pop().unwrap();
        assert_eq!(out.tenant_id, 42);
        assert_eq!(out.resource_hash, 777);
        assert_eq!(ring.pop(), None);
    }

    #[test]
    fn test_overflow_protection() {
        let ring = AuditRingBuffer::new();
        // 填滿佇列
        for i in 0..RING_CAPACITY {
            assert!(ring.push(AuditRecord { tenant_id: i as u32, ..Default::default() }).is_ok());
        }
        // 再推一次應觸發溢位錯誤
        let err = ring.push(AuditRecord::default());
        assert!(err.is_err());
        assert_eq!(err.unwrap_err(), "Audit Ring Buffer Overflow: Consumer too slow!");
    }

    #[test]
    fn test_mpsc_concurrency() {
        // 使用 Arc 共享 Ring Buffer
        let ring = Arc::new(AuditRingBuffer::new());
        let num_threads: usize = 8;
        let pushes_per_thread: i64 = 500; // 總數 4000，小於 CAPACITY 不會阻塞
        
        let mut handles = vec![];
        
        // 生成多個生產者
        for t_id in 0..num_threads {
            let ring_clone = Arc::clone(&ring);
            handles.push(thread::spawn(move || {
                for i in 0..pushes_per_thread {
                    let rec = AuditRecord { tenant_id: t_id as u32, timestamp_ns: i, ..Default::default() };
                    ring_clone.push(rec).unwrap();
                }
            }));
        }
        
        // 等待所有生產者完成
        for h in handles {
            h.join().unwrap();
        }
        
        // 單一消費者驗證數量
        let mut count = 0usize;
        let mut tenant_counts = vec![0; num_threads];
        
        while let Some(rec) = ring.pop() {
            count += 1;
            tenant_counts[rec.tenant_id as usize] += 1;
        }
        
        assert_eq!(count, num_threads * pushes_per_thread as usize);
        for tc in tenant_counts {
            assert_eq!(tc, pushes_per_thread as usize);
        }
    }
}

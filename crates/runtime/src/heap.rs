extern crate alloc;

use buddy_system_allocator::LockedHeap;
use log::info;

include!(concat!(env!("OUT_DIR"), "/consts.rs"));

// 堆大小
// const HEAP_SIZE: usize = 0x0180_0000;
// pub const HEAP_SIZE: usize = 0x0180_0000;

// 堆空间
#[link_section = ".bss.heap"]
static mut HEAP: [u8; HEAP_SIZE] = [0; HEAP_SIZE];

/// 堆内存分配器
#[global_allocator]
static HEAP_ALLOCATOR: LockedHeap<30> = LockedHeap::empty();

/// 获取堆使用统计信息
/// 返回 (总大小, 已分配字节数, 分配计数)
pub fn heap_stats() -> (usize, usize, usize) {
    let heap = HEAP_ALLOCATOR.lock();
    let total_bytes = heap.stats_total_bytes();
    let allocated_bytes = heap.stats_alloc_actual();
    // buddy_system_allocator不提供分配计数，我们可以用已分配字节数除以平均分配大小来估算
    let allocation_count = if allocated_bytes > 0 { allocated_bytes / 64 } else { 0 }; // 假设平均分配64字节
    (total_bytes, allocated_bytes, allocation_count)
}

/// 初始化堆内存分配器
pub fn init() {
    unsafe {
        HEAP_ALLOCATOR
            .lock()
            .init(HEAP.as_mut_ptr() as usize, HEAP_SIZE);

        info!(
            "kernel HEAP init: {:#x} - {:#x}  size: {:#x}",
            HEAP.as_ptr() as usize,
            HEAP.as_ptr() as usize + HEAP_SIZE,
            HEAP_SIZE
        );
    }
}

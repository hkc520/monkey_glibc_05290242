extern crate alloc;

use buddy_system_allocator::LockedHeap;
use log::{info, error};

include!(concat!(env!("OUT_DIR"), "/consts.rs"));

// 堆大小 - 现在增加到128MB以支持更多内存密集型操作
// const HEAP_SIZE: usize = 0x0180_0000;
// pub const HEAP_SIZE: usize = 0x0180_0000;

// 堆空间
#[link_section = ".bss.heap"]
static mut HEAP: [u8; HEAP_SIZE] = [0; HEAP_SIZE];

/// 堆内存分配器
#[global_allocator]
static HEAP_ALLOCATOR: LockedHeap<30> = LockedHeap::empty();

/// 初始化堆内存分配器
pub fn init() {
    unsafe {
        HEAP_ALLOCATOR
            .lock()
            .init(HEAP.as_mut_ptr() as usize, HEAP_SIZE);

        info!(
            "kernel HEAP init: {:#x} - {:#x}  size: {:#x} ({} MB)",
            HEAP.as_ptr() as usize,
            HEAP.as_ptr() as usize + HEAP_SIZE,
            HEAP_SIZE,
            HEAP_SIZE / (1024 * 1024)
        );
    }
}

/// 自定义内存分配错误处理函数
/// 当内存分配失败时提供详细的诊断信息
#[alloc_error_handler]
fn alloc_error_handler(layout: core::alloc::Layout) -> ! {
    error!("=============== MEMORY ALLOCATION FAILED ===============");
    error!("Failed to allocate {} bytes with alignment {}", layout.size(), layout.align());
    error!("Heap size: {} bytes ({} MB)", HEAP_SIZE, HEAP_SIZE / (1024 * 1024));
    error!("Heap range: {:#x} - {:#x}", unsafe { HEAP.as_ptr() as usize }, unsafe { HEAP.as_ptr() as usize + HEAP_SIZE });
    
    // 尝试获取堆使用情况统计
    error!("This error is likely caused by:");
    error!("1. sbrk() using wrong memory type (should be MemType::Mmap, not CodeSection)");
    error!("2. Insufficient initial heap size for the application");
    error!("3. Memory fragmentation in heap allocator");
    error!("======================================================");
    
    panic!("Out of memory");
}

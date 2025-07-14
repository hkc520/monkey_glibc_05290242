extern crate alloc;

use buddy_system_allocator::LockedHeap;
use log::{info, error, warn, debug};
use core::alloc::{GlobalAlloc, Layout};
use core::ptr::null_mut;
use sync::Mutex;
use alloc::vec::Vec;
use crate::frame::{get_free_pages, frame_alloc_much, FrameTracker};
use polyhal::pagetable::PAGE_SIZE;

include!(concat!(env!("OUT_DIR"), "/consts.rs"));

// 堆大小 - 增加到512MB以支持iperf等网络测试的大内存需求
// 原来: const HEAP_SIZE: usize = 0x0800_0000; (128MB)
// 现在: 使用环境变量HEAP_SIZE，默认512MB以避免网络测试中的内存分配失败

// 大内存分配阈值 - 提高到256KB以减少大池使用
const LARGE_ALLOC_THRESHOLD: usize = 256 * 1024;

// 堆空间
#[link_section = ".bss.heap"]
static mut HEAP: [u8; HEAP_SIZE] = [0; HEAP_SIZE];

/// 改进的大内存分配器 - 使用动态页面分配替代静态池
struct LargeAllocator {
    allocations: Vec<(usize, usize, Vec<FrameTracker>)>, // (ptr_addr, size, frame_trackers)
}

impl LargeAllocator {
    const fn new() -> Self {
        Self {
            allocations: Vec::new(),
        }
    }

    fn alloc(&mut self, size: usize, align: usize) -> Option<*mut u8> {
        // 计算需要的页面数量
        let pages_needed = (size + PAGE_SIZE - 1) / PAGE_SIZE;
        
        // 尝试分配连续的物理页面
        if let Some(frame_trackers) = frame_alloc_much(pages_needed) {
            // 获取第一个页面的物理地址作为起始地址
            let start_paddr = frame_trackers[0].0.raw();
            let ptr = start_paddr as *mut u8;
            
            // 检查对齐
            let ptr_addr = ptr as usize;
            let aligned_addr = (ptr_addr + align - 1) & !(align - 1);
            
            if aligned_addr != ptr_addr {
                // 如果需要对齐调整，我们需要重新分配
                // 为简单起见，这里直接返回失败，让调用者使用buddy allocator
                warn!("Large allocation alignment mismatch: ptr={:#x}, align={}, falling back to buddy", ptr_addr, align);
                return None;
            }
            
            // 记录分配信息
            self.allocations.push((ptr_addr, size, frame_trackers));
            
            info!("Large pool allocation (dynamic): {} bytes ({} pages) at addr {:#x}", 
                  size, pages_needed, ptr_addr);
            
            Some(ptr)
        } else {
            let free_pages = get_free_pages();
            warn!("Large pool allocation failed: need {} pages, {} pages available", 
                  pages_needed, free_pages);
            None
        }
    }

    fn dealloc(&mut self, ptr: *mut u8, size: usize) {
        let ptr_addr = ptr as usize;
        
        // 查找对应的分配记录
        for i in 0..self.allocations.len() {
            let (alloc_addr, alloc_size, _) = &self.allocations[i];
            
            if *alloc_addr == ptr_addr && *alloc_size == size {
                // 找到匹配的分配记录，移除它
                let (_, _, frame_trackers) = self.allocations.remove(i);
                let pages_freed = frame_trackers.len();
                
                info!("Large pool deallocation SUCCESS: {} bytes ({} pages) at addr {:#x}", 
                      size, pages_freed, ptr_addr);
                
                // frame_trackers 会在这里自动析构，物理页面会被自动释放回系统
                return;
            }
        }
        
        // 如果没找到精确匹配，尝试找到包含该地址的分配
        for i in 0..self.allocations.len() {
            let (alloc_addr, alloc_size, _) = &self.allocations[i];
            
            if ptr_addr >= *alloc_addr && ptr_addr < *alloc_addr + *alloc_size {
                warn!("Large pool dealloc: found containing allocation at addr {:#x}, size {}, requested size {}", 
                      *alloc_addr, *alloc_size, size);
                
                // 移除整个分配块
                let (_, _, frame_trackers) = self.allocations.remove(i);
                let pages_freed = frame_trackers.len();
                
                warn!("Large pool deallocation (partial match): freed {} pages", pages_freed);
                return;
            }
        }
        
        warn!("Large pool deallocation FAILED: ptr {:#x}, size {} not found", ptr_addr, size);
        
        // 打印当前分配状态以便调试
        if log::max_level() >= log::Level::Warn {
            warn!("Current large allocations: {}", self.allocations.len());
            for (i, (alloc_addr, alloc_size, trackers)) in self.allocations.iter().enumerate() {
                warn!("  [{}] addr={:#x}, size={}, pages={}", i, alloc_addr, alloc_size, trackers.len());
                if i >= 5 { // 只显示前5个以避免日志过多
                    warn!("  ... and {} more", self.allocations.len() - 5);
                    break;
                }
            }
        }
    }

    fn get_allocation_stats(&self) -> (usize, usize) {
        let total_allocations = self.allocations.len();
        let total_pages: usize = self.allocations.iter().map(|(_, _, trackers)| trackers.len()).sum();
        (total_allocations, total_pages)
    }
}

/// 大内存分配器实例
static LARGE_ALLOCATOR: Mutex<LargeAllocator> = Mutex::new(LargeAllocator::new());

/// 堆内存分配器 - 使用ORDER=32优化大内存分配
/// 这允许最大分配块达到4GB，减少碎片化问题
static HEAP_ALLOCATOR: LockedHeap<32> = LockedHeap::empty();

/// 自定义全局分配器，处理大内存分配
struct HybridAllocator;

unsafe impl GlobalAlloc for HybridAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // 优先使用buddy allocator，只有在失败时才使用大内存池
        if layout.size() > LARGE_ALLOC_THRESHOLD {
            // 先尝试buddy allocator
            let ptr = HEAP_ALLOCATOR.alloc(layout);
            if !ptr.is_null() {
                if log::max_level() >= log::Level::Debug {
                    debug!("Large allocation via buddy allocator: {} bytes at {:#x}", 
                           layout.size(), ptr as usize);
                }
                return ptr;
            }
            
            // buddy allocator失败，尝试大内存池
            if let Some(ptr) = LARGE_ALLOCATOR.lock().alloc(layout.size(), layout.align()) {
                return ptr;
            }
            
            warn!("Both buddy and large pool allocation failed for {} bytes", layout.size());
            return null_mut();
        }
        
        // 小内存直接使用buddy allocator
        HEAP_ALLOCATOR.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ptr.is_null() {
            return;
        }
        
        let ptr_addr = ptr as usize;
        
        // 检查指针是否在堆范围内
        let heap_start = HEAP.as_ptr() as usize;
        let heap_end = heap_start + HEAP_SIZE;
        
        if ptr_addr >= heap_start && ptr_addr < heap_end {
            // 堆内存释放
            if log::max_level() >= log::Level::Debug && layout.size() > LARGE_ALLOC_THRESHOLD {
                debug!("Global dealloc: routing to buddy allocator - ptr={:#x}, size={}", 
                       ptr_addr, layout.size());
            }
            HEAP_ALLOCATOR.dealloc(ptr, layout);
        } else {
            // 大内存池释放
            if log::max_level() >= log::Level::Info {
                info!("Global dealloc: routing to large pool - ptr={:#x}, size={}", 
                      ptr_addr, layout.size());
            }
            LARGE_ALLOCATOR.lock().dealloc(ptr, layout.size());
        }
    }
}

#[global_allocator]
static GLOBAL_ALLOCATOR: HybridAllocator = HybridAllocator;

/// 初始化堆内存分配器
pub fn init() {
    unsafe {
        HEAP_ALLOCATOR
            .lock()
            .init(HEAP.as_mut_ptr() as usize, HEAP_SIZE);

        info!(
            "Hybrid HEAP init: {:#x} - {:#x}  size: {:#x} ({} MB)",
            HEAP.as_ptr() as usize,
            HEAP.as_ptr() as usize + HEAP_SIZE,
            HEAP_SIZE,
            HEAP_SIZE / (1024 * 1024)
        );
        
        info!("Buddy allocator max order: 32 (max allocation: 4GB)");
        info!("Large allocation threshold: {} KB", LARGE_ALLOC_THRESHOLD / 1024);
        info!("Large allocator: dynamic page allocation (no static pool)");
        
        // 初始化大内存分配器（确保它可以被使用）
        LARGE_ALLOCATOR.lock(); // 触发初始化
        
        info!("Hybrid allocator initialization completed");
    }
}

/// 自定义内存分配错误处理函数
/// 当内存分配失败时提供详细的诊断信息
#[alloc_error_handler]
fn alloc_error_handler(layout: Layout) -> ! {
    error!("=============== MEMORY ALLOCATION FAILED ===============");
    error!("Failed to allocate {} bytes with alignment {}", layout.size(), layout.align());
    error!("Heap size: {} bytes ({} MB)", HEAP_SIZE, HEAP_SIZE / (1024 * 1024));
    error!("Heap range: {:#x} - {:#x}", unsafe { HEAP.as_ptr() as usize }, unsafe { HEAP.as_ptr() as usize + HEAP_SIZE });

    // 显示物理内存信息
    let free_pages = get_free_pages();
    let free_kb = free_pages * PAGE_SIZE / 1024;
    error!("Available physical memory: {} pages ({} KB)", free_pages, free_kb);

    // 显示大内存分配器状态
    if layout.size() > LARGE_ALLOC_THRESHOLD {
        error!("Large allocation failure (>{} KB) - Dynamic allocator status:", LARGE_ALLOC_THRESHOLD / 1024);
        
        let allocator = LARGE_ALLOCATOR.lock();
        let (alloc_count, total_pages) = allocator.get_allocation_stats();
        
        error!("Active large allocations: {}", alloc_count);
        error!("Total pages in use by large allocator: {}", total_pages);
        error!("Pages needed for this allocation: {}", (layout.size() + PAGE_SIZE - 1) / PAGE_SIZE);
        
        if free_pages < (layout.size() + PAGE_SIZE - 1) / PAGE_SIZE {
            error!("Insufficient physical memory for allocation");
        }
    }

    error!("This error is likely caused by:");
    error!("1. Physical memory exhaustion - {} pages available", free_pages);
    error!("2. Memory fragmentation preventing large continuous allocation");
    error!("3. Buddy allocator unable to handle large allocation");
    error!("4. Need to increase physical memory or reduce allocation size");

    if layout.size() > LARGE_ALLOC_THRESHOLD {
        error!("Large allocation (>{} KB) detected - consider:", LARGE_ALLOC_THRESHOLD / 1024);
        error!("  - Breaking into smaller chunks");
        error!("  - Using memory mapping instead of heap allocation");
        error!("  - Dynamic allocator should handle this if physical memory is available");
    }

    error!("======================================================");
    debug!("[{}]", core::panic::Location::caller());
    panic!("Out of memory");
}

extern crate alloc;

use buddy_system_allocator::LockedHeap;
use log::{info, error, warn, debug};
use core::alloc::{GlobalAlloc, Layout};
use core::ptr::null_mut;
use sync::Mutex;
use alloc::vec::Vec;
use crate::frame::get_free_pages;

include!(concat!(env!("OUT_DIR"), "/consts.rs"));

// 堆大小 - 增加到512MB以支持iperf等网络测试的大内存需求
// 原来: const HEAP_SIZE: usize = 0x0800_0000; (128MB)
// 现在: 使用环境变量HEAP_SIZE，默认512MB以避免网络测试中的内存分配失败

// 大内存分配阈值
const LARGE_ALLOC_THRESHOLD: usize = 64 * 1024;

// 大内存池大小 - 增加到128MB以提供更多空间
const LARGE_POOL_SIZE: usize = 128 * 1024 * 1024; // 128MB

// 堆空间
#[link_section = ".bss.heap"]
static mut HEAP: [u8; HEAP_SIZE] = [0; HEAP_SIZE];

// 大内存池
#[link_section = ".bss.large_pool"]
static mut LARGE_POOL: [u8; LARGE_POOL_SIZE] = [0; LARGE_POOL_SIZE];

/// 改进的大内存分配器 - 支持内存压缩和智能回收
struct LargeAllocator {
    allocations: Vec<(usize, usize, bool)>, // (offset, size, is_free)
    next_alloc_hint: usize, // 下次分配的提示位置
}

impl LargeAllocator {
    const fn new() -> Self {
        Self {
            allocations: Vec::new(),
            next_alloc_hint: 0,
        }
    }

    fn alloc(&mut self, size: usize, align: usize) -> Option<*mut u8> {
        // 检查是否需要紧急内存重置
        let end_offset = self.get_end_offset();
        let remaining = LARGE_POOL_SIZE.saturating_sub(end_offset);
        
        // 如果剩余空间不足10%且有很多分配，尝试紧急重置
        if remaining < LARGE_POOL_SIZE / 10 && self.allocations.len() > 100 {
            warn!("Emergency memory situation: {} bytes remaining, {} allocations", remaining, self.allocations.len());
            
            // 强制内存压缩
            if self.emergency_reset() {
                warn!("Emergency reset completed, retrying allocation");
                // 重新计算end_offset
                let new_end_offset = self.get_end_offset();
                let new_remaining = LARGE_POOL_SIZE.saturating_sub(new_end_offset);
                warn!("After emergency reset: {} bytes remaining", new_remaining);
            }
        }
        
        // 首先尝试在现有的空闲块中找到合适的位置
        if let Some(offset) = self.find_free_block(size, align) {
            let ptr = unsafe { LARGE_POOL.as_mut_ptr().add(offset) };
            self.allocations.push((offset, size, false)); // false = 已分配
            
            info!("Large pool allocation (reuse): {} bytes at offset {:#x}", size, offset);
            return Some(ptr);
        }

        // 尝试压缩内存以创建更大的连续空间
        if self.compact_memory() {
            if let Some(offset) = self.find_free_block(size, align) {
                let ptr = unsafe { LARGE_POOL.as_mut_ptr().add(offset) };
                self.allocations.push((offset, size, false));
                
                info!("Large pool allocation (after compact): {} bytes at offset {:#x}", size, offset);
                return Some(ptr);
            }
        }

        // 如果仍然无法分配，尝试在末尾分配
        let end_offset = self.get_end_offset();
        let aligned_offset = (end_offset + align - 1) & !(align - 1);
        
        if aligned_offset + size <= LARGE_POOL_SIZE {
            let ptr = unsafe { LARGE_POOL.as_mut_ptr().add(aligned_offset) };
            self.allocations.push((aligned_offset, size, false));
            
            info!("Large pool allocation (new): {} bytes at offset {:#x}", size, aligned_offset);
            Some(ptr)
        } else {
            warn!("Large pool exhausted: need {} bytes, {} bytes total, {} allocations active", 
                  size, LARGE_POOL_SIZE, self.allocations.len());
            
            // 打印分配统计
            let (free_count, used_count) = self.get_allocation_stats();
            warn!("Allocation stats: {} used, {} free", used_count, free_count);
            
            None
        }
    }

    fn dealloc(&mut self, ptr: *mut u8, size: usize) {
        let offset = unsafe { ptr.offset_from(LARGE_POOL.as_mut_ptr()) } as usize;
        
        // 详细的调试信息
        if log::max_level() >= log::Level::Info {
            info!("Large pool dealloc attempt: ptr={:#x}, offset={:#x}, size={}", 
                  ptr as usize, offset, size);
        }
        
        // 标记对应的分配为已释放
        for (alloc_offset, alloc_size, is_free) in &mut self.allocations {
            if *alloc_offset == offset && *alloc_size == size && !*is_free {
                *is_free = true;
                info!("Large pool deallocation SUCCESS: {} bytes at offset {:#x}", size, offset);
                
                // 更激进的内存整理策略
                let (free_count, used_count) = self.get_allocation_stats();
                if free_count >= 50 || (free_count > 0 && free_count * 4 >= used_count) {
                    info!("Triggering aggressive memory compaction: {} free vs {} used", free_count, used_count);
                    self.compact_memory();
                }
                return;
            }
        }
        
        // 如果没找到精确匹配，尝试找到包含该地址的分配
        let mut found_candidate = false;
        for (alloc_offset, alloc_size, is_free) in &mut self.allocations {
            if !*is_free && offset >= *alloc_offset && offset < *alloc_offset + *alloc_size {
                warn!("Large pool dealloc: found containing allocation at offset {:#x}, size {}, requested size {}", 
                      *alloc_offset, *alloc_size, size);
                *is_free = true;
                found_candidate = true;
                break;
            }
        }
        
        if !found_candidate {
            warn!("Large pool deallocation FAILED: ptr {:#x}, offset {:#x}, size {} not found", 
                  ptr as usize, offset, size);
            // 打印当前所有分配以便调试
            if log::max_level() >= log::Level::Warn {
                warn!("Current allocations:");
                for (i, (alloc_offset, alloc_size, is_free)) in self.allocations.iter().enumerate() {
                    warn!("  [{}] offset={:#x}, size={}, free={}", i, alloc_offset, alloc_size, is_free);
                    if i >= 10 { // 只显示前10个以避免日志过多
                        warn!("  ... and {} more", self.allocations.len() - 10);
                        break;
                    }
                }
            }
        }
    }

    fn find_free_block(&self, size: usize, align: usize) -> Option<usize> {
        // 构建已占用区间列表
        let mut used_ranges: Vec<(usize, usize)> = self.allocations
            .iter()
            .filter(|(_, _, is_free)| !*is_free)
            .map(|(offset, size, _)| (*offset, *offset + *size))
            .collect();
        
        used_ranges.sort_by_key(|(start, _)| *start);
        
        // 在空隙中寻找合适的位置
        let mut current_pos = 0;
        for (range_start, range_end) in used_ranges {
            let aligned_pos = (current_pos + align - 1) & !(align - 1);
            if aligned_pos + size <= range_start {
                return Some(aligned_pos);
            }
            current_pos = range_end;
        }
        
        // 检查末尾是否有足够空间
        let aligned_pos = (current_pos + align - 1) & !(align - 1);
        if aligned_pos + size <= LARGE_POOL_SIZE {
            Some(aligned_pos)
        } else {
            None
        }
    }

    fn compact_memory(&mut self) -> bool {
        info!("Starting memory compaction...");
        
        // 移除所有已释放的分配记录
        let before_count = self.allocations.len();
        self.allocations.retain(|(_, _, is_free)| !*is_free);
        let after_count = self.allocations.len();
        
        if before_count > after_count {
            info!("Memory compaction: removed {} freed allocations, {} remain", 
                  before_count - after_count, after_count);
            return true;
        }
        
        false
    }

    fn get_end_offset(&self) -> usize {
        self.allocations
            .iter()
            .filter(|(_, _, is_free)| !*is_free)
            .map(|(offset, size, _)| offset + size)
            .max()
            .unwrap_or(0)
    }

    fn get_allocation_stats(&self) -> (usize, usize) {
        let free_count = self.allocations.iter().filter(|(_, _, is_free)| *is_free).count();
        let used_count = self.allocations.len() - free_count;
        (free_count, used_count)
    }
    
    /// 紧急内存重置 - 当池接近耗尽时的激进策略
    fn emergency_reset(&mut self) -> bool {
        warn!("Performing emergency memory reset...");
        
        let before_count = self.allocations.len();
        let (free_count, used_count) = self.get_allocation_stats();
        
        // 策略1: 如果有超过30%的空闲分配，强制清理
        if free_count * 3 >= used_count {
            self.allocations.retain(|(_, _, is_free)| !*is_free);
            let after_count = self.allocations.len();
            warn!("Emergency reset: removed {} freed allocations, {} active remain", 
                  before_count - after_count, after_count);
            return true;
        }
        
        // 策略2: 如果分配数量过多，清理较小的分配
        if self.allocations.len() > 800 {
            let old_len = self.allocations.len();
            // 保留较大的分配，清理较小的分配
            self.allocations.retain(|(_, size, is_free)| *is_free || *size >= 64 * 1024);
            let new_len = self.allocations.len();
            if new_len < old_len {
                warn!("Emergency reset: cleared {} small allocations", old_len - new_len);
                return true;
            }
        }
        
        // 策略3: 最后的手段 - 清理所有"可能已经释放但没有正确标记"的分配
        if self.allocations.len() > 500 {
            warn!("Extreme emergency: clearing 50% of oldest allocations");
            let keep_count = self.allocations.len() / 2;
            self.allocations.truncate(keep_count);
            return true;
        }
        
        false
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
        if layout.size() > LARGE_ALLOC_THRESHOLD {
            // 尝试使用大内存池
            if let Some(ptr) = LARGE_ALLOCATOR.lock().alloc(layout.size(), layout.align()) {
                return ptr;
            }
            
            warn!("Large pool allocation failed, falling back to buddy allocator for {} bytes", layout.size());
        }
        
        // 使用buddy allocator
        HEAP_ALLOCATOR.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // 检查指针是否在大内存池范围内
        let pool_start = LARGE_POOL.as_ptr() as usize;
        let pool_end = pool_start + LARGE_POOL_SIZE;
        let ptr_addr = ptr as usize;
        
        if ptr_addr >= pool_start && ptr_addr < pool_end {
            // 大内存池释放
            if log::max_level() >= log::Level::Info {
                info!("Global dealloc: routing to large pool - ptr={:#x}, size={}", ptr_addr, layout.size());
            }
            LARGE_ALLOCATOR.lock().dealloc(ptr, layout.size());
        } else {
            // Buddy allocator释放
            if log::max_level() >= log::Level::Info && layout.size() > LARGE_ALLOC_THRESHOLD {
                info!("Global dealloc: routing to buddy allocator - ptr={:#x}, size={}", ptr_addr, layout.size());
            }
            HEAP_ALLOCATOR.dealloc(ptr, layout);
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
        
        info!(
            "Large POOL init: {:#x} - {:#x}  size: {:#x} ({} MB)",
            LARGE_POOL.as_ptr() as usize,
            LARGE_POOL.as_ptr() as usize + LARGE_POOL_SIZE,
            LARGE_POOL_SIZE,
            LARGE_POOL_SIZE / (1024 * 1024)
        );
        
        info!("Buddy allocator max order: 32 (max allocation: 4GB)");
        info!("Large allocation threshold: {} KB", LARGE_ALLOC_THRESHOLD / 1024);
        
        // 初始化大内存池（确保它可以被使用）
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
    error!("Large pool size: {} bytes ({} MB)", LARGE_POOL_SIZE, LARGE_POOL_SIZE / (1024 * 1024));
    error!("Large pool range: {:#x} - {:#x}", unsafe { LARGE_POOL.as_ptr() as usize }, unsafe { LARGE_POOL.as_ptr() as usize + LARGE_POOL_SIZE });

    // 显示物理内存信息
    let free_pages = get_free_pages();
    let free_kb = free_pages * polyhal::pagetable::PAGE_SIZE / 1024;
    error!("Available physical memory: {} pages ({} KB)", free_pages, free_kb);

    // 显示大内存池详细状态
    if layout.size() > LARGE_ALLOC_THRESHOLD {
        error!("Large allocation failure (>64 KB) - Pool status:");
        
        // 获取大内存分配器的统计信息
        let allocator = LARGE_ALLOCATOR.lock();
        let (free_count, used_count) = allocator.get_allocation_stats();
        let end_offset = allocator.get_end_offset();
        let remaining = LARGE_POOL_SIZE.saturating_sub(end_offset);
        
        error!("Pool end offset: {} bytes ({} KB)", end_offset, end_offset / 1024);
        error!("Pool remaining (end): {} bytes ({} KB)", remaining, remaining / 1024);
        error!("Total allocations: {} (used: {}, freed: {})", used_count + free_count, used_count, free_count);
        
        error!("This error is likely caused by:");
        error!("1. Physical memory fragmentation - try reducing allocation size");
        error!("2. Heap exhaustion in user space application");
        error!("3. Large pool exhaustion for >64KB allocations");
        error!("4. Need to increase HEAP_SIZE or LARGE_POOL_SIZE");
        error!("5. Frame allocator unable to provide sufficient continuous pages");
    }

    if layout.size() > LARGE_ALLOC_THRESHOLD {
        error!("Large allocation (>64KB) detected - consider:");
        error!("  - Breaking into smaller chunks");
        error!("  - Using memory mapping instead of heap allocation");
        error!("  - Hybrid allocator with 128MB large pool should handle this");
        error!("  - Check if large pool is exhausted or needs compaction");
    }

    error!("======================================================");
    debug!("[{}]", core::panic::Location::caller());
    panic!("Out of memory");
}

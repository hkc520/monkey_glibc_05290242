use fs::Stat;
use crate::tasks::UserTaskControlFlow;  
use crate::tasks::{MapTrack, MemType, UserTask};  
use crate::utils::hexdump;  
use ::signal::SignalFlags;  
use alloc::sync::Arc;  
use devices::PAGE_SIZE;  
use executor::{AsyncTask, TaskId};  
use log::{debug, warn};  
use polyhal::{MappingFlags, Time, VirtAddr};  
use polyhal_trap::trap::{run_user_task, EscapeReason};  
use polyhal_trap::trapframe::{TrapFrame, TrapFrameArgs};  
use runtime::frame::frame_alloc;  
use syscalls::Sysno;  
  
pub mod entry;  
pub mod signal;  
pub mod socket_pair;  
  
pub struct UserTaskContainer {  
    pub task: Arc<UserTask>,  
    pub tid: TaskId,  
}  
  
/// Copy on write.  
/// call this function when trigger store/instruction page fault.  
/// copy page or remap page.  
pub fn user_cow_int(task: Arc<UserTask>, cx_ref: &mut TrapFrame, vaddr: VirtAddr) {
    warn!(
        "store/instruction page fault @ {:#x} vaddr: {} paddr: {:?} task_id: {}",
        cx_ref[TrapFrameArgs::SEPC],
        vaddr,
        task.page_table.translate(vaddr),
        task.get_task_id()
    );

    // 详细输出内存区域信息
    /*warn!("=== Memory areas debug info ===");
    let mut pcb = task.pcb.lock();
    for (i, area) in pcb.memset.iter().enumerate() {
        warn!("  Area {}: start={:#x}, end={:#x}, len={:#x}, offset={:#x}, type={:?}, has_file={}", 
            i, area.start, area.start + area.len, area.len, area.offset, area.mtype, area.file.is_some());
    }
    warn!("=== End debug info ===");*/
    let mut pcb = task.pcb.lock();  
    let area = pcb.memset.iter_mut().find(|x| x.contains(vaddr.raw()));  
    if let Some(area) = area {  
        let finded = area.mtrackers.iter_mut().find(|x| x.vaddr == vaddr.floor());  
        let ppn = match finded {  
            Some(map_track) => {  
                if area.mtype == MemType::Shared {  
                    task.tcb.write().signal.add_signal(SignalFlags::SIGSEGV);  
                    return;  
                }  
                // tips: this finded will consume a strong count.  
                debug!("strong count: {}", Arc::strong_count(&map_track.tracker));  
                if Arc::strong_count(&map_track.tracker) > 1 {  
                    let src = map_track.tracker.0;  
                    let dst = frame_alloc().expect("can't alloc @ user page fault");  
                    unsafe {  
                        dst.0  
                            .get_mut_ptr::<u8>()  
                            .copy_from_nonoverlapping(src.get_ptr(), PAGE_SIZE);  
                    }  
                    map_track.tracker = Arc::new(dst);  
                }  
                map_track.tracker.0  
            }  
            None => {  
                let tracker = Arc::new(frame_alloc().expect("can't alloc frame in cow_fork_int"));  
                let mtracker = MapTrack {  
                    vaddr: vaddr.floor(),  
                    tracker,  
                    rwx: 0b111,  
                };
                let offset = vaddr.floor().raw() + area.offset - area.start;  
                let file_offset = area.offset + (vaddr.floor().raw() - area.start);  
                if let Some(file) = &area.file {  
                    file.readat(offset, mtracker.tracker.0.slice_mut_with_len(PAGE_SIZE))  
                        .expect("can't read file in cow_fork_int");  
                }  
                let ppn = mtracker.tracker.0;  
                area.mtrackers.push(mtracker);  
                ppn  
            }  
        };  
        let flags = if area.mtype == MemType::Mmap && vaddr.raw() >= 0x200000000 {  
            MappingFlags::URWX  // glibc区域需要完整权限  
        } else {  
            MappingFlags::URWX  
        };
        drop(pcb);
          
        task.map(ppn, vaddr.floor(), MappingFlags::URWX);  
    } else {  
        // 释放 pcb 锁以避免死锁  
        drop(pcb);  
          
        // 扩展栈区域处理  
        if vaddr.raw() >= 0x7000_0000 && vaddr.raw() < 0x8000_0000 {  
            warn!("Attempting to allocate Stack for vaddr: {:#x}", vaddr.raw());  
            let stack_page_count = 1;  
            if let Some(_) = task.frame_alloc(vaddr.floor(), MemType::Stack, stack_page_count) {  
                warn!("Successfully allocated Stack for vaddr: {:#x}", vaddr.raw());  
                return;  
            } else {  
                warn!("Failed to allocate Stack for vaddr: {:#x}", vaddr.raw());  
            }  
        }
        else if vaddr.raw() < 0x1000 {
            warn!("Accessing very low address: {:#x}, likely null pointer dereference", vaddr.raw());
            task.tcb.write().signal.add_signal(SignalFlags::SIGSEGV);
            return;
        }  
        // 新增：处理低地址区域（如 0x10690）  
        else if vaddr.raw() >= 0x10000 && vaddr.raw() < 0x100000 {  
            warn!("Attempting to handle CodeSection page fault for vaddr: {:#x}", vaddr.raw());  
            

            // 首先检查是否有对应的内存区域定义  
            let has_mapping = task.pcb.lock().memset.iter().any(|area| {  
                area.contains(vaddr.raw()) && area.file.is_some()  
            });  
            
            if !has_mapping {  
                warn!("No ELF segment mapping found for low address vaddr: {:#x}", vaddr.raw());  
                warn!("Available memory areas:");  
                for (i, area) in task.pcb.lock().memset.iter().enumerate() {  
                    warn!("  Area {}: start={:#x}, len={:#x}, type={:?}, has_file={}",   
                        i, area.start, area.len, area.mtype, area.file.is_some());  
                }  
            }
            // 尝试从ELF文件加载  
            let elf_lookup_task = if task.task_id != task.process_id {
                // 这是一个线程，需要通过进程ID查找主进程
                // 由于我们没有全局进程表，这里使用共享PCB的方式
                task.clone() // PCB已经是共享的，所以应该能看到相同的memset
            } else {
                task.clone()
            };
            
            // 添加详细的调试信息
            warn!("Before get_elf_segment_for_addr: task_id={}, process_id={}, PCB arc count={}", 
                elf_lookup_task.task_id, elf_lookup_task.process_id, Arc::strong_count(&elf_lookup_task.pcb));

            // 再次检查memset状态
            {
                let pcb_guard = elf_lookup_task.pcb.lock();
                warn!("PCB memset size before lookup: {}", pcb_guard.memset.len());
                if pcb_guard.memset.is_empty() {
                    warn!("CRITICAL: memset is empty before get_elf_segment_for_addr!");
                    warn!("PCB address: {:p}", &*pcb_guard);
                    // 打印线程列表状态
                    warn!("Active threads count: {}", pcb_guard.threads.len());
                    for (i, thread_ref) in pcb_guard.threads.iter().enumerate() {
                        if let Some(thread) = thread_ref.upgrade() {
                            warn!("  Thread {}: task_id={}, process_id={}", 
                                i, thread.task_id, thread.process_id);
                        } else {
                            warn!("  Thread {}: dead reference", i);
                        }
                    }
                }
                drop(pcb_guard);
            }
            if let Some((file, file_offset, _)) = elf_lookup_task.get_elf_segment_for_addr(vaddr)  {  
                warn!("Loading code from ELF file at offset: {:#x}", file_offset);  
                
                // 获取文件大小  
                let mut stat = Stat::default();  
                let file_size = if file.stat(&mut stat).is_ok() {  
                    stat.size as usize  
                } else {  
                    warn!("Failed to get file size for vaddr: {:#x}", vaddr.raw());  
                    return; // 如果无法获取文件大小，直接返回  
                };  
                
                // 验证文件偏移是否在有效范围内  
                if file_offset >= file_size {  
                    warn!("File offset {:#x} exceeds file size {:#x} for vaddr: {:#x}",   
                        file_offset, file_size, vaddr.raw());  
                    return; // 偏移超出文件大小，直接返回  
                }  
                
                // 分配页面  
                let page_count = 1;  
                if let Some(ppn) = task.frame_alloc(vaddr.floor(), MemType::CodeSection, page_count) {  
                    let page_data = ppn.slice_mut_with_len(PAGE_SIZE);  
                    
                    // 计算实际可读取的大小，确保不超出文件边界  
                    let remaining_file_size = file_size - file_offset;  
                    let read_size = core::cmp::min(PAGE_SIZE, remaining_file_size);  
                    
                    if read_size > 0 {  
                        if let Ok(_) = file.readat(file_offset, &mut page_data[..read_size]) {  
                            warn!("Successfully loaded code from ELF for vaddr: {:#x}, read_size: {:#x}",   
                                vaddr.raw(), read_size);  
                            return;  
                        } else {  
                            warn!("Failed to read from ELF file for vaddr: {:#x}", vaddr.raw());  
                        }  
                    } else {  
                        warn!("No data to read at offset {:#x} for vaddr: {:#x}", file_offset, vaddr.raw());  
                    }  
                }  
            }  
            
            // 如果无法从ELF加载，则使用原有的空白页面分配逻辑  
            warn!("Falling back to blank page allocation for vaddr: {:#x}", vaddr.raw());  
            let page_count = 1;  
            if let Some(_) = task.frame_alloc(vaddr.floor(), MemType::CodeSection, page_count) {  
                warn!("Successfully allocated blank CodeSection for vaddr: {:#x}", vaddr.raw());  
                return;  
            } else {  
                warn!("Failed to allocate CodeSection for vaddr: {:#x}", vaddr.raw());  
            }  
        }  
        // 新增：处理堆区域扩展  
        else if vaddr.raw() >= 0x1000000 && vaddr.raw() < 0x2000000 {  
            warn!("Attempting to allocate Mmap (heap) for vaddr: {:#x}", vaddr.raw());  
            let heap_page_count = 1;  
            if let Some(_) = task.frame_alloc(vaddr.floor(), MemType::Mmap, heap_page_count) {  
                warn!("Successfully allocated Mmap (heap) for vaddr: {:#x}", vaddr.raw());  
                return;  
            } else {  
                warn!("Failed to allocate Mmap (heap) for vaddr: {:#x}", vaddr.raw());  
            }  
        }  
        // 新增：处理glibc特有的内存区域  
        else if vaddr.raw() >= 0x200000000 && vaddr.raw() < 0x300000000 {  
            warn!("Attempting to allocate Mmap (glibc) for vaddr: {:#x}", vaddr.raw());  
            let glibc_page_count = 1;  
            if let Some(ppn) = task.frame_alloc(vaddr.floor(), MemType::Mmap, glibc_page_count) {
                task.map(ppn, vaddr.floor(), MappingFlags::URWX);  
                warn!("Successfully allocated Mmap (glibc) for vaddr: {:#x}", vaddr.raw());  
                return;  
            } else {  
                warn!("Failed to allocate Mmap (glibc) for vaddr: {:#x}", vaddr.raw());  
            }  
        }  
          
        warn!("No suitable memory region found for vaddr: {:#x}, sending SIGSEGV", vaddr.raw());  
        task.tcb.write().signal.add_signal(SignalFlags::SIGSEGV);  
    }  
}
impl UserTaskContainer {
    /// Handle user interrupt.
    pub async fn handle_syscall(&self, cx_ref: &mut TrapFrame) -> UserTaskControlFlow {
        let ustart = Time::now().raw();
        if matches!(run_user_task(cx_ref), EscapeReason::SysCall) {
            self.task
                .inner_map(|inner| inner.tms.utime += (Time::now().raw() - ustart) as u64);

            let sstart = Time::now().raw();
            if cx_ref[TrapFrameArgs::SYSCALL] == Sysno::rt_sigreturn.id() as _ {
                return UserTaskControlFlow::Break;
            }
            cx_ref.syscall_ok();
            let result = self
                .syscall(cx_ref[TrapFrameArgs::SYSCALL], cx_ref.args())
                .await
                .map_or_else(|e| -e.into_raw() as isize, |x| x as isize)
                as usize;

            debug!(
                "[task {}] syscall result: {}",
                self.task.get_task_id(),
                result as isize
            );

            cx_ref[TrapFrameArgs::RET] = result;
            self.task
                .inner_map(|inner| inner.tms.stime += (Time::now().raw() - sstart) as u64);
        }

        // let trap_type = trap_pre_handle(cx_ref);
        // match trap_type {
        //     arch::TrapType::Time => {
        //         // debug!("time interrupt from user");
        //     }
        //     arch::TrapType::Unknown => {
        //         debug!("unknown trap: {:#x?}", cx_ref);
        //         panic!("");
        //     }
        //     arch::TrapType::SupervisorExternal => {
        //         get_int_device().try_handle_interrupt(u32::MAX);
        //     }
        // }
        UserTaskControlFlow::Continue
    }
}

pub fn task_ilegal(task: &Arc<UserTask>, vaddr: VirtAddr, cx_ref: &mut TrapFrame) {
    let mut pcb = task.pcb.lock();
    let area = pcb.memset.iter_mut().find(|x| x.contains(vaddr.raw()));
    if let Some(area) = area {
        let finded = area.mtrackers.iter_mut().find(|x| x.vaddr == vaddr);
        match finded {
            Some(_) => {
                cx_ref[TrapFrameArgs::SEPC] += 2;
            }
            None => {
                task.tcb.write().signal.add_signal(SignalFlags::SIGILL);
                unsafe {
                    hexdump(
                        core::slice::from_raw_parts_mut(vaddr.raw() as _, 0x1000),
                        vaddr.raw(),
                    );
                }
            }
        };
    } else {
        task.tcb.write().signal.add_signal(SignalFlags::SIGILL);
        unsafe {
            hexdump(
                core::slice::from_raw_parts_mut(vaddr.raw() as _, 0x1000),
                vaddr.raw(),
            );
        }
    }
}

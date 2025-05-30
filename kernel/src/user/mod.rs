use alloc::vec::Vec;
use crate::tasks::MemArea;
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
    // 对TLS区域使用更低的日志级别
    if vaddr.raw() >= 0x200000000 && vaddr.raw() < 0x300000000 {
        debug!(  // 使用debug而不是warn
            "TLS page fault @ {:#x} vaddr: {} paddr: {:?} task_id: {}",
            cx_ref[TrapFrameArgs::SEPC],
            vaddr,
            task.page_table.translate(vaddr),
            task.get_task_id()
        );
    } else {
        warn!(  // 其他区域仍使用warn
            "store/instruction page fault @ {:#x} vaddr: {} paddr: {:?} task_id: {}",
            cx_ref[TrapFrameArgs::SEPC],
            vaddr,
            task.page_table.translate(vaddr),
            task.get_task_id()
        );
    }

    warn!("Processing page fault for vaddr: {:#x}, vaddr.floor(): {:#x}", vaddr.raw(), vaddr.floor().raw());

    let mut pcb = task.pcb.lock();  
    let area = pcb.memset.iter_mut().find(|x| x.contains(vaddr.raw()));  
    if let Some(area) = area {  
        warn!("Found existing memory area for vaddr: {:#x}", vaddr.raw());
        warn!("Area details: start={:#x}, len={:#x}, offset={:#x}, mtype={:?}, has_file={}", 
            area.start, area.len, area.offset, area.mtype, area.file.is_some());
        
        let finded = area.mtrackers.iter_mut().find(|x| x.vaddr == vaddr.floor());  
        let ppn = match finded {  
            Some(map_track) => {  
                warn!("Found existing MapTrack for vaddr: {:#x}", vaddr.raw());
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
                warn!("No existing MapTrack found, creating new one for vaddr: {:#x}", vaddr.raw());
                let tracker = Arc::new(frame_alloc().expect("can't alloc frame in cow_fork_int"));  
                let mtracker = MapTrack {  
                    vaddr: vaddr.floor(),  
                    tracker,  
                    rwx: 0b111,  
                };
                
                let file_offset = area.offset + (vaddr.floor().raw() - area.start);  
                warn!("Calculated file_offset: {:#x} for vaddr: {:#x}", file_offset, vaddr.raw());
                
                if let Some(file) = &area.file {  
                    warn!("Reading from file at offset: {:#x}", file_offset);
                    if let Err(e) = file.readat(file_offset, mtracker.tracker.0.slice_mut_with_len(PAGE_SIZE)) {
                        warn!("Failed to read from file: {:?}", e);
                    } else {
                        warn!("Successfully read from file");
                    }
                } else {
                    warn!("No file associated with this area, using zero-filled page");
                }
                
                let ppn = mtracker.tracker.0;  
                area.mtrackers.push(mtracker);  
                ppn  
            }  
        };  
        
        let flags = if area.mtype == MemType::Mmap && vaddr.raw() >= 0x200000000 {  
            warn!("Using URW flags for TLS region");
            MappingFlags::URW
        } else {  
            warn!("Using URWX flags for other regions");
            MappingFlags::URWX  
        };
        
        drop(pcb);
        
        warn!("Mapping ppn {:#x} to vaddr {:#x} with flags {:?}", ppn.raw(), vaddr.floor().raw(), flags);
        task.map(ppn, vaddr.floor(), flags);  
        
        // 验证映射是否成功
        if let Some((mapped_paddr, mapped_flags)) = task.page_table.translate(vaddr.floor()) {
            warn!("Mapping verification: vaddr {:#x} -> paddr {:#x}, flags {:?}", 
                vaddr.floor().raw(), mapped_paddr.raw(), mapped_flags);
            if mapped_paddr.raw() == 0 || mapped_flags.is_empty() {
                warn!("WARNING: Mapping failed or invalid!");
            } else {
                warn!("Mapping verified successfully");
            }
        } else {
            warn!("WARNING: Mapping verification failed - no translation found!");
        }
        warn!("Mapping completed for vaddr: {:#x}", vaddr.raw());
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
        if vaddr.raw() < 0x1000 {
            warn!("Detected null pointer access for vaddr: {:#x}", vaddr.raw());
            
            // 检查是否已经发送过SIGSEGV信号
            let mut tcb = task.tcb.write();
            if !tcb.signal.has_sig(SignalFlags::SIGSEGV) {
                tcb.signal.add_signal(SignalFlags::SIGSEGV);
                warn!("Added SIGSEGV signal for null pointer access");
            } else {
                warn!("SIGSEGV already pending, force terminating task");
                drop(tcb); // 释放锁
                // 强制终止，不再尝试信号处理
                task.exit(128 + SignalFlags::SIGSEGV.num());
                // 额外确保任务状态被标记为已退出
                let mut pcb = task.pcb.lock();
                pcb.exit_code = Some(128 + SignalFlags::SIGSEGV.num());
                drop(pcb);
                // 直接返回，不再处理页面错误
                return;
            }
            return;
        }  
        // 新增：处理低地址区域（如 0x10690）  
        else if vaddr.raw() >= 0x10000 && vaddr.raw() < 0x100000 {  
            warn!("Detected CodeSection range access for vaddr: {:#x}", vaddr.raw());
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
            warn!("Detected heap range access for vaddr: {:#x}", vaddr.raw());
            warn!("Attempting to allocate Mmap (heap) for vaddr: {:#x}", vaddr.raw());  
            let heap_page_count = 1;  
            if let Some(_) = task.frame_alloc(vaddr.floor(), MemType::Mmap, heap_page_count) {  
                warn!("Successfully allocated Mmap (heap) for vaddr: {:#x}", vaddr.raw());  
                return;  
            } else {  
                warn!("Failed to allocate Mmap (heap) for vaddr: {:#x}", vaddr.raw());  
            }  
        }  

        else if vaddr.raw() >= 0x200000000 && vaddr.raw() < 0x300000000 {
        warn!("Simple TLS handling for vaddr: {:#x}", vaddr.raw());
        
        // 检查循环
        static mut LAST_TLS_ADDR: usize = 0;
        static mut TLS_COUNT: usize = 0;
        
        unsafe {
            if LAST_TLS_ADDR == vaddr.floor().raw() {
                TLS_COUNT += 1;
                if TLS_COUNT > 3 {
                    warn!("TLS loop detected at {:#x}, exiting task {}", vaddr.raw(), task.get_task_id());
                    task.exit(1);
                    return;
                }
            } else {
                LAST_TLS_ADDR = vaddr.floor().raw();
                TLS_COUNT = 1;
            }
        }
        
        // 使用 UserTask 的 frame_alloc 方法分配TLS页面
        let tls_page_count = 1;
        if let Some(ppn) = task.frame_alloc(vaddr.floor(), MemType::Mmap, tls_page_count) {
            // 清零页面内容
            ppn.slice_mut_with_len(PAGE_SIZE).fill(0);
            warn!("Simple TLS page allocated for {:#x}", vaddr.raw());
            
            unsafe {
                TLS_COUNT = 0; // 重置计数器
            }
            return;
        }
        
        warn!("TLS allocation failed for {:#x}", vaddr.raw());
        task.tcb.write().signal.add_signal(SignalFlags::SIGSEGV);
    }  
          
        warn!("No suitable memory region found for vaddr: {:#x}, sending SIGSEGV", vaddr.raw());  
        task.tcb.write().signal.add_signal(SignalFlags::SIGSEGV);  
    }  
}
impl UserTaskContainer {
    pub async fn handle_syscall(&self, cx_ref: &mut TrapFrame) -> UserTaskControlFlow {
        warn!("Task {} entering handle_syscall, SEPC: {:#x}", self.task.get_task_id(), cx_ref[TrapFrameArgs::SEPC]);
        
        let ustart = Time::now().raw();
        let escape_reason = run_user_task(cx_ref);
        
        warn!("Task {} run_user_task returned: {:?}", self.task.get_task_id(), escape_reason);
        
        if matches!(escape_reason, EscapeReason::SysCall) {
            self.task
                .inner_map(|inner| inner.tms.utime += (Time::now().raw() - ustart) as u64);

            let sstart = Time::now().raw();
            let syscall_id = cx_ref[TrapFrameArgs::SYSCALL];
            
            warn!("Task {} syscall: {} ({})", self.task.get_task_id(), syscall_id, 
                  syscalls::Sysno::from(syscall_id as i32));
            
            if syscall_id == Sysno::rt_sigreturn.id() as _ {
                warn!("Task {} rt_sigreturn, returning Break", self.task.get_task_id());
                return UserTaskControlFlow::Break;
            }
            
            cx_ref.syscall_ok();
            let result = self
                .syscall(syscall_id, cx_ref.args())
                .await
                .map_or_else(|e| -e.into_raw() as isize, |x| x as isize)
                as usize;

            warn!("Task {} syscall {} result: {}", self.task.get_task_id(), syscall_id, result as isize);

            cx_ref[TrapFrameArgs::RET] = result;
            self.task
                .inner_map(|inner| inner.tms.stime += (Time::now().raw() - sstart) as u64);
        } else {
            warn!("Task {} non-syscall escape reason: {:?}", self.task.get_task_id(), escape_reason);
        }

        warn!("Task {} handle_syscall returning Continue", self.task.get_task_id());
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

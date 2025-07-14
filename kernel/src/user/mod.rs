// use crate::tasks::MemArea;
use crate::tasks::UserTaskControlFlow;
use crate::tasks::{MapTrack, MemType, UserTask};
use crate::utils::hexdump;
use ::signal::SignalFlags;
use alloc::sync::Arc;
// use alloc::vec::Vec;
use devices::PAGE_SIZE;
use executor::{AsyncTask, TaskId};
use fs::Stat;
use log::{debug, warn};
use polyhal::{MappingFlags, Time, VirtAddr};
use polyhal_trap::trap::{run_user_task, EscapeReason};
use polyhal_trap::trapframe::{TrapFrame, TrapFrameArgs};
use runtime::frame::frame_alloc;
use runtime::frame::get_free_pages;
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
        debug!(
            "TLS page fault @ {:#x} vaddr: {} paddr: {:?} task_id: {}",
            cx_ref[TrapFrameArgs::SEPC],
            vaddr,
            task.page_table.translate(vaddr),
            task.get_task_id()
        );
    }

    let mut pcb = task.pcb.lock();
    let area = pcb.memset.iter_mut().find(|x| x.contains(vaddr.raw()));
    if let Some(area) = area {
        let finded = area.mtrackers.iter_mut().find(|x| x.vaddr == vaddr.floor());
        let ppn = match finded {
            Some(map_track) => {
                // 对于共享内存和共享文件，允许写入操作
                if area.mtype == MemType::Shared || area.mtype == MemType::ShareFile {
                    // 共享内存/文件可以直接写入，不需要COW
                    debug!("Shared memory/file write access at {:#x}", vaddr.raw());
                    map_track.tracker.0
                } else {
                    debug!("strong count: {}", Arc::strong_count(&map_track.tracker));
                    if Arc::strong_count(&map_track.tracker) > 1 {
                        let src = map_track.tracker.0;
                        let dst = match frame_alloc() {
                            Some(frame) => frame,
                            None => {
                                warn!("Frame allocation failed during COW copy");
                                task.tcb.write().signal.add_signal(SignalFlags::SIGSEGV);
                                return;
                            }
                        };
                        unsafe {
                            dst.0
                                .get_mut_ptr::<u8>()
                                .copy_from_nonoverlapping(src.get_ptr(), PAGE_SIZE);
                        }
                        map_track.tracker = Arc::new(dst);
                    }
                    map_track.tracker.0
                }
            }
            None => {
                // Check memory availability before allocation
                if get_free_pages() < 10 {
                    warn!("Insufficient memory for new frame allocation");
                    task.tcb.write().signal.add_signal(SignalFlags::SIGSEGV);
                    return;
                }

                // Use safer allocation pattern
                let tracker = match frame_alloc() {
                    Some(frame) => Arc::new(frame),
                    None => {
                        warn!("Frame allocation failed in COW operation");
                        task.tcb.write().signal.add_signal(SignalFlags::SIGSEGV);
                        return;
                    }
                };

                let mtracker = MapTrack {
                    vaddr: vaddr.floor(),
                    tracker,
                    rwx: 0b111,
                };
                let file_offset = area.offset + (vaddr.floor().raw() - area.start);

                if let Some(file) = &area.file {
                    if let Err(_) = file.readat(
                        file_offset,
                        mtracker.tracker.0.slice_mut_with_len(PAGE_SIZE),
                    ) {
                        // File read failed, continue with zero-filled page
                    }
                }

                let ppn = mtracker.tracker.0;
                area.mtrackers.push(mtracker);
                ppn
            }
        };

        let flags = if area.mtype == MemType::Mmap && vaddr.raw() >= 0x200000000 {
            MappingFlags::URW
        } else {
            MappingFlags::URWX
        };

        drop(pcb);
        task.map(ppn, vaddr.floor(), flags);
    } else {
        // 释放 pcb 锁以避免死锁
        drop(pcb);

        // 扩展栈区域处理
        if vaddr.raw() >= 0x7000_0000 && vaddr.raw() < 0x8000_0000 {
            let stack_page_count = 1;
            if let Some(_) = task.frame_alloc(vaddr.floor(), MemType::Stack, stack_page_count) {
                return;
            }
        }

        if vaddr.raw() < 0x1000 {
            // 检查是否已经发送过SIGSEGV信号
            let mut tcb = task.tcb.write();
            if !tcb.signal.has_sig(SignalFlags::SIGSEGV) {
                tcb.signal.add_signal(SignalFlags::SIGSEGV);
            } else {
                drop(tcb);
                task.exit(128 + SignalFlags::SIGSEGV.num());
                let mut pcb = task.pcb.lock();
                pcb.exit_code = Some(128 + SignalFlags::SIGSEGV.num());
                drop(pcb);
                return;
            }
            return;
        }
        // 处理低地址区域（如 0x10690）
        else if vaddr.raw() >= 0x10000 && vaddr.raw() < 0x100000 {
            // 首先检查是否有对应的内存区域定义
            let has_mapping = task
                .pcb
                .lock()
                .memset
                .iter()
                .any(|area| area.contains(vaddr.raw()) && area.file.is_some());

            if !has_mapping {
                // No mapping found, continue with ELF lookup
            }

            // 尝试从ELF文件加载
            let elf_lookup_task = if task.task_id != task.process_id {
                task.clone()
            } else {
                task.clone()
            };

            // 再次检查memset状态
            {
                let pcb_guard = elf_lookup_task.pcb.lock();
                if pcb_guard.memset.is_empty() {
                    for (i, thread_ref) in pcb_guard.threads.iter().enumerate() {
                        if let Some(thread) = thread_ref.upgrade() {
                            // Thread exists
                        }
                    }
                }
                drop(pcb_guard);
            }

            if let Some((file, file_offset, _)) = elf_lookup_task.get_elf_segment_for_addr(vaddr) {
                // 获取文件大小
                let mut stat = Stat::default();
                let file_size = if file.stat(&mut stat).is_ok() {
                    stat.size as usize
                } else {
                    return;
                };

                // 验证文件偏移是否在有效范围内
                if file_offset >= file_size {
                    return;
                }

                // 分配页面
                let page_count = 1;
                if let Some(ppn) = task.frame_alloc(vaddr.floor(), MemType::Mmap, page_count)
                {
                    let page_data = ppn.slice_mut_with_len(PAGE_SIZE);

                    // 计算实际可读取的大小，确保不超出文件边界
                    let remaining_file_size = file_size - file_offset;
                    let read_size = core::cmp::min(PAGE_SIZE, remaining_file_size);

                    if read_size > 0 {
                        if let Ok(_) = file.readat(file_offset, &mut page_data[..read_size]) {
                            return;
                        }
                    }
                }
            }

            // 如果无法从ELF加载，则使用原有的空白页面分配逻辑
            let page_count = 1;
            if let Some(_) = task.frame_alloc(vaddr.floor(), MemType::Mmap, page_count) {
                return;
            }
        }
        // 处理堆区域扩展
        else if vaddr.raw() >= 0x1000000 && vaddr.raw() < 0x2000000 {
            let heap_page_count = 12; // 增加到12个页面（48KB），为文件系统测试提供更多内存
            if let Some(_) = task.frame_alloc(vaddr.floor(), MemType::Mmap, heap_page_count) {
                return;
            }
        } else if vaddr.raw() >= 0x200000000 && vaddr.raw() < 0x300000000 {
            // 检查循环
            static mut LAST_TLS_ADDR: usize = 0;
            static mut TLS_COUNT: usize = 0;

            unsafe {
                if LAST_TLS_ADDR == vaddr.floor().raw() {
                    TLS_COUNT += 1;
                    if TLS_COUNT > 3 {
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

                unsafe {
                    TLS_COUNT = 0; // 重置计数器
                }
                return;
            }

            task.tcb.write().signal.add_signal(SignalFlags::SIGSEGV);
        }
        // 在现有的地址范围检查中添加新的条件
        else if vaddr.raw() >= 0x200a0000 && vaddr.raw() < 0x300b0000 {
            warn!("Detected gap region access for vaddr: {:#x}", vaddr.raw());

            // 添加详细的调试信息
            warn!(
                "Current task: task_id={}, process_id={}",
                task.task_id, task.process_id
            );
            warn!("Available memory areas:");
            for (i, area) in task.pcb.lock().memset.iter().enumerate() {
                warn!(
                    "  Area {}: start={:#x}, end={:#x}, type={:?}",
                    i,
                    area.start,
                    area.start + area.len,
                    area.mtype
                );
            }

            // 尝试从 ELF 文件加载正确的内容
            if let Some((file, file_offset, _)) = task.get_elf_segment_for_addr(vaddr) {
                warn!(
                    "Found ELF segment for gap region at offset: {:#x}",
                    file_offset
                );

                // 获取文件大小
                let mut stat = Stat::default();
                let file_size = if file.stat(&mut stat).is_ok() {
                    stat.size as usize
                } else {
                    warn!(
                        "Failed to get file size for gap region vaddr: {:#x}",
                        vaddr.raw()
                    );
                    return;
                };

                // 验证文件偏移是否在有效范围内
                if file_offset >= file_size {
                    warn!(
                        "File offset {:#x} exceeds file size {:#x} for gap region vaddr: {:#x}",
                        file_offset,
                        file_size,
                        vaddr.raw()
                    );
                    return;
                }

                let page_count = 1;
                if let Some(ppn) = task.frame_alloc(vaddr.floor(), MemType::Mmap, page_count)
                {
                    let page_data = ppn.slice_mut_with_len(PAGE_SIZE);

                    // 计算实际可读取的大小
                    let remaining_file_size = file_size - file_offset;
                    let read_size = core::cmp::min(PAGE_SIZE, remaining_file_size);

                    if read_size > 0 {
                        if let Ok(_) = file.readat(file_offset, &mut page_data[..read_size]) {
                            warn!("Successfully loaded ELF content for gap region vaddr: {:#x}, read_size: {:#x}",  
                        vaddr.raw(), read_size);

                            // 验证映射是否成功
                            if let Some((mapped_ppn, _)) = task.page_table.translate(vaddr.floor())
                            {
                                warn!("ELF content mapping verification successful: vaddr={:#x} -> ppn={:#x}",   
                            vaddr.floor().raw(), mapped_ppn.raw());
                            } else {
                                warn!(
                                    "ELF content mapping verification FAILED for vaddr: {:#x}",
                                    vaddr.floor().raw()
                                );
                            }
                            return;
                        } else {
                            warn!(
                                "Failed to read ELF content for gap region vaddr: {:#x}",
                                vaddr.raw()
                            );
                        }
                    } else {
                        warn!(
                            "No ELF data to read at offset {:#x} for gap region vaddr: {:#x}",
                            file_offset,
                            vaddr.raw()
                        );
                    }
                } else {
                    warn!(
                        "Failed to allocate memory for ELF content at gap region vaddr: {:#x}",
                        vaddr.raw()
                    );
                }
            } else {
                warn!(
                    "No ELF segment found for gap region vaddr: {:#x}",
                    vaddr.raw()
                );
            }

            // 如果 ELF 加载失败，回退到空白页面分配
            warn!(
                "Falling back to blank page allocation for gap region vaddr: {:#x}",
                vaddr.raw()
            );
            let page_count = 1;
            if let Some(ppn) = task.frame_alloc(vaddr.floor(), MemType::Mmap, page_count) {
                warn!("Successfully allocated blank CodeSection for gap region vaddr: {:#x}, ppn: {:#x}",   
            vaddr.raw(), ppn.raw());

                // 验证映射是否成功
                if let Some((mapped_ppn, _)) = task.page_table.translate(vaddr.floor()) {
                    warn!(
                        "Blank page mapping verification successful: vaddr={:#x} -> ppn={:#x}",
                        vaddr.floor().raw(),
                        mapped_ppn.raw()
                    );
                } else {
                    warn!(
                        "Blank page mapping verification FAILED for vaddr: {:#x}",
                        vaddr.floor().raw()
                    );
                }
                return;
            } else {
                warn!(
                    "Failed to allocate blank CodeSection for gap region vaddr: {:#x}",
                    vaddr.raw()
                );
            }
        }

        // warn!(
        //     "No suitable memory region found for vaddr: {:#x}, sending SIGSEGV",
        //     vaddr.raw()
        // );
        task.tcb.write().signal.add_signal(SignalFlags::SIGSEGV);
    }
}

impl UserTaskContainer {
    pub async fn handle_syscall(&self, cx_ref: &mut TrapFrame) -> UserTaskControlFlow {
        let ustart = Time::now().raw();
        let escape_reason = run_user_task(cx_ref);

        if matches!(escape_reason, EscapeReason::SysCall) {
            self.task
                .inner_map(|inner| inner.tms.utime += (Time::now().raw() - ustart) as u64);

            let sstart = Time::now().raw();
            let syscall_id = cx_ref[TrapFrameArgs::SYSCALL];

            if syscall_id == Sysno::rt_sigreturn.id() as _ {
                // 执行rt_sigreturn系统调用来恢复信号上下文
                let result = self.sys_sigreturn().await
                    .map_or_else(|e| -e.into_raw() as isize, |x| x as isize) as usize;
                cx_ref[TrapFrameArgs::RET] = result;
                return UserTaskControlFlow::Break;
            }

            cx_ref.syscall_ok();
            let result = self
                .syscall(syscall_id, cx_ref.args())
                .await
                .map_or_else(|e| -e.into_raw() as isize, |x| x as isize)
                as usize;

            cx_ref[TrapFrameArgs::RET] = result;
            self.task
                .inner_map(|inner| inner.tms.stime += (Time::now().raw() - sstart) as u64);
        }

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

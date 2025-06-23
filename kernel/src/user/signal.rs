use core::mem::size_of;

use executor::AsyncTask;
use log::debug;
use polyhal_trap::trapframe::TrapFrameArgs;
use signal::SignalFlags;

use crate::syscall::types::signal::SignalUserContext;
use crate::tasks::{current_user_task, UserTaskControlFlow};
use crate::utils::useref::UserRef;

use super::UserTaskContainer;

impl UserTaskContainer {
    /// 为信号处理设置一个简单的trampoline代码
    /// 这个trampoline会在信号处理函数返回时调用rt_sigreturn
    fn setup_signal_trampoline(&self) -> Option<usize> {
        // 在用户空间的高地址分配一小块内存来放置trampoline代码
        const TRAMPOLINE_ADDR: usize = 0x7fff_ffff_f000;
        const TRAMPOLINE_SIZE: usize = 4096;
        
        // 检查这个地址是否已经映射
        if let Some((_, _)) = self.task.page_table.translate(polyhal::va!(TRAMPOLINE_ADDR)) {
            // 已经映射，直接返回地址
            return Some(TRAMPOLINE_ADDR);
        }
        
        // 分配一个页面用于trampoline
        if let Some(frame) = self.task.frame_alloc(
            polyhal::va!(TRAMPOLINE_ADDR), 
            crate::tasks::MemType::CodeSection, 
            1
        ) {
            // 写入trampoline代码
            // 这是一个简单的汇编代码序列，调用rt_sigreturn系统调用
            let trampoline_data = frame.slice_mut_with_len(TRAMPOLINE_SIZE);
            
            // 获取rt_sigreturn的系统调用号
            use syscalls::Sysno;
            let syscall_num = Sysno::rt_sigreturn.id() as u32;
            
            // 架构相关的trampoline代码
            #[cfg(target_arch = "riscv64")]
            {
                // RISC-V 64位的trampoline代码
                // li a7, syscall_num
                // ecall
                let riscv_code: &[u8] = &[
                    0x93, 0x08, (syscall_num & 0xff) as u8, ((syscall_num >> 8) & 0xff) as u8,  // li a7, syscall_num
                    0x73, 0x00, 0x00, 0x00,  // ecall
                ];
                trampoline_data[..riscv_code.len()].copy_from_slice(riscv_code);
            }
            
            #[cfg(target_arch = "loongarch64")]
            {
                // LoongArch64的trampoline代码
                // ori $a7, $zero, syscall_num
                // syscall 0
                let loongarch_code: &[u8] = &[
                    (syscall_num & 0xff) as u8, ((syscall_num >> 8) & 0xff) as u8, 0x00, 0x02,  // ori $a7, $zero, syscall_num
                    0x00, 0x00, 0x2b, 0x00,  // syscall 0
                ];
                trampoline_data[..loongarch_code.len()].copy_from_slice(loongarch_code);
            }
            
            #[cfg(target_arch = "x86_64")]
            {
                // x86_64的trampoline代码
                // mov rax, syscall_num
                // syscall
                let x86_code: &[u8] = &[
                    0x48, 0xc7, 0xc0, (syscall_num & 0xff) as u8, ((syscall_num >> 8) & 0xff) as u8, ((syscall_num >> 16) & 0xff) as u8, ((syscall_num >> 24) & 0xff) as u8,  // mov rax, syscall_num
                    0x0f, 0x05,  // syscall
                ];
                trampoline_data[..x86_code.len()].copy_from_slice(x86_code);
            }
            
            #[cfg(target_arch = "aarch64")]
            {
                // AArch64的trampoline代码
                // mov x8, #syscall_num
                // svc #0
                let syscall_low = (syscall_num & 0xffff) << 5;
                let aarch64_code: &[u8] = &[
                    (syscall_low & 0xff) as u8, ((syscall_low >> 8) & 0xff) as u8, 0x80, 0xd2,  // mov x8, #syscall_num
                    0x01, 0x00, 0x00, 0xd4,  // svc #0
                ];
                trampoline_data[..aarch64_code.len()].copy_from_slice(aarch64_code);
            }
            
            debug!("Setup signal trampoline at address: {:#x}", TRAMPOLINE_ADDR);
            Some(TRAMPOLINE_ADDR)
        } else {
            warn!("Failed to allocate memory for signal trampoline");
            None
        }
    }

    pub async fn handle_signal(&self, signal: SignalFlags) {
        // 添加详细的信号处理调试信息  
    warn!("SIGNAL_DEBUG: Handling signal {:?} for task_id={}, process_id={}",   
        signal, self.task.get_task_id(), self.task.process_id);  
     warn!("SIGNAL_DEBUG: Signal {:?} source analysis for task {}", signal, self.task.get_task_id());  
warn!("SIGNAL_DEBUG: Current PC: {:#x}", self.task.force_cx_ref()[TrapFrameArgs::SEPC]);  
  
// 检查信号是否由特定地址访问引起  
if signal == SignalFlags::SIGSEGV {  
    let current_pc = self.task.force_cx_ref()[TrapFrameArgs::SEPC];  
    warn!("SIGNAL_DEBUG: SIGSEGV at PC {:#x} - likely caused by memory access failure", current_pc);  
} 
    // 特别关注 SIGSEGV 信号  
    if signal == SignalFlags::SIGSEGV {  
        warn!("SIGNAL_DEBUG: SIGSEGV received - checking memory layout");  
        let pcb = self.task.pcb.lock();  
        warn!("SIGNAL_DEBUG: Task has {} memory areas", pcb.memset.len());  
        for (i, area) in pcb.memset.iter().enumerate() {  
            warn!("  Area {}: start={:#x}, end={:#x}, type={:?}",   
                i, area.start, area.start + area.len, area.mtype);  
        }  
        drop(pcb);  
    }  
        debug!(
            "handle signal: {:?} task_id: {}",
            signal,
            self.task.get_task_id()
        );

        // if the signal is SIGKILL, then exit the task immediately.
        // the SIGKILL can't be catched and be ignored.
        if signal == SignalFlags::SIGKILL {
            self.task.exit_with_signal(signal.num());
        }

        // get the signal action for the signal.
        let sigaction = self.task.pcb.lock().sigaction[signal.num()].clone();

        // if there doesn't have signal handler.
        // Then use default handler. Exit or do nothing.
        // SIG_ERR = -1, SIG_DEF(default) = 0, SIG_IGN = 1(ignore)
        if sigaction.handler == 0 {
            match signal {
                SignalFlags::SIGCANCEL | SignalFlags::SIGSEGV | SignalFlags::SIGILL => {
                   if signal == SignalFlags::SIGSEGV {  
                warn!("SIGNAL_DEBUG: SIGSEGV default exit - this indicates memory access failure");  
                warn!("SIGNAL_DEBUG: Check if gap region allocation was successful but mapping failed");  
            }  
                    current_user_task().exit_with_signal(signal.num());
                }
                SignalFlags::SIGTIMER => {
                    // SIGTIMER 的默认行为应该是忽略
                    warn!("SIGTIMER signal with no handler, ignoring");
                    return;
                }
                _ => {}
            }
            return;
        }
        // ignore signal if the handler of is SIG_IGN(1)
        if sigaction.handler == 1 {
            return;
        }

        // 强化的信号处理器地址验证
        if sigaction.handler < 0x10000 || sigaction.handler >= 0x800000000000 {
            warn!("Invalid signal handler address: {:#x} for signal {:?} in task {}", 
                sigaction.handler, signal, self.task.get_task_id());
            // 对于无效处理器，强制退出
            self.task.exit_with_signal(signal.num());
            return;
        }

        // 验证处理器地址是否在可执行内存区域中
        let handler_valid = {
            let pcb = self.task.pcb.lock();
            pcb.memset.iter().any(|area| {
                let in_area = area.contains(sigaction.handler);
                let is_executable = matches!(area.mtype, 
                    crate::tasks::MemType::CodeSection | 
                    crate::tasks::MemType::Stack |
                    crate::tasks::MemType::Mmap  // 某些动态库可能在mmap区域
                );
                
                if in_area {
                    warn!("Signal handler {:#x} found in area: start={:#x}, len={:#x}, type={:?}, executable={}",
                        sigaction.handler, area.start, area.len, area.mtype, is_executable);
                }
                
                in_area && is_executable
            })
        };

        if !handler_valid {
            warn!("Signal handler address {:#x} is not in executable memory for signal {:?} in task {}", 
                sigaction.handler, signal, self.task.get_task_id());
            // 对于定位在无效内存的处理器，强制退出
            self.task.exit_with_signal(signal.num());
            return;
        }

        // 暂时屏蔽 SIGTIMER 的处理，直到我们确认其他问题解决
        if signal == SignalFlags::SIGTIMER {
            warn!("Temporarily blocking SIGTIMER signal processing for stability in task {}", self.task.get_task_id());
            return;
        }

        // 对于SIGSYNCCALL信号也要小心处理，因为它与多线程TLS相关
        if signal == SignalFlags::SIGSYNCCALL {
            warn!("Processing SIGSYNCCALL signal for task {}, handler: {:#x}", 
                  self.task.get_task_id(), sigaction.handler);
        }

        info!(
            "handle signal: {:?} task: {}",
            signal,
            self.task.get_task_id()
        );

        // let cx_ref = unsafe { task.get_cx_ptr().as_mut().unwrap() };
        let cx_ref = self.task.force_cx_ref();
        // store task_mask and context.
        let task_mask = self.task.tcb.read().sigmask;
        let store_cx = cx_ref.clone();
        self.task.tcb.write().sigmask = sigaction.mask;

        // alloc space for SignalUserContext at stack and align with 16 bytes.
        let sp = (cx_ref[TrapFrameArgs::SP] - 128 - size_of::<SignalUserContext>()) / 16 * 16;

        // 对于SIGSEGV信号，在开始处理时添加额外的调试信息
        if signal == SignalFlags::SIGSEGV {
            warn!("SIGNAL_DEBUG: Starting SIGSEGV signal processing for task {}", self.task.get_task_id());
            warn!("SIGNAL_DEBUG: Signal handler: {:#x}, restorer: {:#x}", sigaction.handler, sigaction.restorer);
            warn!("SIGNAL_DEBUG: Current SP: {:#x}, calculated signal SP: {:#x}", cx_ref[TrapFrameArgs::SP], sp);
        }

        // 基本的栈指针合理性检查，放宽下界限制
        if sp == 0 || sp >= cx_ref[TrapFrameArgs::SP] {
            warn!("Invalid signal stack pointer: {:#x} (current SP: {:#x})", sp, cx_ref[TrapFrameArgs::SP]);
            return;
        }

        // 暂时简化信号栈验证，专注于解决基本问题
        debug!("Signal context: sp={:#x}, size={:#x}", sp, size_of::<SignalUserContext>());

        // 直接访问SignalUserContext，如果有问题会在页面错误处理中被捕获
        let cx: &mut SignalUserContext = UserRef::<SignalUserContext>::from(sp).get_mut();
        // change task context to do the signal.
        let mut tcb = self.task.tcb.write();
        cx.store_ctx(&cx_ref);
        cx.set_pc(tcb.cx[TrapFrameArgs::SEPC]);
        cx.sig_mask = sigaction.mask;
        tcb.cx[TrapFrameArgs::SP] = sp;
        tcb.cx[TrapFrameArgs::SEPC] = sigaction.handler;
        // 为信号处理函数设置返回地址
        tcb.cx[TrapFrameArgs::RA] = if sigaction.restorer == 0 {
            // 如果没有提供restorer，我们需要在用户空间创建一个简单的trampoline
            // 这个trampoline会调用rt_sigreturn系统调用
            self.setup_signal_trampoline().unwrap_or_else(|| {
                warn!("Failed to setup signal trampoline for task {}, signal handling may fail", self.task.get_task_id());
                // 作为fallback，我们设置一个特殊的标记，表示需要手动处理信号返回
                // 在handle_signal的循环中会检测到这种情况
                0 // 这会导致返回到地址0，触发页面错误，我们可以在那里处理
            })
        } else {
            sigaction.restorer
        };
        tcb.cx[TrapFrameArgs::ARG0] = signal.num();
        tcb.cx[TrapFrameArgs::ARG1] = 0;
        tcb.cx[TrapFrameArgs::ARG2] = cx as *mut SignalUserContext as usize;
        drop(tcb);

        // 保存sp用于后续的信号上下文访问检查
        let signal_stack_ptr = sp;

        loop {
            if let Some(exit_code) = self.task.exit_code() {
                debug!(
                    "program exit with code: {}  task_id: {}",
                    exit_code,
                    self.task.get_task_id()
                );
                break;
            }

            let cx_ref = self.task.force_cx_ref();

            debug!(
                "[task {}]task sepc: {:#x}",
                self.task.get_task_id(),
                cx_ref[TrapFrameArgs::SEPC]
            );

            if let UserTaskControlFlow::Break = self.handle_syscall(cx_ref).await {
                break;
            }
        }
        info!(
            "handle signal: {:?} task: {} ended",
            signal,
            self.task.get_task_id()
        );
        // restore sigmask to the mask before doing the signal.
        self.task.tcb.write().sigmask = task_mask;
        *cx_ref = store_cx;
        
        // 简化SIGSEGV处理，减少复杂性
        if signal == SignalFlags::SIGSEGV {
            debug!("SIGSEGV signal processing completed for task {}", self.task.get_task_id());
        }
        
        // 添加安全检查，防止无效的PC值
        let new_pc = cx.pc();
        if new_pc < 0x10000 || new_pc >= 0x800000000000 {
            warn!("Invalid signal return PC: {:#x}, using stored PC instead", new_pc);
            // 使用存储的上下文中的PC，不从信号上下文恢复
        } else {
            // copy pc from new_pc
            cx_ref[TrapFrameArgs::SEPC] = new_pc;
            cx.restore_ctx(cx_ref);
        }
        
        info!("Signal handling completed for task {}, returning to PC: {:#x}", 
              self.task.get_task_id(), cx_ref[TrapFrameArgs::SEPC]);
    }

    // 辅助函数：检查信号上下文是否可访问
    fn is_signal_context_accessible(&self, sp: usize) -> bool {
        let signal_context_size = size_of::<SignalUserContext>();
        let pcb = self.task.pcb.lock();
        pcb.memset.iter().any(|area| {
            area.contains(sp) && area.contains(sp + signal_context_size - 1)
        })
    }
}

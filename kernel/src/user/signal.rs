use core::mem::size_of;

use executor::AsyncTask;
use log::debug;
use polyhal_trap::trapframe::TrapFrameArgs;
use signal::SignalFlags;

use crate::syscall::types::signal::{SignalUserContext, SigInfo};
use crate::tasks::{current_user_task, UserTaskControlFlow};
use crate::utils::useref::UserRef;
use polyhal::VirtAddr;

use super::UserTaskContainer;

impl UserTaskContainer {
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
        //for (i, area) in pcb.memset.iter().enumerate() {  
            //warn!("  Area {}: start={:#x}, end={:#x}, type={:?}",   
                //i, area.start, area.start + area.len, area.mtype);  
        //}  
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
                // 这些信号的默认行为是终止进程
                SignalFlags::SIGCANCEL | SignalFlags::SIGSEGV | SignalFlags::SIGILL | 
                SignalFlags::SIGABRT | SignalFlags::SIGIOT | SignalFlags::SIGQUIT | SignalFlags::SIGTERM |
                SignalFlags::SIGHUP | SignalFlags::SIGINT | SignalFlags::SIGPIPE |
                SignalFlags::SIGALRM | SignalFlags::SIGFPE | SignalFlags::SIGBUS |
                SignalFlags::SIGTRAP | SignalFlags::SIGXCPU | SignalFlags::SIGXFSZ |
                SignalFlags::SIGVTALRM | SignalFlags::SIGPROF | SignalFlags::SIGUSR1 |
                SignalFlags::SIGUSR2 => {
                    if signal == SignalFlags::SIGSEGV {  
                        warn!("SIGNAL_DEBUG: SIGSEGV default exit - this indicates memory access failure");  
                        warn!("SIGNAL_DEBUG: Check if gap region allocation was successful but mapping failed");  
                    } else if signal == SignalFlags::SIGABRT || signal == SignalFlags::SIGIOT {
                        debug!("SIGABRT/SIGIOT received, terminating process as expected for abort()");
                    }
                    current_user_task().exit_with_signal(signal.num());
                }
                // 这些信号的默认行为是忽略
                SignalFlags::SIGTIMER | SignalFlags::SIGCHLD | SignalFlags::SIGURG |
                SignalFlags::SIGWINCH | SignalFlags::SIGIO | SignalFlags::SIGPWR => {
                    debug!("Signal {:?} ignored by default handler", signal);
                    return;
                }
                // SIGSTOP和SIGTSTP的默认行为是暂停进程，但我们暂时不支持进程暂停
                SignalFlags::SIGSTOP | SignalFlags::SIGTSTP | SignalFlags::SIGTTIN | SignalFlags::SIGTTOU => {
                    debug!("Stop signal {:?} received, but process suspension not implemented, ignoring", signal);
                    return;
                }
                // SIGCONT的默认行为是继续执行暂停的进程
                SignalFlags::SIGCONT => {
                    debug!("SIGCONT received, continuing process execution");
                    return;
                }
                _ => {
                    warn!("Unknown signal {:?} with default handler, ignoring", signal);
                }
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
                    crate::tasks::MemType::Mmap |  // 现在统一使用Mmap，包括代码段
                    crate::tasks::MemType::Stack |
                    crate::tasks::MemType::CodeSection  // 保持向后兼容
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
        
        // 临时保护措施：对于SIGCHLD信号，如果出现崩溃问题，直接使用默认行为
        if signal == SignalFlags::SIGCHLD {
            warn!("SIGCHLD protection: Using default ignore behavior to avoid crashes");
            return;
        }
        
        // 额外的SIGCHLD保护：如果glibc设置了SIGCHLD处理器，强制忽略
        if signal == SignalFlags::SIGCHLD && sigaction.handler != 0 && sigaction.handler != 1 {
            warn!("SIGCHLD handler detected but forcing ignore to prevent hangs");
            return;
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

        // alloc space for SigInfo + SignalUserContext at stack and align with 16 bytes.
        let current_sp = cx_ref[TrapFrameArgs::SP];
        
        // 计算 signal frame 大小：trampoline + siginfo_t + ucontext
        let trampoline_size = 16; // 4 * 4 bytes
        let frame_size = trampoline_size + size_of::<SigInfo>() + size_of::<SignalUserContext>();
        // 额外预留 128 字节，再按 16 字节对齐
        let sp = (current_sp - 128 - frame_size) & !0xf;
        
        // trampoline、siginfo 和 ucontext 的地址
        let tramp_sp = sp;
        let siginfo_sp = tramp_sp + trampoline_size;
        let uctx_sp = siginfo_sp + size_of::<SigInfo>();

        // 修复栈指针验证逻辑：使用更灵活的验证策略
        // 确保新的栈指针在合理的范围内（不能太远离当前栈指针）
        let max_stack_allocation = 64 * 1024; // 64KB的最大栈分配
        
        warn!("SIGNAL_DEBUG: Current SP: {:#x}, Tramp: {:#x}, Siginfo: {:#x}, UCTX: {:#x}, Difference: {:#x}", 
              current_sp, tramp_sp, siginfo_sp, uctx_sp, current_sp - sp);
        
        // 基于当前栈指针的相对验证，而不是硬编码的地址范围
        if sp >= current_sp || (current_sp - sp) > max_stack_allocation {
            warn!("Invalid signal stack pointer: {:#x}, current SP: {:#x}, max allocation: {:#x}", 
                  sp, current_sp, max_stack_allocation);
            return;
        }
        
        // 基础的地址合理性检查：避免明显无效的地址
        if sp < 0x1000 || sp >= 0x800000000000 {
            warn!("Signal stack pointer {:#x} is clearly invalid", sp);
            return;
        }

        // 验证栈指针是否在有效的内存区域内
        let sp_valid = {
            let pcb = self.task.pcb.lock();
            pcb.memset.iter().any(|area| {
                let in_area = area.contains(siginfo_sp) && area.contains(uctx_sp + size_of::<SignalUserContext>());
                let is_stack = matches!(area.mtype, 
                    crate::tasks::MemType::Stack | 
                    crate::tasks::MemType::Mmap
                );
                in_area && is_stack
            })
        };

        if !sp_valid {
            warn!("Signal stack pointer {:#x} is not in valid memory area for task {}", 
                siginfo_sp, self.task.get_task_id());
            return;
        }

        // 写入 siginfo_t
        {
            if let Some(_) = self.task.page_table.translate(VirtAddr::from(siginfo_sp)) {
                let siginfo_ref = UserRef::<SigInfo>::from(siginfo_sp).get_mut();
                *siginfo_ref = SigInfo::default();
                siginfo_ref.si_signo = signal.num() as i32;
                siginfo_ref.si_errno = 0;
                siginfo_ref.si_code = 0;
            } else {
                warn!("Cannot map siginfo page at {:#x}", siginfo_sp);
                return;
            }
        }

        // 直接访问SignalUserContext，但增强错误处理
        let cx: &mut SignalUserContext = {
            // 首先检查内存页是否可访问
            if let None = self.task.page_table.translate(VirtAddr::from(uctx_sp)) {
                warn!("Signal stack page at {:#x} is not mapped for task {}", 
                    uctx_sp, self.task.get_task_id());
                // 输出当前内存布局以便调试
                let pcb = self.task.pcb.lock();
                warn!("Current memory areas for task {}:", self.task.get_task_id());
                for (i, area) in pcb.memset.iter().enumerate() {
                    warn!("  Area {}: {:#x}-{:#x} (type: {:?})", 
                        i, area.start, area.start + area.len, area.mtype);
                }
                return;
            }
            
            // 添加内存屏障确保之前的内存操作完成
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            
            UserRef::<SignalUserContext>::from(uctx_sp).get_mut()
        };
        // change task context to do the signal.
        let mut tcb = self.task.tcb.write();
        
        // 保存原始PC，用于没有restorer时的返回地址
        let original_pc = tcb.cx[TrapFrameArgs::SEPC];
        
        // 保存当前上下文到SignalUserContext
        cx.store_ctx(&cx_ref);
        cx.set_pc(original_pc);  // 保存原始PC，而不是已经修改的PC
        cx.sig_mask = sigaction.mask;
        
        // 设置新的执行上下文
        tcb.cx[TrapFrameArgs::SP] = tramp_sp;
        tcb.cx[TrapFrameArgs::SEPC] = sigaction.handler;
        
        // 添加详细的restorer调试信息
        warn!("SIGNAL_DEBUG: restorer address for {:?}: {:#x}", signal, sigaction.restorer);
        
        // 验证restorer地址是否在有效的内存区域中（仅当restorer不为0时）
        let restorer_check_passed = if sigaction.restorer != 0 {
            let restorer_valid = {
                let pcb = self.task.pcb.lock();
                pcb.memset.iter().any(|area| {
                    let in_area = area.contains(sigaction.restorer);
                    let is_executable = matches!(area.mtype, 
                        crate::tasks::MemType::Mmap |
                        crate::tasks::MemType::Stack |
                        crate::tasks::MemType::CodeSection
                    );
                    
                    if in_area {
                        warn!("SIGNAL_DEBUG: restorer {:#x} found in area: start={:#x}, len={:#x}, type={:?}, executable={}",
                            sigaction.restorer, area.start, area.len, area.mtype, is_executable);
                    }
                    
                    in_area && is_executable
                })
            };
            
            if !restorer_valid {
                warn!("Invalid restorer address {:#x} for signal {:?}", 
                    sigaction.restorer, signal);
                
                // 对于SIGUSR1/SIGUSR2，即使restorer无效也继续执行
                match signal {
                    SignalFlags::SIGUSR1 | SignalFlags::SIGUSR2 => {
                        warn!("User signal {:?} has invalid restorer but will continue execution", signal);
                        true  // 继续处理
                    }
                    // 其他信号使用默认行为
                    _ => {
                        drop(tcb);
                        match signal {
                            // 默认终止的信号
                            SignalFlags::SIGCANCEL | SignalFlags::SIGSEGV | SignalFlags::SIGILL | 
                            SignalFlags::SIGABRT | SignalFlags::SIGIOT | SignalFlags::SIGQUIT | SignalFlags::SIGTERM |
                            SignalFlags::SIGHUP | SignalFlags::SIGINT | SignalFlags::SIGPIPE |
                            SignalFlags::SIGALRM | SignalFlags::SIGFPE | SignalFlags::SIGBUS |
                            SignalFlags::SIGTRAP | SignalFlags::SIGXCPU | SignalFlags::SIGXFSZ |
                            SignalFlags::SIGVTALRM | SignalFlags::SIGPROF => {
                                warn!("Using default termination for signal {:?}", signal);
                                self.task.exit_with_signal(signal.num());
                            }
                            // 默认忽略的信号
                            _ => {
                                warn!("Using default ignore for signal {:?}", signal);
                            }
                        }
                        return;
                    }
                }
            } else {
                true  // restorer有效，继续处理
            }
        } else {
            true  // 没有restorer，继续处理
        };
        
        if !restorer_check_passed {
            return;
        }
        
        // 智能设置返回地址
        if sigaction.restorer == 0 || sigaction.restorer < 0x1000 {
            // 对于没有restorer的情况，需要为不同架构提供不同的解决方案
            #[cfg(target_arch = "loongarch64")]
            {
                // LoongArch64: 在用户栈上创建signal trampoline
                // 因为LoongArch musl没有提供restorer，需要内核创建trampoline执行rt_sigreturn
                // trampoline地址已经在上面计算好了
                
                // LoongArch64的rt_sigreturn trampoline代码
                // 根据LoongArch64 ABI，系统调用号通过$a7 (r11)传递
                // 正确的指令编码：
                let trampoline_code: [u32; 4] = [
                    // li.w $a7, 139  ($a7是r11，立即数139)
                    // LoongArch instruction format: [31:25][24:10][9:5][4:0]
                    // LI.W: opcode=0x0380000, rd=11, imm12=139
                    0x0380000b | ((139 & 0xfff) << 10),  // li.w $a7, 139
                    0x002b0000,  // syscall 0
                    0x4c000020,  // jirl $r0, $ra, 0 (return)
                    0x00000000,  // padding
                ];
                
                // 将trampoline代码写入用户栈
                match self.task.page_table.translate(VirtAddr::from(tramp_sp)) {
                    Some(_) => {
                        let tramp_ref = UserRef::<[u32; 4]>::from(tramp_sp);
                        let tramp_slice = tramp_ref.get_mut();
                        *tramp_slice = trampoline_code;
                        
                        // 设置返回地址指向trampoline
                        tcb.cx[TrapFrameArgs::RA] = tramp_sp;
                        tcb.cx[TrapFrameArgs::SP] = tramp_sp; // 更新栈指针
                        
                        warn!("SIGNAL_DEBUG: LoongArch - Created trampoline at {:#x}, RA set to trampoline", tramp_sp);
                    },
                    None => {
                        warn!("SIGNAL_DEBUG: LoongArch - Cannot map trampoline page, using original PC fallback");
                        tcb.cx[TrapFrameArgs::RA] = original_pc;
                    }
                }
            }
            #[cfg(target_arch = "riscv64")]
            {
                // RISC-V64: 在用户栈上创建signal trampoline
                // trampoline地址已经在上面计算好了
                
                // RISC-V64的rt_sigreturn trampoline代码
                // 系统调用号通过a7寄存器传递，rt_sigreturn的系统调用号是139
                let trampoline_code: [u32; 4] = [
                    0x08b00893,  // li a7, 139 (系统调用号)
                    0x00000073,  // ecall
                    0x00000000,  // nop
                    0x00000000,  // padding
                ];
                
                // 将trampoline代码写入用户栈
                match self.task.page_table.translate(VirtAddr::from(tramp_sp)) {
                    Some(_) => {
                        let tramp_ref = UserRef::<[u32; 4]>::from(tramp_sp);
                        let tramp_slice = tramp_ref.get_mut();
                        *tramp_slice = trampoline_code;
                        
                        // 设置返回地址指向trampoline
                        tcb.cx[TrapFrameArgs::RA] = tramp_sp;
                        
                        // 对于restorer地址小于0x1000的情况（如glibc中的0x200），
                        // 我们不修改SP，让信号处理器能正确访问其参数
                        if sigaction.restorer < 0x1000 && sigaction.restorer != 0 {
                            // 保持原有的栈指针，不修改SP
                            warn!("SIGNAL_DEBUG: RISC-V64 - Created trampoline at {:#x}, RA set to trampoline, SP unchanged for glibc compatibility", tramp_sp);
                        } else {
                            // 对于restorer为0的情况，我们可以安全地修改SP
                            warn!("SIGNAL_DEBUG: RISC-V64 - Created trampoline at {:#x}, RA set to trampoline", tramp_sp);
                        }
                    },
                    None => {
                        warn!("SIGNAL_DEBUG: RISC-V64 - Cannot map trampoline page, using original PC fallback");
                        tcb.cx[TrapFrameArgs::RA] = original_pc;
                    }
                }
            }
            #[cfg(not(any(target_arch = "loongarch64", target_arch = "riscv64")))]
            {
                // 其他架构：使用原始PC作为返回地址（fallback方案）
                tcb.cx[TrapFrameArgs::RA] = original_pc;
                warn!("SIGNAL_DEBUG: No restorer, setting RA to original PC: {:#x}", tcb.cx[TrapFrameArgs::RA]);
            }
        } else {
            tcb.cx[TrapFrameArgs::RA] = sigaction.restorer;
            warn!("SIGNAL_DEBUG: Setting RA to restorer: {:#x}", sigaction.restorer);
        }
        tcb.cx[TrapFrameArgs::ARG0] = signal.num();
        tcb.cx[TrapFrameArgs::ARG1] = siginfo_sp;
        tcb.cx[TrapFrameArgs::ARG2] = uctx_sp;
        drop(tcb);

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
        
        // 在访问SignalUserContext前再次验证内存可访问性
        if let None = self.task.page_table.translate(VirtAddr::from(uctx_sp)) {
            warn!("Signal context page at {:#x} is no longer mapped for task {}, skipping context restore", 
                uctx_sp, self.task.get_task_id());
            // 不尝试从信号上下文恢复，直接使用存储的上下文
            info!("Signal handling completed for task {}, returning to stored PC: {:#x}", 
                  self.task.get_task_id(), cx_ref[TrapFrameArgs::SEPC]);
            return;
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
}
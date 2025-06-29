use core::mem::size_of;

use executor::AsyncTask;
use log::debug;
use polyhal_trap::trapframe::TrapFrameArgs;
use signal::SignalFlags;

use crate::syscall::types::signal::SignalUserContext;
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
                // SIGSTOP和SIGTSTP的默认行为是暂停进程，但我们目前不支持进程暂停
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

        // 修复栈指针验证逻辑：使用正确的用户栈范围
        // 用户栈在 0x8000_0000 附近，向下增长
        let stack_bottom = 0x7000_0000; // 用户栈底部
        let stack_top = cx_ref[TrapFrameArgs::SP]; // 当前栈顶
        
        if sp < stack_bottom || sp >= stack_top {
            warn!("Invalid signal stack pointer: {:#x}, valid range: {:#x}-{:#x}", 
                  sp, stack_bottom, stack_top);
            return;
        }

        // 验证栈指针是否在有效的内存区域内
        let sp_valid = {
            let pcb = self.task.pcb.lock();
            pcb.memset.iter().any(|area| {
                let in_area = area.contains(sp) && area.contains(sp + size_of::<SignalUserContext>());
                let is_stack = matches!(area.mtype, 
                    crate::tasks::MemType::Stack | 
                    crate::tasks::MemType::Mmap
                );
                in_area && is_stack
            })
        };

        if !sp_valid {
            warn!("Signal stack pointer {:#x} is not in valid memory area for task {}", 
                sp, self.task.get_task_id());
            return;
        }

        // 直接访问SignalUserContext，但增强错误处理
        let cx: &mut SignalUserContext = {
            // 首先检查内存页是否可访问
            if let None = self.task.page_table.translate(VirtAddr::from(sp)) {
                warn!("Signal stack page at {:#x} is not mapped for task {}", 
                    sp, self.task.get_task_id());
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
            
            UserRef::<SignalUserContext>::from(sp).get_mut()
        };
        // change task context to do the signal.
        let mut tcb = self.task.tcb.write();
        cx.store_ctx(&cx_ref);
        cx.set_pc(tcb.cx[TrapFrameArgs::SEPC]);
        cx.sig_mask = sigaction.mask;
        tcb.cx[TrapFrameArgs::SP] = sp;
        tcb.cx[TrapFrameArgs::SEPC] = sigaction.handler;
        tcb.cx[TrapFrameArgs::RA] = if sigaction.restorer == 0 {
            // SIG_RETURN_ADDR
            // TODO: add sigreturn addr.
            0
        } else {
            sigaction.restorer
        };
        tcb.cx[TrapFrameArgs::ARG0] = signal.num();
        tcb.cx[TrapFrameArgs::ARG1] = 0;
        tcb.cx[TrapFrameArgs::ARG2] = cx as *mut SignalUserContext as usize;
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
        if let None = self.task.page_table.translate(VirtAddr::from(sp)) {
            warn!("Signal context page at {:#x} is no longer mapped for task {}, skipping context restore", 
                sp, self.task.get_task_id());
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

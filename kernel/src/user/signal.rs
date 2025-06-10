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
    pub async fn handle_signal(&self, signal: SignalFlags) {
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

        if sp < 0x2_0000_0000 || sp >= cx_ref[TrapFrameArgs::SP] {
            warn!("Invalid signal stack pointer: {:#x}", sp);
            return;
        }

        let cx: &mut SignalUserContext = UserRef::<SignalUserContext>::from(sp).get_mut();
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

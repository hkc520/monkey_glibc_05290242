use super::SysResult;
use crate::syscall::types::mm::{MSyncFlags, MapFlags, MmapProt, ProtFlags};
use crate::tasks::{MemArea, MemType};
use crate::user::UserTaskContainer;
use crate::utils::useref::UserRef;
use devices::PAGE_SIZE;
use log::debug;
use polyhal::VirtAddr;
use runtime::frame::alignup;
use syscalls::Errno;

// The high 25bits in sv39 should be the same as bit 38.
const MAP_AREA_START: usize = 0x2_0000_0000;

impl UserTaskContainer {
    pub async fn sys_brk(&self, addr: usize) -> SysResult {
        debug!("sys_brk @ new: {:#x} old: {:#x}", addr, self.task.heap());
        match addr {
            0 => Ok(self.task.heap()),
            _ => Ok(self.task.sbrk(addr)),
        }
    }

    pub async fn sys_mmap(
        &self,
        start: usize,
        mut len: usize,
        prot: usize,
        flags: usize,
        fd: usize,
        off: usize,
    ) -> SysResult {
        let flags = MapFlags::from_bits_truncate(flags as _);
        let prot = MmapProt::from_bits_truncate(prot as _);
        len = alignup(len, PAGE_SIZE);
        debug!(
            "[task {}] sys_mmap @ start: {:#x}, len: {:#x}, prot: {:?}, flags: {:?}, fd: {}, offset: {}",
            self.tid, start, len, prot, flags, fd as isize, off
        );
        
        // 处理匿名映射：当fd为-1或MAP_ANONYMOUS标志设置时
        let file = if fd == usize::MAX || flags.contains(MapFlags::MAP_ANONYMOUS) {
            None
        } else {
            self.task.get_fd(fd)
        };

        let addr = self.task.get_last_free_addr();

        let addr = if start == 0 {
            if usize::from(addr) >= MAP_AREA_START {
                addr
            } else {
                VirtAddr::from(MAP_AREA_START)
            }
        } else {
            VirtAddr::new(start)
        };

        if len == 0 {
            return Ok(addr.into());
        }

        // 检查地址是否在有效范围内（LoongArch用户空间限制）
        #[cfg(target_arch = "loongarch64")]
        {
            const USER_VADDR_MAX: usize = 0x7F_FFFF_FFFF; // (1 << 39) - 1
            if addr.raw() + len > USER_VADDR_MAX {
                debug!("mmap address out of user space range: {:#x}", addr.raw());
                return Err(Errno::ENOMEM);
            }
        }

        if flags.contains(MapFlags::MAP_FIXED) {
            let overlaped = self
                .task
                .pcb
                .lock()
                .memset
                .overlapping(addr.raw(), addr.raw() + len);
            if overlaped {
                self.task.pcb.lock().memset.sub_area(
                    addr.raw(),
                    addr.raw() + len,
                    &self.task.page_table,
                );
            }
        } else if self
            .task
            .pcb
            .lock()
            .memset
            .overlapping(addr.raw(), addr.raw() + len)
        {
            return Err(Errno::EINVAL);
        }

        // 处理共享映射
        if flags.contains(MapFlags::MAP_SHARED) {
            match &file {
                Some(file) => {
                    // 文件共享映射
                    if let Some(_paddr) = self.task.map_frames(
                        addr,
                        MemType::ShareFile,
                        (len + PAGE_SIZE - 1) / PAGE_SIZE,
                        Some(file.get_bare_file()),
                        off,
                        usize::from(addr),
                        len,
                        prot.into(),
                    ) {
                        // 映射成功
                    } else {
                        debug!("Failed to map shared file");
                        return Err(Errno::EFAULT);
                    }
                },
                None => {
                    // 匿名共享映射
                    let paddr = self
                        .task
                        .frame_alloc(addr, MemType::Shared, len.div_ceil(PAGE_SIZE))
                        .ok_or(Errno::EFAULT)?;

                    for i in 0..(len + PAGE_SIZE - 1) / PAGE_SIZE {
                        self.task
                            .map(paddr + i * PAGE_SIZE, addr + i * PAGE_SIZE, prot.into());
                    }
                }
            };
        } else {
            // 私有映射
            if file.is_some() {
                // 文件私有映射
                self.task
                    .frame_alloc(addr, MemType::Mmap, len.div_ceil(PAGE_SIZE))
                    .ok_or(Errno::EFAULT)?;
            } else {
                // 匿名私有映射
                self.task.pcb.lock().memset.push(MemArea {
                    mtype: MemType::Mmap,
                    mtrackers: vec![],
                    file: None,
                    offset: 0,
                    start: addr.raw(),
                    len,
                });
            }
        };

        // 从文件读取数据（如果有文件）
        if let Some(file) = file {
            // 创建缓冲区前先验证地址是否已映射
            if let Err(e) = (|| -> Result<(), Errno> {
                let buffer = UserRef::<u8>::from(addr).slice_mut_with_len(len);
                file.readat(off, buffer).map(|_| ())
            })() {
                debug!("Failed to read file data: {:?}", e);
                // 清理已分配的内存
                self.task.pcb.lock().memset.sub_area(
                    addr.raw(),
                    addr.raw() + len,
                    &self.task.page_table,
                );
                return Err(e);
            }
        }
        
        Ok(addr.into())
    }

    pub async fn sys_munmap(&self, start: usize, len: usize) -> SysResult {
        debug!("sys_munmap @ start: {:#x}, len: {:#x}", start, len);
        self.task.inner_map(|pcb| {
            pcb.memset
                .sub_area(start, start + len, &self.task.page_table);
        });
        Ok(0)
    }

    pub async fn sys_mprotect(&self, start: usize, len: usize, prot: u32) -> SysResult {
        let prot = ProtFlags::from_bits_truncate(prot);
        debug!(
            "sys_mprotect @ start: {:#x}, len: {:#x}, prot: {:?}",
            start, len, prot
        );
        // Err(LinuxError::EPERM)
        Ok(0)
    }

    pub async fn sys_msync(&self, addr: usize, len: usize, flags: u32) -> SysResult {
        let flags = MSyncFlags::from_bits_truncate(flags);
        debug!(
            "sys_msync @ addr: {:#x} len: {:#x} flags: {:?}",
            addr, len, flags
        );
        // use it temporarily
        Ok(0)
    }

    pub async fn sys_set_robust_list(&self, head: usize, len: usize) -> SysResult {
        // 根据 Linux 标准，robust_list_head 结构体的大小应该是 24 字节（在 64 位系统上）
        const ROBUST_LIST_HEAD_SIZE: usize = 24;
        
        // 验证长度参数
        if len != ROBUST_LIST_HEAD_SIZE {
            warn!("SYS_SET_ROBUST_LIST: Invalid size. Expected: {}, Got: {}", ROBUST_LIST_HEAD_SIZE, len);
            return Err(Errno::EINVAL);
        }

        // 如果 head 不为 0，验证地址有效性
        if head != 0 {
            // 检查地址是否在用户空间范围内
            if head >= 0x8000_0000_0000_0000 {
                warn!("SYS_SET_ROBUST_LIST: Invalid head address: {:#x}", head);
                return Err(Errno::EFAULT);
            }

            // 验证地址是否可访问（通过页表转换）
            let head_addr = VirtAddr::from(head);
            if self.task.page_table.translate(head_addr).is_none() {
                warn!("SYS_SET_ROBUST_LIST: Address {:#x} is not mapped", head);
                return Err(Errno::EFAULT);
            }
        }

        // 设置当前线程的 robust list
        {
            let mut tcb = self.task.tcb.write();
            tcb.robust_list_head = head;
            tcb.robust_list_len = len;
        }

        debug!("SYS_SET_ROBUST_LIST: Set robust list head={:#x}, len={}", head, len);
        Ok(0)
    }

    pub async fn sys_get_robust_list(  
        &self,  
        pid: i32,  
        head_ptr: usize,  
        len_ptr: usize,  
    ) -> SysResult {  
        warn!("SYS_GET_ROBUST_LIST pid: {}, head_ptr: {:#x}, len_ptr: {:#x}", pid, head_ptr, len_ptr);  
        
        // 验证地址是否在合理范围内  
        if head_ptr != 0 {  
            // 检查地址是否在用户空间范围内  
            if head_ptr >= 0x8000_0000_0000_0000 {  
                warn!("Invalid head_ptr address: {:#x}", head_ptr);  
                return Err(Errno::EFAULT);  
            }  
            
            let head_addr = VirtAddr::from(head_ptr);  
            if let Some((paddr, _)) = self.task.page_table.translate(head_addr) {  
                unsafe {  
                    paddr.get_mut_ptr::<usize>().write(0);  
                }  
            } else {  
                warn!("Failed to translate head_ptr address: {:#x}", head_ptr);  
                return Err(Errno::EFAULT);  
            }  
        }  
        
        // 验证长度指针地址  
        if len_ptr != 0 {  
            if len_ptr >= 0x8000_0000_0000_0000 {  
                warn!("Invalid len_ptr address: {:#x}", len_ptr);  
                return Err(Errno::EFAULT);  
            }  
            
            let len_addr = VirtAddr::from(len_ptr);  
            if let Some((paddr, _)) = self.task.page_table.translate(len_addr) {  
                unsafe {  
                    paddr.get_mut_ptr::<usize>().write(0);  
                }  
            } else {  
                warn!("Failed to translate len_ptr address: {:#x}", len_ptr);  
                return Err(Errno::EFAULT);  
            }  
        }  
        
        Ok(0)  
    }
}

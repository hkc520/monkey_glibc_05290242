use crate::tasks::memset;
use super::{
    filetable::{rlimits_new, FileTable},
    memset::{MemSet, MemType},
    shm::MapedSharedMemory,
    SignalList,
};
use crate::{
    syscall::types::{
        fd::AT_CWD,
        time::{ProcessTimer, TMS},
    },
    tasks::{
        futex_wake,
        memset::{MapTrack, MemArea},
    },
};
use alloc::{
    collections::BTreeMap,
    sync::{Arc, Weak},
    vec::Vec,
};
use core::{cmp::max, mem::size_of};
use devices::PAGE_SIZE;
use executor::{release_task, task::TaskType, task_id_alloc, AsyncTask, TaskId};
use fs::{file::File, pathbuf::PathBuf, INodeInterface};
use log::debug;
use polyhal::{va, MappingFlags, MappingSize, PageTableWrapper, PhysAddr, VirtAddr};
use polyhal_trap::trapframe::{TrapFrame, TrapFrameArgs};
use runtime::frame::{alignup, frame_alloc_much};
use signal::{SigAction, SigProcMask, SignalFlags, REAL_TIME_SIGNAL_NUM};
use sync::{Mutex, MutexGuard, RwLock};
use syscalls::Errno;
use vfscore::{OpenFlags, VfsResult};

pub type FutexTable = BTreeMap<usize, Vec<usize>>;

pub struct ProcessControlBlock {
    pub memset: MemSet,
    pub fd_table: FileTable,
    pub curr_dir: Arc<File>,
    pub heap: usize,
    pub entry: usize,
    pub children: Vec<Arc<UserTask>>,
    pub tms: TMS,
    pub rlimits: Vec<usize>,
    pub sigaction: [SigAction; 65],
    pub futex_table: Arc<Mutex<FutexTable>>,
    pub shms: Vec<MapedSharedMemory>,
    pub timer: [ProcessTimer; 3],
    pub threads: Vec<Weak<UserTask>>,
    pub exit_code: Option<usize>,
}

pub struct ThreadControlBlock {
    pub cx: TrapFrame,
    pub sigmask: SigProcMask,
    pub clear_child_tid: usize,
    pub set_child_tid: usize,
    pub signal: SignalList,
    pub signal_queue: [usize; REAL_TIME_SIGNAL_NUM], // a queue for real time signals
    pub exit_signal: u8,
    pub thread_exit_code: Option<u32>,
    pub robust_list_head: usize,    // 添加 robust list 头指针
    pub robust_list_len: usize,     // 添加 robust list 长度
}

#[allow(dead_code)]
pub struct UserTask {
    pub task_id: TaskId,
    pub process_id: TaskId,
    pub page_table: Arc<PageTableWrapper>,
    pub pcb: Arc<Mutex<ProcessControlBlock>>,
    pub parent: RwLock<Weak<UserTask>>,
    pub tcb: RwLock<ThreadControlBlock>,
}

impl UserTask {
    pub fn release(&self) {
        // Ensure that the task was exited successfully.
        assert!(self.exit_code().is_some() || self.tcb.read().thread_exit_code.is_some());
        release_task(self.task_id);
    }
}

impl UserTask {
    pub fn new(parent: Weak<UserTask>, work_dir: PathBuf) -> Arc<Self> {
        let task_id = task_id_alloc();
        // initialize memset
        let memset = MemSet::new(vec![]);

        let curr_dir = File::open(work_dir, OpenFlags::O_DIRECTORY)
            .map(Arc::new)
            .expect("dont' have the home dir");

        let inner = ProcessControlBlock {
            memset,
            fd_table: FileTable::new(),
            curr_dir,
            heap: 0,
            children: Vec::new(),
            entry: 0,
            tms: Default::default(),
            rlimits: rlimits_new(),
            sigaction: [SigAction::new(); 65],
            futex_table: Arc::new(Mutex::new(BTreeMap::new())),
            shms: vec![],
            timer: [Default::default(); 3],
            exit_code: None,
            threads: Vec::new(),
        };

        let tcb = RwLock::new(ThreadControlBlock {
            cx: TrapFrame::new(),
            sigmask: SigProcMask::new(),
            clear_child_tid: 0,
            set_child_tid: 0,
            signal: SignalList::new(),
            signal_queue: [0; REAL_TIME_SIGNAL_NUM],
            exit_signal: 0,
            thread_exit_code: Option::None,
            robust_list_head: 0,            // 初始化为 0
            robust_list_len: 0,             // 初始化为 0
        });

        let task = Arc::new(Self {
            page_table: Arc::new(PageTableWrapper::alloc()),
            task_id,
            process_id: task_id,
            parent: RwLock::new(parent),
            pcb: Arc::new(Mutex::new(inner)),
            tcb,
        });
        task.pcb.lock().threads.push(Arc::downgrade(&task));
        task
    }

    pub fn inner_map<T>(&self, mut f: impl FnMut(&mut MutexGuard<ProcessControlBlock>) -> T) -> T {
        f(&mut self.pcb.lock())
    }

    #[inline]
    pub fn map(&self, paddr: PhysAddr, vaddr: VirtAddr, flags: MappingFlags) {
        assert_eq!(paddr.raw() % PAGE_SIZE, 0);
        assert_eq!(vaddr.raw() % PAGE_SIZE, 0);
        // self.page_table.map(ppn, vpn, flags, 3);
        self.page_table
            .map_page(vaddr, paddr, flags, MappingSize::Page4KB);
    }

    #[inline]
    pub fn frame_alloc(&self, vaddr: VirtAddr, mtype: MemType, count: usize) -> Option<PhysAddr> {
        // 根据内存类型选择合适的权限
        let mapping_flags = match mtype {
            MemType::Stack => MappingFlags::URWX,      // 栈需要读写执行权限
            MemType::CodeSection => MappingFlags::URWX, // 代码段默认读写执行（后续会根据ELF flags调整）
            MemType::Mmap => MappingFlags::URWX,       // mmap区域默认读写执行
            MemType::Shared => MappingFlags::URWX,     // 共享内存读写执行
            MemType::ShareFile => MappingFlags::URW,   // 共享文件读写
        };
        self.map_frames(vaddr, mtype, count, None, 0, vaddr.raw(), count * PAGE_SIZE, mapping_flags)
    }

    pub fn map_frames(
        &self,
        vaddr: VirtAddr,
        mtype: MemType,
        count: usize,
        file: Option<Arc<dyn INodeInterface>>,
        offset: usize,
        start: usize,
        len: usize,
        mapping_flags: MappingFlags,
    ) -> Option<PhysAddr> {
        assert!(count > 0, "can't alloc count = 0 in user_task frame_alloc");
        // alloc trackers and map vpn
        let trackers: Vec<_> = frame_alloc_much(count)?
            .into_iter()
            .enumerate()
            .map(|(i, x)| {
                let vaddr = match vaddr.raw() == 0 {
                    true => vaddr,
                    false => va!(vaddr.raw() + i * PAGE_SIZE),
                };
                MapTrack {
                    vaddr,
                    tracker: Arc::new(x),
                    rwx: 0,
                }
            })
            .collect();
        if vaddr.raw() != 0 {
            debug!(
                "map {:?} @ {:#x} size: {:#x} flags: {:?}",
                vaddr,
                trackers[0].tracker.raw(),
                count * PAGE_SIZE,
                mapping_flags
            );
            // map vpn to ppn
            trackers
                .clone()
                .iter()
                .filter(|x| x.vaddr.raw() != 0)
                .for_each(|x| self.map(x.tracker.0, x.vaddr, mapping_flags));
        }
        let mut inner = self.pcb.lock();
        let ppn = trackers[0].tracker.0;
        if mtype == MemType::Stack {
            let finded_area = inner.memset.iter_mut().find(|x| x.mtype == mtype);
            if let Some(area) = finded_area {
                area.mtrackers.extend(trackers);
            } else if mtype == MemType::Stack {
                inner.memset.push(MemArea {
                    mtype,
                    mtrackers: trackers.clone(),
                    file: None,
                    offset: 0,
                    start: 0x7000_0000,
                    len: 0x1000_0000,
                });
            }
        } else {
            inner.memset.push(MemArea {
                mtype,
                mtrackers: trackers.clone(),
                file,
                offset,
                start,
                len,
            });
        }
        drop(inner);

        Some(ppn)
    }

    pub fn force_cx_ref(&self) -> &'static mut TrapFrame {
        unsafe { &mut self.tcb.as_mut_ptr().as_mut().unwrap().cx }
    }

    pub fn sbrk(&self, addr: usize) -> usize {
        let curr_page = self.pcb.lock().heap.div_ceil(PAGE_SIZE);
        let after_page = addr.div_ceil(PAGE_SIZE);
        // 如果需要申请内存
        (curr_page..after_page).for_each(|i| {
            self.frame_alloc(va!(i * PAGE_SIZE), MemType::CodeSection, 1);
        });
        self.pcb.lock().heap = addr;
        addr
    }

    pub fn heap(&self) -> usize {
        self.pcb.lock().heap
    }

    #[inline]
    pub fn thread_exit(&self, exit_code: usize) {
        let mut tcb_writer = self.tcb.write();
        let uaddr = tcb_writer.clear_child_tid;
        if uaddr != 0 {
            debug!("write addr: {:#x}", uaddr);
            let addr = self
                .page_table
                .translate(VirtAddr::from(uaddr))
                .expect("can't find a valid addr")
                .0;
            unsafe {
                addr.get_mut_ptr::<u32>().write(0);
            }
            futex_wake(self.pcb.lock().futex_table.clone(), uaddr, 1);
        }
        tcb_writer.thread_exit_code = Some(exit_code as u32);
        let exit_signal = tcb_writer.exit_signal;
        drop(tcb_writer);

        // 改进的线程退出逻辑 - 不应该直接清理进程资源
        let should_cleanup_process = {
            let mut pcb = self.pcb.lock();
            
            // 清理线程列表
            pcb.threads.retain(|weak_ref| {
                if let Some(thread) = weak_ref.upgrade() {
                    thread.task_id != self.task_id
                } else {
                    false
                }
            });
            
            let remaining_threads = pcb.threads.len();
            let is_main_thread = self.task_id == self.process_id;
            
            // 更保守的清理条件：只有主线程退出且没有其他活跃线程时才清理
            is_main_thread && remaining_threads == 0
        };

        if should_cleanup_process {
            warn!("Thread exit triggering process cleanup for process_id={}", self.process_id);
            let mut pcb = self.pcb.lock();
            pcb.memset.clear();
            pcb.fd_table.clear();
            pcb.children.clear();
            pcb.exit_code = Some(exit_code);

            if let Some(parent) = self.parent.read().upgrade() {
                if exit_signal != 0 {
                    parent
                        .tcb
                        .write()
                        .signal
                        .add_signal(SignalFlags::from_num(exit_signal as _));
                } else {
                    parent.tcb.write().signal.add_signal(SignalFlags::SIGCHLD);
                }
            }
        } else {
            warn!("Thread exit: task_id={} exited, but process continues", self.task_id);
        }
    }

    #[inline]
    pub fn exit_with_signal(&self, signal: usize) {
        self.exit(128 + signal);
    }

    pub fn cow_fork(self: Arc<Self>) -> Arc<Self> {
        let parent_task: Arc<UserTask> = self.clone();
        let work_dir = parent_task.clone().pcb.lock().curr_dir.path_buf();
        let new_task = Self::new(Arc::downgrade(&parent_task), work_dir);
        let mut new_tcb_writer = new_task.tcb.write();
        
        // 添加调试信息：检查父进程的memset状态
        {
            let parent_pcb = self.pcb.lock();
            warn!("COW_FORK: Parent task_id={}, memset size={}", self.task_id, parent_pcb.memset.len());
            for (i, area) in parent_pcb.memset.iter().enumerate() {
                warn!("COW_FORK: Parent Area {}: start={:#x}, len={:#x}, mtype={:?}, has_file={}, mtrackers={}",
                    i, area.start, area.len, area.mtype, area.file.is_some(), area.mtrackers.len());
            }
            drop(parent_pcb);
        }
        
        // 一次性获取锁并复制所有数据，准备两份memset数据
        let (memset_for_new_pcb, memset_for_cow, fd_table_clone, heap, curr_dir_clone, shms_clone) = {
            let mut pcb = self.pcb.lock();
            let memset_original = pcb.memset.clone();
            let memset_for_new_pcb = memset_original.clone(); // 用于创建new_pcb.memset
            let memset_for_cow = memset_original;              // 用于COW映射
            let fd_table_clone = pcb.fd_table.0.clone();
            let heap = pcb.heap;
            let curr_dir_clone = pcb.curr_dir.clone();
            let shms_clone = pcb.shms.clone();
            
            // 添加子进程
            pcb.children.push(new_task.clone());
            
            (memset_for_new_pcb, memset_for_cow, fd_table_clone, heap, curr_dir_clone, shms_clone)
        };
        
        // 添加调试信息：检查复制的数据
        warn!("COW_FORK: Copied memset size={}", memset_for_new_pcb.len());
        for (i, area) in memset_for_new_pcb.iter().enumerate() {
            warn!("COW_FORK: Copied Area {}: start={:#x}, len={:#x}, mtype={:?}, has_file={}, mtrackers={}",
                i, area.start, area.len, area.mtype, area.file.is_some(), area.mtrackers.len());
        }
        
        // 复制到子进程
        {
            let mut new_pcb = new_task.pcb.lock();
            new_pcb.fd_table.0 = fd_table_clone;
            new_pcb.heap = heap;
            new_pcb.curr_dir = curr_dir_clone;
            new_pcb.shms = shms_clone.clone();
            
            // 使用第一份memset数据创建MemSet（无需clone）
            new_pcb.memset = memset::MemSet::new(memset_for_new_pcb);
            
            // 添加调试信息：确认子进程的memset
            warn!("COW_FORK: Child task_id={} memset created with {} areas", new_task.task_id, new_pcb.memset.len());
        }
        
        new_tcb_writer.cx = self.tcb.read().cx.clone();
        new_tcb_writer.cx[TrapFrameArgs::RET] = 0;
        drop(new_tcb_writer);

        // 使用第二份memset数据进行COW映射处理（无需clone）
        memset_for_cow.iter().for_each(|area| {
            area.mtrackers.iter().for_each(|mtracker| {
                new_task.map(mtracker.tracker.0, mtracker.vaddr, MappingFlags::URX);
                self.map(mtracker.tracker.0, mtracker.vaddr, MappingFlags::URX);
            });
        });
        
        // 处理共享内存
        memset_for_cow.iter().for_each(|x| {
            if let Some(shm) = shms_clone.iter().find(|shm| shm.start <= x.start && x.start < shm.start + shm.size) {
                shm.mem.trackers.iter().enumerate().for_each(|(i, tracker)| {
                    new_task.map(tracker.0, va!(shm.start + i * PAGE_SIZE), MappingFlags::URWX);
                });
            }
        });
        
        warn!("COW_FORK: Completed for child task_id={}", new_task.task_id);
        new_task
    }

    #[inline]
    pub fn thread_clone(self: Arc<Self>) -> Arc<Self> {
        let parent_tcb = self.tcb.read();
        let task_id = task_id_alloc();
        
        let tcb = RwLock::new(ThreadControlBlock {
            cx: parent_tcb.cx.clone(),
            sigmask: parent_tcb.sigmask.clone(),
            clear_child_tid: 0,
            set_child_tid: 0,
            signal: SignalList::new(),
            signal_queue: [0; REAL_TIME_SIGNAL_NUM],
            exit_signal: 0,
            thread_exit_code: Option::None,
            robust_list_head: 0,            // 新线程不继承父线程的 robust list
            robust_list_len: 0,             // 新线程不继承父线程的 robust list
        });

        tcb.write().cx[TrapFrameArgs::RET] = 0;
        drop(parent_tcb);

        let new_task = Arc::new(Self {
            page_table: self.page_table.clone(),
            task_id,
            process_id: self.process_id,  // 重要：保持相同的process_id
            parent: RwLock::new(self.parent.read().clone()),
            pcb: self.pcb.clone(),       // 重要：共享PCB
            tcb,
        });

        // 维护线程列表
        {
            let mut pcb = self.pcb.lock();
            // 清理死亡的线程引用
            pcb.threads.retain(|weak_ref| weak_ref.strong_count() > 0);
            // 添加新线程
            pcb.threads.push(Arc::downgrade(&new_task));
            
            warn!("Thread created: task_id={}, process_id={}, total_active_threads={}", 
                new_task.task_id, new_task.process_id, pcb.threads.len());
        }

        new_task
    }

    pub fn push_str(&self, str: &str) -> usize {
        self.push_arr(str.as_bytes())
    }

    pub fn push_arr(&self, buffer: &[u8]) -> usize {
        let mut tcb = self.tcb.write();

        const ULEN: usize = size_of::<usize>();
        let len = buffer.len();
        let sp = tcb.cx[TrapFrameArgs::SP] - alignup(len + 1, ULEN);
        VirtAddr::from(sp)
            .slice_mut_with_len(len)
            .copy_from_slice(buffer);
        tcb.cx[TrapFrameArgs::SP] = sp;
        sp
    }

    pub fn push_num(&self, num: usize) -> usize {
        let mut tcb = self.tcb.write();

        const ULEN: usize = size_of::<usize>();
        let sp = tcb.cx[TrapFrameArgs::SP] - ULEN;

        *VirtAddr::from(sp).get_mut_ref() = num;
        tcb.cx[TrapFrameArgs::SP] = sp;
        sp
    }

    pub fn get_last_free_addr(&self) -> VirtAddr {
        let map_last = self
            .pcb
            .lock()
            .memset
            .iter()
            .filter(|x| x.mtype != MemType::Stack)
            .fold(0, |acc, x| max(acc, x.start + x.len));
        let shm_last = self
            .pcb
            .lock()
            .shms
            .iter()
            .fold(0, |acc, v| max(v.start + v.size, acc));
        VirtAddr::new(max(map_last, shm_last))
    }

    pub fn get_fd(&self, index: usize) -> Option<Arc<File>> {
        let pcb = self.pcb.lock();
        match index >= pcb.rlimits[7] {
            true => None,
            false => pcb.fd_table.0[index].clone(),
        }
    }

    pub fn set_fd(&self, index: usize, value: Arc<File>) {
        let mut pcb = self.pcb.lock();
        match index >= pcb.rlimits[7] {
            true => {}
            false => pcb.fd_table.0[index] = Some(value),
        }
    }

    pub fn clear_fd(&self, index: usize) {
        let mut pcb = self.pcb.lock();
        match index >= pcb.fd_table.len() {
            true => {}
            false => pcb.fd_table.0[index] = None,
        }
    }

    pub fn alloc_fd(&self) -> Option<usize> {
        let mut pcb = self.pcb.lock();
        let index = pcb
            .fd_table
            .0
            .iter()
            .enumerate()
            .find(|(i, x)| x.is_none() && *i < pcb.rlimits[7])
            .map(|(i, _)| i);
        if index.is_none() && pcb.fd_table.0.len() < pcb.rlimits[7] {
            pcb.fd_table.0.push(None);
            Some(pcb.fd_table.0.len() - 1)
        } else {
            index
        }
    }

    pub fn fd_open(&self, fd: isize, filename: &str, flags: OpenFlags) -> VfsResult<File> {
        let path = self.fd_resolve(fd, filename)?;
        File::open(path, flags)
    }

    #[inline]
    pub fn fd_resolve(&self, fd: isize, filename: &str) -> VfsResult<PathBuf> {
        if filename.starts_with("/") {
            Ok(filename.into())
        } else {
            let parent = match fd {
                AT_CWD => self.pcb.lock().curr_dir.clone(),
                _ => self
                    .pcb
                    .lock()
                    .fd_table
                    .get(fd as usize)
                    .cloned()
                    .flatten()
                    .ok_or(Errno::EBADF)?,
            };
            Ok(parent.path_buf().join(filename))
        }
    }

    pub fn get_elf_segment_for_addr(&self, vaddr: VirtAddr) -> Option<(Arc<dyn INodeInterface>, usize, usize)> {  
        let pcb = self.pcb.lock();  
        
        warn!("get_elf_segment_for_addr: task_id={}, process_id={}, searching for vaddr={:#x}", 
            self.task_id, self.process_id, vaddr.raw());
        warn!("Total memory areas: {}", pcb.memset.len());
        
        // 查找包含该地址且有文件引用的内存区域  
        for (i, area) in pcb.memset.iter().enumerate() {  
            warn!("  Area {}: start={:#x}, end={:#x}, len={:#x}, mtype={:?}, has_file={}, contains={}", 
                i, area.start, area.start + area.len, area.len, area.mtype, area.file.is_some(), area.contains(vaddr.raw()));
                
            if area.contains(vaddr.raw()) && area.file.is_some() {  
                let file = area.file.as_ref().unwrap();  
                
                // 改进偏移计算
                let page_aligned_vaddr = vaddr.floor().raw();
                let file_offset = area.offset + (page_aligned_vaddr - area.start);
                
                warn!("get_elf_segment_for_addr: FOUND! vaddr={:#x}, area_start={:#x}, area_offset={:#x}, calculated_offset={:#x}", 
                    vaddr.raw(), area.start, area.offset, file_offset);
                
                return Some((file.clone(), file_offset, area.len));  
            }  
        }  
        
        warn!("get_elf_segment_for_addr: NOT FOUND for vaddr={:#x}", vaddr.raw());
        None  
    }
}

impl AsyncTask for UserTask {
    fn before_run(&self) {
        self.page_table.change();
    }

    fn get_task_id(&self) -> TaskId {
        self.task_id
    }

    fn get_task_type(&self) -> TaskType {
        TaskType::MonolithicTask
    }

    #[inline]
    fn exit(&self, exit_code: usize) {
        let tcb_writer = self.tcb.write();
        let uaddr = tcb_writer.clear_child_tid;
        if uaddr != 0 {
            debug!("write addr: {:#x}", uaddr);
            let addr = self
                .page_table
                .translate(VirtAddr::from(uaddr))
                .expect("can't find a valid addr")
                .0;
            unsafe {
                addr.get_mut_ptr::<u32>().write(0);
            }
            futex_wake(self.pcb.lock().futex_table.clone(), uaddr, 1);
        }
        
        let exit_signal = tcb_writer.exit_signal;
        drop(tcb_writer);

        // 改进的进程退出逻辑
        let should_cleanup_process = {
            let mut pcb = self.pcb.lock();
            
            pcb.exit_code = Some(exit_code);
            
            pcb.threads.retain(|weak_ref| {
                if let Some(thread) = weak_ref.upgrade() {
                    thread.task_id != self.task_id
                } else {
                    false
                }
            });
            
            let remaining_threads = pcb.threads.len();
            let is_main_thread = self.task_id == self.process_id;
            
            // 只有主线程退出且没有其他线程时才清理
            is_main_thread && remaining_threads == 0
        };

        if should_cleanup_process {
            warn!("Cleaning up process resources for process_id={}", self.process_id);
            let mut pcb = self.pcb.lock();
            pcb.memset.clear();
            pcb.fd_table.clear();
            pcb.children.clear();
            pcb.threads.clear();
        }

        // 通知父进程
        if let Some(parent) = self.parent.read().upgrade() {
            if exit_signal != 0 {
                parent
                    .tcb
                    .write()
                    .signal
                    .add_signal(SignalFlags::from_num(exit_signal as usize));
            } else {
                parent.tcb.write().signal.add_signal(SignalFlags::SIGCHLD);
            }
        } else {
            self.pcb.lock().children.clear();
        }
    }

    #[inline]
    fn exit_code(&self) -> Option<usize> {
        self.pcb.lock().exit_code
    }
}

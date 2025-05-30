use xmas_elf::ElfFile;
use super::UserTask;  
use crate::tasks::initproc::{get_libc_path, get_glibc_path}; // 添加get_glibc_path导入  
use crate::{  
    consts::USER_DYN_ADDR,  
    tasks::{  
        elf::{init_task_stack, ElfExtra},  
        MapTrack, MemArea, MemType,  
    },  
};  
use alloc::{  
    boxed::Box,  
    string::{String, ToString},  
    sync::Arc,  
    vec::Vec,  
};  
use async_recursion::async_recursion;  
use core::ops::{Add, Mul};  
use devices::{frame_alloc_much, FrameTracker, PAGE_SIZE};  
use fs::{file::File, pathbuf::PathBuf, OpenFlags};  
use polyhal::MappingFlags;  
use sync::Mutex;  
use syscalls::Errno;  
use xmas_elf::program::{SegmentData, Type};  
  
// 添加libc类型枚举  
#[derive(Debug, Clone, Copy)]  
enum LibcType {  
    Musl,  
    Glibc,  
    Unknown,  
}  
  
// 添加检测libc类型的函数  
fn detect_libc_type(elf: &xmas_elf::ElfFile) -> LibcType {  
    if let Some(header) = elf.program_iter().find(|ph| ph.get_type() == Ok(Type::Interp)) {  
        if let Ok(SegmentData::Undefined(data)) = header.get_data(&elf) {  
            if let Ok(interp_path) = core::str::from_utf8(data) {  
                let interp_path = interp_path.trim_end_matches('\0');  
                if interp_path.contains("musl") {  
                    return LibcType::Musl;  
                } else if interp_path.contains("glibc") || interp_path.contains("ld-linux") {  
                    return LibcType::Glibc;  
                }  
            }  
        }  
    }  
    LibcType::Unknown  
}  
  
pub struct TaskCacheTemplate {  
    name: PathBuf,  
    entry: usize,  
    maps: Vec<MemArea>,  
    base: usize,  
    heap_bottom: usize,  
    ph_count: usize,  
    ph_entry_size: usize,  
    ph_addr: usize,  
}  
  
pub static TASK_CACHES: Mutex<Vec<TaskCacheTemplate>> = Mutex::new(Vec::new());  
  
pub fn cache_task_template(path: PathBuf) -> Result<(), Errno> {  
    let file = File::open(path.clone(), OpenFlags::O_RDONLY)?;  
    let file_size = file.file_size()?;  
    let frame_paddr = frame_alloc_much(file_size.div_ceil(PAGE_SIZE));  
    let buffer = frame_paddr.as_ref().unwrap()[0].slice_mut_with_len(file_size);  
    let rsize = file.readat(0, buffer)?;  
    assert_eq!(rsize, file_size);  
      
    if let Ok(elf) = xmas_elf::ElfFile::new(&buffer) {  
        let elf_header = elf.header;  
        let entry_point = elf.header.pt2.entry_point() as usize;  
          
        assert_eq!(  
            elf_header.pt1.magic,  
            [0x7f, 0x45, 0x4c, 0x46],  
            "invalid elf!"  
        );  
  
        let header = elf  
            .program_iter()  
            .find(|ph| ph.get_type() == Ok(Type::Interp));  
  
        if let Some(_header) = header {  
            unimplemented!("can't cache dynamic file.");  
        }  
  
        let heap_bottom = elf  
            .program_iter()  
            .map(|x| (x.virtual_addr() + x.mem_size()) as usize)  
            .max()  
            .unwrap()  
            .div_ceil(PAGE_SIZE)  
            .mul(PAGE_SIZE);  
  
        let base = elf.relocate(USER_DYN_ADDR).unwrap_or(0);  
        let mut maps = Vec::new();  
  
        elf.program_iter()  
            .filter(|x| x.get_type().unwrap() == xmas_elf::program::Type::Load)  
            .for_each(|ph| {  
                let file_size = ph.file_size() as usize;  
                let mem_size = ph.mem_size() as usize;  
                let offset = ph.offset() as usize;  
                let virt_addr = base + ph.virtual_addr() as usize;  
                let vpn = virt_addr / PAGE_SIZE;  
  
                let page_count = (virt_addr + mem_size).div_ceil(PAGE_SIZE) - vpn;  
                let pages: Vec<Arc<FrameTracker>> = frame_alloc_much(page_count)  
                    .expect("can't alloc in cache task template")  
                    .into_iter()  
                    .map(|x| Arc::new(x))  
                    .collect();  
                let ppn_space = pages[0]  
                    .add(virt_addr % PAGE_SIZE)  
                    .slice_mut_with_len(file_size);  
  
                ppn_space.copy_from_slice(&buffer[offset..offset + file_size]);  
  
                maps.push(MemArea {  
                    mtype: MemType::CodeSection,  
                    mtrackers: pages  
                        .into_iter()  
                        .enumerate()  
                        .map(|(i, x)| MapTrack {  
                            vaddr: va!((vpn + i) * PAGE_SIZE),  
                            tracker: x,  
                            rwx: 0,  
                        })  
                        .collect(),  
                    file: None,  
                    offset: 0,  
                    start: vpn * PAGE_SIZE,  
                    len: page_count * PAGE_SIZE,  
                })  
            });  
        TASK_CACHES.lock().push(TaskCacheTemplate {  
            name: path,  
            entry: entry_point,  
            maps,  
            base,  
            heap_bottom,  
            ph_count: elf_header.pt2.ph_count() as _,  
            ph_entry_size: elf_header.pt2.ph_entry_size() as _,  
            ph_addr: elf.get_ph_addr().unwrap_or(0) as _,  
        });  
    }  
    Ok(())  
}  

pub fn validate_elf_segment_mapping(  
    user_task: &Arc<UserTask>,  
    elf: &ElfFile,  
    base: usize,  
) -> Result<(), &'static str> {  
    let pcb = user_task.pcb.lock();  
      
    // 检查所有LOAD段是否都有对应的内存区域  
    for ph in elf.program_iter().filter(|x| x.get_type().unwrap() == Type::Load) {  
        let virt_addr = base + ph.virtual_addr() as usize;  
        let mem_size = ph.mem_size() as usize;  
        let end_addr = virt_addr + mem_size;  
          
        // 检查是否存在覆盖该地址范围的内存区域  
        let found = pcb.memset.iter().any(|area| {  
            area.start <= virt_addr &&   
            area.start + area.len >= end_addr &&  
            area.file.is_some()  
        });  
          
        if !found {  
            warn!("Missing memory mapping for ELF segment: vaddr={:#x}, size={:#x}",   
                  virt_addr, mem_size);  
            return Err("Missing ELF segment mapping");  
        }  
          
        // 特别检查低地址区域 (0x10000 - 0x100000)  
        if virt_addr >= 0x10000 && virt_addr < 0x100000 {  
            info!("Low address ELF segment mapped: vaddr={:#x}, size={:#x}",   
                  virt_addr, mem_size);  
        }  
    }  
      
    Ok(())  
}

#[async_recursion(Sync)]  
pub async fn exec_with_process(  
    task: Arc<UserTask>,  
    curr_dir: PathBuf,  
    path: String,  
    args: Vec<String>,  
    envp: Vec<String>,  
) -> Result<Arc<UserTask>, Errno> {  
    let path = curr_dir.join(&path);  
  
    let user_task = task.clone();
    {
        let mut pcb = user_task.pcb.lock();
        
        // 标记所有其他线程为已退出，只保留当前线程
        pcb.threads.retain(|weak_thread| {
            if let Some(thread) = weak_thread.upgrade() {
                // 如果是当前线程，保留
                if thread.task_id == user_task.task_id {
                    true
                } else {
                    // 终止其他线程
                    false
                }
            } else {
                // 已经失效的线程引用，删除
                false
            }
        });
    }  
    user_task.pcb.lock().memset.clear();  
    user_task.page_table.restore();  
    user_task.page_table.change();  
  
    let caches = TASK_CACHES.lock();  
    if let Some(cache_task) = caches.iter().find(|x| x.name == path) {  
        init_task_stack(  
            user_task.clone(),  
            args,  
            cache_task.base,  
            &path.path(),  
            cache_task.entry,  
            cache_task.ph_count,  
            cache_task.ph_entry_size,  
            cache_task.ph_addr,  
            cache_task.heap_bottom,  
        );  
  
        for area in &cache_task.maps {  
            user_task.inner_map(|pcb| {  
                pcb.memset  
                    .sub_area(area.start, area.start + area.len, &user_task.page_table);  
                pcb.memset.push(area.clone());  
            });  
            for mtracker in area.mtrackers.iter() {  
                user_task.map(mtracker.tracker.0, mtracker.vaddr, MappingFlags::URX);  
            }  
        }  
        Ok(user_task)  
    } else {  
        drop(caches);  
          
        let file = File::open(path.clone(), OpenFlags::O_RDONLY)  
            .map(Arc::new)?  
            .clone();  
        let file_size = file.file_size()?;  
        let frame_ppn = frame_alloc_much(file_size.div_ceil(PAGE_SIZE));  
        let buffer = frame_ppn.as_ref().unwrap()[0].slice_mut_with_len(file_size);  
        let rsize = file.readat(0, buffer)?;  
        assert_eq!(rsize, file_size);  
          
        let elf = if let Ok(elf) = xmas_elf::ElfFile::new(&buffer) {  
            elf  
        } else {  
            let mut new_args = vec!["busybox".to_string(), "sh".to_string()];  
            args.iter().for_each(|x| new_args.push(x.clone()));  
            return exec_with_process(task, curr_dir, String::from("busybox"), new_args, envp)  
                .await;  
        };  
        let elf_header = elf.header;  
  
        let entry_point = elf.header.pt2.entry_point() as usize;  
        assert_eq!(  
            elf_header.pt1.magic,  
            [0x7f, 0x45, 0x4c, 0x46],  
            "invalid elf!"  
        );  
          
        let user_task = task.clone();  
  
        // 检查是否需要动态链接器，并根据libc类型选择相应的链接器  
        let header = elf  
            .program_iter()  
            .find(|ph| ph.get_type() == Ok(Type::Interp));  
        if let Some(header) = header {  
            if let Ok(SegmentData::Undefined(_data)) = header.get_data(&elf) {  
                drop(frame_ppn);  
                  
                // 根据检测到的libc类型选择相应的动态链接器  
                let libc_path = match detect_libc_type(&elf) {  
                    LibcType::Musl => get_libc_path(),  
                    LibcType::Glibc => get_glibc_path(),  
                    LibcType::Unknown => get_libc_path(), // 默认使用musl  
                };  
                  
                let mut new_args = vec![libc_path];  
                new_args.extend(args);  
                return exec_with_process(task, curr_dir, new_args[0].clone(), new_args, envp)  
                    .await;  
            }  
        }  
  
        let heap_bottom = elf  
            .program_iter()  
            .map(|x| (x.virtual_addr() + x.mem_size()) as usize)  
            .max()  
            .unwrap()  
            .div_ceil(PAGE_SIZE)  
            .mul(PAGE_SIZE);  
  
        let base = elf.relocate(USER_DYN_ADDR).unwrap_or(0);  
        init_task_stack(  
            user_task.clone(),  
            args,  
            base,  
            &path.path(),  
            entry_point,  
            elf_header.pt2.ph_count() as usize,  
            elf_header.pt2.ph_entry_size() as usize,  
            elf.get_ph_addr().unwrap_or(0) as usize,  
            heap_bottom,  
        );  

        fn elf_flags_to_mapping_flags(elf_flags: xmas_elf::program::Flags) -> MappingFlags {
            let mut flags = MappingFlags::U; // 用户可访问
            
            if elf_flags.is_read() {
                flags |= MappingFlags::R;
            }
            if elf_flags.is_write() {
                flags |= MappingFlags::W;
            }
            if elf_flags.is_execute() {
                flags |= MappingFlags::X;
            }
            
            // 确保至少有读权限
            if !flags.contains(MappingFlags::R) {
                flags |= MappingFlags::R;
            }
            
            flags
        }
  
        elf.program_iter()
            .filter(|x| x.get_type().unwrap() == xmas_elf::program::Type::Load)
            .for_each(|ph| {
                let file_size = ph.file_size() as usize;
                let mem_size = ph.mem_size() as usize;
                let offset = ph.offset() as usize;
                let virt_addr = base + ph.virtual_addr() as usize;
                let vpn = virt_addr / PAGE_SIZE;

                // 获取ELF段的权限并转换为页面权限
                let elf_flags = ph.flags();
                let mapping_flags = elf_flags_to_mapping_flags(elf_flags);

                let page_count = (virt_addr + mem_size).div_ceil(PAGE_SIZE) - vpn;
                
                let ppn_start = user_task.map_frames(
                    va!(virt_addr).floor(), 
                    MemType::CodeSection, 
                    page_count,
                    Some(file.get_bare_file()), 
                    offset,
                    virt_addr,
                    mem_size,
                    mapping_flags // 使用从ELF获取的权限
                );
                
                if let Some(ppn_start) = ppn_start {
                    // 将文件内容拷贝到内存中
                    let ppn_space: &mut [u8] = ppn_start
                        .add(virt_addr % PAGE_SIZE)
                        .slice_mut_with_len(file_size);

                    ppn_space.copy_from_slice(&buffer[offset..offset + file_size]);
                    
                    warn!("Loaded ELF segment: vaddr={:#x}, size={:#x}, file_offset={:#x}", 
                        virt_addr, mem_size, offset);
                } else {
                    panic!("Failed to allocate memory for ELF segment at {:#x}", virt_addr);
                }
            });

        info!("ELF loading completed. Memory areas:");  
        for (i, area) in user_task.pcb.lock().memset.iter().enumerate() {  
            info!("  Area {}: start={:#x}, len={:#x}, offset={:#x}, type={:?}, has_file={}",   
                  i, area.start, area.len, area.offset, area.mtype, area.file.is_some());  
        }

        if let Err(e) = validate_elf_segment_mapping(&user_task, &elf, base) {  
            warn!("ELF segment mapping validation failed: {}", e);  
            return Err(Errno::ENOEXEC);  
        }  
        Ok(user_task)  
    }  
}
#![no_std]
#![feature(extract_if)]
#[macro_use]
extern crate alloc;

use alloc::{string::String, sync::Arc, vec::Vec};
use core::cmp::{self, min};
use core::ops::Add;
use polyhal::pagetable::PAGE_SIZE;
use runtime::frame::{frame_alloc, FrameTracker, get_free_pages};
use sync::Mutex;
use syscalls::Errno;
use vfscore::{
    DirEntry, FileSystem, FileType, INodeInterface, Stat, StatMode, TimeSpec, VfsResult, UTIME_OMIT,
};

pub struct RamFs {
    root: Arc<RamDirInner>,
}

impl RamFs {
    pub fn new() -> Arc<Self> {
        let inner = Arc::new(RamDirInner {
            name: String::from(""),
            children: Mutex::new(Vec::new()),
        });
        Arc::new(Self { root: inner })
    }
}

impl FileSystem for RamFs {
    fn root_dir(&self) -> Arc<dyn INodeInterface> {
        Arc::new(RamDir {
            inner: self.root.clone(),
        })
    }

    fn name(&self) -> &str {
        "ramfs"
    }
}

pub struct RamDirInner {
    name: String,
    children: Mutex<Vec<FileContainer>>,
}

// TODO: use frame insteads of Vec.
pub struct RamFileInner {
    name: String,
    // content: Mutex<Vec<u8>>,
    len: Mutex<usize>,
    pages: Mutex<Vec<FrameTracker>>,
    times: Mutex<[TimeSpec; 3]>, // ctime, atime, mtime.
}

#[allow(dead_code)]
pub struct RamLinkInner {
    name: String,
    link_file: Arc<dyn INodeInterface>,
}

pub enum FileContainer {
    File(Arc<RamFileInner>),
    Dir(Arc<RamDirInner>),
    Link(Arc<RamLinkInner>),
}

impl FileContainer {
    #[inline]
    fn to_inode(&self) -> VfsResult<Arc<dyn INodeInterface>> {
        match self {
            FileContainer::File(file) => Ok(Arc::new(RamFile {
                inner: file.clone(),
            })),
            FileContainer::Dir(dir) => Ok(Arc::new(RamDir { inner: dir.clone() })),
            FileContainer::Link(link) => Ok(Arc::new(RamLink {
                inner: link.clone(),
                link_file: link.link_file.clone(),
            })),
        }
    }

    #[inline]
    fn filename(&self) -> &str {
        match self {
            FileContainer::File(file) => &file.name,
            FileContainer::Dir(dir) => &dir.name,
            FileContainer::Link(link) => &link.name,
        }
    }
}

#[allow(dead_code)]
pub struct RamLink {
    inner: Arc<RamLinkInner>,
    link_file: Arc<dyn INodeInterface>,
}

pub struct RamDir {
    inner: Arc<RamDirInner>,
}

impl RamDir {
    pub const fn new(inner: Arc<RamDirInner>) -> Self {
        Self { inner }
    }
}

impl INodeInterface for RamDir {
    fn mkdir(&self, name: &str) -> VfsResult<()> {
        // Find file, return VfsError::AlreadyExists if file exists
        self.inner
            .children
            .lock()
            .iter()
            .find(|x| x.filename() == name)
            .map_or(Ok(()), |_| Err(Errno::EEXIST))?;

        let new_inner = Arc::new(RamDirInner {
            name: String::from(name),
            children: Mutex::new(Vec::new()),
        });

        self.inner
            .children
            .lock()
            .push(FileContainer::Dir(new_inner));

        Ok(())
    }

    fn lookup(&self, name: &str) -> VfsResult<Arc<dyn INodeInterface>> {
        self.inner
            .children
            .lock()
            .iter()
            .find(|x| x.filename() == name)
            .map(|x| x.to_inode())
            .ok_or(Errno::ENOENT)?
    }

    fn create(&self, name: &str, ty: FileType) -> VfsResult<()> {
        if ty == FileType::Directory {
            let new_inner = Arc::new(RamDirInner {
                name: String::from(name),
                children: Mutex::new(Vec::new()),
            });
            self.inner
                .children
                .lock()
                .push(FileContainer::Dir(new_inner.clone()));
            Ok(())
        } else if ty == FileType::File {
            let new_inner = Arc::new(RamFileInner {
                name: String::from(name),
                // content: Mutex::new(Vec::new()),
                times: Mutex::new([Default::default(); 3]),
                len: Mutex::new(0),
                pages: Mutex::new(vec![]),
            });
            self.inner
                .children
                .lock()
                .push(FileContainer::File(new_inner.clone()));
            Ok(())
        } else {
            unimplemented!("")
        }
    }

    fn rmdir(&self, name: &str) -> VfsResult<()> {
        // TODO: identify whether the dir is empty(through metadata.childrens)
        // return DirectoryNotEmpty if not empty.
        let len = self
            .inner
            .children
            .lock()
            .extract_if(|x| match x {
                FileContainer::Dir(x) => x.name == name,
                _ => false,
            })
            .count();
        match len > 0 {
            true => Ok(()),
            false => Err(Errno::ENOENT),
        }
    }

    fn read_dir(&self) -> VfsResult<Vec<DirEntry>> {
        Ok(self
            .inner
            .children
            .lock()
            .iter()
            .map(|x| match x {
                FileContainer::File(file) => DirEntry {
                    filename: file.name.clone(),
                    // len: file.content.lock().len(),
                    len: *file.len.lock(),
                    file_type: FileType::File,
                },
                FileContainer::Dir(dir) => DirEntry {
                    filename: dir.name.clone(),
                    len: 0,
                    file_type: FileType::Directory,
                },
                FileContainer::Link(link) => DirEntry {
                    filename: link.name.clone(),
                    len: 0,
                    file_type: FileType::Link,
                },
            })
            .collect())
    }

    fn remove(&self, name: &str) -> VfsResult<()> {
        let len = self
            .inner
            .children
            .lock()
            .extract_if(|x| match x {
                FileContainer::File(x) => x.name == name,
                FileContainer::Dir(_) => false,
                FileContainer::Link(x) => x.name == name,
            })
            .count();
        match len > 0 {
            true => Ok(()),
            false => Err(Errno::ENOENT),
        }
    }

    fn unlink(&self, name: &str) -> VfsResult<()> {
        self.remove(name)
    }

    fn stat(&self, stat: &mut Stat) -> VfsResult<()> {
        stat.ino = 1; // TODO: convert path to number(ino)
        stat.mode = StatMode::DIR; // TODO: add access mode
        stat.nlink = 1;
        stat.uid = 0;
        stat.gid = 0;
        stat.size = 0;
        stat.blksize = 512;
        stat.blocks = 0;
        stat.rdev = 0; // TODO: add device id
        stat.mtime = Default::default();
        stat.atime = Default::default();
        stat.ctime = Default::default();
        Ok(())
    }

    fn link(&self, name: &str, src: Arc<dyn INodeInterface>) -> VfsResult<()> {
        // Find file, return VfsError::AlreadyExists if file exists
        self.inner
            .children
            .lock()
            .iter()
            .find(|x| x.filename() == name)
            .map_or(Ok(()), |_| Err(Errno::EEXIST))?;

        let new_inner = Arc::new(RamLinkInner {
            name: String::from(name),
            link_file: src,
        });

        self.inner
            .children
            .lock()
            .push(FileContainer::Link(new_inner));

        Ok(())
    }
}

pub struct RamFile {
    inner: Arc<RamFileInner>,
}

impl RamFile {
    pub const fn new(inner: Arc<RamFileInner>) -> Self {
        Self { inner }
    }
}

impl INodeInterface for RamFile {
    fn readat(&self, mut offset: usize, buffer: &mut [u8]) -> VfsResult<usize> {
        let mut buffer_off = 0;
        // let file_size = self.inner.content.lock().len();
        log::debug!("read ramfs: offset: {} len: {}", offset, buffer.len());
        let file_size = *self.inner.len.lock();
        let inner = self.inner.pages.lock();
        match offset >= file_size {
            true => Ok(0),
            false => {
                // let origin_read_len = min(buffer.len(), file_size - offset);
                // let read_len = if offset >= real_size {
                //     min(origin_read_len, real_size - offset)
                // } else {
                //     0
                // };
                let read_len = min(buffer.len(), file_size - offset);
                let mut last_len = read_len;
                // let content = self.inner.content.lock();
                // buffer[..read_len].copy_from_slice(&content[offset..(offset + read_len)]);
                loop {
                    let curr_size = cmp::min(PAGE_SIZE - offset % PAGE_SIZE, last_len);
                    if curr_size == 0 {
                        break;
                    }
                    let index = offset / PAGE_SIZE;
                    buffer[buffer_off..buffer_off + curr_size].copy_from_slice(
                        inner[index]
                            .0
                            .add(offset % PAGE_SIZE)
                            .slice_with_len(curr_size),
                    );
                    offset += curr_size;
                    last_len -= curr_size;
                    buffer_off += curr_size;
                }
                Ok(read_len)
            }
        }
    }

    fn writeat(&self, mut offset: usize, buffer: &[u8]) -> VfsResult<usize> {
        log::info!("write to ramfs: offset={}, buffer_len={}", offset, buffer.len());
        let mut buffer_off = 0;
        let pages = (offset + buffer.len()).div_ceil(PAGE_SIZE);

        let mut inner = self.inner.pages.lock();
        let current_pages = inner.len();
        let needed_pages = if pages > current_pages { pages - current_pages } else { 0 };
        
        log::info!("ramfs write: current_pages={}, total_needed={}, additional_needed={}", 
                   current_pages, pages, needed_pages);

        // 尝试逐个分配所需的页面，如果失败则尝试部分写入
        let mut allocated_pages = 0;
        for i in inner.len()..pages {
            match frame_alloc() {
                Some(frame) => {
                    inner.push(frame);
                    allocated_pages += 1;
                    log::debug!("ramfs: allocated page {}/{}", i + 1, pages);
                }
                None => {
                    // 获取当前系统内存状态
                    let free_pages = get_free_pages();
                    log::warn!("ramfs: failed to allocate frame for write operation");
                    log::warn!("  - requested pages: {}, current pages: {}", pages, inner.len());
                    log::warn!("  - additional pages needed: {}, allocated: {}, system free pages: {}", 
                              needed_pages, allocated_pages, free_pages);
                    log::warn!("  - file: {}, write offset: {}, buffer size: {}", self.inner.name, offset, buffer.len());
                    
                    // 如果我们已经分配了一些页面，尝试部分写入
                    if allocated_pages > 0 {
                        log::info!("ramfs: attempting partial write with {} allocated pages", allocated_pages);
                        break;
                    } else {
                        // 如果一个页面都分配不了，返回内存不足错误
                        return Err(Errno::ENOMEM);
                    }
                }
            }
        }

        // 计算实际可以写入的数据量
        let available_space = inner.len() * PAGE_SIZE;
        let max_writable = if offset < available_space {
            available_space - offset
        } else {
            0
        };
        let actual_write_size = core::cmp::min(buffer.len(), max_writable);
        
        if actual_write_size < buffer.len() {
            log::warn!("ramfs: partial write - requested {} bytes, can only write {} bytes", 
                      buffer.len(), actual_write_size);
        }

        // 执行实际的写入操作
        let mut wsize = actual_write_size;
        let mut write_offset = offset;
        loop {
            let curr_size = cmp::min(PAGE_SIZE - write_offset % PAGE_SIZE, wsize);
            if curr_size == 0 {
                break;
            }
            let index = write_offset / PAGE_SIZE;
            if index >= inner.len() {
                log::warn!("ramfs: write index {} exceeds available pages {}", index, inner.len());
                break;
            }
            
            inner[index]
                .0
                .add(write_offset % PAGE_SIZE)
                .slice_mut_with_len(curr_size)
                .copy_from_slice(&buffer[buffer_off..buffer_off + curr_size]);
            write_offset += curr_size;
            buffer_off += curr_size;
            wsize -= curr_size;
        }

        let file_size = *self.inner.len.lock();
        if write_offset > file_size {
            *self.inner.len.lock() = write_offset;
        }
        
        log::info!("ramfs write completed: final_file_size={}, pages_used={}, bytes_written={}", 
                  *self.inner.len.lock(), inner.len(), actual_write_size);
        
        // 返回实际写入的字节数
        Ok(actual_write_size)
    }

    fn truncate(&self, size: usize) -> VfsResult<()> {
        // self.inner.content.lock().drain(size..);
        *self.inner.len.lock() = size;

        log::info!("truncate ramfs:{} insize: {}", size, self.inner.len.lock());

        let mut page_cont = self.inner.pages.lock();
        let pages = page_cont.len();
        // TODO: Check this line.
        let target_pages = size.div_ceil(PAGE_SIZE);

        page_cont.iter().skip(target_pages).for_each(|x| x.clear());

        if size % PAGE_SIZE != 0 {
            let page = size / PAGE_SIZE;
            let offset = size % PAGE_SIZE;
            if let Some(page) = page_cont.get(page) {
                page.0.add(offset).clear_len(PAGE_SIZE - offset);
            }
        }

        for _ in pages..target_pages {
            match frame_alloc() {
                Some(frame) => page_cont.push(frame),
                None => {
                    log::error!("ramfs: failed to allocate frame for truncate operation, target pages: {}, current pages: {}", target_pages, pages);
                    return Err(Errno::ENOMEM);
                }
            }
        }

        Ok(())
    }

    fn stat(&self, stat: &mut Stat) -> VfsResult<()> {
        log::debug!("stat ramfs");
        // stat.ino = 1; // TODO: convert path to number(ino)
        if self.inner.name.ends_with(".s") {
            stat.ino = 2; // TODO: convert path to number(ino)
        } else {
            stat.ino = 1; // TODO: convert path to number(ino)
        }
        stat.mode = StatMode::FILE; // TODO: add access mode
        stat.nlink = 1;
        stat.uid = 0;
        stat.gid = 0;
        // stat.size = self.inner.content.lock().len() as u64;
        stat.size = *self.inner.len.lock() as u64;
        stat.blksize = 512;
        stat.blocks = 0;
        stat.rdev = 0; // TODO: add device id

        stat.atime = self.inner.times.lock()[1];
        stat.mtime = self.inner.times.lock()[2];
        Ok(())
    }

    fn utimes(&self, times: &mut [vfscore::TimeSpec]) -> VfsResult<()> {
        if times[0].nsec != UTIME_OMIT {
            self.inner.times.lock()[1] = times[0];
        }
        if times[1].nsec != UTIME_OMIT {
            self.inner.times.lock()[2] = times[1];
        }
        Ok(())
    }
}

impl INodeInterface for RamLink {
    fn stat(&self, stat: &mut Stat) -> VfsResult<()> {
        // self.link_file.stat(stat)
        stat.ino = self as *const RamLink as u64;
        stat.blksize = 4096;
        stat.blocks = 8;
        stat.size = 3;
        stat.uid = 0;
        stat.gid = 0;
        stat.mode = StatMode::LINK;
        Ok(())
    }

    fn readat(&self, offset: usize, buffer: &mut [u8]) -> VfsResult<usize> {
        self.link_file.readat(offset, buffer)
    }

    fn writeat(&self, offset: usize, buffer: &[u8]) -> VfsResult<usize> {
        self.link_file.writeat(offset, buffer)
    }

    fn truncate(&self, size: usize) -> VfsResult<()> {
        self.link_file.truncate(size)
    }
}

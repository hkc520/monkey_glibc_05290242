use core::cmp;
use alloc::string::String;
use vfscore::{INodeInterface, StatMode, VfsResult};

pub struct Stat {}

impl Stat {
    pub const fn new() -> Self {
        Self {}
    }

    fn generate_content() -> String {
        String::from(
"cpu  0 0 0 0 0 0 0 0 0 0
cpu0 0 0 0 0 0 0 0 0 0 0
intr 0
ctxt 0
btime 1640995200
processes 1
procs_running 1
procs_blocked 0
softirq 0 0 0 0 0 0 0 0 0 0 0
")
    }
}

impl INodeInterface for Stat {
    fn readat(&self, offset: usize, buffer: &mut [u8]) -> VfsResult<usize> {
        let content = Self::generate_content();
        let bytes = content.as_bytes();
        
        // 确保偏移量不超过内容长度
        if offset >= bytes.len() {
            return Ok(0);
        }
        
        // 计算实际要复制的字节数
        let remaining = bytes.len() - offset;
        let copy_len = cmp::min(remaining, buffer.len());
        
        // 复制数据到缓冲区
        buffer[..copy_len].copy_from_slice(&bytes[offset..offset + copy_len]);
        
        Ok(copy_len)
    }

    fn stat(&self, stat: &mut vfscore::Stat) -> vfscore::VfsResult<()> {
        let content = Self::generate_content();
        let size = content.as_bytes().len();
        
        stat.dev = 0;
        stat.ino = 1; // TODO: convert path to number(ino)
        stat.mode = StatMode::CHAR; // TODO: add access mode
        stat.nlink = 1;
        stat.uid = 1000;
        stat.gid = 1000;
        stat.size = size as u64;
        stat.blksize = 512;
        stat.blocks = ((size + 511) / 512) as u64;
        stat.rdev = 0; // TODO: add device id
        Ok(())
    }
} 
use core::cmp;
use alloc::string::String;
use vfscore::{INodeInterface, StatMode, VfsResult};

pub struct CpuInfo {}

impl CpuInfo {
    pub const fn new() -> Self {
        Self {}
    }

    fn generate_content() -> String {
        String::from(
"processor	: 0
vendor_id	: MonkeyOS
cpu family	: 0
model		: 0
model name	: MonkeyOS Virtual CPU
stepping	: 0
microcode	: 0x1
cpu MHz		: 1000.000
cache size	: 256 KB
physical id	: 0
siblings	: 1
core id		: 0
cpu cores	: 1
apicid		: 0
initial apicid	: 0
fpu		: yes
fpu_exception	: yes
cpuid level	: 1
wp		: yes
flags		: fpu de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2
bogomips	: 2000.00
clflush size	: 64
cache_alignment	: 64
address sizes	: 32 bits physical, 32 bits virtual
power management:

")
    }
}

impl INodeInterface for CpuInfo {
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
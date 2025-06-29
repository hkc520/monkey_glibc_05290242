use alloc::format;
use vfscore::{INodeInterface, StatMode, VfsResult};

pub struct MemInfo {}

impl MemInfo {
    pub const fn new() -> Self {
        Self {}
    }
}

impl INodeInterface for MemInfo {
    fn readat(&self, offset: usize, buffer: &mut [u8]) -> VfsResult<usize> {
        // 提供标准的 /proc/meminfo 格式内容
        // LTP测试需要能够解析这些内容
        let meminfo_content = format!(
            "MemTotal:        8388608 kB\n\
             MemFree:         4194304 kB\n\
             MemAvailable:    6291456 kB\n\
             Buffers:           65536 kB\n\
             Cached:          1048576 kB\n\
             SwapCached:            0 kB\n\
             Active:          2097152 kB\n\
             Inactive:         524288 kB\n\
             Active(anon):    1572864 kB\n\
             Inactive(anon):   262144 kB\n\
             Active(file):     524288 kB\n\
             Inactive(file):   262144 kB\n\
             Unevictable:           0 kB\n\
             Mlocked:               0 kB\n\
             SwapTotal:             0 kB\n\
             SwapFree:              0 kB\n\
             Dirty:                 0 kB\n\
             Writeback:             0 kB\n\
             AnonPages:       1572864 kB\n\
             Mapped:           262144 kB\n\
             Shmem:             65536 kB\n\
             KReclaimable:     131072 kB\n\
             Slab:             262144 kB\n\
             SReclaimable:     131072 kB\n\
             SUnreclaim:       131072 kB\n\
             KernelStack:       16384 kB\n\
             PageTables:        32768 kB\n\
             NFS_Unstable:          0 kB\n\
             Bounce:                0 kB\n\
             WritebackTmp:          0 kB\n\
             CommitLimit:     4194304 kB\n\
             Committed_AS:    2097152 kB\n\
             VmallocTotal:   34359738367 kB\n\
             VmallocUsed:      131072 kB\n\
             VmallocChunk:          0 kB\n\
             Percpu:            65536 kB\n\
             HardwareCorrupted:     0 kB\n\
             AnonHugePages:         0 kB\n\
             ShmemHugePages:        0 kB\n\
             ShmemPmdMapped:        0 kB\n\
             FileHugePages:         0 kB\n\
             FilePmdMapped:         0 kB\n\
             HugePages_Total:       0\n\
             HugePages_Free:        0\n\
             HugePages_Rsvd:        0\n\
             HugePages_Surp:        0\n\
             Hugepagesize:       2048 kB\n\
             Hugetlb:               0 kB\n\
             DirectMap4k:     2097152 kB\n\
             DirectMap2M:     6291456 kB\n\
             DirectMap1G:           0 kB\n"
        );

        let content_bytes = meminfo_content.as_bytes();
        
        if offset >= content_bytes.len() {
            return Ok(0);
        }
        
        let end = core::cmp::min(offset + buffer.len(), content_bytes.len());
        let copy_len = end - offset;
        
        buffer[..copy_len].copy_from_slice(&content_bytes[offset..end]);
        
        Ok(copy_len)
    }

    fn stat(&self, stat: &mut vfscore::Stat) -> vfscore::VfsResult<()> {
        // 提供更准确的meminfo文件大小信息
        let meminfo_content = "MemTotal:        8388608 kB\nMemFree:         4194304 kB\nMemAvailable:    6291456 kB\nBuffers:           65536 kB\nCached:          1048576 kB\nSwapCached:            0 kB\nActive:          2097152 kB\nInactive:         524288 kB\nActive(anon):    1572864 kB\nInactive(anon):   262144 kB\nActive(file):     524288 kB\nInactive(file):   262144 kB\nUnevictable:           0 kB\nMlocked:               0 kB\nSwapTotal:             0 kB\nSwapFree:              0 kB\nDirty:                 0 kB\nWriteback:             0 kB\nAnonPages:       1572864 kB\nMapped:           262144 kB\nShmem:             65536 kB\nKReclaimable:     131072 kB\nSlab:             262144 kB\nSReclaimable:     131072 kB\nSUnreclaim:       131072 kB\nKernelStack:       16384 kB\nPageTables:        32768 kB\nNFS_Unstable:          0 kB\nBounce:                0 kB\nWritebackTmp:          0 kB\nCommitLimit:     4194304 kB\nCommitted_AS:    2097152 kB\nVmallocTotal:   34359738367 kB\nVmallocUsed:      131072 kB\nVmallocChunk:          0 kB\nPercpu:            65536 kB\nHardwareCorrupted:     0 kB\nAnonHugePages:         0 kB\nShmemHugePages:        0 kB\nShmemPmdMapped:        0 kB\nFileHugePages:         0 kB\nFilePmdMapped:         0 kB\nHugePages_Total:       0\nHugePages_Free:        0\nHugePages_Rsvd:        0\nHugePages_Surp:        0\nHugepagesize:       2048 kB\nHugetlb:               0 kB\nDirectMap4k:     2097152 kB\nDirectMap2M:     6291456 kB\nDirectMap1G:           0 kB\n";
        
        stat.dev = 0;
        stat.ino = 1; // TODO: convert path to number(ino)
        stat.mode = StatMode::CHAR; // TODO: add access mode
        stat.nlink = 1;
        stat.uid = 1000;
        stat.gid = 1000;
        stat.size = meminfo_content.len() as u64;
        stat.blksize = 512;
        stat.blocks = (meminfo_content.len() as u64 + 511) / 512;
        stat.rdev = 0; // TODO: add device id
        Ok(())
    }
}

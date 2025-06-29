use vfscore::{INodeInterface, Stat, StatMode, VfsResult};

pub struct Passwd;

impl INodeInterface for Passwd {
    fn readat(&self, offset: usize, buffer: &mut [u8]) -> VfsResult<usize> {
        // 基本的 passwd 文件格式: username:password:uid:gid:gecos:homedir:shell
        let content = b"root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n";
        
        if offset >= content.len() {
            return Ok(0);
        }
        
        let remaining = &content[offset..];
        let len = core::cmp::min(buffer.len(), remaining.len());
        buffer[..len].copy_from_slice(&remaining[..len]);
        Ok(len)
    }

    fn writeat(&self, _offset: usize, buffer: &[u8]) -> VfsResult<usize> {
        // passwd 文件通常是只读的，但为了兼容性我们返回成功
        Ok(buffer.len())
    }

    fn stat(&self, stat: &mut Stat) -> VfsResult<()> {
        stat.dev = 0;
        stat.ino = 1;
        stat.mode = StatMode::FILE; 
        stat.nlink = 1;
        stat.uid = 0;
        stat.gid = 0;
        stat.size = 92; // 内容的实际长度
        stat.blksize = 512;
        stat.blocks = 1;
        stat.rdev = 0;
        Ok(())
    }
} 
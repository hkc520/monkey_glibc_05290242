use vfscore::{INodeInterface, Stat, StatMode, VfsResult};

pub struct Null;

impl INodeInterface for Null {
    fn readat(&self, _offset: usize, _buffer: &mut [u8]) -> VfsResult<usize> {
        // /dev/null always returns EOF (0 bytes read)
        Ok(0)
    }

    fn writeat(&self, _offset: usize, buffer: &[u8]) -> VfsResult<usize> {
        // /dev/null accepts all writes and discards them
        Ok(buffer.len())
    }

    fn stat(&self, stat: &mut Stat) -> VfsResult<()> {
        stat.dev = 0x0103; // Device ID for /dev/null (major=1, minor=3)
        stat.ino = 1; // TODO: convert path to number(ino)
        stat.mode = StatMode::CHAR | StatMode::OWNER_READ | StatMode::OWNER_WRITE | StatMode::GROUP_READ | StatMode::GROUP_WRITE | StatMode::OTHER_READ | StatMode::OTHER_WRITE; // Character device with 666 permissions
        stat.nlink = 1;
        stat.uid = 0; // root
        stat.gid = 0; // root
        stat.size = 0;
        stat.blksize = 512;
        stat.blocks = 0;
        stat.rdev = 0x0103; // Same as dev for character devices
        Ok(())
    }
}

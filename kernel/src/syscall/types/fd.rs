use num_derive::FromPrimitive;

pub const AT_CWD: isize = -100;

#[repr(u32)]
#[derive(Debug, Clone, PartialEq, FromPrimitive)]
pub enum FcntlCmd {
    /// dup
    DUPFD = 0,
    /// get close_on_exec
    GETFD = 1,
    /// set/clear close_on_exec
    SETFD = 2,
    /// get file->f_flags
    GETFL = 3,
    /// set file->f_flags
    SETFL = 4,
    /// Get record locking info.
    GETLK = 5,
    /// Set record locking info (non-blocking).
    SETLK = 6,
    /// Set record locking info (blocking).
    SETLKW = 7,
    /// like F_DUPFD, but additionally set the close-on-exec flag
    DUPFDCLOEXEC = 0x406,
}

#[derive(Debug, FromPrimitive)]
#[repr(usize)]
pub enum FutexFlags {
    Wait = 0,
    Wake = 1,
    Fd = 2,
    Requeue = 3,
    CmpRequeue = 4,
    WakeOp = 5,
    LockPi = 6,
    UnlockPi = 7,
    TrylockPi = 8,
    WaitBitset = 9,
}

#[repr(C)]
#[derive(Clone)]
pub struct IoVec {
    pub base: usize,
    pub len: usize,
}

// 为glibc测试定义的kstat结构体 - 符合LoongArch LP64数据模型
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct KStat {
    pub st_dev: u64,         // dev_t
    pub st_ino: u64,         // ino_t
    pub st_mode: u32,        // mode_t
    pub st_nlink: u32,       // nlink_t
    pub st_uid: u32,         // uid_t
    pub st_gid: u32,         // gid_t
    pub st_rdev: u64,        // dev_t
    pub __pad: u64,          // unsigned long (64-bit on LoongArch)
    pub st_size: u64,        // off_t (64-bit)
    pub st_blksize: u32,     // blksize_t
    pub __pad2: u32,         // int
    pub st_blocks: u64,      // blkcnt_t (64-bit)
    pub st_atime_sec: i64,   // long (64-bit on LoongArch)
    pub st_atime_nsec: i64,  // long (64-bit on LoongArch)
    pub st_mtime_sec: i64,   // long
    pub st_mtime_nsec: i64,  // long
    pub st_ctime_sec: i64,   // long
    pub st_ctime_nsec: i64,  // long
    pub __unused: [u32; 2],  // unsigned __unused[2]
}
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



// statx 系统调用相关的常量定义
pub const AT_STATX_SYNC_TYPE: u32 = 0x6000;
pub const AT_STATX_SYNC_AS_STAT: u32 = 0x0000;
pub const AT_STATX_FORCE_SYNC: u32 = 0x2000;
pub const AT_STATX_DONT_SYNC: u32 = 0x4000;

// statx mask 标志
pub const STATX_TYPE: u32 = 0x00000001;
pub const STATX_MODE: u32 = 0x00000002;
pub const STATX_NLINK: u32 = 0x00000004;
pub const STATX_UID: u32 = 0x00000008;
pub const STATX_GID: u32 = 0x00000010;
pub const STATX_ATIME: u32 = 0x00000020;
pub const STATX_MTIME: u32 = 0x00000040;
pub const STATX_CTIME: u32 = 0x00000080;
pub const STATX_INO: u32 = 0x00000100;
pub const STATX_SIZE: u32 = 0x00000200;
pub const STATX_BLOCKS: u32 = 0x00000400;
pub const STATX_BASIC_STATS: u32 = 0x000007ff;
pub const STATX_BTIME: u32 = 0x00000800;
pub const STATX_ALL: u32 = 0x00000fff;

// statx 时间戳结构体
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct StatxTimestamp {
    pub tv_sec: i64,    // 秒
    pub tv_nsec: u32,   // 纳秒
    pub __reserved: u32, // 保留字段
}

// statx 结构体 - 根据 Linux statx(2) 手册页定义
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct Statx {
    pub stx_mask: u32,           // 掩码，指示哪些字段有效
    pub stx_blksize: u32,        // 块大小
    pub stx_attributes: u64,     // 额外的文件属性
    pub stx_nlink: u32,          // 硬链接数
    pub stx_uid: u32,            // 用户ID
    pub stx_gid: u32,            // 组ID
    pub stx_mode: u16,           // 文件类型和权限
    pub __spare0: [u16; 1],      // 保留字段
    pub stx_ino: u64,            // inode 号
    pub stx_size: u64,           // 文件大小
    pub stx_blocks: u64,         // 512字节块的数量
    pub stx_attributes_mask: u64, // 支持的属性掩码
    pub stx_atime: StatxTimestamp, // 最后访问时间
    pub stx_btime: StatxTimestamp, // 创建时间
    pub stx_ctime: StatxTimestamp, // 最后状态更改时间
    pub stx_mtime: StatxTimestamp, // 最后修改时间
    pub stx_rdev_major: u32,     // 设备主设备号
    pub stx_rdev_minor: u32,     // 设备次设备号
    pub stx_dev_major: u32,      // 文件系统主设备号
    pub stx_dev_minor: u32,      // 文件系统次设备号
    pub __spare2: [u64; 14],     // 保留字段，为将来扩展
}
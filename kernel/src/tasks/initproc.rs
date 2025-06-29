#![allow(dead_code)]
#![allow(unused_imports)]
use crate::tasks::current_user_task;

extern crate alloc;

use alloc::sync::Arc;

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use devices::utils::get_char;
use executor::{current_task, release_task, task::TaskType, tid2task, yield_now, TASK_MAP};
use fs::{file::File, FileType, OpenFlags};
use log::debug;
use polyhal::{debug_console::DebugConsole, instruction::shutdown};
use vfscore::INodeInterface;

use crate::tasks::add_user_task;
use executor::AsyncTask;
use sync::Mutex;

use crate::tasks::exec_with_process;
use crate::user::entry::user_entry;
use alloc::sync::Weak;
use executor::thread;
use fs::pathbuf::PathBuf;

use super::UserTask;

/*Add：全局配置libc.so的路径 */
static LIBC_PATH: Mutex<String> = Mutex::new(String::new());
static GLIBC_PATH: Mutex<String> = Mutex::new(String::new());
static DYN_PATH: Mutex<String> = Mutex::new(String::new());

pub fn set_libc_path(path: String) {
    *LIBC_PATH.lock() = path;
}

pub fn get_libc_path() -> String {
    LIBC_PATH.lock().clone()
}

pub fn set_glibc_path(path: String) {
    *GLIBC_PATH.lock() = path;
}

pub fn get_glibc_path() -> String {
    GLIBC_PATH.lock().clone()
}

pub fn set_dyn_path(path: String) {
    *DYN_PATH.lock() = path;
}

pub fn get_dyn_path() -> String {
    DYN_PATH.lock().clone()
}

fn clear() {
    DebugConsole::putchar(0x1b);
    DebugConsole::putchar(0x5b);
    DebugConsole::putchar(0x48);
    DebugConsole::putchar(0x1b);
    DebugConsole::putchar(0x5b);
    DebugConsole::putchar(0x32);
    DebugConsole::putchar(0x4a);
}

async fn kill_all_tasks() {
    TASK_MAP.lock().values().into_iter().for_each(|task| {
        task.upgrade().inspect(|x| {
            if x.get_task_type() == TaskType::MonolithicTask {
                x.exit(100)
            }
        });
    });
}

/*async fn command(cmd: &str) {
    let mut args: Vec<&str> = cmd.split(" ").filter(|x| *x != "").collect();
    debug!("cmd: {}  args: {:?}", cmd, args);
    let filename = args.drain(..1).last().unwrap();
    match File::open(filename.into(), OpenFlags::O_RDONLY) {
        Ok(_) => {
            info!("exec: {}", filename);
            let mut args_extend = vec![filename];
            args_extend.extend(args.into_iter());
            let task_id = add_user_task(&filename, args_extend, Vec::new()).await;
            let task = tid2task(task_id).unwrap();
            loop {
                if task.exit_code().is_some() {
                    release_task(task_id);
                    break;
                }
                yield_now().await;
            }
            // syscall(SYS_WAIT4, [0,0,0,0,0,0,0])
            //     .await
            //     .expect("can't wait a pid");
        }
        Err(_) => {
            println!("unknown command: {}", cmd);
        }
    }
}*/
async fn command(cmd: &str, work_dir: PathBuf) {
    // 改进的参数解析，支持引号
    let mut args = Vec::new();
    let mut current_arg = String::new();
    let mut in_quotes = false;
    let mut escape_next = false;

    for ch in cmd.chars() {
        if escape_next {
            current_arg.push(ch);
            escape_next = false;
        } else if ch == '\\' {
            escape_next = true;
        } else if ch == '\'' || ch == '"' {
            in_quotes = !in_quotes;
        } else if ch == ' ' && !in_quotes {
            if !current_arg.is_empty() {
                args.push(current_arg.clone());
                current_arg.clear();
            }
        } else {
            current_arg.push(ch);
        }
    }

    // 添加最后一个参数
    if !current_arg.is_empty() {
        args.push(current_arg);
    }

    // 转换为字符串切片
    let args_str: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    debug!("cmd: {}  args: {:?}", cmd, args_str);

    if args_str.is_empty() {
        println!("empty command");
        return;
    }

    let filename = &args_str[0];
    let remaining_args = &args_str[1..];
    match File::open((*filename).into(), OpenFlags::O_RDONLY) {
        Ok(_) => {
            info!("exec: {}", filename);
            let mut args_extend = vec![*filename];
            args_extend.extend(remaining_args.iter().copied());
            // 在这里克隆 work_dir，以便后续使用
            let work_dir_clone = work_dir.clone();
            // Use custom working directory to create task
            let curr_task = current_task();
            let task = UserTask::new(Weak::new(), work_dir);
            task.before_run();
            match exec_with_process(
                task.clone(),
                work_dir_clone, // 使用传入的工作目录，而不是空的PathBuf
                String::from(*filename),
                args_extend.into_iter().map(String::from).collect(),
                Vec::<&str>::new().into_iter().map(String::from).collect(),
            )
            .await
            {
                Ok(_) => {}
                Err(e) => {
                    println!("exec failed for {}: {:?}", filename, e);
                    return;
                }
            }
            curr_task.before_run();
            let task_id = task.get_task_id();
            thread::spawn(task.clone(), user_entry());

            let task = tid2task(task_id).unwrap();
            loop {
                if task.exit_code().is_some() {
                    release_task(task_id);
                    break;
                }
                yield_now().await;
            }

            // 额外等待确保进程完全清理
            for _ in 0..100000 {
                yield_now().await;
            }

            // 强制内存屏障确保状态一致性
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        }
        Err(_) => {
            println!("unknown command: {}", cmd);
        }
    }
}

/// 专门用于iperf测试的命令执行，包含额外的网络隔离和清理
async fn command_iperf(cmd: &str, work_dir: PathBuf) {
    log::warn!("Starting iperf test with enhanced isolation: {}", cmd);

    // 第一步：强制清理所有现有任务
    kill_all_tasks().await;

    // 第二步：内存屏障确保所有状态同步
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    for _ in 0..100000 {
        core::hint::spin_loop();
    }

    // 第三步：执行iperf测试
    command(cmd, work_dir.clone()).await;

    // 第四步：测试后强制清理
    kill_all_tasks().await;

    // 第五步：额外的清理等待
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    for _ in 0..200000 {
        core::hint::spin_loop();
    }

    log::warn!("Completed iperf test with enhanced isolation");
}

pub async fn initproc() {
    #[cfg(not(target_arch = "loongarch64"))]
    {
        set_libc_path("/musl/lib/libc.so".to_string());
        set_dyn_path("/musl/lib/libc.so".to_string());
        //set_dyn_path("/glibc/lib/ld-linux-riscv64-lp64d.so.1".to_string());

        // 创建必要的链接以支持busybox测试
        let home_dir = PathBuf::from("/musl/basic");
        command("/musl/busybox mkdir -p /bin", home_dir.clone()).await;

        // 创建常用命令的链接，确保基本命令可用
        command("/musl/busybox cp /musl/busybox /sleep", home_dir.clone()).await;
        command(
            "/musl/busybox cp /musl/busybox /bin/sleep",
            home_dir.clone(),
        )
        .await;
        command("/musl/busybox cp /musl/busybox /bin/cp", home_dir.clone()).await;
        command("/musl/busybox cp /musl/busybox /bin/ls", home_dir.clone()).await;
        command(
            "/musl/busybox cp /musl/busybox /bin/mkdir",
            home_dir.clone(),
        )
        .await;
        command("/musl/busybox cp /musl/busybox /bin/mv", home_dir.clone()).await;
        command("/musl/busybox cp /musl/busybox /bin/rm", home_dir.clone()).await;
        command("/musl/busybox cp /musl/busybox /bin/cat", home_dir.clone()).await;
        command("/musl/busybox cp /musl/busybox /bin/echo", home_dir.clone()).await;
        command(
            "/musl/busybox cp /musl/busybox /bin/chmod",
            home_dir.clone(),
        )
        .await;

        command("/musl/busybox chmod +x /sleep", home_dir.clone()).await;
        command("/musl/busybox chmod +x /bin/sleep", home_dir.clone()).await;
        command("/musl/busybox chmod +x /bin/cp", home_dir.clone()).await;
        command("/musl/busybox chmod +x /bin/ls", home_dir.clone()).await;
        command("/musl/busybox chmod +x /bin/mkdir", home_dir.clone()).await;
        command("/musl/busybox chmod +x /bin/mv", home_dir.clone()).await;
        command("/musl/busybox chmod +x /bin/rm", home_dir.clone()).await;
        command("/musl/busybox chmod +x /bin/cat", home_dir.clone()).await;
        command("/musl/busybox chmod +x /bin/echo", home_dir.clone()).await;
        command("/musl/busybox chmod +x /bin/chmod", home_dir.clone()).await;
        command(
            "/musl/busybox cp /glibc/lib/libm.so /glibc/lib/libm.so.6",
            home_dir.clone(),
        )
        .await;
        command(
            "/musl/busybox cp /glibc/lib/libc.so /glibc/lib/libc.so.6",
            home_dir.clone(),
        )
        .await;

        command(
            "/musl/busybox echo #### OS COMP TEST GROUP START basic-musl ####",
            home_dir.clone(),
        )
        .await;
        command("/musl/busybox sh /musl/basic/run-all.sh", home_dir.clone()).await;
        command(
            "/musl/busybox echo #### OS COMP TEST GROUP END basic-musl ####",
            home_dir.clone(),
        )
        .await;
        let home_dir = PathBuf::from("/musl");
        
        // 为LTP测试准备环境
        command("/musl/busybox echo #### OS COMP TEST GROUP START ltp-musl ####", home_dir.clone()).await;
        
        // 确保LTP测试需要的目录存在并有正确权限
        command("/musl/busybox mkdir -p /tmp", home_dir.clone()).await;
        command("/musl/busybox mkdir -p /var/tmp", home_dir.clone()).await;
        command("/musl/busybox chmod 1777 /tmp", home_dir.clone()).await;
        command("/musl/busybox chmod 1777 /var/tmp", home_dir.clone()).await;
        
        // 创建一些LTP测试可能需要的基础文件
        command("/musl/busybox touch /tmp/.test_marker", home_dir.clone()).await;
        command("/musl/busybox rm -f /tmp/.test_marker", home_dir.clone()).await;
        
        command("/musl/busybox sh ", home_dir.clone()).await;
        command("/musl/busybox sh ltp_testcode.sh", home_dir.clone()).await;
        
        command("/musl/busybox echo #### OS COMP TEST GROUP END ltp-musl ####", home_dir.clone()).await;

        // 使用专门的iperf测试函数，包含增强的隔离机制
        //command_iperf("/musl/busybox sh iperf_testcode.sh", home_dir.clone()).await;
        command(
            "/musl/busybox echo #### OS COMP TEST GROUP START lmbench-musl ####",
            home_dir.clone(),
        )
        .await;

        command("/musl/busybox echo latency measurements", home_dir.clone()).await;
        command("/musl/lmbench_all lat_syscall -P 1 null", home_dir.clone()).await;
        command("/musl/lmbench_all lat_syscall -P 1 read", home_dir.clone()).await;
        command("/musl/lmbench_all lat_syscall -P 1 write", home_dir.clone()).await;

        command("/musl/busybox mkdir -p /var/tmp", home_dir.clone()).await;
        command("/musl/busybox touch /var/tmp/lmbench", home_dir.clone()).await;

        command(
            "/musl/lmbench_all lat_syscall -P 1 stat /var/tmp/lmbench",
            home_dir.clone(),
        )
        .await;
        command(
            "/musl/lmbench_all lat_syscall -P 1 fstat /var/tmp/lmbench",
            home_dir.clone(),
        )
        .await;
        command(
            "/musl/lmbench_all lat_syscall -P 1 open /var/tmp/lmbench",
            home_dir.clone(),
        )
        .await;

        command(
            "/musl/lmbench_all lat_select -n 100 -P 1 file",
            home_dir.clone(),
        )
        .await;

        command("/musl/lmbench_all lat_sig -P 1 install", home_dir.clone()).await;
        command("/musl/lmbench_all lat_sig -P 1 catch", home_dir.clone()).await;
        command(
            "/musl/lmbench_all lat_sig -P 1 prot lat_sig",
            home_dir.clone(),
        )
        .await;

        command("/musl/lmbench_all lat_pipe -P 1", home_dir.clone()).await;

        command("/musl/lmbench_all lat_proc -P 1 fork", home_dir.clone()).await;
        //command("/musl/lmbench_all lat_proc -P 1 exec", home_dir.clone()).await;

        command("/musl/busybox cp hello /tmp", home_dir.clone()).await;
        //command("/musl/lmbench_all lat_proc -P 1 shell", home_dir.clone()).await;

        // 先创建目录
        command("/musl/busybox mkdir -p /var/tmp", home_dir.clone()).await;

        // 现在使用改进的command函数，可以正确处理引号
        command("/musl/lmbench_all lmdd label=\"File /var/tmp/XXX write bandwidth:\" of=/var/tmp/XXX move=1m fsync=1 print=3", home_dir.clone()).await;
        command(
            "/musl/lmbench_all lat_pagefault -P 1 /var/tmp/XXX",
            home_dir.clone(),
        )
        .await;
        command(
            "/musl/lmbench_all lat_mmap -P 1 512k /var/tmp/XXX",
            home_dir.clone(),
        )
        .await;

        command("/musl/busybox echo file system latency", home_dir.clone()).await;
        command("/musl/lmbench_all lat_fs /var/tmp", home_dir.clone()).await;

        command(
            "/musl/busybox echo Bandwidth measurements",
            home_dir.clone(),
        )
        .await;
        command("/musl/lmbench_all bw_pipe -P 1", home_dir.clone()).await;
        command(
            "/musl/lmbench_all bw_file_rd -P 1 512k io_only /var/tmp/XXX",
            home_dir.clone(),
        )
        .await;
        command(
            "/musl/lmbench_all bw_file_rd -P 1 512k open2close /var/tmp/XXX",
            home_dir.clone(),
        )
        .await;
        command(
            "/musl/lmbench_all bw_mmap_rd -P 1 512k mmap_only /var/tmp/XXX",
            home_dir.clone(),
        )
        .await;
        command(
            "/musl/lmbench_all bw_mmap_rd -P 1 512k open2close /var/tmp/XXX",
            home_dir.clone(),
        )
        .await;

        command(
            "/musl/busybox echo context switch overhead",
            home_dir.clone(),
        )
        .await;
        command(
            "/musl/lmbench_all lat_ctx -P 1 -s 32 2 4 8 16 24 32 64 96",
            home_dir.clone(),
        )
        .await;

        command(
            "/musl/busybox echo #### OS COMP TEST GROUP END lmbench-musl ####",
            home_dir.clone(),
        )
        .await;
        command(
            "/musl/busybox sh /musl/iozone_testcode.sh",
            home_dir.clone(),
        )
        .await;
        //command("/musl/busybox sh ", home_dir.clone()).await;
        command(
            "/musl/busybox sh /musl/libcbench_testcode.sh",
            home_dir.clone(),
        )
        .await;
        command("/musl/busybox sh busybox_testcode.sh", home_dir.clone()).await;

        command("/musl/busybox sh lua_testcode.sh", home_dir.clone()).await;
        command("/musl/busybox sh libctest_testcode.sh", home_dir.clone()).await;
        command(
            "/musl/busybox echo #### OS COMP TEST GROUP END libctest-musl ####",
            home_dir.clone().clone(),
        )
        .await;
        set_libc_path("/glibc/lib".to_string());
        set_dyn_path("/glibc/lib/ld-linux-riscv64-lp64d.so.1".to_string());
        let glibc_home_dir = PathBuf::from("/glibc/basic");
        // 为glibc环境创建链接
        command("/glibc/busybox mkdir -p /bin", glibc_home_dir.clone()).await;
        command(
            "/glibc/busybox cp /glibc/busybox /sleep",
            glibc_home_dir.clone(),
        )
        .await;
        command(
            "/glibc/busybox cp /glibc/busybox /bin/sleep",
            glibc_home_dir.clone(),
        )
        .await;
        command("/glibc/busybox chmod +x /sleep", glibc_home_dir.clone()).await;
        command("/glibc/busybox chmod +x /bin/sleep", glibc_home_dir.clone()).await;
        //command("/musl/busybox sh", glibc_home_dir.clone()).await;
        // command(
        //     "/glibc/busybox sh /glibc/iozone_testcode.sh",
        //     glibc_home_dir.clone(),
        // )
        // .await;
        command(
            "/glibc/busybox echo #### OS COMP TEST GROUP START basic-glibc ####",
            glibc_home_dir.clone(),
        )
        .await;
        command(
            "/glibc/busybox sh /glibc/basic/run-all.sh",
            glibc_home_dir.clone(),
        )
        .await;
        command(
            "/glibc/busybox echo #### OS COMP TEST GROUP END basic-glibc ####",
            glibc_home_dir.clone().clone(),
        )
        .await;

        let glibc_home_dir = PathBuf::from("/glibc");
        // 确保glibc目录也有正确的链接
        command("/glibc/busybox mkdir -p /bin", glibc_home_dir.clone()).await;
        command(
            "/glibc/busybox cp /glibc/busybox /sleep",
            glibc_home_dir.clone(),
        )
        .await;
        command(
            "/glibc/busybox cp /glibc/busybox /bin/sleep",
            glibc_home_dir.clone(),
        )
        .await;
        command("/glibc/busybox chmod +x /sleep", glibc_home_dir.clone()).await;
        command("/glibc/busybox chmod +x /bin/sleep", glibc_home_dir.clone()).await;

        //command("/musl/busybox sh ", glibc_home_dir.clone()).await;
        // 使用专门的iperf测试函数，包含增强的隔离机制 (glibc)
        command_iperf(
            "/glibc/busybox sh iperf_testcode.sh",
            glibc_home_dir.clone(),
        )
        .await;
        command(
            "/glibc/busybox echo #### OS COMP TEST GROUP START lmbench-glibc ####",
            glibc_home_dir.clone(),
        )
        .await;

        command(
            "/glibc/busybox echo latency measurements",
            glibc_home_dir.clone(),
        )
        .await;
        command(
            "/glibc/lmbench_all lat_syscall -P 1 null",
            glibc_home_dir.clone(),
        )
        .await;
        command(
            "/glibc/lmbench_all lat_syscall -P 1 read",
            glibc_home_dir.clone(),
        )
        .await;
        command(
            "/glibc/lmbench_all lat_syscall -P 1 write",
            glibc_home_dir.clone(),
        )
        .await;

        command("/glibc/busybox mkdir -p /var/tmp", glibc_home_dir.clone()).await;
        command(
            "/glibc/busybox touch /var/tmp/lmbench",
            glibc_home_dir.clone(),
        )
        .await;

        command(
            "/glibc/lmbench_all lat_syscall -P 1 stat /var/tmp/lmbench",
            glibc_home_dir.clone(),
        )
        .await;
        command(
            "/glibc/lmbench_all lat_syscall -P 1 fstat /var/tmp/lmbench",
            glibc_home_dir.clone(),
        )
        .await;
        command(
            "/glibc/lmbench_all lat_syscall -P 1 open /var/tmp/lmbench",
            glibc_home_dir.clone(),
        )
        .await;

        command(
            "/glibc/lmbench_all lat_select -n 100 -P 1 file",
            glibc_home_dir.clone(),
        )
        .await;

        command(
            "/glibc/lmbench_all lat_sig -P 1 install",
            glibc_home_dir.clone(),
        )
        .await;
        command(
            "/glibc/lmbench_all lat_sig -P 1 catch",
            glibc_home_dir.clone(),
        )
        .await;
        command(
            "/glibc/lmbench_all lat_sig -P 1 prot lat_sig",
            glibc_home_dir.clone(),
        )
        .await;

        command("/glibc/lmbench_all lat_pipe -P 1", glibc_home_dir.clone()).await;

        command(
            "/glibc/lmbench_all lat_proc -P 1 fork",
            glibc_home_dir.clone(),
        )
        .await;
        // //command("/glibc/lmbench_all lat_proc -P 1 exec", glibc_home_dir.clone()).await;

        command("/glibc/busybox cp hello /tmp", glibc_home_dir.clone()).await;
        //command("/glibc/lmbench_all lat_proc -P 1 shell", glibc_home_dir.clone()).await;

        // 先创建目录
        command("/glibc/busybox mkdir -p /var/tmp", glibc_home_dir.clone()).await;

        // 现在使用改进的command函数，可以正确处理引号
        command("/glibc/lmbench_all lmdd label=\"File /var/tmp/XXX write bandwidth:\" of=/var/tmp/XXX move=1m fsync=1 print=3", glibc_home_dir.clone()).await;
        command(
            "/glibc/lmbench_all lat_pagefault -P 1 /var/tmp/XXX",
            glibc_home_dir.clone(),
        )
        .await;
        command(
            "/glibc/lmbench_all lat_mmap -P 1 512k /var/tmp/XXX",
            glibc_home_dir.clone(),
        )
        .await;

        command(
            "/glibc/busybox echo file system latency",
            glibc_home_dir.clone(),
        )
        .await;
        command("/glibc/lmbench_all lat_fs /var/tmp", glibc_home_dir.clone()).await;

        command(
            "/glibc/busybox echo Bandwidth measurements",
            glibc_home_dir.clone(),
        )
        .await;
        command("/glibc/lmbench_all bw_pipe -P 1", glibc_home_dir.clone()).await;
        command(
            "/glibc/lmbench_all bw_file_rd -P 1 512k io_only /var/tmp/XXX",
            glibc_home_dir.clone(),
        )
        .await;
        command(
            "/glibc/lmbench_all bw_file_rd -P 1 512k open2close /var/tmp/XXX",
            glibc_home_dir.clone(),
        )
        .await;
        command(
            "/glibc/lmbench_all bw_mmap_rd -P 1 512k mmap_only /var/tmp/XXX",
            glibc_home_dir.clone(),
        )
        .await;
        command(
            "/glibc/lmbench_all bw_mmap_rd -P 1 512k open2close /var/tmp/XXX",
            glibc_home_dir.clone(),
        )
        .await;

        command(
            "/glibc/busybox echo context switch overhead",
            glibc_home_dir.clone(),
        )
        .await;
        command(
            "/glibc/lmbench_all lat_ctx -P 1 -s 32 2 4 8 16 24 32 64 96",
            glibc_home_dir.clone(),
        )
        .await;

        command(
            "/glibc/busybox echo #### OS COMP TEST GROUP END lmbench-glibc ####",
            glibc_home_dir.clone(),
        )
        .await;
        //command("/glibc/busybox sh lmbench_testcode.sh", glibc_home_dir.clone()).await;
        command(
            "/glibc/busybox sh /glibc/libcbench_testcode.sh",
            glibc_home_dir.clone(),
        )
        .await;
        command(
            "/glibc/busybox sh busybox_testcode.sh",
            glibc_home_dir.clone(),
        )
        .await;
        command("/glibc/busybox sh lua_testcode.sh", glibc_home_dir.clone()).await;

        //command("/musl/busybox sh run-dynamic-all.sh", home_dir.clone()).await;
        //command("/musl/busybox sh run-static-all.sh", home_dir.clone()).await;
        // command("/musl/busybox sh run-dynamic.sh", home_dir.clone()).await;
        // command("/musl/busybox sh run-static.sh", home_dir.clone()).await;
        // command("/musl/busybox sh cyclictest_testcode.sh", home_dir.clone()).await;

        // command("/musl/busybox sh unixbench_testcode.sh", home_dir.clone()).await;
        //command("/musl/busybox sh lmbench_testcode.sh", home_dir.clone()).await;
        // command("/musl/busybox sh iperf_testcode.sh", home_dir.clone()).await;
        // command("/musl/busybox sh multi.sh", home_dir.clone()).await;
        // command("/musl/busybox sh iozone_testcode.sh", home_dir.clone()).await;

        // command(
        //     "/glibc/busybox sh cyclictest_testcode.sh",
        //     glibc_home_dir.clone(),
        // )
        // .await;
    }

    #[cfg(target_arch = "loongarch64")]
    {
        set_libc_path("/musl/lib/libc.so".to_string());
        set_dyn_path("/musl/lib/libc.so".to_string());
        println!("start kernel tasks");

        // 创建必要的链接以支持busybox测试
        let home_dir = PathBuf::from("/musl/basic");
        command("/musl/busybox mkdir -p /bin", home_dir.clone()).await;

        // 创建常用命令的链接，确保基本命令可用
        command("/musl/busybox cp /musl/busybox /sleep", home_dir.clone()).await;
        command(
            "/musl/busybox cp /musl/busybox /bin/sleep",
            home_dir.clone(),
        )
        .await;
        command("/musl/busybox cp /musl/busybox /bin/cp", home_dir.clone()).await;
        command("/musl/busybox cp /musl/busybox /bin/ls", home_dir.clone()).await;
        command(
            "/musl/busybox cp /musl/busybox /bin/mkdir",
            home_dir.clone(),
        )
        .await;
        command("/musl/busybox cp /musl/busybox /bin/mv", home_dir.clone()).await;
        command("/musl/busybox cp /musl/busybox /bin/rm", home_dir.clone()).await;
        command("/musl/busybox cp /musl/busybox /bin/cat", home_dir.clone()).await;
        command("/musl/busybox cp /musl/busybox /bin/echo", home_dir.clone()).await;
        command(
            "/musl/busybox cp /musl/busybox /bin/chmod",
            home_dir.clone(),
        )
        .await;

        command("/musl/busybox chmod +x /sleep", home_dir.clone()).await;
        command("/musl/busybox chmod +x /bin/sleep", home_dir.clone()).await;
        command("/musl/busybox chmod +x /bin/cp", home_dir.clone()).await;
        command("/musl/busybox chmod +x /bin/ls", home_dir.clone()).await;
        command("/musl/busybox chmod +x /bin/mkdir", home_dir.clone()).await;
        command("/musl/busybox chmod +x /bin/mv", home_dir.clone()).await;
        command("/musl/busybox chmod +x /bin/rm", home_dir.clone()).await;
        command("/musl/busybox chmod +x /bin/cat", home_dir.clone()).await;
        command("/musl/busybox chmod +x /bin/echo", home_dir.clone()).await;
        command("/musl/busybox chmod +x /bin/chmod", home_dir.clone()).await;
        command(
            "/musl/busybox echo #### OS COMP TEST GROUP START basic-musl ####",
            home_dir.clone(),
        )
        .await;
        command("/musl/busybox sh /musl/basic/run-all.sh", home_dir.clone()).await;
        command(
            "/musl/busybox echo #### OS COMP TEST GROUP END basic-musl ####",
            home_dir.clone(),
        )
        .await;
        //let home_dir = PathBuf::from("/musl");
        let home_dir = PathBuf::from("/musl");

        // 为LTP测试准备环境 (LoongArch64)
        command("/musl/busybox echo #### OS COMP TEST GROUP START ltp-musl ####", home_dir.clone()).await;
        
        // 确保LTP测试需要的目录存在并有正确权限
        command("/musl/busybox mkdir -p /tmp", home_dir.clone()).await;
        command("/musl/busybox mkdir -p /var/tmp", home_dir.clone()).await;
        command("/musl/busybox chmod 1777 /tmp", home_dir.clone()).await;
        command("/musl/busybox chmod 1777 /var/tmp", home_dir.clone()).await;
        
        // 创建一些LTP测试可能需要的基础文件
        command("/musl/busybox touch /tmp/.test_marker", home_dir.clone()).await;
        command("/musl/busybox rm -f /tmp/.test_marker", home_dir.clone()).await;

        //command("/musl/busybox sh ", home_dir.clone()).await;
        command("/musl/busybox sh ltp_testcode.sh", home_dir.clone()).await;
        
        command("/musl/busybox echo #### OS COMP TEST GROUP END ltp-musl ####", home_dir.clone()).await;

        // 使用专门的iperf测试函数，包含增强的隔离机制 (loongarch64)
        command_iperf("/musl/busybox sh iperf_testcode.sh", home_dir.clone()).await;
        command("/musl/busybox sh lmbench_testcode.sh", home_dir.clone()).await;

        command(
            "/musl/busybox sh /musl/iozone_testcode.sh",
            home_dir.clone(),
        )
        .await;
        command("/musl/busybox sh libcbench_testcode.sh", home_dir.clone()).await;
        command("/musl/busybox sh busybox_testcode.sh", home_dir.clone()).await;
        command("/musl/busybox sh lua_testcode.sh", home_dir.clone()).await;
        //command("/musl/busybox sh libctest_testcode.sh", home_dir.clone()).await;
        command(
            "/musl/busybox echo #### OS COMP TEST GROUP START libctest-musl ####",
            home_dir.clone(),
        )
        .await;
        let musl_exclude = vec![
            (
                "/musl/runtest.exe",
                "entry-static.exe",
                "pthread_robust_detach",
                home_dir.clone(),
            ),
            (
                "/musl/runtest.exe",
                "entry-static.exe",
                "setvbuf_unget",
                home_dir.clone(),
            ),
            (
                "/musl/runtest.exe",
                "entry-static.exe",
                "pthread_cancel_points",
                home_dir.clone(),
            ),
            (
                "/musl/runtest.exe",
                "entry-static.exe",
                "pthread_cancel",
                home_dir.clone(),
            ),
            (
                "/musl/runtest.exe",
                "entry-static.exe",
                "pthread_cond",
                home_dir.clone(),
            ),
            (
                "/musl/runtest.exe",
                "entry-static.exe",
                "pthread_tsd",
                home_dir.clone(),
            ),
            (
                "/musl/runtest.exe",
                "entry-static.exe",
                "pthread_cancel_sem_wait",
                home_dir.clone(),
            ),
            (
                "/musl/runtest.exe",
                "entry-static.exe",
                "pthread_cond_smasher",
                home_dir.clone(),
            ),
            (
                "/musl/runtest.exe",
                "entry-static.exe",
                "pthread_condattr_setclock",
                home_dir.clone(),
            ),
            (
                "/musl/runtest.exe",
                "entry-static.exe",
                "pthread_exit_cancel",
                home_dir.clone(),
            ),
            (
                "/musl/runtest.exe",
                "entry-static.exe",
                "pthread_once_deadlock",
                home_dir.clone(),
            ),
            (
                "/musl/runtest.exe",
                "entry-static.exe",
                "pthread_rwlock_ebusy",
                home_dir.clone(),
            ),
            (
                "/musl/runtest.exe",
                "entry-dynamic.exe",
                "pthread_robust_detach",
                home_dir.clone(),
            ),
            (
                "/musl/runtest.exe",
                "entry-dynamic.exe",
                "setvbuf_unget",
                home_dir.clone(),
            ),
            (
                "/musl/runtest.exe",
                "entry-dynamic.exe",
                "pthread_cancel_points",
                home_dir.clone(),
            ),
            (
                "/musl/runtest.exe",
                "entry-dynamic.exe",
                "pthread_cancel",
                home_dir.clone(),
            ),
            (
                "/musl/runtest.exe",
                "entry-dynamic.exe",
                "pthread_cond",
                home_dir.clone(),
            ),
            (
                "/musl/runtest.exe",
                "entry-dynamic.exe",
                "pthread_tsd",
                home_dir.clone(),
            ),
            (
                "/musl/runtest.exe",
                "entry-dynamic.exe",
                "pthread_cancel_sem_wait",
                home_dir.clone(),
            ),
            (
                "/musl/runtest.exe",
                "entry-dynamic.exe",
                "pthread_cond_smasher",
                home_dir.clone(),
            ),
            (
                "/musl/runtest.exe",
                "entry-dynamic.exe",
                "pthread_condattr_setclock",
                home_dir.clone(),
            ),
            (
                "/musl/runtest.exe",
                "entry-dynamic.exe",
                "pthread_exit_cancel",
                home_dir.clone(),
            ),
            (
                "/musl/runtest.exe",
                "entry-dynamic.exe",
                "pthread_once_deadlock",
                home_dir.clone(),
            ),
            (
                "/musl/runtest.exe",
                "entry-dynamic.exe",
                "pthread_rwlock_ebusy",
                home_dir.clone(),
            ),
        ];
        run_musl_tests(home_dir.clone(), musl_exclude).await;
        command(
            "/musl/busybox echo #### OS COMP TEST GROUP END libctest-musl ####",
            home_dir.clone().clone(),
        )
        .await;

        //command("/musl/busybox sh run-dynamic-all.sh", home_dir.clone()).await;
        //command("/musl/busybox sh run-static-all.sh", home_dir.clone()).await;
        // command("/musl/busybox sh run-dynamic.sh", home_dir.clone()).await;
        // command("/musl/busybox sh run-static.sh", home_dir.clone()).await;
        //command("/musl/busybox sh cyclictest_testcode.sh", home_dir.clone()).await;

        // command("/musl/busybox sh unixbench_testcode.sh", home_dir.clone()).await;
        //command("/musl/busybox sh lmbench_testcode.sh", home_dir.clone()).await;
        // command("/musl/busybox sh iperf_testcode.sh", home_dir.clone()).await;
        // command("/musl/busybox sh multi.sh", home_dir.clone()).await;
        // command("/musl/busybox sh iozone_testcode.sh", home_dir.clone()).await;
        set_libc_path("/glibc/lib".to_string());
        set_dyn_path("/glibc/lib/ld-linux-loongarch-lp64d.so.1".to_string());
        let glibc_home_dir = PathBuf::from("/glibc/basic");
        // 为glibc环境创建链接
        command("/glibc/busybox mkdir -p /bin", glibc_home_dir.clone()).await;
        command(
            "/glibc/busybox cp /glibc/busybox /sleep",
            glibc_home_dir.clone(),
        )
        .await;
        command(
            "/glibc/busybox cp /glibc/busybox /bin/sleep",
            glibc_home_dir.clone(),
        )
        .await;
        command("/glibc/busybox chmod +x /sleep", glibc_home_dir.clone()).await;
        command("/glibc/busybox chmod +x /bin/sleep", glibc_home_dir.clone()).await;
        //command("/glibc/busybox sh", glibc_home_dir.clone()).await;
        command(
            "/glibc/busybox echo #### OS COMP TEST GROUP START basic-glibc ####",
            glibc_home_dir.clone(),
        )
        .await;
        command(
            "/glibc/busybox sh /glibc/basic/run-all.sh",
            glibc_home_dir.clone(),
        )
        .await;
        command(
            "/glibc/busybox echo #### OS COMP TEST GROUP END basic-glibc ####",
            glibc_home_dir.clone().clone(),
        )
        .await;

        let glibc_home_dir = PathBuf::from("/glibc");
        // 确保glibc目录也有正确的链接
        command("/glibc/busybox mkdir -p /bin", glibc_home_dir.clone()).await;
        command(
            "/glibc/busybox cp /glibc/busybox /sleep",
            glibc_home_dir.clone(),
        )
        .await;
        command(
            "/glibc/busybox cp /glibc/busybox /bin/sleep",
            glibc_home_dir.clone(),
        )
        .await;
        command("/glibc/busybox chmod +x /sleep", glibc_home_dir.clone()).await;
        command("/glibc/busybox chmod +x /bin/sleep", glibc_home_dir.clone()).await;

        //command("/musl/busybox sh ", glibc_home_dir.clone()).await;
        command(
            "/glibc/busybox sh lmbench_testcode.sh",
            glibc_home_dir.clone(),
        )
        .await;

        command(
            "/glibc/busybox sh libcbench_testcode.sh",
            glibc_home_dir.clone(),
        )
        .await;
        command(
            "/glibc/busybox sh busybox_testcode.sh",
            glibc_home_dir.clone(),
        )
        .await;
        command("/glibc/busybox sh lua_testcode.sh", glibc_home_dir.clone()).await;

        // command(
        //     "/glibc/busybox sh cyclictest_testcode.sh",
        //     glibc_home_dir.clone(),
        // )
        // .await;
    }
    println!("!TEST FINISH!");
    shutdown();

    // Shutdown if there just have blankkernel task.
    if TASK_MAP
        .lock()
        .values()
        .find(|x| {
            x.upgrade()
                .map(|x| x.get_task_type() != TaskType::BlankKernel)
                .unwrap_or(false)
        })
        .is_none()
    {
        shutdown();
    }
}
async fn run_musl_tests(home_dir: PathBuf, exclude: Vec<(&str, &str, &str, PathBuf)>) {
    let musl_static_tests = vec![
        ("/musl/runtest.exe", "entry-static.exe", "argv"),
        ("/musl/runtest.exe", "entry-static.exe", "basename"),
        ("/musl/runtest.exe", "entry-static.exe", "clocale_mbfuncs"),
        ("/musl/runtest.exe", "entry-static.exe", "clock_gettime"),
        ("/musl/runtest.exe", "entry-static.exe", "dirname"),
        ("/musl/runtest.exe", "entry-static.exe", "env"),
        ("/musl/runtest.exe", "entry-static.exe", "fdopen"),
        ("/musl/runtest.exe", "entry-static.exe", "fnmatch"),
        ("/musl/runtest.exe", "entry-static.exe", "fscanf"),
        ("/musl/runtest.exe", "entry-static.exe", "fwscanf"),
        ("/musl/runtest.exe", "entry-static.exe", "iconv_open"),
        ("/musl/runtest.exe", "entry-static.exe", "inet_pton"),
        ("/musl/runtest.exe", "entry-static.exe", "mbc"),
        ("/musl/runtest.exe", "entry-static.exe", "memstream"),
        (
            "/musl/runtest.exe",
            "entry-static.exe",
            "pthread_cancel_points",
        ),
        ("/musl/runtest.exe", "entry-static.exe", "pthread_cancel"),
        ("/musl/runtest.exe", "entry-static.exe", "pthread_cond"),
        ("/musl/runtest.exe", "entry-static.exe", "pthread_tsd"),
        ("/musl/runtest.exe", "entry-static.exe", "qsort"),
        ("/musl/runtest.exe", "entry-static.exe", "random"),
        ("/musl/runtest.exe", "entry-static.exe", "search_hsearch"),
        ("/musl/runtest.exe", "entry-static.exe", "search_insque"),
        ("/musl/runtest.exe", "entry-static.exe", "search_lsearch"),
        ("/musl/runtest.exe", "entry-static.exe", "search_tsearch"),
        ("/musl/runtest.exe", "entry-static.exe", "setjmp"),
        ("/musl/runtest.exe", "entry-static.exe", "snprintf"),
        ("/musl/runtest.exe", "entry-static.exe", "socket"),
        ("/musl/runtest.exe", "entry-static.exe", "sscanf"),
        ("/musl/runtest.exe", "entry-static.exe", "sscanf_long"),
        ("/musl/runtest.exe", "entry-static.exe", "stat"),
        ("/musl/runtest.exe", "entry-static.exe", "strftime"),
        ("/musl/runtest.exe", "entry-static.exe", "string"),
        ("/musl/runtest.exe", "entry-static.exe", "string_memcpy"),
        ("/musl/runtest.exe", "entry-static.exe", "string_memmem"),
        ("/musl/runtest.exe", "entry-static.exe", "string_memset"),
        ("/musl/runtest.exe", "entry-static.exe", "string_strchr"),
        ("/musl/runtest.exe", "entry-static.exe", "string_strcspn"),
        ("/musl/runtest.exe", "entry-static.exe", "string_strstr"),
        ("/musl/runtest.exe", "entry-static.exe", "strptime"),
        ("/musl/runtest.exe", "entry-static.exe", "strtod"),
        ("/musl/runtest.exe", "entry-static.exe", "strtod_simple"),
        ("/musl/runtest.exe", "entry-static.exe", "strtof"),
        ("/musl/runtest.exe", "entry-static.exe", "strtol"),
        ("/musl/runtest.exe", "entry-static.exe", "strtold"),
        ("/musl/runtest.exe", "entry-static.exe", "swprintf"),
        ("/musl/runtest.exe", "entry-static.exe", "tgmath"),
        ("/musl/runtest.exe", "entry-static.exe", "time"),
        ("/musl/runtest.exe", "entry-static.exe", "tls_align"),
        ("/musl/runtest.exe", "entry-static.exe", "udiv"),
        ("/musl/runtest.exe", "entry-static.exe", "ungetc"),
        ("/musl/runtest.exe", "entry-static.exe", "utime"),
        ("/musl/runtest.exe", "entry-static.exe", "wcsstr"),
        ("/musl/runtest.exe", "entry-static.exe", "wcstol"),
        ("/musl/runtest.exe", "entry-static.exe", "daemon_failure"),
        ("/musl/runtest.exe", "entry-static.exe", "dn_expand_empty"),
        ("/musl/runtest.exe", "entry-static.exe", "dn_expand_ptr_0"),
        ("/musl/runtest.exe", "entry-static.exe", "fflush_exit"),
        ("/musl/runtest.exe", "entry-static.exe", "fgets_eof"),
        ("/musl/runtest.exe", "entry-static.exe", "fgetwc_buffering"),
        (
            "/musl/runtest.exe",
            "entry-static.exe",
            "fpclassify_invalid_ld80",
        ),
        (
            "/musl/runtest.exe",
            "entry-static.exe",
            "ftello_unflushed_append",
        ),
        ("/musl/runtest.exe", "entry-static.exe", "getpwnam_r_crash"),
        ("/musl/runtest.exe", "entry-static.exe", "getpwnam_r_errno"),
        ("/musl/runtest.exe", "entry-static.exe", "iconv_roundtrips"),
        (
            "/musl/runtest.exe",
            "entry-static.exe",
            "inet_ntop_v4mapped",
        ),
        (
            "/musl/runtest.exe",
            "entry-static.exe",
            "inet_pton_empty_last_field",
        ),
        ("/musl/runtest.exe", "entry-static.exe", "iswspace_null"),
        (
            "/musl/runtest.exe",
            "entry-static.exe",
            "lrand48_signextend",
        ),
        ("/musl/runtest.exe", "entry-static.exe", "lseek_large"),
        ("/musl/runtest.exe", "entry-static.exe", "malloc_0"),
        (
            "/musl/runtest.exe",
            "entry-static.exe",
            "mbsrtowcs_overflow",
        ),
        ("/musl/runtest.exe", "entry-static.exe", "memmem_oob_read"),
        ("/musl/runtest.exe", "entry-static.exe", "memmem_oob"),
        ("/musl/runtest.exe", "entry-static.exe", "mkdtemp_failure"),
        ("/musl/runtest.exe", "entry-static.exe", "mkstemp_failure"),
        ("/musl/runtest.exe", "entry-static.exe", "printf_1e9_oob"),
        (
            "/musl/runtest.exe",
            "entry-static.exe",
            "printf_fmt_g_round",
        ),
        (
            "/musl/runtest.exe",
            "entry-static.exe",
            "printf_fmt_g_zeros",
        ),
        ("/musl/runtest.exe", "entry-static.exe", "printf_fmt_n"),
        (
            "/musl/runtest.exe",
            "entry-static.exe",
            "pthread_robust_detach",
        ),
        (
            "/musl/runtest.exe",
            "entry-static.exe",
            "pthread_cancel_sem_wait",
        ),
        (
            "/musl/runtest.exe",
            "entry-static.exe",
            "pthread_cond_smasher",
        ),
        (
            "/musl/runtest.exe",
            "entry-static.exe",
            "pthread_condattr_setclock",
        ),
        (
            "/musl/runtest.exe",
            "entry-static.exe",
            "pthread_exit_cancel",
        ),
        (
            "/musl/runtest.exe",
            "entry-static.exe",
            "pthread_once_deadlock",
        ),
        (
            "/musl/runtest.exe",
            "entry-static.exe",
            "pthread_rwlock_ebusy",
        ),
        ("/musl/runtest.exe", "entry-static.exe", "putenv_doublefree"),
        ("/musl/runtest.exe", "entry-static.exe", "regex_backref_0"),
        (
            "/musl/runtest.exe",
            "entry-static.exe",
            "regex_bracket_icase",
        ),
        ("/musl/runtest.exe", "entry-static.exe", "regex_ere_backref"),
        (
            "/musl/runtest.exe",
            "entry-static.exe",
            "regex_escaped_high_byte",
        ),
        (
            "/musl/runtest.exe",
            "entry-static.exe",
            "regex_negated_range",
        ),
        ("/musl/runtest.exe", "entry-static.exe", "regexec_nosub"),
        (
            "/musl/runtest.exe",
            "entry-static.exe",
            "rewind_clear_error",
        ),
        ("/musl/runtest.exe", "entry-static.exe", "rlimit_open_files"),
        (
            "/musl/runtest.exe",
            "entry-static.exe",
            "scanf_bytes_consumed",
        ),
        (
            "/musl/runtest.exe",
            "entry-static.exe",
            "scanf_match_literal_eof",
        ),
        (
            "/musl/runtest.exe",
            "entry-static.exe",
            "scanf_nullbyte_char",
        ),
        ("/musl/runtest.exe", "entry-static.exe", "setvbuf_unget"),
        (
            "/musl/runtest.exe",
            "entry-static.exe",
            "sigprocmask_internal",
        ),
        ("/musl/runtest.exe", "entry-static.exe", "sscanf_eof"),
        ("/musl/runtest.exe", "entry-static.exe", "statvfs"),
        ("/musl/runtest.exe", "entry-static.exe", "strverscmp"),
        (
            "/musl/runtest.exe",
            "entry-static.exe",
            "syscall_sign_extend",
        ),
        ("/musl/runtest.exe", "entry-static.exe", "uselocale_0"),
        (
            "/musl/runtest.exe",
            "entry-static.exe",
            "wcsncpy_read_overflow",
        ),
        (
            "/musl/runtest.exe",
            "entry-static.exe",
            "wcsstr_false_negative",
        ),
    ];

    let musl_dynamic_tests = vec![
        ("/musl/runtest.exe", "entry-dynamic.exe", "argv"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "basename"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "clocale_mbfuncs"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "clock_gettime"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "dirname"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "dlopen"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "env"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "fdopen"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "fnmatch"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "fscanf"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "fwscanf"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "iconv_open"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "inet_pton"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "mbc"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "memstream"),
        (
            "/musl/runtest.exe",
            "entry-dynamic.exe",
            "pthread_cancel_points",
        ),
        ("/musl/runtest.exe", "entry-dynamic.exe", "pthread_cancel"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "pthread_cond"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "pthread_tsd"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "qsort"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "random"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "search_hsearch"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "search_insque"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "search_lsearch"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "search_tsearch"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "sem_init"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "setjmp"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "snprintf"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "socket"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "sscanf"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "sscanf_long"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "stat"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "strftime"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "string"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "string_memcpy"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "string_memmem"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "string_memset"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "string_strchr"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "string_strcspn"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "string_strstr"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "strptime"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "strtod"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "strtod_simple"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "strtof"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "strtol"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "strtold"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "swprintf"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "tgmath"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "time"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "tls_init"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "tls_local_exec"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "udiv"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "ungetc"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "utime"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "wcsstr"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "wcstol"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "daemon_failure"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "dn_expand_empty"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "dn_expand_ptr_0"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "fflush_exit"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "fgets_eof"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "fgetwc_buffering"),
        (
            "/musl/runtest.exe",
            "entry-dynamic.exe",
            "fpclassify_invalid_ld80",
        ),
        (
            "/musl/runtest.exe",
            "entry-dynamic.exe",
            "ftello_unflushed_append",
        ),
        ("/musl/runtest.exe", "entry-dynamic.exe", "getpwnam_r_crash"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "getpwnam_r_errno"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "iconv_roundtrips"),
        (
            "/musl/runtest.exe",
            "entry-dynamic.exe",
            "inet_ntop_v4mapped",
        ),
        (
            "/musl/runtest.exe",
            "entry-dynamic.exe",
            "inet_pton_empty_last_field",
        ),
        ("/musl/runtest.exe", "entry-dynamic.exe", "iswspace_null"),
        (
            "/musl/runtest.exe",
            "entry-dynamic.exe",
            "lrand48_signextend",
        ),
        ("/musl/runtest.exe", "entry-dynamic.exe", "lseek_large"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "malloc_0"),
        (
            "/musl/runtest.exe",
            "entry-dynamic.exe",
            "mbsrtowcs_overflow",
        ),
        ("/musl/runtest.exe", "entry-dynamic.exe", "memmem_oob_read"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "memmem_oob"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "mkdtemp_failure"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "mkstemp_failure"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "printf_1e9_oob"),
        (
            "/musl/runtest.exe",
            "entry-dynamic.exe",
            "printf_fmt_g_round",
        ),
        (
            "/musl/runtest.exe",
            "entry-dynamic.exe",
            "printf_fmt_g_zeros",
        ),
        ("/musl/runtest.exe", "entry-dynamic.exe", "printf_fmt_n"),
        (
            "/musl/runtest.exe",
            "entry-dynamic.exe",
            "pthread_robust_detach",
        ),
        (
            "/musl/runtest.exe",
            "entry-dynamic.exe",
            "pthread_cond_smasher",
        ),
        (
            "/musl/runtest.exe",
            "entry-dynamic.exe",
            "pthread_condattr_setclock",
        ),
        (
            "/musl/runtest.exe",
            "entry-dynamic.exe",
            "pthread_exit_cancel",
        ),
        (
            "/musl/runtest.exe",
            "entry-dynamic.exe",
            "pthread_once_deadlock",
        ),
        (
            "/musl/runtest.exe",
            "entry-dynamic.exe",
            "pthread_rwlock_ebusy",
        ),
        (
            "/musl/runtest.exe",
            "entry-dynamic.exe",
            "putenv_doublefree",
        ),
        ("/musl/runtest.exe", "entry-dynamic.exe", "regex_backref_0"),
        (
            "/musl/runtest.exe",
            "entry-dynamic.exe",
            "regex_bracket_icase",
        ),
        (
            "/musl/runtest.exe",
            "entry-dynamic.exe",
            "regex_ere_backref",
        ),
        (
            "/musl/runtest.exe",
            "entry-dynamic.exe",
            "regex_escaped_high_byte",
        ),
        (
            "/musl/runtest.exe",
            "entry-dynamic.exe",
            "regex_negated_range",
        ),
        ("/musl/runtest.exe", "entry-dynamic.exe", "regexec_nosub"),
        (
            "/musl/runtest.exe",
            "entry-dynamic.exe",
            "rewind_clear_error",
        ),
        (
            "/musl/runtest.exe",
            "entry-dynamic.exe",
            "rlimit_open_files",
        ),
        (
            "/musl/runtest.exe",
            "entry-dynamic.exe",
            "scanf_bytes_consumed",
        ),
        (
            "/musl/runtest.exe",
            "entry-dynamic.exe",
            "scanf_match_literal_eof",
        ),
        (
            "/musl/runtest.exe",
            "entry-dynamic.exe",
            "scanf_nullbyte_char",
        ),
        ("/musl/runtest.exe", "entry-dynamic.exe", "setvbuf_unget"),
        (
            "/musl/runtest.exe",
            "entry-dynamic.exe",
            "sigprocmask_internal",
        ),
        ("/musl/runtest.exe", "entry-dynamic.exe", "sscanf_eof"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "statvfs"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "strverscmp"),
        (
            "/musl/runtest.exe",
            "entry-dynamic.exe",
            "syscall_sign_extend",
        ),
        ("/musl/runtest.exe", "entry-dynamic.exe", "tls_get_new_dtv"),
        ("/musl/runtest.exe", "entry-dynamic.exe", "uselocale_0"),
        (
            "/musl/runtest.exe",
            "entry-dynamic.exe",
            "wcsncpy_read_overflow",
        ),
        (
            "/musl/runtest.exe",
            "entry-dynamic.exe",
            "wcsstr_false_negative",
        ),
    ];

    for tests in vec![musl_static_tests, musl_dynamic_tests] {
        for (runtest, entry, test_name) in tests {
            let test_dir = home_dir.clone();
            if !exclude
                .iter()
                .any(|&(ex_runtest, ex_entry, ex_test_name, ref ex_dir)| {
                    ex_runtest == runtest
                        && ex_entry == entry
                        && ex_test_name == test_name
                        && ex_dir == &test_dir
                })
            {
                command(
                    &alloc::format!("{} -w {} {}", runtest, entry, test_name),
                    test_dir,
                )
                .await;
            }
        }
    }
}

async fn run_glibc_tests(glibc_home_dir: PathBuf, exclude: Vec<(&str, &str, &str, PathBuf)>) {
    let glibc_static_tests = vec![
        ("/glibc/runtest.exe", "entry-static.exe", "argv"),
        ("/glibc/runtest.exe", "entry-static.exe", "basename"),
        ("/glibc/runtest.exe", "entry-static.exe", "clocale_mbfuncs"),
        ("/glibc/runtest.exe", "entry-static.exe", "clock_gettime"),
        ("/glibc/runtest.exe", "entry-static.exe", "dirname"),
        ("/glibc/runtest.exe", "entry-static.exe", "env"),
        ("/glibc/runtest.exe", "entry-static.exe", "fdopen"),
        ("/glibc/runtest.exe", "entry-static.exe", "fnmatch"),
        ("/glibc/runtest.exe", "entry-static.exe", "fscanf"),
        ("/glibc/runtest.exe", "entry-static.exe", "fwscanf"),
        ("/glibc/runtest.exe", "entry-static.exe", "iconv_open"),
        ("/glibc/runtest.exe", "entry-static.exe", "inet_pton"),
        ("/glibc/runtest.exe", "entry-static.exe", "mbc"),
        ("/glibc/runtest.exe", "entry-static.exe", "memstream"),
        (
            "/glibc/runtest.exe",
            "entry-static.exe",
            "pthread_cancel_points",
        ),
        ("/glibc/runtest.exe", "entry-static.exe", "pthread_cancel"),
        ("/glibc/runtest.exe", "entry-static.exe", "pthread_cond"),
        ("/glibc/runtest.exe", "entry-static.exe", "pthread_tsd"),
        ("/glibc/runtest.exe", "entry-static.exe", "qsort"),
        ("/glibc/runtest.exe", "entry-static.exe", "random"),
        ("/glibc/runtest.exe", "entry-static.exe", "search_hsearch"),
        ("/glibc/runtest.exe", "entry-static.exe", "search_insque"),
        ("/glibc/runtest.exe", "entry-static.exe", "search_lsearch"),
        ("/glibc/runtest.exe", "entry-static.exe", "search_tsearch"),
        ("/glibc/runtest.exe", "entry-static.exe", "setjmp"),
        ("/glibc/runtest.exe", "entry-static.exe", "snprintf"),
        ("/glibc/runtest.exe", "entry-static.exe", "socket"),
        ("/glibc/runtest.exe", "entry-static.exe", "sscanf"),
        ("/glibc/runtest.exe", "entry-static.exe", "sscanf_long"),
        ("/glibc/runtest.exe", "entry-static.exe", "stat"),
        ("/glibc/runtest.exe", "entry-static.exe", "strftime"),
        ("/glibc/runtest.exe", "entry-static.exe", "string"),
        ("/glibc/runtest.exe", "entry-static.exe", "string_memcpy"),
        ("/glibc/runtest.exe", "entry-static.exe", "string_memmem"),
        ("/glibc/runtest.exe", "entry-static.exe", "string_memset"),
        ("/glibc/runtest.exe", "entry-static.exe", "string_strchr"),
        ("/glibc/runtest.exe", "entry-static.exe", "string_strcspn"),
        ("/glibc/runtest.exe", "entry-static.exe", "string_strstr"),
        ("/glibc/runtest.exe", "entry-static.exe", "strptime"),
        ("/glibc/runtest.exe", "entry-static.exe", "strtod"),
        ("/glibc/runtest.exe", "entry-static.exe", "strtod_simple"),
        ("/glibc/runtest.exe", "entry-static.exe", "strtof"),
        ("/glibc/runtest.exe", "entry-static.exe", "strtol"),
        ("/glibc/runtest.exe", "entry-static.exe", "strtold"),
        ("/glibc/runtest.exe", "entry-static.exe", "swprintf"),
        ("/glibc/runtest.exe", "entry-static.exe", "tgmath"),
        ("/glibc/runtest.exe", "entry-static.exe", "time"),
        ("/glibc/runtest.exe", "entry-static.exe", "tls_align"),
        ("/glibc/runtest.exe", "entry-static.exe", "udiv"),
        ("/glibc/runtest.exe", "entry-static.exe", "ungetc"),
        ("/glibc/runtest.exe", "entry-static.exe", "utime"),
        ("/glibc/runtest.exe", "entry-static.exe", "wcsstr"),
        ("/glibc/runtest.exe", "entry-static.exe", "wcstol"),
        ("/glibc/runtest.exe", "entry-static.exe", "daemon_failure"),
        ("/glibc/runtest.exe", "entry-static.exe", "dn_expand_empty"),
        ("/glibc/runtest.exe", "entry-static.exe", "dn_expand_ptr_0"),
        ("/glibc/runtest.exe", "entry-static.exe", "fflush_exit"),
        ("/glibc/runtest.exe", "entry-static.exe", "fgets_eof"),
        ("/glibc/runtest.exe", "entry-static.exe", "fgetwc_buffering"),
        (
            "/glibc/runtest.exe",
            "entry-static.exe",
            "fpclassify_invalid_ld80",
        ),
        (
            "/glibc/runtest.exe",
            "entry-static.exe",
            "ftello_unflushed_append",
        ),
        ("/glibc/runtest.exe", "entry-static.exe", "getpwnam_r_crash"),
        ("/glibc/runtest.exe", "entry-static.exe", "getpwnam_r_errno"),
        ("/glibc/runtest.exe", "entry-static.exe", "iconv_roundtrips"),
        (
            "/glibc/runtest.exe",
            "entry-static.exe",
            "inet_ntop_v4mapped",
        ),
        (
            "/glibc/runtest.exe",
            "entry-static.exe",
            "inet_pton_empty_last_field",
        ),
        ("/glibc/runtest.exe", "entry-static.exe", "iswspace_null"),
        (
            "/glibc/runtest.exe",
            "entry-static.exe",
            "lrand48_signextend",
        ),
        ("/glibc/runtest.exe", "entry-static.exe", "lseek_large"),
        ("/glibc/runtest.exe", "entry-static.exe", "malloc_0"),
        (
            "/glibc/runtest.exe",
            "entry-static.exe",
            "mbsrtowcs_overflow",
        ),
        ("/glibc/runtest.exe", "entry-static.exe", "memmem_oob_read"),
        ("/glibc/runtest.exe", "entry-static.exe", "memmem_oob"),
        ("/glibc/runtest.exe", "entry-static.exe", "mkdtemp_failure"),
        ("/glibc/runtest.exe", "entry-static.exe", "mkstemp_failure"),
        ("/glibc/runtest.exe", "entry-static.exe", "printf_1e9_oob"),
        (
            "/glibc/runtest.exe",
            "entry-static.exe",
            "printf_fmt_g_round",
        ),
        (
            "/glibc/runtest.exe",
            "entry-static.exe",
            "printf_fmt_g_zeros",
        ),
        ("/glibc/runtest.exe", "entry-static.exe", "printf_fmt_n"),
        (
            "/glibc/runtest.exe",
            "entry-static.exe",
            "pthread_robust_detach",
        ),
        (
            "/glibc/runtest.exe",
            "entry-static.exe",
            "pthread_cancel_sem_wait",
        ),
        (
            "/glibc/runtest.exe",
            "entry-static.exe",
            "pthread_cond_smasher",
        ),
        (
            "/glibc/runtest.exe",
            "entry-static.exe",
            "pthread_condattr_setclock",
        ),
        (
            "/glibc/runtest.exe",
            "entry-static.exe",
            "pthread_exit_cancel",
        ),
        (
            "/glibc/runtest.exe",
            "entry-static.exe",
            "pthread_once_deadlock",
        ),
        (
            "/glibc/runtest.exe",
            "entry-static.exe",
            "pthread_rwlock_ebusy",
        ),
        (
            "/glibc/runtest.exe",
            "entry-static.exe",
            "putenv_doublefree",
        ),
        ("/glibc/runtest.exe", "entry-static.exe", "regex_backref_0"),
        (
            "/glibc/runtest.exe",
            "entry-static.exe",
            "regex_bracket_icase",
        ),
        (
            "/glibc/runtest.exe",
            "entry-static.exe",
            "regex_ere_backref",
        ),
        (
            "/glibc/runtest.exe",
            "entry-static.exe",
            "regex_escaped_high_byte",
        ),
        (
            "/glibc/runtest.exe",
            "entry-static.exe",
            "regex_negated_range",
        ),
        ("/glibc/runtest.exe", "entry-static.exe", "regexec_nosub"),
        (
            "/glibc/runtest.exe",
            "entry-static.exe",
            "rewind_clear_error",
        ),
        (
            "/glibc/runtest.exe",
            "entry-static.exe",
            "rlimit_open_files",
        ),
        (
            "/glibc/runtest.exe",
            "entry-static.exe",
            "scanf_bytes_consumed",
        ),
        (
            "/glibc/runtest.exe",
            "entry-static.exe",
            "scanf_match_literal_eof",
        ),
        (
            "/glibc/runtest.exe",
            "entry-static.exe",
            "scanf_nullbyte_char",
        ),
        ("/glibc/runtest.exe", "entry-static.exe", "setvbuf_unget"),
        (
            "/glibc/runtest.exe",
            "entry-static.exe",
            "sigprocmask_internal",
        ),
        ("/glibc/runtest.exe", "entry-static.exe", "sscanf_eof"),
        ("/glibc/runtest.exe", "entry-static.exe", "statvfs"),
        ("/glibc/runtest.exe", "entry-static.exe", "strverscmp"),
        (
            "/glibc/runtest.exe",
            "entry-static.exe",
            "syscall_sign_extend",
        ),
        ("/glibc/runtest.exe", "entry-static.exe", "uselocale_0"),
        (
            "/glibc/runtest.exe",
            "entry-static.exe",
            "wcsncpy_read_overflow",
        ),
        (
            "/glibc/runtest.exe",
            "entry-static.exe",
            "wcsstr_false_negative",
        ),
    ];

    let glibc_dynamic_tests = vec![
        ("/glibc/runtest.exe", "entry-dynamic.exe", "argv"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "basename"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "clocale_mbfuncs"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "clock_gettime"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "dirname"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "dlopen"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "env"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "fdopen"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "fnmatch"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "fscanf"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "fwscanf"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "iconv_open"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "inet_pton"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "mbc"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "memstream"),
        (
            "/glibc/runtest.exe",
            "entry-dynamic.exe",
            "pthread_cancel_points",
        ),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "pthread_cancel"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "pthread_cond"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "pthread_tsd"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "qsort"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "random"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "search_hsearch"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "search_insque"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "search_lsearch"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "search_tsearch"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "sem_init"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "setjmp"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "snprintf"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "socket"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "sscanf"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "sscanf_long"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "stat"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "strftime"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "string"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "string_memcpy"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "string_memmem"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "string_memset"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "string_strchr"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "string_strcspn"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "string_strstr"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "strptime"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "strtod"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "strtod_simple"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "strtof"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "strtol"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "strtold"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "swprintf"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "tgmath"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "time"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "tls_init"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "tls_local_exec"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "udiv"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "ungetc"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "utime"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "wcsstr"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "wcstol"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "daemon_failure"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "dn_expand_empty"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "dn_expand_ptr_0"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "fflush_exit"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "fgets_eof"),
        (
            "/glibc/runtest.exe",
            "entry-dynamic.exe",
            "fgetwc_buffering",
        ),
        (
            "/glibc/runtest.exe",
            "entry-dynamic.exe",
            "fpclassify_invalid_ld80",
        ),
        (
            "/glibc/runtest.exe",
            "entry-dynamic.exe",
            "ftello_unflushed_append",
        ),
        (
            "/glibc/runtest.exe",
            "entry-dynamic.exe",
            "getpwnam_r_crash",
        ),
        (
            "/glibc/runtest.exe",
            "entry-dynamic.exe",
            "getpwnam_r_errno",
        ),
        (
            "/glibc/runtest.exe",
            "entry-dynamic.exe",
            "iconv_roundtrips",
        ),
        (
            "/glibc/runtest.exe",
            "entry-dynamic.exe",
            "inet_ntop_v4mapped",
        ),
        (
            "/glibc/runtest.exe",
            "entry-dynamic.exe",
            "inet_pton_empty_last_field",
        ),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "iswspace_null"),
        (
            "/glibc/runtest.exe",
            "entry-dynamic.exe",
            "lrand48_signextend",
        ),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "lseek_large"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "malloc_0"),
        (
            "/glibc/runtest.exe",
            "entry-dynamic.exe",
            "mbsrtowcs_overflow",
        ),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "memmem_oob_read"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "memmem_oob"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "mkdtemp_failure"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "mkstemp_failure"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "printf_1e9_oob"),
        (
            "/glibc/runtest.exe",
            "entry-dynamic.exe",
            "printf_fmt_g_round",
        ),
        (
            "/glibc/runtest.exe",
            "entry-dynamic.exe",
            "printf_fmt_g_zeros",
        ),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "printf_fmt_n"),
        (
            "/glibc/runtest.exe",
            "entry-dynamic.exe",
            "pthread_robust_detach",
        ),
        (
            "/glibc/runtest.exe",
            "entry-dynamic.exe",
            "pthread_cond_smasher",
        ),
        (
            "/glibc/runtest.exe",
            "entry-dynamic.exe",
            "pthread_condattr_setclock",
        ),
        (
            "/glibc/runtest.exe",
            "entry-dynamic.exe",
            "pthread_exit_cancel",
        ),
        (
            "/glibc/runtest.exe",
            "entry-dynamic.exe",
            "pthread_once_deadlock",
        ),
        (
            "/glibc/runtest.exe",
            "entry-dynamic.exe",
            "pthread_rwlock_ebusy",
        ),
        (
            "/glibc/runtest.exe",
            "entry-dynamic.exe",
            "putenv_doublefree",
        ),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "regex_backref_0"),
        (
            "/glibc/runtest.exe",
            "entry-dynamic.exe",
            "regex_bracket_icase",
        ),
        (
            "/glibc/runtest.exe",
            "entry-dynamic.exe",
            "regex_ere_backref",
        ),
        (
            "/glibc/runtest.exe",
            "entry-dynamic.exe",
            "regex_escaped_high_byte",
        ),
        (
            "/glibc/runtest.exe",
            "entry-dynamic.exe",
            "regex_negated_range",
        ),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "regexec_nosub"),
        (
            "/glibc/runtest.exe",
            "entry-dynamic.exe",
            "rewind_clear_error",
        ),
        (
            "/glibc/runtest.exe",
            "entry-dynamic.exe",
            "rlimit_open_files",
        ),
        (
            "/glibc/runtest.exe",
            "entry-dynamic.exe",
            "scanf_bytes_consumed",
        ),
        (
            "/glibc/runtest.exe",
            "entry-dynamic.exe",
            "scanf_match_literal_eof",
        ),
        (
            "/glibc/runtest.exe",
            "entry-dynamic.exe",
            "scanf_nullbyte_char",
        ),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "setvbuf_unget"),
        (
            "/glibc/runtest.exe",
            "entry-dynamic.exe",
            "sigprocmask_internal",
        ),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "sscanf_eof"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "statvfs"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "strverscmp"),
        (
            "/glibc/runtest.exe",
            "entry-dynamic.exe",
            "syscall_sign_extend",
        ),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "tls_get_new_dtv"),
        ("/glibc/runtest.exe", "entry-dynamic.exe", "uselocale_0"),
        (
            "/glibc/runtest.exe",
            "entry-dynamic.exe",
            "wcsncpy_read_overflow",
        ),
        (
            "/glibc/runtest.exe",
            "entry-dynamic.exe",
            "wcsstr_false_negative",
        ),
    ];

    for tests in vec![glibc_static_tests, glibc_dynamic_tests] {
        for (runtest, entry, test_name) in tests {
            let test_dir = glibc_home_dir.clone();
            if !exclude
                .iter()
                .any(|&(ex_runtest, ex_entry, ex_test_name, ref ex_dir)| {
                    ex_runtest == runtest
                        && ex_entry == entry
                        && ex_test_name == test_name
                        && ex_dir == &test_dir
                })
            {
                command(
                    &alloc::format!("{} -w {} {}", runtest, entry, test_name),
                    test_dir,
                )
                .await;
            }
        }
    }
}

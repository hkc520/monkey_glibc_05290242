#![allow(dead_code)]
#![allow(unused_imports)]
use crate::tasks::current_user_task;
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

pub fn set_libc_path(path: String) {
    *LIBC_PATH.lock() = path;
}

pub fn get_libc_path() -> String {
    LIBC_PATH.lock().clone()
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
    let mut args: Vec<&str> = cmd.split(" ").filter(|x| *x != "").collect();
    debug!("cmd: {}  args: {:?}", cmd, args);
    let filename = args.drain(..1).last().unwrap();
    match File::open(filename.into(), OpenFlags::O_RDONLY) {
        Ok(_) => {
            info!("exec: {}", filename);
            let mut args_extend = vec![filename];
            args_extend.extend(args.into_iter());
            // 在这里克隆 work_dir，以便后续使用
            let work_dir_clone = work_dir.clone();
            // Use custom working directory to create task
            let curr_task = current_task();
            let task = UserTask::new(Weak::new(), work_dir);
            task.before_run();
            exec_with_process(
                task.clone(),
                work_dir_clone, // 使用传入的工作目录，而不是空的PathBuf
                String::from(filename),
                args_extend.into_iter().map(String::from).collect(),
                Vec::<&str>::new().into_iter().map(String::from).collect(),
            )
            .await
            .expect("can't add task to excutor");
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
        }
        Err(_) => {
            println!("unknown command: {}", cmd);
        }
    }
}

pub async fn initproc() {
    set_libc_path("/musl/lib/libc.so".to_string());
    println!("start kernel tasks");
    //command("/musl/busybox ls /").await;
    //command("/musl/busybox ls /bin").await;
    //command("/musl/runtest.exe -w entry-dynamic.exe argv").await;
    //command("/musl/entry-dynamic.exe argv").await;
    //command("/musl/busybox echo run time-test").await;
    //command("/musl/time-test").await;

    //command("/musl/busybox sh basic/run-all.sh").await;
    //command("busybox echo run netperf_testcode.sh").await;
    // command("busybox sh netperf_testcode.sh").await;

    //command("busybox echo run busybox_testcode.sh").await;
    // command("busybox sh busybox_testcode.sh").await;

    // command("busybox echo run libctest_testcode.sh").await;
    //command("/musl/busybox sh ").await;
    // command("runtest.exe -w entry-static.exe utime").await;
    // command("busybox ln -s /busybox /bin/cat").await;
    // command("./bin/cat libctest_testcode.sh").await;
    // command("busybox ls -l /bin").await;
    // command("busybox ln -s /busybox /bin/ln").await;
    // command("busybox ln -s /busybox /bin/wget").await;
    // command("busybox ln -s /busybox /bin/xz").await;
    // command("busybox ls -l /bin").await;
    // command("busybox sh init.sh").await;
    ///command("/musl/busybox ls -l /bin").await;
    //let home_dir = PathBuf::from("/");
    // command(
    //     "/musl/busybox ln -sf /musl/busybox /bin/ls",
    //     home_dir.clone(),
    // )
    // .await;
    //let home_dir = PathBuf::from("/musl");

    /*command(
        "/musl/busybox ln -s /musl/busybox /bin/ls",
        home_dir.clone(),
    )
    .await;*/
    let home_dir = PathBuf::from("/musl/basic");
    command("/musl/busybox sh ", home_dir.clone()).await;

    /*  command(
        "/musl/busybox echo #### OS COMP TEST GROUP START basic-musl-musl ####",
        home_dir.clone(),
    )
    .await;
    command("/musl/busybox sh /musl/basic/run-all.sh", home_dir.clone()).await;
    command(
        "/musl/busybox echo #### OS COMP TEST GROUP END basic-musl-musl ####",
        home_dir.clone(),
    )
    .await;*/
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
        command("/musl/busybox sh libctest_testcode.sh", home_dir.clone()).await;
        command("/musl/busybox sh busybox_testcode.sh", home_dir.clone()).await;
        command("/musl/busybox sh lua_testcode.sh", home_dir.clone()).await;
        command("/musl/busybox sh run-dynamic-all.sh", home_dir.clone()).await;
        command("/musl/busybox sh run-static-all.sh", home_dir.clone()).await;
        command("/musl/busybox sh run-dynamic.sh", home_dir.clone()).await;
        command("/musl/busybox sh run-static.sh", home_dir.clone()).await;
        command("/musl/busybox sh cyclictest_testcode.sh", home_dir.clone()).await;
        // command("/musl/busybox sh unixbench_testcode.sh", home_dir.clone()).await;
        //command("/musl/busybox sh lmbench_testcode.sh", home_dir.clone()).await;
        // command("/musl/busybox sh iperf_testcode.sh", home_dir.clone()).await;
        // command("/musl/busybox sh multi.sh", home_dir.clone()).await;
        // command("/musl/busybox sh iozone_testcode.sh", home_dir.clone()).await;
    
    //command("/musl/busybox sh basic_testcode.sh", home_dir.clone()).await;

    // command("/musl/busybox sh", home_dir.clone()).await;
    //let home_dir = PathBuf::from("/glibc");
    //command("/glibc/busybox sh", home_dir.clone()).await;
    /*command("/glibc/busybox sh libctest_testcode.sh", home_dir.clone()).await;
    command("/glibc/busybox sh busybox_testcode.sh", home_dir.clone()).await;
    command("/glibc/busybox sh cyclictest_testcode.sh", home_dir.clone()).await;
    command("/glibc/busybox sh unixbench_testcode.sh", home_dir.clone()).await;
    command("/glibc/busybox sh lmbench_testcode.sh", home_dir.clone()).await;
    command("/glibc/busybox sh run-dynamic.sh", home_dir.clone()).await;
    command("/glibc/busybox sh run-static.sh", home_dir.clone()).await;
    command("/glibc/busybox sh run-dynamic-all.sh", home_dir.clone()).await;
    command("/glibc/busybox sh iperf_testcode.sh", home_dir.clone()).await;
    command("/glibc/busybox sh multi.sh", home_dir.clone()).await;
    command("/glibc/busybox sh libctest_testcode.sh", home_dir.clone()).await;
    command("/glibc/busybox sh run-dynamic-all.sh", home_dir.clone()).await;
    command("/glibc/busybox sh run-static-all.sh", home_dir.clone()).await;
    command("/glibc/busybox sh iozone_testcode.sh", home_dir.clone()).await;
    command("/glibc/busybox sh lua_testcode.sh", home_dir.clone()).await;
    command("/glibc/busybox sh basic_testcode.sh", home_dir.clone()).await;*/

    //command("/musl/busybox sh", home_dir.clone()).await;

    //command("/musl/busybox sh /musl/libctest_testcode.sh").await; //有错误
    //command("busybox sh libctest_testcode.sh");
    // Get the current user task
    //command("/musl/busybox sh run-dynamic.sh", home_dir.clone()).await;
    // Execute the script with relative paths
    // Execute the script with relative paths
    // 获取当前用户任务
    //let current_task = current_user_task();
    // 打开 /musl 目录
    // let musl_dir = File::open("/musl".into(), OpenFlags::O_DIRECTORY).expect("无法打开musl目录");
    // 将当前目录设置为 /musl
    // current_task.pcb.lock().curr_dir = Arc::new(musl_dir);
    // 执行脚本，使用相对路径
    // command("./busybox sh ./basic_testcode.sh").await;
    // command("/musl/busybox sh -c 'cd /musl && ./busybox sh ./basic_testcode.sh'").await;
    // command("busybox init").await;
    // command("busybox sh").await;
    // command("busybox sh init.sh").await;

    // command("busybox echo run cyclic_testcode.sh").await;
    // command("busybox sh cyclictest_testcode.sh").await;
    // kill_all_tasks().await;

    // command("busybox echo run iperf_testcode.sh").await;
    // command("busybox sh iperf_testcode.sh").await;
    // kill_all_tasks().await;

    // command("busybox echo run iozone_testcode.sh").await;
    // command("busybox sh iozone_testcode.sh ").await;

    // command("busybox echo run lmbench_testcode.sh").await;
    // command("busybox sh lmbench_testcode.sh").await;

    // command("busybox echo run unixbench_testcode.sh").await;
    // command("busybox sh unixbench_testcode.sh").await;

    // command("copy-file-range-test-1").await;
    // command("copy-file-range-test-2").await;
    // command("copy-file-range-test-3").await;
    // command("copy-file-range-test-4").await;
    // command("interrupts-test-1").await;
    // command("interrupts-test-2").await;

    // switch_to_kernel_page_table();
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

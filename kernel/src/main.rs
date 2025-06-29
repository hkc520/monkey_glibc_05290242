#![no_main]
#![no_std]
#![feature(extract_if)]
#![feature(async_closure)]
#![feature(let_chains)]

// include modules drivers
// mod drivers;
include!(concat!(env!("OUT_DIR"), "/drivers.rs"));

#[macro_use]
extern crate alloc;
#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate log;
#[macro_use]
extern crate polyhal;
#[macro_use]
extern crate cfg_if;

extern crate polyhal_boot;
extern crate polyhal_trap;

#[macro_use]
mod logging;

mod consts;
mod panic;
mod socket;
mod syscall;
mod tasks;
mod user;
mod utils;

use crate::tasks::current_user_task;
use crate::user::task_ilegal;
// use alloc::sync::Arc;
use core::hint::spin_loop;
use devices::{self, get_int_device, PAGE_SIZE, VIRT_ADDR_START};
use executor::current_task;
use fs::file::File;
use fs::FileType;
use polyhal::common::PageAlloc;
use polyhal::irq::IRQ;
use polyhal::mem::{get_fdt, get_mem_areas};
use polyhal::{va, PhysAddr};
use polyhal_trap::trap::TrapType;
use polyhal_trap::trapframe::{TrapFrame, TrapFrameArgs};
use runtime::frame::{frame_alloc_persist, frame_unalloc};
use tasks::UserTask;
use user::user_cow_int;
use vfscore::OpenFlags;

pub struct PageAllocImpl;

impl PageAlloc for PageAllocImpl {
    #[inline]
    fn alloc(&self) -> PhysAddr {
        unsafe { frame_alloc_persist().expect("can't alloc frame") }
    }

    #[inline]
    fn dealloc(&self, paddr: PhysAddr) {
        unsafe {
            frame_unalloc(paddr);
            paddr.clear_len(PAGE_SIZE);
        }
    }
}

#[export_name = "_interrupt_for_arch"]
/// Handle kernel interrupt
fn kernel_interrupt(cx_ref: &mut TrapFrame, trap_type: TrapType) {
    match trap_type {
        TrapType::StorePageFault(addr)
        | TrapType::InstructionPageFault(addr)
        | TrapType::LoadPageFault(addr) => {
            if addr > VIRT_ADDR_START {
                panic!(
                    "kernel page error: {:#x} sepc: {:#x}",
                    addr,
                    cx_ref[TrapFrameArgs::SEPC]
                );
            }
            // judge whether it is trigger by a user_task handler.
            if let Some(task) = current_task().downcast_arc::<UserTask>().ok() {
                let cx_ref = task.force_cx_ref();
                if task.pcb.is_locked() {
                    // task.pcb.force_unlock();
                    unsafe {
                        task.pcb.force_unlock();
                    }
                }
                user_cow_int(task, cx_ref, va!(addr));
            } else {
                panic!("page fault: {:#x?}", trap_type);
            }
        }
        TrapType::IllegalInstruction(addr) => {
            if addr > VIRT_ADDR_START {
                return;
            }
            let task = current_user_task();
            warn!(
                "illegal instruction fault @ {:#x} paddr: {:?}",
                addr,
                task.page_table.translate(addr.into()),
            );
            warn!("the fault occurs @ {:#x}", cx_ref[TrapFrameArgs::SEPC]);
            // warn!("user_task map: {:#x?}", task.pcb.lock().memset);
            warn!(
                "mapped ppn addr: {:#x} @ {:?}",
                cx_ref[TrapFrameArgs::SEPC],
                task.page_table
                    .translate(cx_ref[TrapFrameArgs::SEPC].into())
            );
            task_ilegal(&task, va!(cx_ref[TrapFrameArgs::SEPC]), cx_ref);
            // panic!("illegal Instruction")
            // let signal = task.tcb.read().signal.clone();
            // if signal.has_sig(SignalFlags::SIGSEGV) {
            //     task.exit_with_signal(SignalFlags::SIGSEGV.num());
            // } else {
            //     return UserTaskControlFlow::Break
            // }
            // current_user_task()
            //     .tcb
            //     .write()
            //     .signal
            //     .add_signal(SignalFlags::SIGSEGV);
            // return UserTaskControlFlow::Break;
        }
        TrapType::SupervisorExternal => {
            get_int_device().try_handle_interrupt(u32::MAX);
        }
        _ => {
            // warn!("trap_type: {:?}  context: {:#x?}", trap_type, cx);
            // debug!("kernel_interrupt");
        }
    };
}

/// The kernel entry
fn main(hart_id: usize) {
    IRQ::int_disable();
    //println!("猴子1号，你好！");
    // Ensure this is the first core
    runtime::init();
    //println!("猴子1号，你好！");

    let str = include_str!("banner.txt");
    println!("{}", str);
    //println!("猴子1号，你好！");

    polyhal::common::init(&PageAllocImpl);
    get_mem_areas().cloned().for_each(|(start, size)| {
        info!("memory area: {:#x} - {:#x}", start, start + size);
        runtime::frame::add_frame_map(start, start + size);
    });

    println!("run kernel @ hart {}", hart_id);
    //println!("猴子1号，你好！");
    extern "C" {
        fn _start();
        fn _end();
    }
    info!(
        "program size: {}KB",
        (_start as usize - _end as usize) / 1024
    );

    // Boot all application core.
    // polyhal::multicore::MultiCore::boot_all();
    //println!("猴子1号，你好！");
    devices::prepare_drivers();

    if let Ok(fdt) = get_fdt() {
        for node in fdt.all_nodes() {
            devices::try_to_add_device(&node);
        }
    }
    //println!("猴子1号，你好！");
    // get devices and init
    devices::regist_devices_irq();

    // TODO: test ebreak
    // Instruction::ebreak();
    //println!("猴子1号，你好！");

    // initialize filesystem
    fs::init();
    // Note: /var/tmp is already mounted as RamFs in fs::init(), no need to create it manually
    // 输出根目录下的文件
    /*  println!("根目录下的文件列表：");
    let root_dir = File::open("/".into(), OpenFlags::O_DIRECTORY).expect("无法打开根目录");
    match root_dir.read_dir() {
        Ok(entries) => {
            for entry in entries {
                println!(
                    "{} ({})",
                    entry.filename,
                    match entry.file_type {
                        FileType::File => "文件",
                        FileType::Directory => "目录",
                        FileType::Device => "设备",
                        FileType::Socket => "套接字",
                        FileType::Link => "链接",
                    }
                );
            }
        }
        Err(e) => println!("读取目录失败: {:?}", e),
    }
    // println!("猴子1号，你好！");
    // enable interrupts
    IRQ::int_enable();
    // println!("猴子2号，你好！");

    println!("musl目录内容：");
    let musl_dir = File::open("/musl".into(), OpenFlags::O_DIRECTORY).expect("无法打开musl目录");
    match musl_dir.read_dir() {
        Ok(entries) => {
            for entry in entries {
                println!(
                    "{} ({})",
                    entry.filename,
                    match entry.file_type {
                        FileType::File => "文件",
                        FileType::Directory => "目录",
                        FileType::Device => "设备",
                        FileType::Socket => "套接字",
                        FileType::Link => "链接",
                    }
                );
            }
        }
        Err(e) => println!("读取musl目录失败: {:?}", e),
    }
    println!("glibc目录内容：");
    let musl_dir = File::open("/glibc".into(), OpenFlags::O_DIRECTORY).expect("无法打开glibc目录");
    match musl_dir.read_dir() {
        Ok(entries) => {
            for entry in entries {
                println!(
                    "{} ({})",
                    entry.filename,
                    match entry.file_type {
                        FileType::File => "文件",
                        FileType::Directory => "目录",
                        FileType::Device => "设备",
                        FileType::Socket => "套接字",
                        FileType::Link => "链接",
                    }
                );
            }
        }
        Err(e) => println!("读取glibc目录失败: {:?}", e),
    }

    println!("musl basic目录内容：");
    let musl_dir =
        File::open("/musl/basic".into(), OpenFlags::O_DIRECTORY).expect("无法打开musl/basic目录");
    match musl_dir.read_dir() {
        Ok(entries) => {
            for entry in entries {
                println!(
                    "{} ({})",
                    entry.filename,
                    match entry.file_type {
                        FileType::File => "文件",
                        FileType::Directory => "目录",
                        FileType::Device => "设备",
                        FileType::Socket => "套接字",
                        FileType::Link => "链接",
                    }
                );
            }
        }
        Err(e) => println!("读取musl/basic目录失败: {:?}", e),
    }

    println!("musl lib目录内容：");
    let musl_dir =
        File::open("/musl/lib".into(), OpenFlags::O_DIRECTORY).expect("无法打开musl/lib目录");
    match musl_dir.read_dir() {
        Ok(entries) => {
            for entry in entries {
                println!(
                    "{} ({})",
                    entry.filename,
                    match entry.file_type {
                        FileType::File => "文件",
                        FileType::Directory => "目录",
                        FileType::Device => "设备",
                        FileType::Socket => "套接字",
                        FileType::Link => "链接",
                    }
                );
            }
        }
        Err(e) => println!("读取musl/lib目录失败: {:?}", e),
    }

    println!("musl/ltp目录内容：");
    let musl_dir =
        File::open("/musl/ltp".into(), OpenFlags::O_DIRECTORY).expect("无法打开musl/ltp目录");
    match musl_dir.read_dir() {
        Ok(entries) => {
            for entry in entries {
                println!(
                    "{} ({})",
                    entry.filename,
                    match entry.file_type {
                        FileType::File => "文件",
                        FileType::Directory => "目录",
                        FileType::Device => "设备",
                        FileType::Socket => "套接字",
                        FileType::Link => "链接",
                    }
                );
            }
        }
        Err(e) => println!("读取musl/ltp目录失败: {:?}", e),
    }*/
    //println!("bin目录内容：");
    /*  let musl_dir = File::open("/bin".into(), OpenFlags::O_DIRECTORY).expect("无法打开bin目录");
    match musl_dir.read_dir() {
        Ok(entries) => {
            for entry in entries {
                println!(
                    "{} ({})",
                    entry.filename,
                    match entry.file_type {
                        FileType::File => "文件",
                        FileType::Directory => "目录",
                        FileType::Device => "设备",
                        FileType::Socket => "套接字",
                        FileType::Link => "链接",
                    }
                );
            }
        }
        Err(e) => println!("读取bin目录失败: {:?}", e),
    }*/
    // cache task with task templates
    //tasks::exec::cache_task_template("/musl/busybox".into()).expect("can't cache task");
    // tasks::exec::cache_task_template("/runtest.exe".into()).expect("can't cache task");
    //  tasks::exec::cache_task_template("/entry-static.exe".into()).expect("can't cache task");
    //tasks::exec::cache_task_template("/musl/lib/libc.so".into()).expect("can't cache task");
    // tasks::exec::cache_task_template("/lua".into()).expect("can't cache task");tasks::exec::cache_task_template("/lmbench_all").expect("can't cache task");

    // init kernel threads and async executor
    //tasks::init();
    //log::info!("run tasks");
    // loop { arch::wfi() }
    tasks::init();
    log::info!("run tasks");
    //println!("猴子1000号，你好！");
    //let current_task = current_user_task();
    // Open the /musl directory
    //let musl_dir = File::open("/musl".into(), OpenFlags::O_DIRECTORY).expect("无法打开/musl目录");
    // Change the current directory to /musl
    //current_task.pcb.lock().curr_dir = Arc::new(musl_dir);
    tasks::run_tasks();

    println!("Task All Finished!");
}

fn secondary(hart_id: usize) {
    println!("run kernel @ hart {}", hart_id);
    // loop { arch::wfi() }
    // tasks::run_tasks();
    loop {
        spin_loop();
    }
}

polyhal_boot::define_entry!(main, secondary);

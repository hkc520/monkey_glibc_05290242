use std::{env, fs, path::PathBuf};

#[allow(unused_macros)]
macro_rules! display {
    ($fmt:expr) => (println!("cargo:warning={}", format!($fmt)));
    ($fmt:expr, $($arg:tt)*) => (println!(concat!("cargo:warning=", $fmt), $($arg)*));
}

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("can't find manifest dir"));

    // 生成空的 ramdisk 段，避免符号未定义
    fs::write(
        out_dir.join("inc.S"),
        ".section .data\n\
        .global ramdisk_start\n\
        .global ramdisk_end\n\
         .p2align 12\n\
         ramdisk_start:\n\
         .byte 0\n\
        ramdisk_end:",
    )
    .expect("can't write ram file to out_dir");

    println!("cargo:rerun-if-changed=build.rs");
    /*let out_dir = PathBuf::from(env::var("OUT_DIR").expect("can't find manifest dir"));
    let img_relative_path = env::var("MOUNT_IMG_PATH").unwrap_or("mount.img".into());
    let project_dir =
        PathBuf::from(env::var("ROOT_MANIFEST_DIR").expect("can't find manifest directory"));

    let img_path = project_dir.join(img_relative_path);
    let img_path = img_path.to_str().expect("can't build a valid img path");
    fs::write(
        out_dir.join("inc.S"),
        format!(
            ".section .data
    .global ramdisk_start
    .global ramdisk_end
    .p2align 12
    ramdisk_start:
    .incbin \"{img_path}\"
    ramdisk_end:"
        ),
    )
    .expect("can't write ram file to out_dir");

    // fs::write(path, contents)

    // write module configuration to OUT_PATH, then it will be included in the main.rs
    println!("cargo:rerun-if-env-changed=MOUNT_IMG_PATH");
    println!("cargo:rerun-if-changed=mount.img");
    println!("cargo:rerun-if-changed=build.rs");*/
}

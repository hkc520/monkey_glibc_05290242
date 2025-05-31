#![no_std]
#![feature(used_with_arg)]
#![feature(strict_provenance)]

extern crate alloc;
#[macro_use]
extern crate log;

pub mod virtio_blk;
pub mod virtio_impl;
pub mod virtio_input;
pub mod virtio_net;

use core::ptr::NonNull;

use alloc::vec;
use alloc::{sync::Arc, vec::Vec};
use devices::{
    device::{Driver, UnsupportedDriver},
    driver_define,
    fdt::Node,
    node_to_interrupts, VIRT_ADDR_START,
};
use virtio_drivers::transport::{
    mmio::{MmioTransport, VirtIOHeader},
    DeviceType, Transport,
};

#[cfg(target_arch = "loongarch64")]
use devices::ALL_DEVICES;
#[cfg(target_arch = "loongarch64")]
use virtio_drivers::transport::pci::bus::MmioCam;

#[cfg(target_arch = "loongarch64")]
use virtio_drivers::transport::pci::{
    bus::{BarInfo, Cam, Command, DeviceFunction, PciRoot},
    virtio_device_type, PciTransport,
};

#[cfg(target_arch = "loongarch64")]
use crate::virtio_impl::HalImpl;
#[cfg(target_arch = "loongarch64")]
use virtio_drivers::transport::pci::bus::MemoryBarType;

#[cfg(target_arch = "loongarch64")]
fn align_up(addr: u64, align: u64) -> u64 {
    (addr + align - 1) & !(align - 1)
}
#[cfg(target_arch = "loongarch64")]
fn assign_bars_with_pci_root(pci_root: &mut PciRoot<MmioCam>, device_function: DeviceFunction) {
    info!("Starting BAR allocation for device {}", device_function);

    let mut bar_index = 0;
    while bar_index < 6 {
        match pci_root.bar_info(device_function, bar_index) {
            Ok(bar_info) => match bar_info {
                BarInfo::Memory {
                    size,
                    address_type,
                    address,
                    ..
                } if size > 0 && address == 0 => {
                    if let Some(allocated_addr) = allocate_bar_address(size as u64) {
                        info!(
                            "Allocating BAR{}: size={}, address={:#x}",
                            bar_index, size, allocated_addr
                        );
                        match address_type {
                            MemoryBarType::Width32 => {
                                pci_root.set_bar_32(
                                    device_function,
                                    bar_index,
                                    allocated_addr as u32,
                                );
                                bar_index += 1;
                            }
                            MemoryBarType::Width64 => {
                                pci_root.set_bar_64(device_function, bar_index, allocated_addr);
                                bar_index += 2;
                            }
                            _ => {
                                info!("Unsupported memory BAR type for BAR{}", bar_index);
                                bar_index += 1;
                            }
                        }
                    } else {
                        error!("Failed to allocate address for BAR{}", bar_index);
                        bar_index += 1;
                    }
                }
                BarInfo::IO { size, address, .. } if size > 0 && address == 0 => {
                    if let Some(allocated_addr) = allocate_bar_address(size as u64) {
                        info!(
                            "Allocating I/O BAR{}: size={}, address={:#x}",
                            bar_index, size, allocated_addr
                        );
                        pci_root.set_bar_32(device_function, bar_index, allocated_addr as u32);
                    }
                    bar_index += 1;
                }
                _ => {
                    info!(
                        "BAR{} already allocated or size is 0: {:?}",
                        bar_index, bar_info
                    );
                    if bar_index > 0 {
                        if let Ok(prev_bar) = pci_root.bar_info(device_function, bar_index - 1) {
                            if prev_bar.takes_two_entries() {
                                info!(
                                    "BAR{} is high part of 64-bit BAR{}, skipping",
                                    bar_index,
                                    bar_index - 1
                                );
                                bar_index += 1;
                                continue;
                            }
                        }
                    }
                    bar_index += 1;
                }
            },
            Err(e) => {
                info!("BAR{} not available: {:?}", bar_index, e);
                bar_index += 1;
            }
        }
    }
    info!("BAR allocation completed for device {}", device_function);
}
pub fn init_mmio(node: &Node) -> Arc<dyn Driver> {
    if let Some(reg) = node.reg().and_then(|mut reg| reg.next()) {
        let paddr = reg.address as usize;
        let vaddr = VIRT_ADDR_START + paddr;
        let header = NonNull::new(vaddr as *mut VirtIOHeader).unwrap();
        if let Ok(transport) = unsafe { MmioTransport::new(header) } {
            info!(
                "Detected virtio MMIO device with
                    vendor id {:#X}
                    device type {:?}
                    version {:?}
                    addr @ {:#X}
                    interrupt: {:?}",
                transport.vendor_id(),
                transport.device_type(),
                transport.version(),
                vaddr,
                node.interrupts().unwrap().flatten().collect::<Vec<u32>>()
            );
            return virtio_device(transport, node);
        }
    }
    Arc::new(UnsupportedDriver)
}

fn virtio_device(transport: MmioTransport, node: &Node) -> Arc<dyn Driver> {
    let irqs = node_to_interrupts(node);
    match transport.device_type() {
        DeviceType::Block => virtio_blk::init(transport, irqs),
        DeviceType::Input => virtio_input::init(transport, irqs),
        DeviceType::Network => virtio_net::init(transport, irqs),
        device_type => {
            warn!("Unrecognized virtio device: {:?}", device_type);
            Arc::new(UnsupportedDriver)
        }
    }
}
#[cfg(target_arch = "loongarch64")]
static mut NEXT_BAR_ADDR: u64 = 0x5800_0000; // Use Memory32 space start

#[cfg(target_arch = "loongarch64")]
const LOONGARCH64_PCI_MEMORY32_START: u64 = 0x5800_0000;
#[cfg(target_arch = "loongarch64")]
const LOONGARCH64_PCI_MEMORY32_END: u64 = 0x8000_0000;
#[cfg(target_arch = "loongarch64")]
const LOONGARCH64_PCI_MEMORY64_START: u64 = 0x1000_0000_0000;

#[cfg(target_arch = "loongarch64")]
fn allocate_bar_address(size: u64) -> Option<u64> {
    unsafe {
        let aligned_addr = align_up(NEXT_BAR_ADDR, size);

        // Check if it fits in Memory32 range
        if aligned_addr + size <= LOONGARCH64_PCI_MEMORY32_END {
            NEXT_BAR_ADDR = aligned_addr + size;
            Some(aligned_addr)
        } else {
            // Switch to Memory64 space if Memory32 is exhausted
            if NEXT_BAR_ADDR < LOONGARCH64_PCI_MEMORY64_START {
                NEXT_BAR_ADDR = LOONGARCH64_PCI_MEMORY64_START;
                let aligned_addr = align_up(NEXT_BAR_ADDR, size);
                NEXT_BAR_ADDR = aligned_addr + size;
                Some(aligned_addr)
            } else {
                None
            }
        }
    }
}
#[cfg(target_arch = "loongarch64")]
fn enumerate_pci(mmconfig_base: *mut u8) {
    info!("Starting enhanced PCI enumeration with debugging...");

    // 1. 验证地址转换
    verify_address_translation(mmconfig_base);

    let mut pci_root = unsafe { PciRoot::<MmioCam>::new(MmioCam::new(mmconfig_base, Cam::Ecam)) };

    for (device_function, info) in pci_root.enumerate_bus(0) {
        if let Some(virtio_type) = virtio_device_type(&info) {
            info!(
                "Found VirtIO device: {:?} at {}",
                virtio_type, device_function
            );

            // 分配 BAR
            assign_bars_with_pci_root(&mut pci_root, device_function);

            // 启用设备
            pci_root.set_command(
                device_function,
                Command::IO_SPACE | Command::MEMORY_SPACE | Command::BUS_MASTER,
            );
            // 2. 验证 PCI 配置
            verify_pci_configuration(&mut pci_root, device_function);
            // 3. 创建 Transport 并测试寄存器访问
            let mut transport =
                match PciTransport::new::<HalImpl, MmioCam>(&mut pci_root, device_function) {
                    Ok(transport) => transport,
                    Err(e) => {
                        error!(
                            "Failed to create PCI transport for {}: {:?}",
                            device_function, e
                        );
                        continue; // Skip this device and continue with others
                    }
                };
            test_register_access(&mut transport);
            virtio_device_probe(transport);
        }
    }
}
#[cfg(target_arch = "loongarch64")]
fn verify_pci_configuration(pci_root: &mut PciRoot<MmioCam>, device_function: DeviceFunction) {
    let (status, command) = pci_root.get_status_command(device_function);
    info!(
        "PCI Config - Status: {:#x}, Command: {:#x}",
        status, command
    );

    let required_command = Command::MEMORY_SPACE | Command::BUS_MASTER;
    if !command.contains(required_command) {
        error!(
            "PCI Config - Missing required command bits: required={:?}, actual={:?}",
            required_command, command
        );
    }

    for bar_idx in 0..6 {
        match pci_root.bar_info(device_function, bar_idx) {
            Ok(bar_info) => {
                info!("PCI Config - BAR{}: {:?}", bar_idx, bar_info);

                if let BarInfo::Memory { address, size, .. } = bar_info {
                    if address != 0 && size > 0 {
                        info!(
                            "PCI Config - BAR{} mapped: addr={:#x}, size={}",
                            bar_idx, address, size
                        );

                        if address < 0x5800_0000
                            || (address >= 0x8000_0000 && address < 0x1000_0000_0000)
                        {
                            warn!(
                                "PCI Config - BAR{} address {:#x} outside expected ranges",
                                bar_idx, address
                            );
                        }
                    }
                }
            }
            Err(e) => info!("PCI Config - BAR{} error: {:?}", bar_idx, e),
        }
    }
}

#[cfg(target_arch = "loongarch64")]
fn test_register_access(transport: &mut PciTransport) {
    info!("Testing register access...");

    let device_features = transport.read_device_features();
    info!("Device features read: {:#018x}", device_features);

    let initial_status = transport.get_status();
    info!("Initial device status: {:?}", initial_status);

    transport.set_status(DeviceStatus::ACKNOWLEDGE);
    let after_ack = transport.get_status();
    info!("After ACKNOWLEDGE: {:?}", after_ack);

    if after_ack.contains(DeviceStatus::ACKNOWLEDGE) {
        info!("Register access test: ACKNOWLEDGE bit set successfully");
    } else {
        error!("Register access test: ACKNOWLEDGE bit NOT set - register write failed");
    }

    let device_type = transport.device_type();
    info!("Device type: {:?}", device_type);
}

#[cfg(target_arch = "loongarch64")]
fn verify_address_translation(mmconfig_base: *mut u8) {
    info!("Verifying address translation...");
    info!("MMCONFIG base: {:#x}", mmconfig_base as usize);

    unsafe {
        let test_ptr = mmconfig_base as *mut u32;
        let value = core::ptr::read_volatile(test_ptr);
        info!("MMCONFIG test read: {:#x}", value);
    }

    let test_paddr = 0x20004000u64;
    let expected_vaddr = test_paddr | 0x8000_0000_0000_0000;
    info!(
        "Address translation test: paddr={:#x} -> vaddr={:#x}",
        test_paddr, expected_vaddr
    );

    if expected_vaddr % 4 != 0 {
        error!(
            "Address alignment error: vaddr={:#x} not 4-byte aligned",
            expected_vaddr
        );
    }
}
#[cfg(target_arch = "loongarch64")]
use virtio_drivers::transport::DeviceStatus;
#[cfg(target_arch = "loongarch64")]
fn virtio_device_probe(transport: impl Transport + 'static) {
    let device = match transport.device_type() {
        DeviceType::Block => Some(virtio_blk::init(transport, Vec::new())),
        // DeviceType::Input => virtio_input::init(transport, Vec::new()),
        DeviceType::Network => Some(virtio_net::init(transport, Vec::new())),
        t => {
            warn!("Unrecognized virtio device: {:?}", t);
            None
        }
    };

    if let Some(device) = device {
        info!("is locked: {}", ALL_DEVICES.is_locked());
        ALL_DEVICES.lock().add_device(device);
    }
}

#[cfg(target_arch = "loongarch64")]
fn dump_bar_contents(root: &mut PciRoot<MmioCam>, device_function: DeviceFunction, bar_index: u8) {
    let bar_info = root.bar_info(device_function, bar_index).unwrap();
    info!("Dumping bar {}: {:#x?}", bar_index, bar_info);
    trace!("Dumping bar {}: {:#x?}", bar_index, bar_info);
    if let BarInfo::Memory { address, size, .. } = bar_info {
        let start = address as *const u8;
        unsafe {
            let mut buf = [0u8; 32];
            for i in 0..size / 32 {
                let ptr = start.add(i as usize * 32);
                core::ptr::copy(ptr, buf.as_mut_ptr(), 32);
                if buf.iter().any(|b| *b != 0xff) {
                    trace!("  {:?}: {:x?}", ptr, buf);
                }
            }
        }
    }
    info!("End of bar dump");
    trace!("End of dump");
}

#[cfg(not(any(target_arch = "loongarch64")))]
driver_define!("virtio,mmio", init_mmio);

#[cfg(target_arch = "loongarch64")]
driver_define!({
    info!("LoongArch64 VirtIO driver initialization starting");
    let uncached_addr = 0x2000_0000usize | 0x8000_0000_0000_0000usize;
    enumerate_pci(uncached_addr as _);
    info!("enumerate_pci call completed");
    None
});

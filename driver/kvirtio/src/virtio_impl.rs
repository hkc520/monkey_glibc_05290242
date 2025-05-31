use alloc::vec::Vec;
use core::ptr::NonNull;
use devices::{frame_alloc_much, utils::virt_to_phys, FrameTracker, Mutex, VIRT_ADDR_START};
use log::info;
use log::trace;
use virtio_drivers::{BufferDirection, Hal, PhysAddr};
static VIRTIO_CONTAINER: Mutex<Vec<FrameTracker>> = Mutex::new(Vec::new());

pub struct HalImpl;

unsafe impl Hal for HalImpl {
    fn dma_alloc(pages: usize, _direction: BufferDirection) -> (PhysAddr, NonNull<u8>) {
        info!("DEBUG: VirtIO DMA alloc requested for {} pages", pages);
        let trackers = frame_alloc_much(pages).expect("can't alloc page in virtio");
        let paddr = trackers[0].0;
        let vaddr = NonNull::new(paddr.get_mut_ptr()).unwrap();
        info!(
            "DEBUG: VirtIO DMA allocated - paddr={:#x}, vaddr={:#x}, pages={}",
            paddr.raw(),
            vaddr.as_ptr() as usize,
            pages
        );
        trace!("alloc DMA: paddr={:#x}, pages={:?}", paddr.raw(), trackers);
        VIRTIO_CONTAINER.lock().extend(trackers.into_iter());
        (paddr.raw(), vaddr)
    }

    unsafe fn dma_dealloc(paddr: PhysAddr, _vaddr: NonNull<u8>, pages: usize) -> i32 {
        trace!("dealloc DMA: paddr={:#x}, pages={}", paddr, pages);
        // VIRTIO_CONTAINER.lock().drain_filter(|x| {
        //     let phy_page = paddr as usize >> 12;
        //     let calc_page = usize::from(x.0);

        //     calc_page >= phy_page && calc_page - phy_page < pages
        // });
        VIRTIO_CONTAINER.lock().retain(|x| {
            let phy_page = paddr as usize >> 12;
            let calc_page = x.0.raw();

            !(phy_page..phy_page + pages).contains(&calc_page)
        });
        0
    }

    unsafe fn mmio_phys_to_virt(paddr: PhysAddr, _size: usize) -> NonNull<u8> {
        let vaddr = (usize::from(paddr) | 0x8000_0000_0000_0000) as *mut u8;
        info!("Mapping paddr {:#x} to vaddr {:#x}", paddr, vaddr as usize);

        // 尝试读取映射后的地址
        let test_read = core::ptr::read_volatile(vaddr as *const u32);
        info!("Test read from vaddr: {:#x}", test_read);

        NonNull::new(vaddr).unwrap()
    }

    unsafe fn share(buffer: NonNull<[u8]>, _direction: BufferDirection) -> PhysAddr {
        let raw_ptr = buffer.as_ptr() as *mut u8 as usize;
        // Nothing to do, as the host already has access to all memory.
        virt_to_phys(raw_ptr).unwrap_or(raw_ptr & (!VIRT_ADDR_START))
        // buffer.as_ptr() as *mut u8 as usize - VIRT_ADDR_START
    }

    unsafe fn unshare(_paddr: PhysAddr, _buffer: NonNull<[u8]>, _direction: BufferDirection) {
        // Nothing to do, as the host already has access to all memory and we didn't copy the buffer
        // anywhere else.
    }
}

use alloc::sync::Arc;
use alloc::vec::Vec;
use devices::device::{BlkDriver, DeviceType, Driver};
use devices::{register_device_irqs, Mutex};
use virtio_drivers::device::blk::VirtIOBlk;
use virtio_drivers::transport::Transport;

use super::virtio_impl::HalImpl;

pub struct VirtIOBlock<T: Transport> {
    inner: Mutex<VirtIOBlk<HalImpl, T>>,
    irqs: Vec<u32>,
}

unsafe impl<T: Transport> Sync for VirtIOBlock<T> {}
unsafe impl<T: Transport> Send for VirtIOBlock<T> {}

impl<T: Transport + 'static> Driver for VirtIOBlock<T> {
    fn interrupts(&self) -> &[u32] {
        &self.irqs
    }

    fn get_id(&self) -> &str {
        "virtio-blk"
    }

    fn get_device_wrapper(self: Arc<Self>) -> DeviceType {
        DeviceType::BLOCK(self.clone())
    }
}

impl<T: Transport + 'static> BlkDriver for VirtIOBlock<T> {
    fn read_blocks(&self, block_id: usize, buf: &mut [u8]) {
        self.inner
            .lock()
            .read_blocks(block_id, buf)
            .expect("can't read block by virtio block");
    }

    fn write_blocks(&self, block_id: usize, buf: &[u8]) {
        self.inner
            .lock()
            .write_blocks(block_id, buf)
            .expect("can't write block by virtio block");
    }

    fn capacity(&self) -> usize {
        self.inner.lock().capacity() as usize * 0x200
    }
}

pub fn init<T: Transport + 'static>(mut transport: T, irqs: Vec<u32>) -> Arc<dyn Driver> {
    info!("Starting VirtIO block device initialization");
    info!("IRQs: {:?}", irqs);

    // 验证transport状态
    info!("Transport device type: {:?}", transport.device_type());
    info!("Transport status: {:?}", transport.get_status());

    info!("About to create VirtIOBlk device...");
    let blk_device = match VirtIOBlk::<HalImpl, T>::new(transport) {
        Ok(device) => {
            info!("VirtIOBlk device created successfully");
            Arc::new(VirtIOBlock {
                inner: Mutex::new(device),
                irqs,
            })
        }
        Err(e) => {
            error!("Failed to create VirtIOBlk device: {:?}", e);
            panic!("VirtIOBlk device creation failed: {:?}", e);
        }
    };

    info!("VirtIO block device initialized successfully");
    blk_device
}

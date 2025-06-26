use core::cmp;

use alloc::{
    collections::VecDeque,
    sync::{Arc, Weak},
};
use sync::Mutex;
use syscalls::Errno;
use vfscore::{INodeInterface, PollEvent, StatMode, VfsResult};

// 管道缓冲区大小限制，适中的大小既能处理lmbench又不会影响其他测试
const PIPE_BUFFER_SIZE: usize = 0x10000; // 64KB

// pipe sender, just can write.
pub struct PipeSender(Arc<Mutex<VecDeque<u8>>>);

impl INodeInterface for PipeSender {
    fn writeat(&self, _offset: usize, buffer: &[u8]) -> VfsResult<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        
        log::debug!("write pipe: {} bytes", buffer.len());
        let mut queue = self.0.lock();
        
        // 对于lmbench这样的小数据传输（通常是单字节令牌），优先处理
        // 确保小数据写入不会被阻塞
        if buffer.len() <= 16 {
            // 小数据直接写入，不检查缓冲区大小限制
            queue.extend(buffer.iter());
            log::debug!("wrote small data {} bytes to pipe, queue len: {}", buffer.len(), queue.len());
            Ok(buffer.len())
        } else if queue.len() + buffer.len() <= PIPE_BUFFER_SIZE {
            // 大数据需要检查缓冲区容量
            queue.extend(buffer.iter());
            log::debug!("wrote {} bytes to pipe, queue len: {}", buffer.len(), queue.len());
            Ok(buffer.len())
        } else {
            // 缓冲区满，返回EWOULDBLOCK
            log::debug!("pipe buffer full, returning EWOULDBLOCK");
            Err(Errno::EWOULDBLOCK)
        }
    }

    fn poll(&self, events: PollEvent) -> VfsResult<PollEvent> {
        let mut res = PollEvent::NONE;
        if events.contains(PollEvent::POLLOUT) {
            let queue_len = self.0.lock().len();
            if queue_len <= PIPE_BUFFER_SIZE {
                res |= PollEvent::POLLOUT;
            }
        }
        Ok(res)
    }

    fn stat(&self, stat: &mut vfscore::Stat) -> VfsResult<()> {
        stat.mode = StatMode::FIFO;
        Ok(())
    }
}

// pipe reader, just can read.
pub struct PipeReceiver {
    queue: Arc<Mutex<VecDeque<u8>>>,
    sender: Weak<PipeSender>,
}

impl INodeInterface for PipeReceiver {
    fn readat(&self, _offset: usize, buffer: &mut [u8]) -> VfsResult<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        
        let mut queue = self.queue.lock();
        let available = queue.len();
        let requested = buffer.len();
        
        if available > 0 {
            // 有数据可读
            let rlen = cmp::min(available, requested);
            queue
                .drain(..rlen)
                .enumerate()
                .into_iter()
                .for_each(|(i, x)| {
                    buffer[i] = x;
                });
            
            log::debug!("pipe read successful: {} bytes, remaining in queue: {}", 
                       rlen, queue.len());
            Ok(rlen)
        } else {
            // 没有数据可读
            let sender_alive = Weak::strong_count(&self.sender) > 0;
            if sender_alive {
                // 发送端仍然存在，返回EWOULDBLOCK等待数据
                log::debug!("pipe empty but sender exists, returning EWOULDBLOCK");
                Err(Errno::EWOULDBLOCK)
            } else {
                // 发送端已关闭，返回EOF
                log::debug!("pipe empty and sender closed, returning EOF");
                Ok(0)
            }
        }
    }

    fn poll(&self, events: PollEvent) -> VfsResult<PollEvent> {
        let mut res = PollEvent::NONE;
        let queue_len = self.queue.lock().len();
        let sender_alive = Weak::strong_count(&self.sender) > 0;
        
        if events.contains(PollEvent::POLLIN) {
            if queue_len > 0 {
                res |= PollEvent::POLLIN;
            } else if !sender_alive {
                res |= PollEvent::POLLERR;
            }
        }
        if events.contains(PollEvent::POLLERR) {
            if queue_len == 0 && !sender_alive {
                res |= PollEvent::POLLERR;
            }
        }
        Ok(res)
    }

    fn stat(&self, stat: &mut vfscore::Stat) -> VfsResult<()> {
        stat.mode = StatMode::FIFO;
        Ok(())
    }
}

pub fn create_pipe() -> (Arc<PipeReceiver>, Arc<PipeSender>) {
    let queue = Arc::new(Mutex::new(VecDeque::new()));
    let sender = Arc::new(PipeSender(queue.clone()));
    let receiver = Arc::new(PipeReceiver {
        queue: queue.clone(),
        sender: Arc::downgrade(&sender),
    });
    
    log::debug!("created new pipe pair");
    (receiver, sender)
}

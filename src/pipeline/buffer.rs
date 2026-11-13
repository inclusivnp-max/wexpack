use super::{PipelineError, Result};
use crossbeam_channel::{Receiver, Sender, bounded, select};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use zeroize::Zeroize;

pub(super) struct Buffers {
    pub input: Vec<u8>,
    pub output: Vec<u8>,
}
struct Inner {
    sender: Sender<Buffers>,
    receiver: Receiver<Buffers>,
    sensitive: bool,
    capacity: usize,
    active: AtomicUsize,
    peak: AtomicUsize,
}
/// Fixed number of reusable input/output pairs. A lease remains live through
/// compression, result reordering and writing, so a slow first job bounds the tail.
#[derive(Clone)]
pub struct BufferPool {
    inner: Arc<Inner>,
}
impl BufferPool {
    pub fn new(slots: usize, max_chunk: usize, sensitive: bool) -> Result<Self> {
        if !(1..=256).contains(&slots)
            || max_chunk == 0
            || max_chunk > crate::format::MAX_CHUNK_SIZE as usize
        {
            return Err(PipelineError::ResourceLimit("buffer geometry"));
        }
        let (sender, receiver) = bounded(slots);
        for _ in 0..slots {
            let mut input = Vec::new();
            let mut output = Vec::new();
            input
                .try_reserve_exact(max_chunk)
                .map_err(|_| PipelineError::AllocationFailed)?;
            output
                .try_reserve_exact(max_chunk + (64 << 10))
                .map_err(|_| PipelineError::AllocationFailed)?;
            sender
                .try_send(Buffers { input, output })
                .map_err(|_| PipelineError::Cancelled)?;
        }
        Ok(Self {
            inner: Arc::new(Inner {
                sender,
                receiver,
                sensitive,
                capacity: slots,
                active: AtomicUsize::new(0),
                peak: AtomicUsize::new(0),
            }),
        })
    }
    pub fn capacity(&self) -> usize {
        self.inner.capacity
    }
    pub fn peak_inflight(&self) -> usize {
        self.inner.peak.load(Ordering::Relaxed)
    }
    pub(super) fn acquire(&self, cancel: &Receiver<()>) -> Result<BufferLease> {
        let buffers = select! {recv(cancel)->_=>return Err(PipelineError::Cancelled),recv(self.inner.receiver)->slot=>slot.map_err(|_|PipelineError::Cancelled)?};
        let active = self.inner.active.fetch_add(1, Ordering::Relaxed) + 1;
        self.inner.peak.fetch_max(active, Ordering::Relaxed);
        Ok(BufferLease {
            inner: self.inner.clone(),
            buffers: Some(buffers),
        })
    }
}
pub(super) struct BufferLease {
    inner: Arc<Inner>,
    buffers: Option<Buffers>,
}
impl BufferLease {
    pub fn buffers_mut(&mut self) -> &mut Buffers {
        self.buffers.as_mut().expect("live buffer lease")
    }
}
impl Drop for BufferLease {
    fn drop(&mut self) {
        if let Some(mut buffers) = self.buffers.take() {
            if self.inner.sensitive {
                buffers.input.zeroize();
                buffers.output.zeroize();
            } else {
                buffers.input.clear();
                buffers.output.clear();
            }
            self.inner.active.fetch_sub(1, Ordering::Relaxed);
            // The pool has exactly one credit per lease; returning never blocks.
            let _ = self.inner.sender.try_send(buffers);
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn leases_reuse_storage_clear_secrets_and_cancel() {
        let pool = BufferPool::new(1, 1024, true).unwrap();
        let (tx, rx) = bounded(0);
        let mut lease = pool.acquire(&rx).unwrap();
        lease.buffers_mut().input.extend_from_slice(b"secret");
        let pointer = lease.buffers_mut().input.as_ptr();
        drop(lease);
        let mut lease = pool.acquire(&rx).unwrap();
        assert_eq!(lease.buffers_mut().input.as_ptr(), pointer);
        assert!(lease.buffers_mut().input.is_empty());
        assert_eq!(pool.peak_inflight(), 1);
        drop(tx);
        assert!(pool.acquire(&rx).is_err());
        drop(lease);
    }
}

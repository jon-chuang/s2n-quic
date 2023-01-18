use alloc::sync::Arc;
use core::{
    cell::UnsafeCell,
    task::{Context, Poll},
};
use futures::ready;
use s2n_quic_core::{
    inet::{self, ExplicitCongestionNotification},
    io::{rx, tx},
    path::{Handle, LocalAddress},
    sync::spsc,
};

pub(crate) struct Shared<H> {
    pub(crate) handles: Box<[H]>,
    pub(crate) lens: Box<[u16]>,
    pub(crate) ecn: Box<[ExplicitCongestionNotification]>,
    pub(crate) data: Data,
}

pub(crate) struct Data {
    data: Box<[u8]>,
    segment_size: usize,
}

impl Data {
    pub fn payload(&self, idx: u32) -> &[u8] {
        let offset = idx as usize * self.segment_size;
        &self.data[offset..offset + self.segment_size]
    }

    pub fn payload_mut(&mut self, idx: u32) -> &mut [u8] {
        let offset = idx as usize * self.segment_size;
        &mut self.data[offset..offset + self.segment_size]
    }
}

pub struct Unfilled<H: Handle> {
    pub(crate) shared: Arc<UnsafeCell<Shared<H>>>,
    pub(crate) local: spsc::Receiver<u32>,
    pub(crate) remote: spsc::Sender<u32>,
    pub(crate) buffer: Option<u32>,
    pub(crate) sent: Vec<Entry<H>>,
}

unsafe impl<H: Handle> Send for Unfilled<H> {}
unsafe impl<H: Handle> Sync for Unfilled<H> {}

pub struct Error;

impl<H: Handle> Unfilled<H> {
    pub async fn ready(&mut self) -> Result<(), Error> {
        futures::future::poll_fn(|cx| {
            let _local = ready!(self.local.poll_slice(cx)).map_err(|_| Error)?;
            Ok(()).into()
        })
        .await
    }

    pub async fn tx_ready(&mut self) -> Result<(), Error> {
        futures::future::poll_fn(|cx| {
            // only poll if we don't have capacity
            if self.local.capacity() == 0 {
                let _local = ready!(self.local.poll_slice(cx)).map_err(|_| Error)?;
                Ok(()).into()
            } else {
                Poll::Pending
            }
        })
        .await
    }

    pub fn try_slice(&mut self) -> Result<UnfilledSlice<H>, Error> {
        let local = self.local.try_slice().map_err(|_| Error)?.ok_or(Error)?;
        let remote = self.remote.try_slice().map_err(|_| Error)?.ok_or(Error)?;
        self.sent.clear();
        let slice = UnfilledSlice {
            shared: &self.shared,
            buffer: &mut self.buffer,
            local,
            remote,
            sent: &mut self.sent,
        };
        Ok(slice)
    }

    pub fn poll_slice(&mut self, cx: &mut Context) -> Poll<Result<UnfilledSlice<H>, Error>> {
        let local = ready!(self.local.poll_slice(cx)).map_err(|_| Error)?;
        let remote = ready!(self.remote.poll_slice(cx)).map_err(|_| Error)?;
        self.sent.clear();
        let slice = UnfilledSlice {
            shared: &self.shared,
            buffer: &mut self.buffer,
            local,
            remote,
            sent: &mut self.sent,
        };
        Poll::Ready(Ok(slice))
    }
}

pub struct UnfilledSlice<'a, H: Handle> {
    pub(crate) shared: &'a UnsafeCell<Shared<H>>,
    pub(crate) buffer: &'a mut Option<u32>,
    pub(crate) local: spsc::RecvSlice<'a, u32>,
    pub(crate) remote: spsc::SendSlice<'a, u32>,
    pub(crate) sent: &'a mut Vec<Entry<H>>,
}

unsafe impl<'a, H: Handle> Send for UnfilledSlice<'a, H> {}
unsafe impl<'a, H: Handle> Sync for UnfilledSlice<'a, H> {}

impl<'a, H: Handle> UnfilledSlice<'a, H> {
    pub(crate) fn pop(&mut self) -> Option<u32> {
        if let Some(idx) = self.buffer.take() {
            Some(idx)
        } else {
            self.local.pop()
        }
    }
}

impl<'a, H: Handle> tx::Queue for UnfilledSlice<'a, H> {
    type Handle = H;
    type Entry = Entry<H>;

    fn len(&self) -> usize {
        self.sent.len()
    }

    fn capacity(&self) -> usize {
        self.remote.capacity().min(self.local.len())
    }

    fn as_slice_mut(&mut self) -> &mut [Self::Entry] {
        self.sent
    }

    fn push<M: tx::Message<Handle = Self::Handle>>(
        &mut self,
        mut message: M,
    ) -> Result<tx::Outcome, tx::Error> {
        let idx = self.pop().ok_or(tx::Error::AtCapacity)?;
        let shared = unsafe { &mut *self.shared.get() };
        let payload = shared.data.payload_mut(idx);
        let payload = tx::PayloadBuffer::new(payload);

        let len = match message.write_payload(payload, 0) {
            Ok(len) => len,
            Err(err) => {
                *self.buffer = Some(idx);
                return Err(err);
            }
        };

        {
            let idx = idx as usize;
            shared.lens[idx] = len as u16;
            shared.ecn[idx] = message.ecn();
            shared.handles[idx] = *message.path_handle();
        }

        let push_res = self.remote.push(idx);

        debug_assert!(push_res.is_ok(), "queue size mismatch");
        let index = self.sent.len();
        self.sent.push(Entry {
            ptr: self.shared as *const _,
            idx,
        });

        Ok(tx::Outcome { len, index })
    }
}

pub struct Entry<H: Handle> {
    ptr: *const UnsafeCell<Shared<H>>,
    idx: u32,
}

unsafe impl<H: Handle> Send for Entry<H> {}
unsafe impl<H: Handle> Sync for Entry<H> {}

impl<H: Handle> Entry<H> {
    pub(crate) fn handle(&self) -> &H {
        let shared = unsafe { &mut *(*self.ptr).get() };
        &shared.handles[self.idx as usize]
    }

    pub(crate) fn handle_mut(&mut self) -> &mut H {
        let shared = unsafe { &mut *(*self.ptr).get() };
        &mut shared.handles[self.idx as usize]
    }

    pub(crate) fn ecn(&self) -> &ExplicitCongestionNotification {
        let shared = unsafe { &mut *(*self.ptr).get() };
        &shared.ecn[self.idx as usize]
    }

    pub(crate) fn ecn_mut(&mut self) -> &mut ExplicitCongestionNotification {
        let shared = unsafe { &mut *(*self.ptr).get() };
        &mut shared.ecn[self.idx as usize]
    }

    pub(crate) fn payload(&self) -> &[u8] {
        let shared = unsafe { &mut *(*self.ptr).get() };
        let idx = self.idx;
        let len = shared.lens[idx as usize] as usize;
        &shared.data.payload(idx)[..len]
    }

    pub(crate) fn payload_mut(&mut self) -> &mut [u8] {
        let shared = unsafe { &mut *(*self.ptr).get() };
        let idx = self.idx;
        let len = shared.lens[idx as usize] as usize;
        &mut shared.data.payload_mut(idx)[..len]
    }
}

impl<H: Handle> tx::Entry for Entry<H> {
    type Handle = H;

    fn set<M: tx::Message<Handle = H>>(&mut self, _message: M) -> Result<usize, tx::Error> {
        todo!()
    }

    fn payload(&self) -> &[u8] {
        todo!()
    }

    fn payload_mut(&mut self) -> &mut [u8] {
        todo!()
    }
}

impl<H: Handle> rx::Entry for Entry<H> {
    type Handle = H;

    fn read(&mut self, _local: &LocalAddress) -> Option<(inet::Header<Self::Handle>, &mut [u8])> {
        let path = *self.handle();
        let ecn = *self.ecn();
        let header = inet::Header { path, ecn };
        let payload = self.payload_mut();
        Some((header, payload))
    }
}

pub struct Filled<H: Handle> {
    shared: Arc<UnsafeCell<Shared<H>>>,
    local: spsc::Receiver<u32>,
    remote: spsc::Sender<u32>,
    filled: Vec<Entry<H>>,
}

unsafe impl<H: Handle> Send for Filled<H> {}
unsafe impl<H: Handle> Sync for Filled<H> {}

pub struct FilledSlice<'a, H: Handle> {
    remote: spsc::SendSlice<'a, u32>,
    filled: &'a mut Vec<Entry<H>>,
}

unsafe impl<'a, H: Handle> Send for FilledSlice<'a, H> {}
unsafe impl<'a, H: Handle> Sync for FilledSlice<'a, H> {}

impl<H: Handle> Filled<H> {
    pub async fn ready(&mut self) -> Result<(), Error> {
        futures::future::poll_fn(|cx| {
            let _local = ready!(self.local.poll_slice(cx)).map_err(|_| Error)?;
            Ok(()).into()
        })
        .await
    }

    pub fn try_slice(&mut self) -> Result<FilledSlice<H>, Error> {
        let mut local = self.local.try_slice().map_err(|_| Error)?.ok_or(Error)?;
        let remote = self.remote.try_slice().map_err(|_| Error)?.ok_or(Error)?;
        let ptr = &*self.shared as *const UnsafeCell<Shared<H>>;

        while let Some(idx) = local.pop() {
            self.filled.push(Entry { ptr, idx });
        }

        Ok(FilledSlice {
            remote,
            filled: &mut self.filled,
        })
    }

    pub fn poll_slice(&mut self, cx: &mut Context) -> Poll<Result<FilledSlice<H>, Error>> {
        let mut local = ready!(self.local.poll_slice(cx)).map_err(|_| Error)?;
        let remote = ready!(self.remote.poll_slice(cx)).map_err(|_| Error)?;

        let ptr = &*self.shared as *const UnsafeCell<Shared<H>>;

        while let Some(idx) = local.pop() {
            self.filled.push(Entry { ptr, idx });
        }

        Poll::Ready(Ok(FilledSlice {
            remote,
            filled: &mut self.filled,
        }))
    }
}

impl<'a, H: Handle> rx::Queue for FilledSlice<'a, H> {
    type Entry = Entry<H>;
    type Handle = H;

    fn local_address(&self) -> LocalAddress {
        Default::default()
    }

    fn len(&self) -> usize {
        self.filled.len()
    }

    fn finish(&mut self, count: usize) {
        for entry in self.filled.drain(..count) {
            let _ = self.remote.push(entry.idx);
        }
    }

    fn as_slice_mut(&mut self) -> &mut [Self::Entry] {
        self.filled
    }
}

pub fn pair<H: Default + Handle>(segment_size: u16, count: u16) -> (Unfilled<H>, Filled<H>) {
    let segment_size = segment_size as usize;
    let count = count as usize;

    let shared = Shared {
        handles: vec![Default::default(); count].into(),
        lens: vec![0; count].into(),
        ecn: vec![ExplicitCongestionNotification::default(); count].into(),
        data: Data {
            data: vec![0; segment_size * count].into(),
            segment_size,
        },
    };
    let shared = Arc::new(UnsafeCell::new(shared));

    let (filled_send, filled_recv) = spsc::channel(count);
    let (mut unfilled_send, unfilled_recv) = spsc::channel(count);

    // put all of the messages in the "unfilled" queue
    let mut unfilled = 0..count as u32;
    unfilled_send
        .try_slice()
        .unwrap()
        .unwrap()
        .extend(&mut unfilled)
        .unwrap();

    let unfilled = Unfilled {
        shared: shared.clone(),
        local: unfilled_recv,
        remote: filled_send,
        buffer: None,
        sent: Vec::with_capacity(count),
    };

    let filled = Filled {
        shared,
        local: filled_recv,
        remote: unfilled_send,
        filled: Vec::with_capacity(count),
    };

    (unfilled, filled)
}

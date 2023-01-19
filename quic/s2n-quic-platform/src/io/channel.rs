use core::{
    cmp::Ordering,
    fmt,
    task::{Context, Poll},
};
use futures::ready;
use s2n_quic_core::{
    inet::{self, ExplicitCongestionNotification},
    io::{rx, tx},
    path::Handle,
    sync::spsc,
};
use std::collections::BinaryHeap;

pub struct Entry<H: Handle>(pub(crate) Box<InnerEntry<H>>);

pub(crate) struct InnerEntry<H> {
    pub(crate) handle: H,
    pub(crate) ecn: ExplicitCongestionNotification,
    pub(crate) payload: Buffer,
    pub(crate) id: u16,
    pub(crate) queue: u16,
}

impl<H: Handle> Entry<H> {
    #[inline]
    pub fn handle(&self) -> &H {
        &self.0.handle
    }

    #[inline]
    pub fn handle_mut(&mut self) -> &mut H {
        &mut self.0.handle
    }

    #[inline]
    pub fn ecn(&self) -> &ExplicitCongestionNotification {
        &self.0.ecn
    }

    #[inline]
    pub fn ecn_mut(&mut self) -> &mut ExplicitCongestionNotification {
        &mut self.0.ecn
    }

    #[inline]
    pub fn payload(&self) -> &Buffer {
        &self.0.payload
    }

    #[inline]
    pub fn payload_mut(&mut self) -> &mut Buffer {
        &mut self.0.payload
    }

    #[inline]
    fn can_gso<M: tx::Message<Handle = H>>(&self, msg: &mut M) -> bool {
        let payload = &self.0.payload;

        // the first message can always be written
        if payload.segment_size == 0 {
            return true;
        }

        msg.can_gso(payload.segment_size as _, payload.segment_count as _)
            && self.0.ecn == msg.ecn()
            && self.0.handle.strict_eq(msg.path_handle())
    }
}

impl<H: Handle> Drop for Entry<H> {
    fn drop(&mut self) {
        // TODO panic in debug mode if the storage isn't shut down
    }
}

pub struct Buffer {
    pub(crate) data: Box<[u8]>,
    pub(crate) segment_size: u16,
    pub(crate) segment_count: u16,
    pub(crate) segment_write_cursor: u16,
    pub(crate) segment_read_cursor: u16,
}

impl fmt::Debug for Buffer {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Buffer")
            .field("segment_size", &self.segment_size)
            .field("segment_count", &self.segment_count)
            .field("segment_write_cursor", &self.segment_write_cursor)
            .field("segment_read_cursor", &self.segment_read_cursor)
            .finish()
    }
}

impl Buffer {
    pub fn new(max_payload: u16) -> Self {
        let data = vec![0u8; max_payload as usize].into();
        Self {
            data,
            segment_size: 0,
            segment_count: 0,
            segment_write_cursor: 0,
            segment_read_cursor: 0,
        }
    }

    pub fn reset(&mut self) {
        self.segment_size = 0;
        self.segment_count = 0;
        self.segment_write_cursor = 0;
        self.segment_read_cursor = 0;
        self.invariants();
    }

    pub fn segments(&self) -> impl Iterator<Item = &[u8]> {
        let start = self.segment_read_cursor as usize;
        let end = self.segment_write_cursor as usize;
        self.data[start..end].chunks(self.segment_size as usize)
    }

    pub fn segments_mut(&mut self) -> impl Iterator<Item = &mut [u8]> {
        let start = self.segment_read_cursor as usize;
        let end = self.segment_write_cursor as usize;
        self.data[start..end].chunks_mut(self.segment_size as usize)
    }

    #[inline]
    pub fn invariants(&self) {
        if !cfg!(debug_assertions) {
            return;
        }

        if self.segment_count > 0 {
            assert_ne!(self.segment_size, 0, "invalid segment size {:?}", self);
            assert_ne!(
                self.segment_write_cursor, 0,
                "invalid write cursor {:?}",
                self
            );
        } else {
            assert_eq!(self.segment_size, 0, "invalid segment size {:?}", self);
            assert_eq!(
                self.segment_write_cursor, 0,
                "invalid write cursor {:?}",
                self
            );
            assert_eq!(
                self.segment_read_cursor, 0,
                "invalid read cursor {:?}",
                self
            );
        }

        assert!(self.segment_write_cursor >= self.segment_read_cursor);
    }
}

pub struct Unfilled<H: Handle> {
    pub(crate) local: spsc::Receiver<Entry<H>>,
    pub(crate) remote: spsc::Sender<Entry<H>>,
    pub(crate) buffer: Option<Entry<H>>,
}

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
        let slice = UnfilledSlice {
            buffer: &mut self.buffer,
            local,
            remote,
        };
        Ok(slice)
    }

    pub fn poll_slice(&mut self, cx: &mut Context) -> Poll<Result<UnfilledSlice<H>, Error>> {
        let local = ready!(self.local.poll_slice(cx)).map_err(|_| Error)?;
        let remote = ready!(self.remote.poll_slice(cx)).map_err(|_| Error)?;
        let slice = UnfilledSlice {
            buffer: &mut self.buffer,
            local,
            remote,
        };
        Poll::Ready(Ok(slice))
    }
}

pub struct UnfilledSlice<'a, H: Handle> {
    pub(crate) buffer: &'a mut Option<Entry<H>>,
    pub(crate) local: spsc::RecvSlice<'a, Entry<H>>,
    pub(crate) remote: spsc::SendSlice<'a, Entry<H>>,
}

unsafe impl<'a, H: Handle> Send for UnfilledSlice<'a, H> {}
unsafe impl<'a, H: Handle> Sync for UnfilledSlice<'a, H> {}

impl<'a, H: Handle> UnfilledSlice<'a, H> {
    pub(crate) fn pop(&mut self) -> Option<Entry<H>> {
        if let Some(idx) = self.buffer.take() {
            Some(idx)
        } else {
            self.local.pop()
        }
    }

    fn flush(&mut self) {
        if let Some(entry) = self.buffer.take() {
            if entry.0.payload.segment_count > 0 {
                entry.0.payload.invariants();
                let _ = self.remote.push(entry);
            } else {
                *self.buffer = Some(entry);
            }
        }
    }
}

impl<'a, H: Handle> tx::Queue for UnfilledSlice<'a, H> {
    type Handle = H;
    type Entry = Entry<H>;

    fn len(&self) -> usize {
        todo!()
    }

    fn capacity(&self) -> usize {
        self.remote.capacity().min(self.local.len())
    }

    fn as_slice_mut(&mut self) -> &mut [Self::Entry] {
        todo!()
    }

    fn push<M: tx::Message<Handle = Self::Handle>>(
        &mut self,
        mut message: M,
    ) -> Result<tx::Outcome, tx::Error> {
        let mut entry = self.pop().ok_or(tx::Error::AtCapacity)?;

        let mut segment_size = entry.0.payload.segment_size;
        let mut segment_count = entry.0.payload.segment_count;

        // check to see if we can write to the same entry, otherwise flush it
        if !entry.can_gso(&mut message) {
            entry.0.payload.invariants();

            let _ = self.remote.push(entry);

            entry = self.pop().ok_or(tx::Error::AtCapacity)?;
            segment_size = 0;
            segment_count = 0;
        }

        let payload = if segment_size == 0 {
            &mut entry.0.payload.data[..]
        } else {
            let start = entry.0.payload.segment_write_cursor as usize;
            let end = start + segment_size as usize;
            &mut entry.0.payload.data[start..end]
        };
        let payload = tx::PayloadBuffer::new(payload);

        let len = match message.write_payload(payload, segment_count as usize) {
            Ok(len) => len as u16,
            Err(err) => {
                *self.buffer = Some(entry);
                return Err(err);
            }
        };

        if segment_size == 0 {
            entry.0.handle = *message.path_handle();
            entry.0.payload.segment_count = 1;
            entry.0.payload.segment_size = len;
            entry.0.payload.segment_write_cursor = len;
        } else {
            entry.0.payload.segment_count += 1;
            entry.0.payload.segment_write_cursor += len;
        }

        segment_size = entry.0.payload.segment_size;

        entry.0.payload.invariants();

        // if we have an undersized packet, then we need to flush it
        // TODO check max_degment count
        if len < segment_size
            || (entry.0.payload.segment_write_cursor as usize + segment_size as usize)
                > entry.0.payload.data.len()
        {
            let _ = self.remote.push(entry);
        } else {
            *self.buffer = Some(entry);
        }

        let index = 0;

        Ok(tx::Outcome {
            len: len as usize,
            index,
        })
    }
}

impl<'a, H: Handle> Drop for UnfilledSlice<'a, H> {
    fn drop(&mut self) {
        self.flush();
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

    fn next_segment(&mut self) -> Option<(inet::Header<Self::Handle>, &mut [u8])> {
        let payload = &mut self.0.payload;

        if payload.segment_read_cursor == payload.segment_write_cursor {
            return None;
        }

        let path = self.0.handle;
        let ecn = self.0.ecn;
        let header = inet::Header { path, ecn };

        let start = payload.segment_read_cursor;
        let end = payload
            .segment_write_cursor
            .min(start + payload.segment_size);

        payload.segment_read_cursor = end;

        payload.invariants();

        let payload = &mut payload.data[start as usize..end as usize];

        Some((header, payload))
    }
}

pub struct Filled<H: Handle> {
    pub(crate) local: spsc::Receiver<Entry<H>>,
    pub(crate) remote: spsc::Sender<Entry<H>>,
    pub(crate) buffer: Option<Entry<H>>,
}

unsafe impl<H: Handle> Send for Filled<H> {}
unsafe impl<H: Handle> Sync for Filled<H> {}

pub struct FilledSlice<'a, H: Handle> {
    pub(crate) local: spsc::RecvSlice<'a, Entry<H>>,
    pub(crate) remote: spsc::SendSlice<'a, Entry<H>>,
    pub(crate) buffer: &'a mut Option<Entry<H>>,
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
        let local = self.local.try_slice().map_err(|_| Error)?.ok_or(Error)?;
        let remote = self.remote.try_slice().map_err(|_| Error)?.ok_or(Error)?;

        Ok(FilledSlice {
            local,
            remote,
            buffer: &mut self.buffer,
        })
    }

    pub fn poll_slice(&mut self, cx: &mut Context) -> Poll<Result<FilledSlice<H>, Error>> {
        let local = ready!(self.local.poll_slice(cx)).map_err(|_| Error)?;
        let remote = ready!(self.remote.poll_slice(cx)).map_err(|_| Error)?;

        Poll::Ready(Ok(FilledSlice {
            local,
            remote,
            buffer: &mut self.buffer,
        }))
    }

    pub fn pop(&mut self) -> Option<Entry<H>> {
        if let Some(entry) = self.buffer.take() {
            Some(entry)
        } else if let Ok(Some(mut queue)) = self.local.try_slice() {
            queue.pop()
        } else {
            None
        }
    }
}

impl<'a, H: Handle> FilledSlice<'a, H> {
    pub(crate) fn pop(&mut self) -> Option<Entry<H>> {
        if let Some(idx) = self.buffer.take() {
            Some(idx)
        } else {
            self.local.pop()
        }
    }
}

impl<'a, H: Handle> rx::Queue for FilledSlice<'a, H> {
    type Entry = Entry<H>;
    type Handle = H;

    fn pop(&mut self) -> Option<Self::Entry> {
        (*self).pop()
    }

    fn finish(&mut self, entry: Self::Entry) {
        entry.0.payload.invariants();

        let _ = self.remote.push(entry);
    }
}

pub fn pair<H: Default + Handle>(max_payload: u16, count: u16) -> (Unfilled<H>, Filled<H>) {
    pair_inner(max_payload, count, 0)
}

pub fn set<H: Default + Handle>(
    max_payload: u16,
    count: u16,
    len: usize,
) -> (UnfilledSet<H>, FilledSet<H>) {
    let mut unfilled = UnfilledSet {
        inner: vec![],
        // buffer: BinaryHeap::with_capacity(count as usize * len),
        cursor: 0,
    };
    let mut filled = FilledSet { inner: vec![] };

    for queue in 0..len {
        let (unfilled_t, filled_t) = pair_inner(max_payload, count, queue as _);
        unfilled.inner.push(unfilled_t);
        filled.inner.push(filled_t);
    }

    (unfilled, filled)
}

fn pair_inner<H: Default + Handle>(
    max_payload: u16,
    count: u16,
    queue: u16,
) -> (Unfilled<H>, Filled<H>) {
    let count = count as usize;

    let (filled_send, filled_recv) = spsc::channel(count);
    let (mut unfilled_send, unfilled_recv) = spsc::channel(count);

    // put all of the messages in the "unfilled" queue
    let ids = 0..count as u16;
    let mut unfilled = ids.map(|id| {
        let handle = Default::default();
        let ecn = Default::default();
        let payload = Buffer::new(max_payload);
        let entry = InnerEntry {
            handle,
            ecn,
            payload,
            id,
            queue,
        };
        Entry(Box::new(entry))
    });

    unfilled_send
        .try_slice()
        .unwrap()
        .unwrap()
        .extend(&mut unfilled)
        .unwrap();

    let unfilled = Unfilled {
        local: unfilled_recv,
        remote: filled_send,
        buffer: None,
    };

    let filled = Filled {
        local: filled_recv,
        remote: unfilled_send,
        buffer: None,
    };

    (unfilled, filled)
}

pub struct UnfilledSet<H: Handle> {
    pub(crate) inner: Vec<Unfilled<H>>,
    cursor: usize,
}

struct BufferedEntry<H: Handle>(Entry<H>);

impl<H: Handle> PartialEq for BufferedEntry<H> {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other).is_eq()
    }
}

impl<H: Handle> PartialOrd for BufferedEntry<H> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<H: Handle> Eq for BufferedEntry<H> {}

impl<H: Handle> Ord for BufferedEntry<H> {
    fn cmp(&self, other: &Self) -> Ordering {
        let a = &(self.0).0;
        let b = &(other.0).0;

        b.id.cmp(&a.id).then(b.queue.cmp(&a.queue))
    }
}

impl<H: Handle> UnfilledSet<H> {
    /*
    pub async fn ready(&mut self) -> Result<(), Error> {
        futures::future::poll_fn(|cx| {
            let mut is_ready = !self.buffer.is_empty();

            for filled in &mut self.inner {
                match filled.local.poll_slice(cx) {
                    Poll::Ready(Ok(mut slice)) => {
                        is_ready = true;
                        while let Some(entry) = slice.pop() {
                            self.buffer.push(BufferedEntry(entry));
                        }
                    }
                    Poll::Ready(Err(_)) => {
                        // TODO remove from the set?
                    }
                    Poll::Pending => {
                        continue;
                    }
                }
            }

            if is_ready {
                Ok(()).into()
            } else {
                Poll::Pending
            }
        })
        .await
    }
    */

    pub async fn tx_ready(&mut self) -> Result<(), Error> {
        futures::future::poll_fn(|cx| {
            let mut is_ready = false;

            // only poll if we don't have capacity
            let (back, front) = self.inner.split_at_mut(self.cursor);

            for (index, queue) in front.iter_mut().chain(back).enumerate() {
                // only poll if we don't have any items
                if queue.local.capacity() > 0 {
                    self.cursor = index;
                    break;
                }

                match queue.local.poll_slice(cx) {
                    Poll::Ready(Ok(_)) => {
                        is_ready = true;
                        self.cursor = index;
                        break;
                    }
                    Poll::Ready(Err(_)) => {
                        // TODO remove from the set?
                    }
                    Poll::Pending => {
                        // move on to the next item
                        continue;
                    }
                }
            }

            if is_ready {
                Ok(()).into()
            } else {
                Poll::Pending
            }
        })
        .await
    }

    pub fn try_slice(&mut self) -> Result<UnfilledSlice<H>, Error> {
        let cursor = self.cursor;
        self.cursor = cursor + 1;
        if self.cursor >= self.inner.len() {
            self.cursor = 0;
        }
        self.inner[cursor].try_slice()
        /*
        Ok(UnfilledSetSlice {
            inner: &mut self.inner,
            buffer: &mut self.buffer,
        })
            */
    }
}

pub struct UnfilledSetSlice<'a, H: Handle> {
    inner: &'a mut [Unfilled<H>],
    buffer: &'a mut BinaryHeap<BufferedEntry<H>>,
}

impl<'a, H: Handle> UnfilledSetSlice<'a, H> {
    fn finish(&mut self, entry: Entry<H>) {
        let inner = &mut self.inner[entry.0.queue as usize];
        if let Ok(Some(mut slice)) = inner.remote.try_slice() {
            let _ = slice.push(entry);
        }
    }
}

impl<'a, H: Handle> tx::Queue for UnfilledSetSlice<'a, H> {
    type Handle = H;
    type Entry = Entry<H>;

    fn len(&self) -> usize {
        todo!()
    }

    fn capacity(&self) -> usize {
        todo!()
    }

    fn as_slice_mut(&mut self) -> &mut [Self::Entry] {
        todo!()
    }

    fn push<M: tx::Message<Handle = Self::Handle>>(
        &mut self,
        mut message: M,
    ) -> Result<tx::Outcome, tx::Error> {
        let mut entry = self.buffer.pop().ok_or(tx::Error::AtCapacity)?.0;

        let mut segment_size = entry.0.payload.segment_size;
        let mut segment_count = entry.0.payload.segment_count;

        // check to see if we can write to the same entry, otherwise flush it
        if !entry.can_gso(&mut message) {
            entry.0.payload.invariants();

            self.finish(entry);

            entry = self.buffer.pop().ok_or(tx::Error::AtCapacity)?.0;
            segment_size = 0;
            segment_count = 0;
        }

        let payload = if segment_size == 0 {
            &mut entry.0.payload.data[..]
        } else {
            let start = entry.0.payload.segment_write_cursor as usize;
            let end = start + segment_size as usize;
            &mut entry.0.payload.data[start..end]
        };
        let payload = tx::PayloadBuffer::new(payload);

        let len = match message.write_payload(payload, segment_count as usize) {
            Ok(len) => len as u16,
            Err(err) => {
                self.buffer.push(BufferedEntry(entry));
                return Err(err);
            }
        };

        if segment_size == 0 {
            entry.0.handle = *message.path_handle();
            entry.0.payload.segment_count = 1;
            entry.0.payload.segment_size = len;
            entry.0.payload.segment_write_cursor = len;
        } else {
            entry.0.payload.segment_count += 1;
            entry.0.payload.segment_write_cursor += len;
        }

        segment_size = entry.0.payload.segment_size;

        entry.0.payload.invariants();

        // if we have an undersized packet, then we need to flush it
        // TODO check max_degment count
        if len < segment_size
            || (entry.0.payload.segment_write_cursor as usize + segment_size as usize)
                > entry.0.payload.data.len()
        {
            self.finish(entry);
        } else {
            self.buffer.push(BufferedEntry(entry));
        }

        let index = 0;

        Ok(tx::Outcome {
            len: len as usize,
            index,
        })
    }
}

impl<'a, H: Handle> Drop for UnfilledSetSlice<'a, H> {
    fn drop(&mut self) {
        if let Some(BufferedEntry(entry)) = self.buffer.pop() {
            if entry.0.payload.segment_count > 0 {
                entry.0.payload.invariants();
                self.finish(entry);
            } else {
                self.buffer.push(BufferedEntry(entry));
            }
        }
    }
}

pub struct FilledSet<H: Handle> {
    pub(crate) inner: Vec<Filled<H>>,
}

pub struct FilledSetSlice<'a, H: Handle> {
    inner: &'a mut [Filled<H>],
    cursor: usize,
}

impl<H: Handle> FilledSet<H> {
    pub async fn ready(&mut self) -> Result<(), Error> {
        futures::future::poll_fn(|cx| {
            let mut is_ready = false;

            for filled in &mut self.inner {
                match filled.local.poll_slice(cx) {
                    Poll::Ready(Ok(_)) => {
                        is_ready = true;
                    }
                    Poll::Ready(Err(_)) => {
                        // TODO remove from the set?
                    }
                    Poll::Pending => {
                        continue;
                    }
                }
            }

            if is_ready {
                Ok(()).into()
            } else {
                Poll::Pending
            }
        })
        .await
    }

    pub fn try_slice(&mut self) -> Result<FilledSetSlice<H>, Error> {
        Ok(FilledSetSlice {
            inner: &mut self.inner,
            cursor: 0,
        })
    }

    pub fn poll_slice(&mut self, cx: &mut Context) -> Poll<Result<FilledSetSlice<H>, Error>> {
        let mut first_ready = None;

        for (idx, filled) in &mut self.inner.iter_mut().enumerate() {
            match filled.local.poll_slice(cx) {
                Poll::Ready(Ok(_)) if first_ready.is_none() => {
                    first_ready = Some(idx);
                }
                Poll::Ready(Ok(_)) => {
                    continue;
                }
                Poll::Ready(Err(_)) => {
                    // TODO remove from the set?
                }
                Poll::Pending => {
                    continue;
                }
            }
        }

        if let Some(cursor) = first_ready {
            Poll::Ready(Ok(FilledSetSlice {
                inner: &mut self.inner,
                cursor,
            }))
        } else {
            Poll::Pending
        }
    }
}

impl<'a, H: Handle> rx::Queue for FilledSetSlice<'a, H> {
    type Entry = Entry<H>;
    type Handle = H;

    fn pop(&mut self) -> Option<Self::Entry> {
        loop {
            let inner = self.inner.get_mut(self.cursor)?;
            if let Some(entry) = inner.pop() {
                return Some(entry);
            } else {
                self.cursor += 1;
            }
        }
    }

    fn finish(&mut self, entry: Self::Entry) {
        entry.0.payload.invariants();

        let index = entry.0.queue;
        let inner = &mut self.inner[index as usize];
        if let Ok(Some(mut slice)) = inner.remote.try_slice() {
            let _ = slice.push(entry);
        }
    }
}

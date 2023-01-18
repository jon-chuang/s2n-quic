// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    buffer::Buffer,
    message::{
        queue,
        simple::{self, Message, Ring},
        Message as _,
    },
};
use errno::errno;
use s2n_quic_core::{event, inet::SocketAddress, io, path::LocalAddress};

pub use simple::Handle;

pub trait Socket {
    type Error: Error;

    /// Receives a payload and returns the length and source address
    fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, Option<SocketAddress>), Self::Error>;

    /// Sends a payload to the given address and returns the length of the sent payload
    fn send_to(&self, buf: &[u8], addr: &SocketAddress) -> Result<usize, Self::Error>;
}

#[cfg(feature = "std")]
impl Socket for std::net::UdpSocket {
    type Error = std::io::Error;

    fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, Option<SocketAddress>), Self::Error> {
        debug_assert!(!buf.is_empty());
        let (len, addr) = self.recv_from(buf)?;
        Ok((len, Some(addr.into())))
    }

    fn send_to(&self, buf: &[u8], addr: &SocketAddress) -> Result<usize, Self::Error> {
        debug_assert!(!buf.is_empty());
        let addr: std::net::SocketAddr = (*addr).into();
        self.send_to(buf, addr)
    }
}

pub trait Error {
    fn would_block(&self) -> bool;
    fn was_interrupted(&self) -> bool;
    fn permission_denied(&self) -> bool;
}

#[cfg(feature = "std")]
impl Error for std::io::Error {
    fn would_block(&self) -> bool {
        self.kind() == std::io::ErrorKind::WouldBlock
    }

    fn was_interrupted(&self) -> bool {
        self.kind() == std::io::ErrorKind::Interrupted
    }

    fn permission_denied(&self) -> bool {
        self.kind() == std::io::ErrorKind::PermissionDenied
    }
}

pub fn tx<S: Socket>(
    socket: &S,
    channel: &mut crate::io::channel::FilledSlice<Handle>,
) -> Result<(), S::Error> {
    use io::rx::Queue;
    let entries = channel.as_slice_mut();
    let mut count = 0;
    let mut result = Ok(());

    for entry in entries {
        let handle = entry.handle();
        let payload = entry.payload();

        match socket.send_to(payload, &handle.remote_address) {
            Ok(_) => {
                count += 1;
            }
            Err(err) => {
                result = Err(err);
                break;
            }
        }
    }

    if count > 0 {
        channel.finish(count);
    }

    result
}

pub fn rx<S: Socket>(
    socket: &S,
    channel: &mut crate::io::channel::UnfilledSlice<Handle>,
) -> Result<(), S::Error> {
    let mut result = Ok(());

    while let Some(idx) = channel.pop() {
        let shared = unsafe { &mut *channel.shared.get() };
        let payload = shared.data.payload_mut(idx);

        match socket.recv_from(payload) {
            Ok((len, remote_address)) => {
                if let Some(remote_address) = remote_address {
                    shared.lens[idx as usize] = len as _;
                    shared.handles[idx as usize].remote_address = remote_address.into();

                    let _ = channel.remote.push(idx);
                } else {
                    *channel.buffer = Some(idx);
                }
            }
            Err(err) => {
                *channel.buffer = Some(idx);
                result = Err(err);
                break;
            }
        }
    }

    result
}

#[derive(Debug, Default)]
pub struct Queue<B: Buffer>(queue::Queue<Ring<B>>);

impl<B: Buffer> Queue<B> {
    pub fn new(buffer: B) -> Self {
        let queue = queue::Queue::new(Ring::new(buffer, 1));

        Self(queue)
    }

    pub fn free_len(&self) -> usize {
        self.0.free_len()
    }

    pub fn occupied_len(&self) -> usize {
        self.0.occupied_len()
    }

    pub fn set_local_address(&mut self, local_address: LocalAddress) {
        self.0.set_local_address(local_address)
    }

    pub fn tx<S: Socket, Publisher: event::EndpointPublisher>(
        &mut self,
        socket: &S,
        publisher: &mut Publisher,
    ) -> Result<usize, S::Error> {
        let mut count = 0;
        let mut entries = self.0.occupied_mut();

        for entry in entries.as_mut() {
            if let Some(remote_address) = entry.remote_address() {
                match socket.send_to(entry.payload_mut(), &remote_address) {
                    Ok(_) => {
                        count += 1;

                        publisher.on_platform_tx(event::builder::PlatformTx { count: 1 });
                    }
                    Err(err) if count > 0 && err.would_block() => {
                        break;
                    }
                    Err(err) if err.was_interrupted() || err.permission_denied() => {
                        break;
                    }
                    Err(err) => {
                        entries.finish(count);

                        publisher.on_platform_rx_error(event::builder::PlatformRxError {
                            errno: errno().0,
                        });

                        return Err(err);
                    }
                }
            }
        }

        entries.finish(count);

        Ok(count)
    }

    pub fn rx<S: Socket, Publisher: event::EndpointPublisher>(
        &mut self,
        socket: &S,
        publisher: &mut Publisher,
    ) -> Result<usize, S::Error> {
        let mut count = 0;
        let mut entries = self.0.free_mut();

        while let Some(entry) = entries.get_mut(count) {
            match socket.recv_from(entry.payload_mut()) {
                Ok((payload_len, Some(remote_address))) => {
                    entry.set_remote_address(&remote_address);
                    unsafe {
                        // Safety: The payload_len should not be bigger than the number of
                        // allocated bytes.

                        debug_assert!(payload_len < entry.payload_len());
                        let payload_len = payload_len.min(entry.payload_len());

                        entry.set_payload_len(payload_len);
                    }

                    count += 1;

                    publisher.on_platform_rx(event::builder::PlatformRx { count: 1 });
                }
                Ok((_payload_len, None)) => {}
                Err(err) if count > 0 && err.would_block() => {
                    break;
                }
                Err(err) if err.was_interrupted() => {
                    break;
                }
                Err(err) => {
                    entries.finish(count);

                    publisher
                        .on_platform_rx_error(event::builder::PlatformRxError { errno: errno().0 });

                    return Err(err);
                }
            }
        }

        entries.finish(count);

        Ok(count)
    }

    pub fn rx_queue(&mut self) -> queue::Occupied<Message> {
        self.0.occupied_mut()
    }

    pub fn tx_queue(&mut self) -> queue::Free<Message> {
        self.0.free_mut()
    }
}

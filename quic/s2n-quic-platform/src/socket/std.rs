// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use errno::errno;
use s2n_quic_core::{event, inet::SocketAddress, io, path::LocalAddress};

pub use s2n_quic_core::path::Tuple as Handle;

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

#[derive(Default)]
pub struct Tx;

impl Tx {
    pub fn apply<S: Socket>(
        &mut self,
        socket: &S,
        channel: &mut crate::io::channel::FilledSlice<Handle>,
    ) -> Result<(), S::Error> {
        while let Some(mut entry) = channel.pop() {
            {
                let handle = &entry.0.handle;
                let payload = &entry.0.payload;

                payload.invariants();

                // make sure we have at least one segment to read
                debug_assert!(payload.segment_read_cursor < payload.segment_write_cursor);

                let mut count = 0;

                let mut segments = payload.segments();

                while let Some(segment) = segments.next() {
                    match socket.send_to(segment, &handle.remote_address) {
                        Ok(_) => {
                            count += segment.len() as u32;
                        }
                        Err(err) => {
                            drop(segments);

                            // save our place for the next time the socket is ready
                            entry.0.payload.segment_read_cursor += count;
                            *channel.buffer = Some(entry);
                            return Err(err);
                        }
                    }
                }
            }

            let payload = &mut entry.0.payload;

            payload.reset();
            let _ = channel.remote.push(entry);
        }

        Ok(())
    }
}

#[derive(Default)]
pub struct Rx;

impl Rx {
    pub fn apply<S: Socket>(
        &mut self,
        socket: &S,
        channel: &mut crate::io::channel::UnfilledSlice<Handle>,
    ) -> Result<(), S::Error> {
        let mut result = Ok(());

        while let Some(mut entry) = channel.pop() {
            let payload = entry.payload_mut();
            match socket.recv_from(&mut payload.data) {
                Ok((0, _)) => {
                    *channel.buffer = Some(entry);
                    break;
                }
                Err(err) => {
                    *channel.buffer = Some(entry);
                    result = Err(err);
                    break;
                }
                Ok((len, remote_address)) => {
                    if let Some(remote_address) = remote_address {
                        payload.segment_count = 1;
                        payload.segment_size = len as _;
                        payload.segment_write_cursor = len as _;
                        payload.segment_read_cursor = 0;
                        entry.handle_mut().remote_address = remote_address.into();
                        let _ = channel.remote.push(entry);
                    } else {
                        *channel.buffer = Some(entry);
                    }
                }
            }
        }

        result
    }
}

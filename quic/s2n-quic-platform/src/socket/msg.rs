// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::message::{
    cmsg,
    msg::{self, Message},
    Message as _,
};
use core::{
    cell::UnsafeCell,
    ops::{Deref, DerefMut},
    pin::Pin,
};
use std::{io, os::unix::io::AsRawFd};

pub use msg::Handle;

const MAX_NAMELEN: usize = core::mem::size_of::<libc::sockaddr_in6>();

pub trait SocketExt {
    fn sendmsg(&self, msg: &mut Message) -> io::Result<usize>;
    fn recvmsg(&self, msg: &mut Message) -> io::Result<usize>;
}

impl<S: AsRawFd> SocketExt for S {
    fn sendmsg(&self, msg: &mut Message) -> io::Result<usize> {
        // macOS doesn't like when msg_control have valid pointers but the len is 0
        //
        // If that's the case here, then set the `msg_control` to null and restore it after
        // calling sendmsg.
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        let msg_control = {
            let msg_control = entry.0.msg_control;

            if entry.0.msg_controllen == 0 {
                entry.0.msg_control = core::ptr::null_mut();
            }

            msg_control
        };

        // Safety: calling a libc function is inherently unsafe as rust cannot
        // make any invariant guarantees. This has to be reviewed by humans instead
        // so the [docs](https://linux.die.net/man/2/sendmsg) are inlined here:

        // > The argument sockfd is the file descriptor of the sending socket.
        let sockfd = self.as_raw_fd();

        // > The address of the target is given by msg.msg_name, with msg.msg_namelen
        // > specifying its size.
        //
        // > The message is pointed to by the elements of the array msg.msg_iov.
        // > The sendmsg() call also allows sending ancillary data (also known as
        // > control information).
        let msg = msg.as_mut_ptr() as _;

        // > The flags argument is the bitwise OR of zero or more flags.
        //
        // No flags are currently set
        let flags = Default::default();

        // > On success, these calls return the number of characters sent.
        // > On error, -1 is returned, and errno is set appropriately.
        let result = libc!(sendmsg(sockfd, msg, flags));

        #[cfg(any(target_os = "macos", target_os = "ios"))]
        {
            entry.0.msg_control = msg_control;
        }

        let len = result?;

        Ok(len as usize)
    }

    fn recvmsg(&self, msg: &mut Message) -> io::Result<usize> {
        // Safety: calling a libc function is inherently unsafe as rust cannot
        // make any invariant guarantees. This has to be reviewed by humans instead
        // so the [docs](https://linux.die.net/man/2/recvmsg) are inlined here:

        // > The argument sockfd is the file descriptor of the receiving socket.
        let sockfd = self.as_raw_fd();

        // > The recvmsg() call uses a msghdr structure to minimize the number of
        // > directly supplied arguments.
        //
        // > Here msg_name and msg_namelen specify the source address if the
        // > socket is unconnected.
        //
        // > The fields msg_iov and msg_iovlen describe scatter-gather locations
        //
        // > When recvmsg() is called, msg_controllen should contain the length
        // > of the available buffer in msg_control; upon return from a successful
        // > call it will contain the length of the control message sequence.
        let msg = msg.as_mut_ptr() as _;

        // > The flags argument to a recv() call is formed by ORing one or more flags
        //
        // No flags are currently set
        let flags = Default::default();

        // > recvmsg() calls are used to receive messages from a socket
        //
        // > All three routines return the length of the message on successful completion.
        // > If a message is too long to fit in the supplied buffer, excess bytes may be
        // > discarded depending on the type of socket the message is received from.
        //
        // > These calls return the number of bytes received, or -1 if an error occurred.
        let len = libc!(recvmsg(sockfd, msg, flags))?;

        Ok(len as usize)
    }
}

#[derive(Default)]
pub struct Tx {
    message: OwnedMessage,
}

impl Tx {
    pub fn apply<S: SocketExt>(
        &mut self,
        socket: &S,
        channel: &mut crate::io::channel::FilledSlice<Handle>,
    ) -> io::Result<()> {
        let mut count = 0;

        while let Some(mut entry) = channel.pop() {
            entry.payload().invariants();

            self.message.0.msg_controllen = 0;

            entry.handle().update_msg_hdr(&mut self.message.0);
            self.message
                .set_ecn(*entry.ecn(), &entry.handle().remote_address);

            unsafe {
                let payload = entry.payload_mut();

                let iovec = &mut *self.message.0.msg_iov;
                iovec.iov_base = payload.data.as_mut_ptr() as *mut _;
                iovec.iov_len = payload.segment_write_cursor as _;

                // TODO make this conditional
                self.message.set_segment_size(payload.segment_size as _);
            }

            // TODO handle GSO EIO error
            match socket.sendmsg(&mut self.message) {
                Ok(_len) => {
                    // TODO should we check if the message was truncated?

                    // continue to the next entry
                    entry.payload_mut().reset();
                    let _ = channel.remote.push(entry);
                }
                Err(err) if count == 0 && err.kind() == io::ErrorKind::Interrupted => {
                    // try to send again if we haven't sent already
                    count += 1;
                    *channel.buffer = Some(entry);
                }
                Err(err)
                    if matches!(
                        err.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    *channel.buffer = Some(entry);
                    return Err(err);
                }
                Err(_) => {
                    count += 1;

                    entry.payload_mut().reset();
                    let _ = channel.remote.push(entry);
                }
            }
        }

        Ok(())
    }
}

#[derive(Default)]
pub struct Rx {
    message: OwnedMessage,
}

impl Rx {
    pub fn apply<S: SocketExt>(
        &mut self,
        socket: &S,
        channel: &mut crate::io::channel::UnfilledSlice<Handle>,
    ) -> io::Result<()> {
        let mut count = 0;

        while let Some(mut entry) = channel.pop() {
            entry.payload().invariants();

            unsafe {
                let iovec = &mut *self.message.0.msg_iov;
                let payload = entry.payload_mut();
                iovec.iov_base = payload.data.as_mut_ptr() as *mut _;
                iovec.iov_len = payload.data.len() as _;

                self.message.0.msg_controllen = cmsg::MAX_LEN as _;
                self.message.0.msg_namelen = MAX_NAMELEN as _;
            }

            match socket.recvmsg(&mut self.message) {
                Ok(len) => {
                    let cmsg = self.message.ancillary_data();

                    if let Some(remote) = self.message.remote_address() {
                        let handle = entry.handle_mut();
                        handle.remote_address = remote.into();
                        // TODO set the correct port
                        handle.local_address = cmsg.local_address;
                    } else {
                        *channel.buffer = Some(entry);
                        continue;
                    };

                    // ensure the returned length does not exceed what is
                    // allocated
                    let payload = entry.payload_mut();
                    debug_assert!(len <= payload.data.len(), "cannot exceed payload_len");
                    let len = len.min(payload.data.len());

                    payload.segment_read_cursor = 0;
                    payload.segment_write_cursor = len as _;

                    if cmsg.segment_size == 0 {
                        payload.segment_size = len as _;
                        payload.segment_count = 1;
                    } else {
                        payload.segment_size = cmsg.segment_size as _;
                        payload.segment_count =
                            ((len + cmsg.segment_size - 1) / cmsg.segment_size) as _;
                    }

                    payload.invariants();

                    let _ = channel.remote.push(entry);

                    count += 1;
                }
                Err(err) if count == 0 && err.kind() == io::ErrorKind::Interrupted => {
                    // try to receive again if we haven't received something already
                    count += 1;
                    *channel.buffer = Some(entry);
                }
                Err(err)
                    if matches!(
                        err.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    *channel.buffer = Some(entry);
                    return Err(err);
                }
                Err(_) => {
                    *channel.buffer = Some(entry);
                    count += 1;
                }
            }
        }

        Ok(())
    }
}

struct OwnedMessage {
    #[allow(dead_code)]
    storage: Pin<Box<UnsafeCell<Storage>>>,
    message: Message,
}

unsafe impl Send for OwnedMessage {}
unsafe impl Sync for OwnedMessage {}

impl Deref for OwnedMessage {
    type Target = Message;

    fn deref(&self) -> &Self::Target {
        &self.message
    }
}

impl DerefMut for OwnedMessage {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.message
    }
}

impl Default for OwnedMessage {
    fn default() -> Self {
        let mut storage = Pin::new(Box::new(UnsafeCell::new(Storage::default())));

        let message = {
            let storage = storage.get_mut();
            Message::new(
                &mut storage.iovec,
                storage.msg_name.as_mut_ptr() as *mut _,
                0,
                storage.cmsgs.as_mut_ptr() as *mut _,
                0,
            )
        };

        Self { storage, message }
    }
}

struct Storage {
    iovec: libc::iovec,
    msg_name: [u8; MAX_NAMELEN],
    cmsgs: [u8; cmsg::MAX_LEN],
}

impl Default for Storage {
    fn default() -> Self {
        Self {
            iovec: unsafe { core::mem::zeroed() },
            msg_name: [0u8; MAX_NAMELEN],
            cmsgs: [0u8; cmsg::MAX_LEN],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integration() {
        let (mut unfilled_tx, mut filled_tx) = crate::io::channel::pair::<Handle>(u16::MAX, 64);
        let (mut unfilled_rx, mut filled_rx) = crate::io::channel::pair::<Handle>(u16::MAX, 64);

        let rx_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        rx_socket.set_nonblocking(true).unwrap();

        crate::socket::configure_gro(&rx_socket).unwrap();

        let tx_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        tx_socket.set_nonblocking(true).unwrap();

        let rx_addr = rx_socket.local_addr().unwrap();
        let rx_addr: s2n_quic_core::inet::SocketAddress = rx_addr.into();

        if let Ok(mut unfilled_tx) = unfilled_tx.try_slice() {
            while let Some(mut entry) = unfilled_tx.pop() {
                entry.handle_mut().remote_address = rx_addr.into();

                let payload = entry.payload_mut();
                let message = b"hello world";
                payload.segment_size = message.len() as _;
                payload.segment_count = 0;
                for _ in 0..64 {
                    let start = payload.segment_write_cursor as usize;
                    let end = start + message.len();
                    payload.data[start..end].copy_from_slice(message);
                    payload.segment_write_cursor = end as _;
                    payload.segment_count += 1;
                }
                payload.segment_read_cursor = 0;
                payload.invariants();

                let _ = unfilled_tx.remote.push(entry);
            }
        }

        let mut tx = Tx::default();
        if let Ok(mut filled_tx) = filled_tx.try_slice() {
            dbg!();
            let _ = tx.apply(&tx_socket, &mut filled_tx);
            dbg!();
        }

        let mut rx = Rx::default();
        if let Ok(mut unfilled_rx) = unfilled_rx.try_slice() {
            dbg!();
            let _ = rx.apply(&rx_socket, &mut unfilled_rx);
        }

        if let Ok(mut filled_rx) = filled_rx.try_slice() {
            dbg!();
            while let Some(entry) = filled_rx.pop() {
                dbg!(entry.handle());
                for segment in entry.payload().segments() {
                    let segment = String::from_utf8_lossy(segment);
                    eprintln!("packet {:?}", segment);
                }
            }
        };

        //
    }
}

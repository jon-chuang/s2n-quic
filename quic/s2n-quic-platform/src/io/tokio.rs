// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{features::gso, io::EventLoop, socket::bind};
use s2n_quic_core::{
    endpoint::Endpoint,
    event::{self, EndpointPublisher as _},
    inet::SocketAddress,
    path::MaxMtu,
    time::Clock as ClockTrait,
};
use std::{convert::TryInto, io, io::ErrorKind};
use tokio::{net::UdpSocket, runtime::Handle};

// pub type PathHandle = socket::Handle;
pub type PathHandle = crate::socket::msg::Handle;

mod clock;

mod builder;
mod socket;

pub use builder::Builder;
use clock::Clock;

impl crate::socket::stdlib::Socket for UdpSocket {
    type Error = io::Error;

    fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, Option<SocketAddress>), Self::Error> {
        let (len, addr) = self.try_recv_from(buf)?;
        Ok((len, Some(addr.into())))
    }

    fn send_to(&self, buf: &[u8], addr: &SocketAddress) -> Result<usize, Self::Error> {
        self.try_send_to(buf, (*addr).into())
    }
}

#[derive(Debug, Default)]
pub struct Io {
    builder: Builder,
}

impl Io {
    pub fn builder() -> Builder {
        Builder::default()
    }

    pub fn new<A: std::net::ToSocketAddrs>(addr: A) -> io::Result<Self> {
        let address = addr.to_socket_addrs()?.next().expect("missing address");
        let builder = Builder::default().with_receive_address(address)?;
        Ok(Self { builder })
    }

    pub fn start<E: Endpoint<PathHandle = PathHandle>>(
        self,
        mut endpoint: E,
    ) -> io::Result<(tokio::task::JoinHandle<()>, SocketAddress)> {
        let Builder {
            handle,
            rx_socket,
            tx_socket,
            recv_addr,
            send_addr,
            recv_buffer_size,
            send_buffer_size,
            max_mtu,
            max_segments,
            reuse_port,
        } = self.builder;

        let reuse_port = true;
        let recv_buffer_size = 4 * 1024 * 1024;
        let send_buffer_size = 4 * 1024 * 1024;

        endpoint.set_max_mtu(max_mtu);

        let clock = Clock::default();

        let mut publisher = event::EndpointPublisherSubscriber::new(
            event::builder::EndpointMeta {
                endpoint_type: E::ENDPOINT_TYPE,
                timestamp: clock.get_time(),
            },
            None,
            endpoint.subscriber(),
        );

        publisher.on_platform_feature_configured(event::builder::PlatformFeatureConfigured {
            configuration: event::builder::PlatformFeatureConfiguration::MaxMtu {
                mtu: max_mtu.into(),
            },
        });

        publisher.on_platform_feature_configured(event::builder::PlatformFeatureConfigured {
            configuration: event::builder::PlatformFeatureConfiguration::Gso {
                max_segments: max_segments.into(),
            },
        });

        let handle = if let Some(handle) = handle {
            handle
        } else {
            Handle::try_current().map_err(|err| std::io::Error::new(io::ErrorKind::Other, err))?
        };

        let guard = handle.enter();

        let mut rx_sockets = vec![];

        if let Some(rx_socket) = rx_socket {
            // ensure the socket is non-blocking
            rx_socket.set_nonblocking(true)?;
            rx_sockets.push(rx_socket);
        } else if let Some(recv_addr) = recv_addr {
            for _ in 0..1 {
                rx_sockets.push(bind(recv_addr, reuse_port)?);
            }
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "missing bind address",
            ));
        };

        let mut tx_sockets = vec![];

        if let Some(tx_socket) = tx_socket {
            // ensure the socket is non-blocking
            tx_socket.set_nonblocking(true)?;
            tx_sockets.push(tx_socket);
        } else if let Some(send_addr) = send_addr {
            for _ in 0..1 {
                tx_sockets.push(bind(send_addr, reuse_port)?);
            }
        } else {
            // No tx_socket or send address was specified, so the tx socket
            // will be a handle to the rx socket.
            for rx_socket in &rx_sockets {
                tx_sockets.push(rx_socket.try_clone()?);
            }
        };

        /*
        if let Some(size) = send_buffer_size {
            tx_socket.set_send_buffer_size(size)?;
        }

        if let Some(size) = recv_buffer_size {
            rx_socket.set_recv_buffer_size(size)?;
        }
        */

        fn convert_addr_to_std(addr: socket2::SockAddr) -> io::Result<std::net::SocketAddr> {
            addr.as_socket().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid domain for socket")
            })
        }

        #[allow(unused_variables)] // some platform builds won't use these so ignore warnings
        let (tx_addr, rx_addr) = (
            convert_addr_to_std(tx_sockets[0].local_addr()?)?,
            convert_addr_to_std(rx_sockets[0].local_addr()?)?,
        );

        /*

        cfg_if! {
            if #[cfg(any(s2n_quic_platform_socket_msg, s2n_quic_platform_socket_mmsg))] {
                let mut rx = socket::Queue::<buffer::Buffer>::new(buffer::Buffer::default(), max_segments.into());
                let tx = socket::Queue::<buffer::Buffer>::new(buffer::Buffer::default(), max_segments.into());
            } else {
                let mut rx = socket::Queue::default();
                let tx = socket::Queue::default();
            }
        }

        // tell the queue the local address so it can fill it in on each message
        rx.set_local_address({
            let addr: inet::SocketAddress = rx_addr.into();
            addr.into()
        });
        */

        let mut local_addr = Default::default();

        let rx_size = std::env::var("RX_SIZE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(u16::MAX as u32);

        let rx_count = std::env::var("RX_COUNT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(4096);

        let (unfilled_rx, filled_rx) = crate::io::channel::pair(rx_size, rx_count);
        let rx_socket = rx_sockets.pop().unwrap();
        //let (unfilled_rx, filled_rx) = crate::io::channel::set(u16::MAX, 1024, rx_sockets.len());

        //for (rx_socket, mut unfilled_rx) in rx_sockets.into_iter().zip(unfilled_rx.inner) {
        let rx_socket: std::net::UdpSocket = rx_socket.into();
        let _ = crate::socket::configure_gro(&rx_socket);
        local_addr = rx_socket.local_addr()?.into();
        handle.spawn(socket::msg::rx(rx_socket, unfilled_rx));
        //}

        let tx_size = std::env::var("TX_SIZE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(u16::MAX as u32);
        let tx_count = std::env::var("TX_COUNT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(4096);
        let (unfilled_tx, filled_tx) = crate::io::channel::pair(tx_size, tx_count);
        let tx_socket = tx_sockets.pop().unwrap();
        //let (unfilled_tx, filled_tx) = crate::io::channel::set(u16::MAX, 1024, 2);

        //for (tx_socket, mut filled_tx) in tx_sockets.into_iter().zip(filled_tx.inner) {
        let tx_socket: std::net::UdpSocket = tx_socket.into();
        handle.spawn(socket::msg::tx(tx_socket, filled_tx));
        //}

        let instance = EventLoop {
            clock,
            rx: filled_rx,
            tx: unfilled_tx,
            endpoint,
        };

        let task = handle.spawn(async move {
            instance.start().await;
        });

        drop(guard);

        Ok((task, local_addr))
    }
}

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use cfg_if::cfg_if;
use std::io;

#[cfg(s2n_quic_platform_socket_msg)]
pub mod msg;

//#[cfg(s2n_quic_platform_socket_mmsg)]
//pub mod mmsg;

#[path = "socket/std.rs"]
pub mod stdlib;

//cfg_if! {
//    if #[cfg(s2n_quic_platform_socket_mmsg)] {
//        pub use mmsg as default;
//    } else if #[cfg(s2n_quic_platform_socket_msg)] {
//        pub use msg as default;
//    } else {
pub use stdlib as default;
//    }
//}

pub fn bind<A: std::net::ToSocketAddrs>(addr: A, reuse_port: bool) -> io::Result<socket2::Socket> {
    use socket2::{Domain, Protocol, Socket, Type};

    let addr = addr.to_socket_addrs()?.next().ok_or_else(|| {
        std::io::Error::new(
            io::ErrorKind::InvalidInput,
            "the provided bind address was empty",
        )
    })?;

    let domain = Domain::for_address(addr);
    let socket_type = Type::DGRAM;
    let protocol = Some(Protocol::UDP);

    cfg_if! {
        // Set non-blocking mode in a single syscall if supported
        if #[cfg(any(
            target_os = "android",
            target_os = "dragonfly",
            target_os = "freebsd",
            target_os = "fuchsia",
            target_os = "illumos",
            target_os = "linux",
            target_os = "netbsd",
            target_os = "openbsd"
        ))] {
            let socket_type = socket_type.nonblocking();
            let socket = Socket::new(domain, socket_type, protocol)?;
        } else {
            let socket = Socket::new(domain, socket_type, protocol)?;
            socket.set_nonblocking(true)?;
        }
    };

    // allow ipv4 to also connect
    if addr.is_ipv6() {
        socket.set_only_v6(false)?;
    }

    socket.set_reuse_address(true)?;

    #[cfg(unix)]
    socket.set_reuse_port(reuse_port)?;

    // mark the variable as "used" regardless of platform support
    let _ = reuse_port;

    socket.bind(&addr.into())?;

    Ok(socket)
}

pub fn configure() -> io::Result<()> {
    /*

    //= https://www.rfc-editor.org/rfc/rfc9000#section-14
    //# UDP datagrams MUST NOT be fragmented at the IP layer.

    //= https://www.rfc-editor.org/rfc/rfc9000#section-14
    //# In IPv4 [IPv4], the Don't Fragment (DF) bit MUST be set if possible, to
    //# prevent fragmentation on the path.

    //= https://www.rfc-editor.org/rfc/rfc8899#section-3
    //# In IPv4, a probe packet MUST be sent with the Don't
    //# Fragment (DF) bit set in the IP header and without network layer
    //# endpoint fragmentation.

    //= https://www.rfc-editor.org/rfc/rfc8899#section-4.5
    //# A PL implementing this specification MUST suspend network layer
    //# processing of outgoing packets that enforces a PMTU
    //# [RFC1191][RFC8201] for each flow utilizing DPLPMTUD and instead use
    //# DPLPMTUD to control the size of packets that are sent by a flow.
    #[cfg(s2n_quic_platform_mtu_disc)]
    {
        use std::os::unix::io::AsRawFd;

        // IP_PMTUDISC_PROBE setting will set the DF (Don't Fragment) flag
        // while also ignoring the Path MTU. This means packets will not
        // be fragmented, and the EMSGSIZE error will not be returned for
        // packets larger than the Path MTU according to the kernel.
        libc!(setsockopt(
            tx_socket.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_MTU_DISCOVER,
            &libc::IP_PMTUDISC_PROBE as *const _ as _,
            core::mem::size_of_val(&libc::IP_PMTUDISC_PROBE) as _,
        ))?;

        if tx_addr.is_ipv6() {
            libc!(setsockopt(
                tx_socket.as_raw_fd(),
                libc::IPPROTO_IPV6,
                libc::IPV6_MTU_DISCOVER,
                &libc::IP_PMTUDISC_PROBE as *const _ as _,
                core::mem::size_of_val(&libc::IP_PMTUDISC_PROBE) as _,
            ))?;
        }
    }

    // Set up the RX socket to pass ECN information
    #[cfg(s2n_quic_platform_tos)]
    {
        use std::os::unix::io::AsRawFd;
        let enabled: libc::c_int = 1;

        // This option needs to be enabled regardless of domain (IPv4 vs IPv6), except on mac
        if rx_addr.is_ipv4() || !cfg!(any(target_os = "macos", target_os = "ios")) {
            libc!(setsockopt(
                rx_socket.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_RECVTOS,
                &enabled as *const _ as _,
                core::mem::size_of_val(&enabled) as _,
            ))?;
        }

        if rx_addr.is_ipv6() {
            libc!(setsockopt(
                rx_socket.as_raw_fd(),
                libc::IPPROTO_IPV6,
                libc::IPV6_RECVTCLASS,
                &enabled as *const _ as _,
                core::mem::size_of_val(&enabled) as _,
            ))?;
        }
    }
    publisher.on_platform_feature_configured(event::builder::PlatformFeatureConfigured {
        configuration: event::builder::PlatformFeatureConfiguration::Ecn {
            enabled: cfg!(s2n_quic_platform_tos),
        },
    });

    // Set up the RX socket to pass information about the local address and interface
    #[cfg(s2n_quic_platform_pktinfo)]
    {
        use std::os::unix::io::AsRawFd;
        let enabled: libc::c_int = 1;

        if rx_addr.is_ipv4() {
            libc!(setsockopt(
                rx_socket.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_PKTINFO,
                &enabled as *const _ as _,
                core::mem::size_of_val(&enabled) as _,
            ))?;
        } else {
            libc!(setsockopt(
                rx_socket.as_raw_fd(),
                libc::IPPROTO_IPV6,
                libc::IPV6_RECVPKTINFO,
                &enabled as *const _ as _,
                core::mem::size_of_val(&enabled) as _,
            ))?;
        }
    }

    */

    Ok(())
}

pub fn configure_gro<S: std::os::unix::io::AsRawFd>(s: &S) -> io::Result<()> {
    #[cfg(s2n_quic_platform_gso)]
    {
        let enabled: libc::c_int = 1;
        libc!(setsockopt(
            s.as_raw_fd(),
            libc::SOL_UDP,
            libc::UDP_GRO,
            &enabled as *const _ as _,
            core::mem::size_of_val(&enabled) as _
        ))?;
    }

    Ok(())
}

pub mod stdlib {
    use crate::{
        io::channel::{Filled, Unfilled},
        socket::stdlib::{self as socket, Handle},
    };
    use std::net::UdpSocket;
    use tokio::net::UdpSocket as Inner;

    pub async fn rx(socket: UdpSocket, mut channel: Unfilled<Handle>) {
        let mut rx = socket::Rx::default();
        let socket = Inner::from_std(socket).unwrap();

        while channel.ready().await.is_ok() {
            if socket.readable().await.is_ok() {
                if let Ok(mut slice) = channel.try_slice() {
                    let _ = rx.apply(&socket, &mut slice);
                }
            }
        }
    }

    pub async fn tx(socket: UdpSocket, mut channel: Filled<Handle>) {
        let mut tx = socket::Tx::default();
        let socket = Inner::from_std(socket).unwrap();

        while channel.ready().await.is_ok() {
            if socket.writable().await.is_ok() {
                if let Ok(mut slice) = channel.try_slice() {
                    let _ = tx.apply(&socket, &mut slice);
                }
            }
        }
    }
}

pub mod msg {
    use crate::{
        io::channel::{Filled, Unfilled},
        socket::msg::{self as socket, Handle},
    };
    use std::net::UdpSocket;
    use tokio::io::unix::AsyncFd;

    pub async fn rx(socket: UdpSocket, mut channel: Unfilled<Handle>) {
        let socket = AsyncFd::new(socket).expect("invalid socket");
        let mut rx = socket::Rx::default();
        let count = std::env::var("S2N_RX_ITER")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1usize);

        while channel.ready().await.is_ok() {
            if let Ok(mut socket) = socket.readable().await {
                for _ in 0..count {
                    if let Ok(mut slice) = channel.try_slice() {
                        let _ = socket.try_io(|socket| rx.apply(socket.get_ref(), &mut slice));
                    }
                }
            }
        }
    }

    pub async fn tx(socket: UdpSocket, mut channel: Filled<Handle>) {
        let socket = AsyncFd::new(socket).expect("invalid socket");
        let mut tx = socket::Tx::default();
        let count = std::env::var("S2N_TX_ITER")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1usize);

        while channel.ready().await.is_ok() {
            if let Ok(mut socket) = socket.writable().await {
                for _ in 0..count {
                    if let Ok(mut slice) = channel.try_slice() {
                        let _ = socket.try_io(|socket| tx.apply(socket.get_ref(), &mut slice));
                    }
                }
            }
        }
    }
}

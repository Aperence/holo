//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::BTreeSet;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use holo_utils::capabilities;
use holo_utils::ip::{AddressFamily, IpAddrExt, IpAddrKind};
use holo_utils::quic::QuicError;
use holo_utils::socket::{
    Socket, SocketExt, QuicConnectionStream, UdpSocket, TTL_MAX,
    QuicSocket, QuicSocketRead, QuicSocketWrite, Domain, Type, SockAddr
};
use tokio_quiche::{listen, metrics::DefaultMetrics, settings::{Hooks, TlsCertificatePaths, CertificateKind, QuicSettings, ConnectionParams}, quic::SimpleConnectionIdGenerator};
use tokio::time::sleep;
use tokio::sync::mpsc::error::SendError;
use tokio::sync::mpsc::{Sender, UnboundedReceiver};

use futures_util::StreamExt;

use crate::error::{Error, IoError, NbrRxError};
use crate::packet::message::{DecodeCxt, EncodeCxt, Message};
use crate::tasks::messages::input::{NbrRxMsg, QuicAcceptMsg};
use crate::tasks::messages::output::NbrTxMsg;

const BGP_PORT: u16 = 179;
const CLIENT_STREAM: u64 = 0x02;
const SERVER_STREAM: u64 = 0x03;

// ===== global functions =====

pub(crate) fn listen_socket(
    af: AddressFamily,
    cert: &str,
    private_key: &str
) -> Result<QuicConnectionStream<DefaultMetrics>, std::io::Error> {
    #[cfg(not(feature = "testing"))]
    {
        // Create UDP socket.
        let socket = socket(af)?;

        // Bind socket.
        let sockaddr = SocketAddr::from((IpAddr::unspecified(af), BGP_PORT));
        let sockaddr: SockAddr = sockaddr.into();
        socket.set_reuse_address(true)?;
        capabilities::raise(|| socket.bind(&sockaddr))?;

        // GTSM Procedure: set TTL to max for outgoing packets.
        match af {
            AddressFamily::Ipv4 => {
                socket.set_ipv4_ttl(TTL_MAX)?;
            }
            AddressFamily::Ipv6 => {
                socket.set_ipv6_tclass(TTL_MAX)?;
            }
        }

        // Convert socket into tokio socket.
        let socket = UdpSocket::from_std(socket.into())?;

        // TODO: add correct certs to config
        let mut listeners = listen(
            [socket],
            ConnectionParams::new_server(
                QuicSettings::default(), 
                TlsCertificatePaths{
                    cert, 
                    private_key,
                    kind: CertificateKind::X509
                }, 
                Hooks::default()
            ),
            SimpleConnectionIdGenerator,
            DefaultMetrics,
        )?;

        if listeners.len() < 1{
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other, 
                "failed getting listener"
            ));
        }

        Ok(listeners.swap_remove(0))
    }
    #[cfg(feature = "testing")]
    {
        Ok(QuicConnectionStream::default())
    }
}


#[cfg(not(feature = "testing"))]
pub(crate) async fn listen_loop(
    mut listener: QuicConnectionStream<DefaultMetrics>,
    quic_acceptp: Sender<QuicAcceptMsg>,
) -> Result<(), SendError<QuicAcceptMsg>> {
    loop {
        match listener.next().await{
            Some(accepted) => match accepted {
                Ok(conn) => {
                    match QuicSocket::accept(conn).await{
                        Ok(socket) => {
                            match socket.conn_info() {
                                Ok(conn_info) => {
                                    let msg = QuicAcceptMsg {
                                        conn: Some(socket),
                                        conn_info,
                                    };
                                    quic_acceptp.send(msg).await?;
                                }
                                Err(error) => {
                                    IoError::QuicInfoError(error).log();
                                }
                            }
                        },
                        Err(err) => {
                            IoError::QuicAcceptError(err).log();
                        }
                    }
                },
                Err(error) => {
                    IoError::QuicAcceptError(error).log();
                }
            },
            None => {
                IoError::QuicAcceptError(io::Error::new(io::ErrorKind::Other, "Failed getting next listener")).log();
                break;
            }
        }
    }

    Ok(())
}

/* // TODO: is this necessary ?
pub(crate) fn accepted_stream_init(
    stream: &TcpStream,
    af: AddressFamily,
    ttl: u8,
    ttl_security: Option<u8>,
    tcp_mss: Option<u16>,
) -> Result<(), std::io::Error> {
    //#[cfg(not(feature = "testing"))]
    {
        // Set TTL.
        match af {
            AddressFamily::Ipv4 => stream.set_ipv4_ttl(ttl)?,
            AddressFamily::Ipv6 => stream.set_ipv6_unicast_hops(ttl)?,
        }

        // Set TTL security check.
        if let Some(ttl_security_hops) = ttl_security {
            let ttl = TTL_MAX - ttl_security_hops + 1;
            match af {
                AddressFamily::Ipv4 => stream.set_ipv4_minttl(ttl)?,
                AddressFamily::Ipv6 => stream.set_ipv6_min_hopcount(ttl)?,
            }
        }

        // Set the TCP Maximum Segment Size.
        if let Some(tcp_mss) = tcp_mss {
            stream.set_mss(tcp_mss.into())?;
        }
    }

    Ok(())
}
*/

#[cfg(not(feature = "testing"))]
pub(crate) async fn connect(
    remote_addr: IpAddr,
    local_addr: Option<IpAddr>,
    ttl: u8,
    ttl_security: Option<u8>,
    verify_peer: bool
) -> Result<QuicSocket, Error> {
    let af = remote_addr.address_family();

    // Create QUIC socket.
    let socket = socket(af).map_err(IoError::QuicSocketError)?;

    // Bind socket.
    if let Some(local_addr) = local_addr {
        let sockaddr = SocketAddr::from((local_addr, 0));
        let sockaddr: SockAddr = sockaddr.into();
        socket
            .set_reuse_address(true)
            .map_err(IoError::QuicSocketError)?;
        capabilities::raise(|| socket.bind(&sockaddr))
            .map_err(IoError::QuicSocketError)?;
    }

    let socket = UdpSocket::from_std(socket.into()).map_err(IoError::QuicSocketError)?;

    // Set TTL.
    match af {
        AddressFamily::Ipv4 => socket.set_ipv4_ttl(ttl),
        AddressFamily::Ipv6 => socket.set_ipv6_unicast_hops(ttl),
    }
    .map_err(IoError::QuicSocketError)?;

    // Set TTL security check.
    if let Some(ttl_security_hops) = ttl_security {
        let ttl = TTL_MAX - ttl_security_hops + 1;
        match af {
            AddressFamily::Ipv4 => socket.set_ipv4_minttl(ttl),
            AddressFamily::Ipv6 => socket.set_ipv6_min_hopcount(ttl),
        }
        .map_err(IoError::QuicSocketError)?;
    }


    // Connect to remote address on the BGP port.
    let sockaddr = SocketAddr::from((remote_addr, BGP_PORT));
    socket
        .connect(sockaddr)
        .await
        .map_err(IoError::QuicConnectError)?;

    let mut params = ConnectionParams::default();
    params.settings.verify_peer = verify_peer;

    let socket = QuicSocket::connect(socket, params).await.map_err(IoError::QuicSocketError)?;

    Ok(socket)
}


#[cfg(not(feature = "testing"))]
pub(crate) async fn nbr_write_loop(
    mut conn: QuicSocketWrite,
    mut cxt: EncodeCxt,
    mut nbr_msg_txc: UnboundedReceiver<NbrTxMsg>,
) {
    let stream = if conn.is_server() { SERVER_STREAM } else { CLIENT_STREAM };
    while let Some(msg) = nbr_msg_txc.recv().await {
        match msg {
            // Send message to the peer.
            NbrTxMsg::SendMessage { msg, .. } => {
                let buf = msg.encode(&cxt);
                if let Err(_) = conn.write_stream(&buf, stream).await {
                    IoError::QuicSendError(io::Error::new(io::ErrorKind::BrokenPipe, "")).log();
                }
            }
            // Send list of messages to the peer.
            NbrTxMsg::SendMessageList { msg_list, .. } => {
                for msg in msg_list {
                    let buf = msg.encode(&cxt);
                    if let Err(_) = conn.write_stream(&buf, stream).await {
                        IoError::QuicSendError(io::Error::new(io::ErrorKind::BrokenPipe, "")).log();
                    }
                }
            }
            // Update negotiated capabilities.
            NbrTxMsg::UpdateCapabilities(caps) => cxt.capabilities = caps,
        }
    }
}

#[cfg(not(feature = "testing"))]
pub(crate) async fn nbr_read_loop(
    mut conn: QuicSocketRead,
    nbr_addr: IpAddr,
    mut cxt: DecodeCxt,
    nbr_msg_rxp: Sender<NbrRxMsg>,
) -> Result<(), SendError<NbrRxMsg>> {
    const BUF_SIZE: usize = 65535;
    let mut data = Vec::with_capacity(BUF_SIZE);
    let stream = if conn.is_server() { CLIENT_STREAM } else { SERVER_STREAM };

    loop {
        // Read data from the network.
        match conn.read_stream(stream).await {
            Ok(buf) => data.extend_from_slice(&buf),
            Err(QuicError::ConnClosed) => {
                // Notify that the connection was closed by the remote end.
                let msg = NbrRxMsg {
                    nbr_addr,
                    msg: Err(NbrRxError::TcpConnClosed),
                };
                nbr_msg_rxp.send(msg).await?;
                return Ok(());
            }
            Err(err) => {
                IoError::QuicRecvError(io::Error::new(io::ErrorKind::BrokenPipe, format!("{}", err))).log();
                sleep(Duration::from_millis(10)).await;
                continue;
            }
        };

        // Decode message(s).
        while let Some(msg_size) = Message::get_message_len(&data) {
            let msg = Message::decode(&data[0..msg_size], &cxt)
                .map_err(NbrRxError::MsgDecodeError);
            data.drain(..msg_size);

            // Keep track of received capabilities as they influence how some
            // messages should be decoded.
            if let Ok(Message::Open(msg)) = &msg {
                let capabilities = msg
                    .capabilities
                    .iter()
                    .map(|cap| cap.as_negotiated())
                    .collect::<BTreeSet<_>>();
                cxt.capabilities = capabilities;
            }

            // Notify that the BGP message was received.
            let msg = NbrRxMsg { nbr_addr, msg };
            nbr_msg_rxp.send(msg).await?;
        }
    }
}

// ===== helper functions =====

#[cfg(not(feature = "testing"))]
fn socket(af: AddressFamily) -> Result<Socket, std::io::Error> {
    let socket = match af {
        AddressFamily::Ipv4 => Socket::new(Domain::IPV4, Type::DGRAM, None)?,
        AddressFamily::Ipv6 => {
            let socket = Socket::new(Domain::IPV6, Type::DGRAM, None)?;
            socket.set_only_v6(true)?;
            socket
        }
    };

    socket.set_nonblocking(true)?;

    // Set socket options.
    match af {
        AddressFamily::Ipv4 => {
            socket.set_ipv4_tos(libc::IPTOS_PREC_INTERNETCONTROL)?;
        }
        AddressFamily::Ipv6 => {
            socket.set_ipv6_tclass(libc::IPTOS_PREC_INTERNETCONTROL)?;
        }
    }

    Ok(socket)
}

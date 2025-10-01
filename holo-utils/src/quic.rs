use std::{collections::{HashMap, HashSet}, error::Error, fmt::Display, io, net::IpAddr};
use tokio_quiche::{metrics::{DefaultMetrics, Metrics}, quic::{connect_with_config, HandshakeInfo, QuicheConnection}, quiche::Shutdown, ApplicationOverQuic, ConnectionParams, InitialQuicConnection, QuicConnectionStream, QuicResult};
use tokio::{net::UdpSocket, select, sync::mpsc::{self, error::{TryRecvError, TrySendError}, Receiver, Sender}};
use crate::socket::{ConnInfo, ConnInfoExt};

type Data = Vec<u8>;

enum Command{
    Connected,
    OpenStreams,
    NewStreamRead(u64),
    NewStreamWrite(u64),
}

enum CommandResult{
    Connected,
    OpenStreams(HashSet<u64>),
    NewStreamRead(u64, Receiver<Data>),
    NewStreamWrite(u64, Sender<Data>),
    StreamAlreadyCreated,
    StreamAlreadyClosed
}

#[derive(Debug, Clone, Copy)]
pub enum RequestError{
    ConnClosed,
    StreamClosed
}

impl Display for RequestError{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for RequestError{}

pub struct QuicSocketRead{
    streams: HashMap<u64, Receiver<Data>>,
    send: Sender<Command>,
    recv: Receiver<CommandResult>
}

impl QuicSocketRead{
    pub async fn read_stream(&mut self, stream: u64) -> Result<Data, RequestError>{
        if !self.streams.contains_key(&stream){
            self.send.send(Command::NewStreamRead(stream))
                .await.map_err(|_| 
                    RequestError::ConnClosed
                )?;

            match self.recv.recv().await{
                Some(CommandResult::NewStreamRead(stream, stream_handle)) => self.streams.insert(stream, stream_handle),
                Some(_) => todo!("Should handle this impossible case"),
                None => return Err(RequestError::ConnClosed),
            };
        }


        loop{
            let ret = match self.streams.get_mut(&stream).expect("Impossible error").recv().await{
                Some(data) if data.len() > 0=> Ok(data),
                None => Err(RequestError::StreamClosed),
                _ => continue
            };
            return ret;
        }
    }

    pub async fn streams(&mut self) -> Result<HashSet<u64>, RequestError>{
        self.send.send(Command::OpenStreams)
            .await.map_err(|_| RequestError::ConnClosed)?;

        match self.recv.recv().await{
            Some(CommandResult::OpenStreams(data)) => Ok(data),
            Some(_) => todo!("Should handle this impossible case"),
            None => Err(RequestError::ConnClosed),
        }
    }
}

pub struct QuicSocketWrite{
    streams: HashMap<u64, Sender<Data>>,
    send: Sender<Command>,
    recv: Receiver<CommandResult>
}

impl QuicSocketWrite{
    pub async fn write_stream(&mut self, data: &[u8], stream: u64) -> Result<(), RequestError>{
        if !self.streams.contains_key(&stream){
            self.send.send(Command::NewStreamWrite(stream))
                .await.map_err(|_| RequestError::ConnClosed)?;

            match self.recv.recv().await{
                Some(CommandResult::NewStreamWrite(stream, stream_handle)) => self.streams.insert(stream, stream_handle),
                // TODO: handle StreamAlreadyCreated/Closed
                Some(_) => todo!("Should handle this impossible case"),
                None => return Err(RequestError::ConnClosed),
            };
        }

        match self.streams.get_mut(&stream).expect("Impossible error").send(data.to_vec()).await{
            Ok(data) => Ok(data),
            Err(_) => Err(RequestError::StreamClosed)
        }
    }

    pub fn close_stream(&mut self, stream: u64){
        self.streams.remove(&stream);
    }
}

pub struct QuicSocket{
    conn_info: ConnInfo,
    send: Sender<Command>,
    recv_read: Receiver<CommandResult>,
    recv_write: Receiver<CommandResult>,
}

impl QuicSocket{
    pub fn conn_info(&self) -> io::Result<ConnInfo> {
        Ok(self.conn_info.clone())
    }

    pub fn split(self) -> (QuicSocketRead, QuicSocketWrite) {
        let reader = QuicSocketRead{ streams: HashMap::new(), send: self.send.clone(), recv: self.recv_read };
        let writer = QuicSocketWrite{ streams: HashMap::new(), send: self.send.clone(), recv: self.recv_write };

        (reader, writer)
    }

    pub async fn wait_connected(&mut self) -> Result<(), RequestError>{
        self.send.send(Command::Connected).await.map_err(|_| RequestError::ConnClosed)?;

        match self.recv_read.recv().await{
            Some(CommandResult::Connected) => Ok(()),
            _ => Err(RequestError::ConnClosed),
        }
    }
}


impl QuicSocket{
    pub async fn connect<'a>(socket: UdpSocket, params: ConnectionParams<'a>) -> io::Result<QuicSocket>{
        let local = socket.local_addr()?;
        let peer = socket.peer_addr()?;

        let conn_info = ConnInfo{ 
            local_addr: local.ip(), 
            local_port: local.port(),
            remote_addr: peer.ip(),
            remote_port: peer.port()
        };

        let (driver, mut controller) = QuicSocket::new(conn_info);
        let _ = connect_with_config(socket.try_into()?, None, &params, driver).await;

        controller.wait_connected().await.map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "Failed to connect"))?;

        Ok(controller)
    }

    pub async fn accept(conn: InitialQuicConnection<UdpSocket, DefaultMetrics>) -> io::Result<QuicSocket>{
        let conn_info = ConnInfo{ 
            local_addr: conn.local_addr().ip(), 
            local_port: conn.local_addr().port(),
            remote_addr: conn.peer_addr().ip(),
            remote_port: conn.peer_addr().port()
        };

        let (driver, mut controller) = QuicSocket::new(conn_info);

        let _ = conn.start(driver);

        controller.wait_connected().await.map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "Failed to connect"))?;

        Ok(controller)
    }

    fn new(conn_info: ConnInfo) -> (QuicDriver, QuicSocket){
        let channel_buf = 1024;
        let (command_tx, command_rx) = mpsc::channel(channel_buf);
        let (read_tx, read_rx) = mpsc::channel(channel_buf);
        let (write_tx, write_rx) = mpsc::channel(channel_buf);

        let driver = QuicDriver {
            buf: [0; 4096], 
            channel_buf,
            streams_read: HashMap::new(),
            streams_write: HashMap::new(),
            recv: command_rx, 
            send_read: read_tx,
            send_write: write_tx,
            state: DriverState::Initial
        };

        let socket = QuicSocket{ 
            conn_info, 
            send: command_tx,
            recv_read: read_rx,
            recv_write: write_rx
        };

        (driver, socket)
    }
}

impl ConnInfoExt for QuicSocket{
    fn conn_info(&self) -> io::Result<ConnInfo> {
        Ok(self.conn_info.clone())
    }
}

enum StreamState<T>{
    NotCreated,
    NoChannel,
    Channel(T),
    Closed
}

enum DriverState{
    Initial,
    Started,
    Exit
}

pub struct QuicDriver{
    buf: [u8; 4096],
    channel_buf: usize,
    streams_read: HashMap<u64, StreamState<Sender<Data>>>,
    streams_write: HashMap<u64, StreamState<(Data, Receiver<Data>)>>,
    recv: Receiver<Command>,
    send_read: Sender<CommandResult>,
    send_write: Sender<CommandResult>,
    state: DriverState
}

impl QuicDriver{
    async fn process_msg(&mut self, msg: Option<Command>, qconn: &mut QuicheConnection) -> QuicResult<()>{
        match msg {
            Some(Command::NewStreamRead(stream)) => {
                let (tx, rx) = mpsc::channel(self.channel_buf);
                let entry = self.streams_read.entry(stream).or_insert(StreamState::NotCreated);

                let response = match entry{
                    StreamState::NotCreated => {
                        // channel doesn't exist, create it
                        self.streams_read.insert(stream, StreamState::Channel(tx));
                        CommandResult::NewStreamRead(stream, rx)
                    }
                    StreamState::NoChannel => {
                        // channel doesn't exist, create it
                        self.streams_read.insert(stream, StreamState::Channel(tx));
                        self.process_reads(qconn)?; // force a refresh of stream which received data while having no channel
                        CommandResult::NewStreamRead(stream, rx)
                    },
                    StreamState::Channel(_) => CommandResult::StreamAlreadyCreated,
                    StreamState::Closed => CommandResult::StreamAlreadyClosed,
                };
                self.send_read.send(response).await?;
            },
            Some(Command::NewStreamWrite(stream)) => {
                let (tx, rx) = mpsc::channel(self.channel_buf);

                let entry = self.streams_write.entry(stream).or_insert(StreamState::NotCreated);

                let response = match entry{
                    StreamState::NotCreated | StreamState::NoChannel => {
                        // channel doesn't exist, create it
                        self.streams_write.insert(stream, StreamState::Channel((vec![], rx)));
                        CommandResult::NewStreamWrite(stream, tx)
                    }
                    StreamState::Channel(_) => CommandResult::StreamAlreadyCreated,
                    StreamState::Closed => CommandResult::StreamAlreadyClosed,
                };
                self.send_write.send(response).await?;
            },
            Some(Command::OpenStreams) => {
                let streams = self.streams_read.iter()
                    .filter(|(_, status)| matches!(status, StreamState::NoChannel | StreamState::Channel(_)))
                    .map(|(id, _)| *id)
                    .collect();
                self.send_read.send(CommandResult::OpenStreams(streams)).await?;
            },
            Some(Command::Connected) => {
                self.send_read.send(CommandResult::Connected).await?;
            }
            None => { 
                if !qconn.is_closed(){
                    qconn.close(true, 0, "Connection closed".as_bytes())?; 
                }
                self.state = DriverState::Exit;
            }
        }

        Ok(())
    }
}

impl ApplicationOverQuic for QuicDriver{
    fn on_conn_established(
        &mut self, _qconn: &mut QuicheConnection, _handshake_info: &HandshakeInfo,
    ) -> QuicResult<()> {
        self.state = DriverState::Started;
        QuicResult::Ok(())
    }

    fn should_act(&self) -> bool {
        matches!(self.state, DriverState::Started)
    }

    fn buffer(&mut self) -> &mut [u8] {
        &mut self.buf
    }

    async fn wait_for_data(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<()> {
        select! {
            msg = self.recv.recv() => {
                self.process_msg(msg, qconn).await?;
            }
        };

        Ok(())
    }

    fn process_reads(&mut self, qconn: &mut QuicheConnection) -> tokio_quiche::QuicResult<()> {
        let mut buf = [0; 65536];

        while let Some(stream) = qconn.stream_readable_next(){
            self.streams_read.entry(stream).or_insert(StreamState::NoChannel);
        }

        let streams = self.streams_read.iter_mut().filter(|(_, status)| matches!(status, StreamState::Channel(_)));

        for (stream, state) in streams{
            let mut closed = false;
            if let StreamState::Channel(send) = state{
                let slot = match send.try_reserve(){
                    Ok(slot) => Some(slot),
                    Err(TrySendError::Full(_)) => continue,
                    Err(TrySendError::Closed(_)) => {
                        qconn.stream_shutdown(*stream, Shutdown::Read, 0)?;
                        closed = true;
                        None
                    }
                };

                if let Some(slot) = slot{
                    match qconn.stream_recv(*stream, &mut buf){
                        Ok((n, fin)) => {
                            slot.send(buf[..n].to_vec());
                            closed = fin;
                        },
                        Err(_) => (), // no data to read
                    }
                }
            };

            if closed{
                *state = StreamState::Closed;
            }
        }

        Ok(())
    }

    fn process_writes(&mut self, qconn: &mut QuicheConnection) -> tokio_quiche::QuicResult<()> {
        for (stream, state) in &mut self.streams_write{
            if let StreamState::Channel((buffered_data, rx)) = state{
                if buffered_data.len() > 0{
                    let written = qconn.stream_send(*stream, &buffered_data, false)?;
                    *buffered_data = buffered_data.drain(..written).collect();
                    if buffered_data.len() > 0{
                        continue; // stream has not yet received all data
                    }
                }

                match rx.try_recv(){
                    Ok(data) => {
                        let written = qconn.stream_send(*stream, &data, false)?;
                        if written < data.len(){
                            buffered_data.extend_from_slice(&data[written..]);
                        }
                    },
                    Err(TryRecvError::Disconnected) => {
                        qconn.stream_send(*stream, "".as_bytes(), true)?;
                        *state = StreamState::Closed;
                    },
                    _ => continue
                }
            }
        }
        
        Ok(())
    }

    fn on_conn_close<M: Metrics>(
        &mut self, _qconn: &mut QuicheConnection, _metrics: &M,
        connection_result: &QuicResult<()>,
    ) {
        //println!("Connection closed: {:?}", connection_result);
    }
}

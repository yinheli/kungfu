use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Result, anyhow};
use bytes::{BufMut, BytesMut};
use log::debug;
use moka::sync::Cache;

use std::net::{IpAddr, Ipv4Addr};
use tokio::sync::Mutex;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    sync::mpsc::Receiver,
    time::timeout,
};
use url::Url;

use super::{common, nat::Session};
use crate::{gateway::stats, runtime::ArcRuntime};

const UDP_BUFFER_SIZE: usize = 1500;
const UDP_ASSOCIATE_TIMEOUT: Duration = Duration::from_secs(5);
const UDP_RESPONSE_TIMEOUT: Duration = Duration::from_secs(2);
const SOCKS5_UDP_HEADER_MIN: usize = 10; // RSV(2) + FRAG(1) + ATYP(1) + LEN(1) + PORT(2)

/// SOCKS5 reply descriptions indexed by reply code
const SOCKS5_REPLIES: [&str; 9] = [
    "succeeded",
    "general SOCKS server failure",
    "connection not allowed by ruleset",
    "network unreachable",
    "host unreachable",
    "connection refused",
    "TTL expired",
    "command not supported (UDP ASSOCIATE not supported by proxy server)",
    "address type not supported",
];

/// UDP Association maintains the SOCKS5 UDP ASSOCIATE control channel and UDP socket
struct UdpAssociation {
    _tcp_control: TcpStream,
    udp_socket: Arc<UdpSocket>,
    socks_udp_addr: SocketAddr,
}

impl UdpAssociation {
    async fn new(proxy_url: &str, nat_port: u16) -> Result<Self> {
        let url = Url::parse(proxy_url)?;
        let host = url.host().ok_or_else(|| anyhow!("missing host"))?;
        let port = url.port().unwrap_or(1080);

        let proxy_addr = format!("{}:{}", host, port);
        let mut tcp_control = TcpStream::connect(&proxy_addr).await?;

        // SOCKS5 handshake
        if url.username() != "" {
            perform_auth(
                &mut tcp_control,
                url.username(),
                url.password().unwrap_or(""),
            )
            .await?;
        } else {
            perform_no_auth(&mut tcp_control).await?;
        }

        let socks_udp_addr = perform_udp_associate(&mut tcp_control).await?;

        // Some SOCKS5 proxies return 0.0.0.0 but expect UDP on the same port as TCP
        let socks_udp_addr = if socks_udp_addr.ip().is_unspecified() {
            // Use the same host as the TCP connection but the port returned by UDP ASSOCIATE
            let peer_addr = tcp_control.peer_addr()?;
            SocketAddr::new(peer_addr.ip(), socks_udp_addr.port())
        } else {
            socks_udp_addr
        };

        let udp_socket = Arc::new(UdpSocket::bind(format!("0.0.0.0:{}", nat_port)).await?);

        Ok(Self {
            _tcp_control: tcp_control,
            udp_socket,
            socks_udp_addr,
        })
    }

    async fn send(&self, data: &[u8]) -> Result<usize> {
        self.udp_socket
            .send_to(data, self.socks_udp_addr)
            .await
            .map_err(|e| e.into())
    }

    async fn recv(&self) -> Result<Option<Vec<u8>>> {
        let mut buf = vec![0u8; UDP_BUFFER_SIZE];
        match timeout(UDP_RESPONSE_TIMEOUT, self.udp_socket.recv_from(&mut buf))
            .await
            .map_err(|e| anyhow!("UDP receive timeout: {}", e))?
            .map(|(len, _)| len)
        {
            Ok(len) => {
                buf.truncate(len);
                Ok(Some(buf))
            }
            Err(e) => {
                debug!("receive error:{}", e);
                Ok(None)
            }
        }
    }
}

/// SOCKS5 authentication with username/password
async fn perform_auth(stream: &mut TcpStream, username: &str, password: &str) -> Result<()> {
    let auth_methods = vec![5u8, 1, 2];
    stream.write_all(&auth_methods).await?;

    let mut response = [0u8; 2];
    stream.read_exact(&mut response).await?;

    if response[1] != 2 {
        return Err(anyhow!("Server doesn't support username/password auth"));
    }
    let mut auth_req = BytesMut::new();
    auth_req.put_u8(1);
    auth_req.put_u8(username.len().min(255) as u8);
    auth_req.put_slice(username.as_bytes());
    auth_req.put_u8(password.len().min(255) as u8);
    auth_req.put_slice(password.as_bytes());

    stream.write_all(&auth_req).await?;
    let mut auth_response = [0u8; 2];
    stream.read_exact(&mut auth_response).await?;

    if auth_response[1] != 0 {
        return Err(anyhow!("Authentication failed"));
    }

    Ok(())
}

/// SOCKS5 no authentication
async fn perform_no_auth(stream: &mut TcpStream) -> Result<()> {
    let auth_methods = vec![5u8, 1, 0];
    stream.write_all(&auth_methods).await?;

    let mut response = [0u8; 2];
    stream.read_exact(&mut response).await?;

    if response[1] != 0 {
        return Err(anyhow!("Server doesn't support no auth"));
    }

    Ok(())
}

/// Perform SOCKS5 UDP ASSOCIATE and return the UDP relay address
async fn perform_udp_associate(stream: &mut TcpStream) -> Result<SocketAddr> {
    let mut request = BytesMut::new();
    request.put_u8(5);
    request.put_u8(3);
    request.put_u8(0);
    request.put_u8(1);
    request.put_slice(&[0, 0, 0, 0]);
    request.put_u16(0);

    stream.write_all(&request).await?;
    let mut response = [0u8; 4];
    stream.read_exact(&mut response).await?;

    if response[1] != 0 {
        return Err(anyhow!(
            "UDP ASSOCIATE failed: {} (reply code: {})",
            SOCKS5_REPLIES
                .get(response[1] as usize)
                .copied()
                .unwrap_or("unknown error"),
            response[1]
        ));
    }

    let atyp = response[3];
    let addr = match atyp {
        1 => {
            let mut addr_bytes = [0u8; 4];
            stream.read_exact(&mut addr_bytes).await?;
            let mut port_bytes = [0u8; 2];
            stream.read_exact(&mut port_bytes).await?;
            let port = u16::from_be_bytes(port_bytes);
            SocketAddr::new(IpAddr::V4(Ipv4Addr::from(addr_bytes)), port)
        }
        3 => {
            let mut len_byte = [0u8; 1];
            stream.read_exact(&mut len_byte).await?;
            let domain_len = len_byte[0] as usize;
            if domain_len == 0 {
                return Err(anyhow!("Empty domain name in response"));
            }
            let mut domain_bytes = vec![0u8; domain_len];
            stream.read_exact(&mut domain_bytes).await?;
            let mut port_bytes = [0u8; 2];
            stream.read_exact(&mut port_bytes).await?;
            let domain = String::from_utf8(domain_bytes)
                .map_err(|_| anyhow!("Invalid domain name in response"))?;
            let port = u16::from_be_bytes(port_bytes);
            format!("{}:{}", domain, port).parse()?
        }
        4 => {
            let mut addr_bytes = [0u8; 16];
            stream.read_exact(&mut addr_bytes).await?;
            let mut port_bytes = [0u8; 2];
            stream.read_exact(&mut port_bytes).await?;
            let port = u16::from_be_bytes(port_bytes);
            SocketAddr::new(IpAddr::V6(addr_bytes.into()), port)
        }
        _ => return Err(anyhow!("Unknown address type: {}", atyp)),
    };

    Ok(addr)
}

/// Encode SOCKS5 UDP datagram: [RSV(2) | FRAG | ATYP | DST.ADDR | DST.PORT | DATA]
///
/// Always use domain name (ATYP=3) to let SOCKS5 proxy server resolve the address.
/// This is essential for DNS hijacking scenarios where we need the proxy to resolve
/// the original domain name instead of connecting to the hijacked IP.
fn encode_socks5_udp(target_addr: &str, target_port: u16, data: &[u8]) -> Result<Vec<u8>> {
    if target_addr.len() > 255 {
        return Err(anyhow!("Domain name too long"));
    }

    // SOCKS5 UDP header: RSV(2) | FRAG(1) | ATYP(1) | DST.ADDR | DST.PORT(2) | DATA
    let header_size = 6 + target_addr.len() + 2; // 6 + domain_len + port
    let total_size = header_size + data.len();
    let mut encoded = Vec::with_capacity(total_size);

    // RSV (2 bytes)
    encoded.extend_from_slice(&[0, 0]);
    // FRAG (1 byte)
    encoded.push(0);
    // ATYP (1 byte) - 3 for domain name
    encoded.push(3);
    // Domain length (1 byte)
    encoded.push(target_addr.len() as u8);
    // Domain
    encoded.extend_from_slice(target_addr.as_bytes());
    // Port (2 bytes)
    encoded.extend_from_slice(&target_port.to_be_bytes());
    // Data
    encoded.extend_from_slice(data);

    Ok(encoded)
}

fn decode_socks5_udp(buf: &[u8]) -> Result<(String, u16, Vec<u8>)> {
    if buf.len() < 10 {
        return Err(anyhow!("UDP datagram too short"));
    }

    let atyp = buf[3];

    let (addr, port_offset) = match atyp {
        1 => {
            if buf.len() < 10 {
                return Err(anyhow!("Truncated IPv4 address"));
            }
            let a = buf[4];
            let b = buf[5];
            let c = buf[6];
            let d = buf[7];
            (format!("{}.{}.{}.{}", a, b, c, d), 8)
        }
        3 => {
            if buf.len() < 5 {
                return Err(anyhow!("Invalid domain length"));
            }
            let len = buf[4] as usize;
            if len == 0 || buf.len() < 5 + len + 2 {
                return Err(anyhow!("Invalid domain length"));
            }
            let domain_bytes = &buf[5..5 + len];
            let domain = String::from_utf8_lossy(domain_bytes).into_owned();
            (domain, 5 + len)
        }
        4 => {
            if buf.len() < 22 {
                return Err(anyhow!("Truncated IPv6 address"));
            }
            let octets = &buf[5..21];
            let mut arr = [0u8; 16];
            arr.copy_from_slice(octets);
            (std::net::Ipv6Addr::from(arr).to_string(), 21)
        }
        _ => return Err(anyhow!("Unknown ATYP: {}", atyp)),
    };

    if buf.len() < port_offset + 2 {
        return Err(anyhow!("Truncated port"));
    }

    let port = u16::from_be_bytes([buf[port_offset], buf[port_offset + 1]]);
    let data = buf[port_offset + 2..].to_vec();

    Ok((addr, port, data))
}

pub(crate) struct UdpRelay {
    runtime: ArcRuntime,
    associations: Cache<u16, Arc<UdpAssociation>>,
    lock: Mutex<HashMap<u16, Arc<Mutex<Option<()>>>>>,
}

impl UdpRelay {
    pub fn new(runtime: ArcRuntime, rx: Receiver<u16>) -> Self {
        let associations = Cache::builder().build();

        let invalidates = associations.clone();
        tokio::spawn(async move {
            let mut rx = rx;
            while let Some(nat_port) = rx.recv().await {
                invalidates.invalidate(&nat_port);
            }
        });

        Self {
            runtime,
            associations,
            lock: Default::default(),
        }
    }

    async fn get_or_create_association<F, Fut>(
        &self,
        proxy_name: &str,
        target_host: &str,
        nat_port: u16,
        callback: F,
    ) -> Result<Arc<UdpAssociation>>
    where
        F: Fn(Vec<u8>) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send,
    {
        if let Some(assoc) = self.associations.get(&nat_port) {
            return Ok(assoc);
        }
        let pending_lock = {
            let mut pending = self.lock.lock().await;
            pending
                .entry(nat_port)
                .or_insert(Arc::new(Default::default()))
                .clone()
        };

        let _guard = pending_lock.lock().await;

        if let Some(assoc) = self.associations.get(&nat_port) {
            return Ok(assoc);
        }

        debug!(
            "No cached association for proxy: {}, creating new",
            proxy_name
        );

        let proxy_config = self
            .runtime
            .setting
            .proxy
            .iter()
            .find(|p| p.name == proxy_name)
            .ok_or_else(|| anyhow!("Proxy not found: {}", proxy_name))?;

        let proxy_url = common::random_proxy(&proxy_config.values);

        let assoc = timeout(
            UDP_ASSOCIATE_TIMEOUT,
            UdpAssociation::new(&proxy_url, nat_port),
        )
        .await??;
        let assoc = Arc::new(assoc);
        self.associations.insert(nat_port, assoc.clone());

        let assoc_clone = assoc.clone();
        let runtime = self.runtime.clone();
        let proxy_name = proxy_name.to_string();
        let target_host = target_host.to_string();
        tokio::spawn(async move {
            while let Ok(Some(data)) = assoc_clone.recv().await {
                if let Ok((_src_addr, _src_port, data)) = decode_socks5_udp(&data) {
                    let down = data.len() as u64;
                    callback(data).await;
                    stats::update_metrics(
                        &runtime,
                        stats::Protocol::Udp,
                        &proxy_name,
                        &target_host,
                        0,
                        down,
                    );
                }
            }
        });

        Ok(assoc)
    }

    pub async fn send<F, Fut>(
        &self,
        session: Session,
        payload: &[u8],
        callback: F,
    ) -> anyhow::Result<()>
    where
        F: Fn(Vec<u8>) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send,
    {
        let nat_port = session.nat_port;
        let target = self.find_target(session)?;
        let (proxy_name, target_host, target_port) = target;
        let max_payload = UDP_BUFFER_SIZE - (SOCKS5_UDP_HEADER_MIN + target_host.len());
        if payload.len() > max_payload {
            debug!("UDP payload too large: {} > {}", payload.len(), max_payload);
            return Ok(());
        }

        let assoc = self
            .get_or_create_association(&proxy_name, &target_host, nat_port, callback)
            .await?;

        let encoded = encode_socks5_udp(&target_host, target_port, payload)?;

        let _ = assoc.send(&encoded).await?;

        stats::update_metrics(
            &self.runtime,
            stats::Protocol::Udp,
            &proxy_name,
            &target_host,
            payload.len() as u64,
            0,
        );

        Ok(())
    }

    fn find_target(&self, session: Session) -> anyhow::Result<(String, String, u16)> {
        common::find_target(self.runtime.clone(), session)
            .ok_or_else(|| anyhow!("No route found for {}", session.dst_addr))
    }
}

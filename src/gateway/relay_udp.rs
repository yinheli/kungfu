use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Result, anyhow};
use bytes::{BufMut, BytesMut};
use log::debug;
use moka::sync::Cache;
use std::net::{IpAddr, Ipv4Addr};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    sync::RwLock,
    time::timeout,
};
use url::Url;

use super::{
    common,
    nat::{Nat, Session},
    stats::{self, Protocol},
};
use crate::runtime::ArcRuntime;

const UDP_SESSION_TTL: Duration = Duration::from_secs(300);
const UDP_BUFFER_SIZE: usize = 1500;
const UDP_ASSOCIATE_TIMEOUT: Duration = Duration::from_secs(5);
const UDP_RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);
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
    last_active: RwLock<Instant>,
}

impl UdpAssociation {
    async fn new(proxy_url: &str) -> Result<Self> {
        let url = Url::parse(proxy_url)?;
        let host = url.host().ok_or_else(|| anyhow!("missing host"))?;
        let port = url.port().unwrap_or(1080);

        let proxy_addr = format!("{}:{}", host, port);
        let mut tcp_stream = TcpStream::connect(&proxy_addr).await?;

        // SOCKS5 handshake
        if url.username() != "" {
            perform_auth(
                &mut tcp_stream,
                url.username(),
                url.password().unwrap_or(""),
            )
            .await?;
        } else {
            perform_no_auth(&mut tcp_stream).await?;
        }

        let socks_udp_addr = perform_udp_associate(&mut tcp_stream).await?;

        // Some SOCKS5 proxies return 0.0.0.0 but expect UDP on the same port as TCP
        let final_udp_addr = if socks_udp_addr.ip().is_unspecified() {
            // Use the same host as the TCP connection but the port returned by UDP ASSOCIATE
            let peer_addr = tcp_stream.peer_addr()?;
            SocketAddr::new(peer_addr.ip(), socks_udp_addr.port())
        } else {
            socks_udp_addr
        };

        let local_udp = UdpSocket::bind("0.0.0.0:0").await?;

        Ok(Self {
            _tcp_control: tcp_stream,
            udp_socket: Arc::new(local_udp),
            socks_udp_addr: final_udp_addr,
            last_active: RwLock::new(Instant::now()),
        })
    }

    async fn is_expired(&self) -> bool {
        self.last_active.read().await.elapsed() > UDP_SESSION_TTL
    }

    async fn touch(&self) {
        *self.last_active.write().await = Instant::now();
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
    _nat: Arc<Nat>,
    associations: Cache<String, Arc<UdpAssociation>>,
}

impl UdpRelay {
    pub fn new(runtime: ArcRuntime, nat: Arc<Nat>) -> Self {
        let associations = Cache::builder()
            .time_to_live(UDP_SESSION_TTL)
            .eviction_listener(|key, assoc: Arc<UdpAssociation>, cause| {
                debug!(
                    "UDP association for proxy {} expired, cause: {:?}",
                    key, cause
                );
                tokio::spawn(async move {
                    if assoc.is_expired().await {
                        debug!("Removed expired UDP association: {}", key);
                    }
                });
            })
            .build();

        Self {
            runtime,
            _nat: nat,
            associations,
        }
    }

    pub async fn handle_packet(&self, session: Session, payload: &[u8]) -> Result<Option<Vec<u8>>> {
        let target = self.find_target(session)?;
        let (proxy_name, target_host, target_port) = target;

        let assoc = self.get_or_create_association(&proxy_name).await?;

        let max_payload = UDP_BUFFER_SIZE - (SOCKS5_UDP_HEADER_MIN + target_host.len());
        if payload.len() > max_payload {
            debug!("UDP payload too large: {} > {}", payload.len(), max_payload);
            return Ok(None);
        }

        let encoded = encode_socks5_udp(&target_host, target_port, payload)?;
        assoc
            .udp_socket
            .send_to(&encoded, assoc.socks_udp_addr)
            .await?;

        assoc.touch().await;

        let udp_socket = assoc.udp_socket.clone();
        let expected_addr = assoc.socks_udp_addr;

        match timeout(UDP_RESPONSE_TIMEOUT, async {
            let mut buf = [0u8; UDP_BUFFER_SIZE];
            let (len, from_addr) = udp_socket.recv_from(&mut buf).await?;

            if from_addr != expected_addr {
                return Err(anyhow!("UDP response from unexpected address"));
            }
            let data = buf[..len].to_vec();
            Ok::<_, anyhow::Error>(data)
        })
        .await
        {
            Ok(Ok(response)) => {
                let (_, _, data) = decode_socks5_udp(&response)?;
                stats::update_metrics(
                    &self.runtime,
                    Protocol::Udp,
                    &proxy_name,
                    &target_host,
                    payload.len() as u64,
                    data.len() as u64,
                );
                Ok(Some(data))
            }
            Ok(Err(_)) => Ok(None),
            Err(_) => Ok(None), // Timeout is normal for UDP
        }
    }

    async fn get_or_create_association(&self, proxy_name: &str) -> Result<Arc<UdpAssociation>> {
        if let Some(assoc) = self.associations.get(proxy_name) {
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

        let assoc = timeout(UDP_ASSOCIATE_TIMEOUT, UdpAssociation::new(&proxy_url)).await??;
        let assoc = Arc::new(assoc);
        self.associations
            .insert(proxy_name.to_string(), assoc.clone());
        Ok(assoc)
    }

    fn find_target(&self, session: Session) -> Result<(String, String, u16)> {
        common::find_target(self.runtime.clone(), session)
            .ok_or_else(|| anyhow!("No route found for {}", session.dst_addr))
    }
}

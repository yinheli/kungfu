use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::{Result, anyhow};
use bytes::{BufMut, Bytes, BytesMut};
use log::debug;
use moka::sync::Cache;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    sync::{Mutex, Notify, mpsc::UnboundedReceiver},
    time::timeout,
};
use url::Url;

use super::{common, nat::Session};
use crate::{gateway::stats, runtime::ArcRuntime};

const UDP_BUFFER_SIZE: usize = 4096;
const UDP_ASSOCIATE_TIMEOUT: Duration = Duration::from_secs(5);
const UDP_ASSOCIATION_TTL: Duration = Duration::from_secs(300);
const SOCKS5_UDP_HEADER_MIN: usize = 10;

const ATYP_IPV4: u8 = 1;
const ATYP_DOMAIN: u8 = 3;
const ATYP_IPV6: u8 = 4;

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

struct UdpAssociation {
    _control: TcpStream,
    socket: UdpSocket,
    addr: SocketAddr,
    active: AtomicBool,
    notify: Arc<Notify>,
}

impl UdpAssociation {
    async fn new(proxy_url: &str, nat_port: u16) -> Result<Self> {
        let url = Url::parse(proxy_url)?;
        let host = url.host().ok_or_else(|| anyhow!("missing host"))?;
        let port = url.port().unwrap_or(1080);

        let proxy_addr = format!("{}:{}", host, port);
        let mut tcp_control = TcpStream::connect(&proxy_addr).await?;

        if url.username() != "" {
            Self::perform_auth(
                &mut tcp_control,
                url.username(),
                url.password().unwrap_or(""),
            )
            .await?;
        } else {
            Self::perform_no_auth(&mut tcp_control).await?;
        }

        let addr = Self::perform_udp_associate(&mut tcp_control).await?;

        let addr = if addr.ip().is_unspecified() {
            let peer_addr = tcp_control.peer_addr()?;
            SocketAddr::new(peer_addr.ip(), addr.port())
        } else {
            addr
        };

        let socket = UdpSocket::bind(format!("0.0.0.0:{}", nat_port)).await?;
        let active = AtomicBool::new(true);
        let notify = Arc::new(Notify::new());

        Ok(Self {
            _control: tcp_control,
            socket,
            addr,
            active,
            notify,
        })
    }

    async fn send(&self, data: &Bytes) -> Result<usize> {
        self.socket
            .send_to(data, self.addr)
            .await
            .map_err(|e| e.into())
    }

    async fn recv(&self) -> Result<Option<Bytes>> {
        let mut buf = [0u8; UDP_BUFFER_SIZE];

        loop {
            tokio::select! {
                result = self.socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, _)) => return Ok(Some(Bytes::copy_from_slice(&buf[..len]))),
                        Err(e) => {
                            debug!("receive error: {}", e);
                            return Ok(None);
                        }
                    }
                }
                _ = self.notify.notified() => {
                    if !self.active.load(Ordering::Relaxed) {
                        return Ok(None);
                    }
                }
            }
        }
    }

    fn deactivate(&self) {
        self.active.store(false, Ordering::Relaxed);
        self.notify.notify_one();
    }

    fn encode_socks5_udp(&self, target_addr: &str, target_port: u16, data: &[u8]) -> Result<Bytes> {
        if target_addr.len() > 255 {
            return Err(anyhow!("Domain name too long"));
        }

        let header_size = 7 + target_addr.len();
        let total_size = header_size + data.len();
        let mut encoded = BytesMut::with_capacity(total_size);

        encoded.extend_from_slice(&[0, 0]);
        encoded.put_u8(0);
        encoded.put_u8(ATYP_DOMAIN);
        encoded.put_u8(target_addr.len() as u8);
        encoded.extend_from_slice(target_addr.as_bytes());
        encoded.extend_from_slice(&target_port.to_be_bytes());
        encoded.extend_from_slice(data);

        Ok(encoded.freeze())
    }

    fn decode_socks5_udp(buf: &[u8]) -> Result<(String, u16, Bytes)> {
        if buf.len() < SOCKS5_UDP_HEADER_MIN {
            return Err(anyhow!("UDP datagram too short"));
        }

        let atyp = buf[3];

        let (addr, port_offset) = match atyp {
            ATYP_IPV4 => {
                if buf.len() < 10 {
                    return Err(anyhow!("Truncated IPv4 address"));
                }
                let a = buf[4];
                let b = buf[5];
                let c = buf[6];
                let d = buf[7];
                (format!("{}.{}.{}.{}", a, b, c, d), 8)
            }
            ATYP_DOMAIN => {
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
            ATYP_IPV6 => {
                if buf.len() < 22 {
                    return Err(anyhow!("Truncated IPv6 address"));
                }
                let octets = &buf[4..20];
                let mut arr = [0u8; 16];
                arr.copy_from_slice(octets);
                (std::net::Ipv6Addr::from(arr).to_string(), 20)
            }
            _ => return Err(anyhow!("Unknown ATYP: {}", atyp)),
        };

        if buf.len() < port_offset + 2 {
            return Err(anyhow!("Truncated port"));
        }

        let port = u16::from_be_bytes([buf[port_offset], buf[port_offset + 1]]);
        let data = Bytes::copy_from_slice(&buf[port_offset + 2..]);

        Ok((addr, port, data))
    }

    async fn send_auth_methods(stream: &mut TcpStream, methods: &[u8]) -> Result<u8> {
        let mut buf = BytesMut::with_capacity(2 + methods.len());
        buf.put_u8(5);
        buf.put_u8(methods.len() as u8);
        buf.extend_from_slice(methods);
        stream.write_all(&buf).await?;

        let mut response = [0u8; 2];
        stream.read_exact(&mut response).await?;

        Ok(response[1])
    }

    async fn perform_auth(stream: &mut TcpStream, username: &str, password: &str) -> Result<()> {
        let method = Self::send_auth_methods(stream, &[2]).await?;
        if method != 2 {
            return Err(anyhow!("Server doesn't support username/password auth"));
        }

        let auth_len = 1 + 1 + username.len().min(255) + 1 + password.len().min(255);
        let mut auth_req = BytesMut::with_capacity(auth_len);
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

    async fn perform_no_auth(stream: &mut TcpStream) -> Result<()> {
        let method = Self::send_auth_methods(stream, &[0]).await?;
        if method != 0 {
            return Err(anyhow!("Server doesn't support no auth"));
        }
        Ok(())
    }

    async fn perform_udp_associate(stream: &mut TcpStream) -> Result<SocketAddr> {
        let mut request = BytesMut::with_capacity(10);
        request.put_u8(5);
        request.put_u8(3);
        request.put_u8(0);
        request.put_u8(1);
        request.extend_from_slice(&[0, 0, 0, 0]);
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
            ATYP_IPV4 => {
                let mut addr_bytes = [0u8; 4];
                stream.read_exact(&mut addr_bytes).await?;
                let mut port_bytes = [0u8; 2];
                stream.read_exact(&mut port_bytes).await?;
                let port = u16::from_be_bytes(port_bytes);
                SocketAddr::new(IpAddr::V4(Ipv4Addr::from(addr_bytes)), port)
            }
            ATYP_DOMAIN => {
                let mut len_byte = [0u8; 1];
                stream.read_exact(&mut len_byte).await?;
                let domain_len = len_byte[0] as usize;
                if domain_len == 0 {
                    return Err(anyhow!("Empty domain name in response"));
                }
                let mut domain_bytes = BytesMut::zeroed(domain_len);
                stream.read_exact(&mut domain_bytes).await?;
                let mut port_bytes = [0u8; 2];
                stream.read_exact(&mut port_bytes).await?;
                let domain = String::from_utf8(domain_bytes.to_vec())
                    .map_err(|_| anyhow!("Invalid domain name in response"))?;
                let port = u16::from_be_bytes(port_bytes);
                format!("{}:{}", domain, port).parse()?
            }
            ATYP_IPV6 => {
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
}

pub(crate) struct UdpRelay {
    runtime: ArcRuntime,
    associations: Cache<u16, Arc<UdpAssociation>>,
    lock: Mutex<HashMap<u16, Arc<Mutex<Option<()>>>>>,
}

impl UdpRelay {
    pub fn new(runtime: ArcRuntime, mut rx: UnboundedReceiver<u16>) -> Self {
        let associations: Cache<u16, Arc<UdpAssociation>> =
            Cache::builder().time_to_idle(UDP_ASSOCIATION_TTL).build();

        let invalidates = associations.clone();
        tokio::spawn(async move {
            while let Some(nat_port) = rx.recv().await {
                if let Some(assoc) = invalidates.get(&nat_port) {
                    assoc.deactivate();
                }
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
        F: Fn(Bytes) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send,
    {
        if let Some(assoc) = self.associations.get(&nat_port) {
            return Ok(assoc);
        }
        let pending_lock = {
            let mut pending = self.lock.lock().await;
            pending
                .entry(nat_port)
                .or_insert_with(|| Arc::new(Mutex::new(None)))
                .clone()
        };

        let _guard = pending_lock.lock().await;

        if let Some(assoc) = self.associations.get(&nat_port) {
            self.lock.lock().await.remove(&nat_port);
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

        let result = timeout(
            UDP_ASSOCIATE_TIMEOUT,
            UdpAssociation::new(&proxy_url, nat_port),
        )
        .await;

        let assoc = match result {
            Ok(Ok(assoc)) => assoc,
            Ok(Err(e)) => {
                self.lock.lock().await.remove(&nat_port);
                return Err(e);
            }
            Err(_) => {
                self.lock.lock().await.remove(&nat_port);
                return Err(anyhow!("UDP ASSOCIATE timeout"));
            }
        };

        let assoc = Arc::new(assoc);
        self.associations.insert(nat_port, assoc.clone());
        self.lock.lock().await.remove(&nat_port);

        let assoc_clone = assoc.clone();
        let runtime = self.runtime.clone();
        let proxy_name = proxy_name.to_string();
        let target_host = target_host.to_string();
        let associations_cache = self.associations.clone();
        tokio::spawn(async move {
            while let Ok(Some(data)) = assoc_clone.recv().await {
                if let Ok((_src_addr, _src_port, data)) = UdpAssociation::decode_socks5_udp(&data) {
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
            log::debug!(
                "UDP receive loop ended for proxy {} (nat_port: {}), invalidating association",
                proxy_name,
                nat_port
            );
            associations_cache.invalidate(&nat_port);
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
        F: Fn(Bytes) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send,
    {
        let nat_port = session.nat_port;
        let target = self.find_target(session).await?;
        let (proxy_name, target_host, target_port) = target;
        let max_payload = UDP_BUFFER_SIZE - (7 + target_host.len());
        if payload.len() > max_payload {
            log::warn!(
                "UDP payload too large: {} > {} (host: {}, nat_port: {})",
                payload.len(),
                max_payload,
                target_host,
                nat_port
            );
            return Ok(());
        }

        let assoc = self
            .get_or_create_association(&proxy_name, &target_host, nat_port, callback)
            .await?;

        let encoded = assoc.encode_socks5_udp(&target_host, target_port, payload)?;

        if let Err(e) = assoc.send(&encoded).await {
            log::warn!(
                "UDP send failed for {}:{} via proxy {} (nat_port: {}): {}",
                target_host,
                target_port,
                proxy_name,
                nat_port,
                e
            );
            assoc.deactivate();
            self.associations.invalidate(&nat_port);
            return Err(e);
        }

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

    async fn find_target(&self, session: Session) -> anyhow::Result<(String, String, u16)> {
        common::find_target(self.runtime.clone(), session)
            .await
            .ok_or_else(|| anyhow!("No route found for {}", session.dst_addr))
    }
}

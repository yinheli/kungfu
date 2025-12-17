use dashmap::DashMap;
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    net::{self, Ipv4Addr},
    sync::Arc,
    time::Duration,
};
use tokio::sync::mpsc::Sender;

use moka::future::Cache;
use rand::random;

pub struct Nat {
    nat_type: Type,
    port_mapping: Arc<DashMap<PortKey, u16>>,
    reverse_port_mapping: Arc<DashMap<u16, PortKey>>,
    sessions: Cache<u64, Arc<Session>>,
}

pub enum Type {
    Tcp,
    Udp,
}

/// Port mapping key for EIM - only source endpoint
#[derive(Hash, Eq, PartialEq, Clone, Copy, Debug)]
struct PortKey {
    src_addr: Ipv4Addr,
    src_port: u16,
}

impl PortKey {
    fn new(src_addr: Ipv4Addr, src_port: u16) -> Self {
        Self { src_addr, src_port }
    }
}

/// Session represents a NAT mapping entry
#[derive(Debug, Copy, PartialEq, Eq, Clone)]
pub struct Session {
    pub src_addr: Ipv4Addr,
    pub dst_addr: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub nat_port: u16,
}

impl Nat {
    /// Create NAT instance with tiered TTL (TCP 60s, UDP 20s)
    pub fn new(nat_type: Type, tx: Option<Sender<u16>>) -> Self {
        let ttl = match nat_type {
            Type::Tcp => Duration::from_secs(60),
            Type::Udp => Duration::from_secs(20),
        };

        let port_mapping = Arc::new(DashMap::new());
        let reverse_port_mapping = Arc::new(DashMap::new());

        let sessions = Self::new_cache(ttl, port_mapping.clone(), reverse_port_mapping.clone(), tx);

        Self {
            nat_type,
            port_mapping,
            reverse_port_mapping,
            sessions,
        }
    }

    /// Create or retrieve session (EIM: same source -> same nat_port)
    pub async fn create(
        &self,
        src_addr: Ipv4Addr,
        src_port: u16,
        dst_addr: Ipv4Addr,
        dst_port: u16,
    ) -> Session {
        let session_key = Self::compute_session_key(src_addr, src_port, dst_addr, dst_port);

        if let Some(session) = self.sessions.get(&session_key).await {
            return *session;
        }

        let port_key = PortKey::new(src_addr, src_port);
        let nat_port = self.get_or_allocate_port(port_key);

        let session = Arc::new(Session {
            src_addr,
            dst_addr,
            src_port,
            dst_port,
            nat_port,
        });

        self.sessions.insert(session_key, session.clone()).await;
        *session
    }

    /// Find session by NAT port (reverse lookup)
    pub async fn find(&self, nat_port: u16) -> Option<Session> {
        self.reverse_port_mapping.get(&nat_port)?;

        for (_key, session) in self.sessions.iter() {
            if session.nat_port == nat_port {
                return Some(*session);
            }
        }

        None
    }

    fn get_or_allocate_port(&self, port_key: PortKey) -> u16 {
        if let Some(nat_port) = self.port_mapping.get(&port_key) {
            return *nat_port;
        }

        let nat_port = self.get_available_port();
        self.port_mapping.insert(port_key, nat_port);
        self.reverse_port_mapping.insert(nat_port, port_key);
        nat_port
    }

    fn get_available_port(&self) -> u16 {
        match self.nat_type {
            Type::Tcp => {
                let ln = net::TcpListener::bind("127.0.0.1:0");
                match ln {
                    Ok(listener) => match listener.local_addr() {
                        Ok(addr) => addr.port(),
                        Err(_) => random::<u16>().max(1024),
                    },
                    Err(_) => random::<u16>().max(1024),
                }
            }
            Type::Udp => {
                let ln = net::UdpSocket::bind("127.0.0.1:0");
                match ln {
                    Ok(socket) => match socket.local_addr() {
                        Ok(addr) => addr.port(),
                        Err(_) => random::<u16>().max(1024),
                    },
                    Err(_) => random::<u16>().max(1024),
                }
            }
        }
    }

    fn compute_session_key(
        src_addr: Ipv4Addr,
        src_port: u16,
        dst_addr: Ipv4Addr,
        dst_port: u16,
    ) -> u64 {
        let mut hasher = DefaultHasher::new();
        src_addr.hash(&mut hasher);
        src_port.hash(&mut hasher);
        dst_addr.hash(&mut hasher);
        dst_port.hash(&mut hasher);
        hasher.finish()
    }

    fn new_cache(
        ttl: Duration,
        port_mapping: Arc<DashMap<PortKey, u16>>,
        reverse_port_mapping: Arc<DashMap<u16, PortKey>>,
        tx: Option<Sender<u16>>,
    ) -> Cache<u64, Arc<Session>> {
        Cache::builder()
            .max_capacity(10_000)
            .time_to_idle(ttl)
            .eviction_listener(move |_key: Arc<u64>, session: Arc<Session>, _cause| {
                let tx_clone = tx.clone();
                let port_mapping_clone = port_mapping.clone();
                let reverse_port_mapping_clone = reverse_port_mapping.clone();

                tokio::task::spawn(async move {
                    if let Some(ref tx) = tx_clone {
                        let _ = tx.try_send(session.nat_port);
                    }

                    let port_key = PortKey::new(session.src_addr, session.src_port);
                    port_mapping_clone.remove(&port_key);
                    reverse_port_mapping_clone.remove(&session.nat_port);
                });
            })
            .build()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_eim_same_source_same_port() {
        let nat = Nat::new(Type::Tcp, None);

        let session1 = nat
            .create(
                Ipv4Addr::new(192, 168, 1, 100),
                12345,
                Ipv4Addr::new(10, 89, 0, 2),
                443,
            )
            .await;

        let session2 = nat
            .create(
                Ipv4Addr::new(192, 168, 1, 100),
                12345,
                Ipv4Addr::new(10, 89, 0, 3),
                443,
            )
            .await;

        assert_eq!(session1.nat_port, session2.nat_port);
        assert_ne!(session1.dst_addr, session2.dst_addr);
    }

    #[tokio::test]
    async fn test_session_tracking_no_overwrite() {
        let nat = Nat::new(Type::Tcp, None);

        nat.create(
            Ipv4Addr::new(192, 168, 1, 100),
            12345,
            Ipv4Addr::new(10, 89, 0, 2),
            443,
        )
        .await;

        nat.create(
            Ipv4Addr::new(192, 168, 1, 100),
            12345,
            Ipv4Addr::new(10, 89, 0, 3),
            443,
        )
        .await;

        let found1 = nat
            .sessions
            .get(&Nat::compute_session_key(
                Ipv4Addr::new(192, 168, 1, 100),
                12345,
                Ipv4Addr::new(10, 89, 0, 2),
                443,
            ))
            .await;

        let found2 = nat
            .sessions
            .get(&Nat::compute_session_key(
                Ipv4Addr::new(192, 168, 1, 100),
                12345,
                Ipv4Addr::new(10, 89, 0, 3),
                443,
            ))
            .await;

        assert!(found1.is_some());
        assert!(found2.is_some());
        assert_eq!(found1.unwrap().dst_addr, Ipv4Addr::new(10, 89, 0, 2));
        assert_eq!(found2.unwrap().dst_addr, Ipv4Addr::new(10, 89, 0, 3));
    }

    #[tokio::test]
    async fn test_reverse_lookup() {
        let nat = Nat::new(Type::Tcp, None);

        let session = nat
            .create(
                Ipv4Addr::new(192, 168, 1, 100),
                12345,
                Ipv4Addr::new(10, 89, 0, 2),
                443,
            )
            .await;

        let found = nat.find(session.nat_port).await;
        assert!(found.is_some());

        let found_session = found.unwrap();
        assert_eq!(found_session.src_addr, session.src_addr);
        assert_eq!(found_session.src_port, session.src_port);
        assert_eq!(found_session.dst_addr, session.dst_addr);
        assert_eq!(found_session.dst_port, session.dst_port);
    }

    #[tokio::test]
    async fn test_port_mapping_cleanup() {
        use std::time::Duration;
        use tokio::time::sleep;

        let port_mapping = Arc::new(DashMap::new());
        let reverse_port_mapping = Arc::new(DashMap::new());

        let nat = Nat {
            nat_type: Type::Tcp,
            port_mapping: port_mapping.clone(),
            reverse_port_mapping: reverse_port_mapping.clone(),
            sessions: Nat::new_cache(
                Duration::from_millis(100), // 100ms TTL
                port_mapping.clone(),
                reverse_port_mapping.clone(),
                None,
            ),
        };

        let session = nat
            .create(
                Ipv4Addr::new(192, 168, 1, 100),
                12345,
                Ipv4Addr::new(10, 89, 0, 2),
                443,
            )
            .await;

        assert!(!nat.port_mapping.is_empty());
        assert!(nat.reverse_port_mapping.contains_key(&session.nat_port));

        sleep(Duration::from_millis(200)).await;

        nat.sessions.run_pending_tasks().await;

        sleep(Duration::from_millis(50)).await;

        assert_eq!(nat.port_mapping.len(), 0);
        assert!(!nat.reverse_port_mapping.contains_key(&session.nat_port));
    }
}

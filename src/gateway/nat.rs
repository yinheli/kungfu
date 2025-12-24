use bimap::BiMap;
use std::{
    io::Error,
    net::{self, Ipv4Addr},
    sync::Arc,
    time::Duration,
};
use tokio::sync::{RwLock, mpsc::UnboundedSender};

use moka::future::Cache;

pub struct Nat {
    nat_type: Type,
    cache: Cache<u32, Arc<Session>>,
    mapping: Arc<RwLock<BiMap<u32, u16>>>,
}

pub enum Type {
    Tcp,
    Udp,
}

#[derive(Debug, Copy, PartialEq, Eq, Clone)]
pub struct Session {
    pub src_addr: Ipv4Addr,
    pub dst_addr: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub nat_port: u16,
}

impl Nat {
    pub fn new(nat_type: Type, tx: Option<UnboundedSender<u16>>) -> Self {
        let ttl = match nat_type {
            Type::Tcp => Duration::from_secs(60),
            Type::Udp => Duration::from_secs(20),
        };

        let mapping = Arc::new(RwLock::new(BiMap::new()));
        let cache = Self::new_cache(ttl, mapping.clone(), tx);

        Self {
            nat_type,
            cache,
            mapping,
        }
    }

    pub async fn create(
        &self,
        src_addr: Ipv4Addr,
        src_port: u16,
        dst_addr: Ipv4Addr,
        dst_port: u16,
    ) -> Result<Session, Error> {
        let addr_key = u32::from_be_bytes(src_addr.octets()) + src_port as u32;

        if let Some(session) = self.cache.get(&addr_key).await {
            return Ok(*session);
        }

        let nat_port = {
            let mapping = self.mapping.read().await;

            if let Some(&nat_port) = mapping.get_by_left(&addr_key) {
                return Ok(Session {
                    src_addr,
                    dst_addr,
                    src_port,
                    dst_port,
                    nat_port,
                });
            }

            self.get_available_port()?
        };

        let session = Arc::new(Session {
            src_addr,
            dst_addr,
            src_port,
            dst_port,
            nat_port,
        });

        self.cache.insert(addr_key, session.clone()).await;

        {
            let mut mapping = self.mapping.write().await;
            mapping.insert(addr_key, nat_port);
        }

        Ok(*session)
    }

    pub async fn find(&self, nat_port: u16) -> Option<Session> {
        if let Some(addr_key) = self.get_addr_key_by_port_fast(&nat_port).await
            && let Some(session) = self.cache.get(&addr_key).await
        {
            return Some(*session);
        }

        None
    }

    #[allow(dead_code)]
    pub async fn clear(&self) {
        self.cache.invalidate_all();

        {
            let mut mapping = self.mapping.write().await;
            mapping.clear();
        }
    }

    #[allow(dead_code)]
    pub async fn stats(&self) -> (usize, usize) {
        let mapping_count = self.mapping.read().await.len();
        (mapping_count, self.cache.entry_count() as usize)
    }

    fn new_cache(
        ttl: Duration,
        mapping: Arc<RwLock<BiMap<u32, u16>>>,
        tx: Option<UnboundedSender<u16>>,
    ) -> Cache<u32, Arc<Session>> {
        Cache::builder()
            .max_capacity(5000)
            .time_to_idle(ttl)
            .eviction_listener(move |addr_key: Arc<u32>, session: Arc<Session>, _cause| {
                let mapping = mapping.clone();
                let tx = tx.clone();
                tokio::task::spawn(async move {
                    let mut mapping_guard = mapping.write().await;
                    let _ = mapping_guard.remove_by_left(&*addr_key);
                    if let Some(ref tx) = tx {
                        let _ = tx.send(session.nat_port);
                    }
                });
            })
            .build()
    }

    async fn get_addr_key_by_port_fast(&self, nat_port: &u16) -> Option<u32> {
        let mapping = self.mapping.read().await;
        mapping.get_by_right(nat_port).copied()
    }

    fn get_available_port(&self) -> Result<u16, Error> {
        match self.nat_type {
            Type::Tcp => {
                let listener = net::TcpListener::bind("127.0.0.1:0")?;
                let addr = listener.local_addr()?;
                Ok(addr.port())
            }
            Type::Udp => {
                let socket = net::UdpSocket::bind("127.0.0.1:0")?;
                let addr = socket.local_addr()?;
                Ok(addr.port())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn it_works() {
        let tcp_nat = Nat::new(Type::Tcp, None);
        let session = tcp_nat
            .create(
                Ipv4Addr::new(127, 0, 0, 1),
                32,
                Ipv4Addr::new(127, 0, 0, 1),
                80,
            )
            .await
            .unwrap();

        assert_ne!(session.nat_port, 0);

        let session2 = tcp_nat.find(session.nat_port).await;
        assert!(session2.is_some());
        assert_eq!(session2.unwrap(), session);

        let udp_nat = Nat::new(Type::Udp, None);
        let session = udp_nat
            .create(
                Ipv4Addr::new(127, 0, 0, 1),
                32,
                Ipv4Addr::new(127, 0, 0, 1),
                80,
            )
            .await
            .unwrap();
        assert_ne!(session.nat_port, 0);
    }
}

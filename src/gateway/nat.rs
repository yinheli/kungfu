use bimap::BiMap;
use parking_lot::RwLock;
use std::{
    io::{Error, ErrorKind},
    net::Ipv4Addr,
    sync::{
        Arc,
        atomic::{AtomicU16, Ordering},
    },
    time::Duration,
};
use tokio::sync::mpsc::UnboundedSender;

use moka::future::Cache;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionKey {
    pub src_addr: Ipv4Addr,
    pub dst_addr: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
}

const EPHEMERAL_PORT_START: u16 = 1024;
const EPHEMERAL_PORT_END: u16 = 65535;
const EPHEMERAL_PORT_RANGE: u16 = EPHEMERAL_PORT_END - EPHEMERAL_PORT_START + 1;

pub struct Nat {
    cache: Cache<SessionKey, Session>,
    mapping: Arc<RwLock<BiMap<SessionKey, u16>>>,
    port_counter: AtomicU16,
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
            Type::Tcp => Duration::from_secs(300),
            Type::Udp => Duration::from_secs(60),
        };

        let mapping = Arc::new(RwLock::new(BiMap::new()));
        let cache = Self::new_cache(ttl, mapping.clone(), tx);

        Self {
            cache,
            mapping,
            port_counter: AtomicU16::new(0),
        }
    }

    pub async fn create(
        &self,
        src_addr: Ipv4Addr,
        src_port: u16,
        dst_addr: Ipv4Addr,
        dst_port: u16,
    ) -> Result<Session, Error> {
        let addr_key = SessionKey {
            src_addr,
            dst_addr,
            src_port,
            dst_port,
        };

        if let Some(session) = self.cache.get(&addr_key).await {
            return Ok(session);
        }

        let nat_port = {
            let mut mapping = self.mapping.write();

            if let Some(&nat_port) = mapping.get_by_left(&addr_key) {
                nat_port
            } else {
                let mut assigned_port = 0;
                for _ in 0..EPHEMERAL_PORT_RANGE {
                    let port = self.next_ephemeral_port();
                    if !mapping.contains_right(&port) {
                        assigned_port = port;
                        break;
                    }
                }

                if assigned_port == 0 {
                    return Err(Error::new(
                        ErrorKind::AddrInUse,
                        "No available NAT port: ephemeral range exhausted",
                    ));
                }

                mapping.insert(addr_key, assigned_port);
                assigned_port
            }
        };

        let session = Session {
            src_addr,
            dst_addr,
            src_port,
            dst_port,
            nat_port,
        };

        self.cache.insert(addr_key, session).await;

        Ok(session)
    }

    pub async fn find(&self, nat_port: u16) -> Option<Session> {
        if let Some(addr_key) = self.get_addr_key_by_port_fast(&nat_port) {
            if let Some(session) = self.cache.get(&addr_key).await {
                return Some(session);
            }

            let session = Session {
                src_addr: addr_key.src_addr,
                dst_addr: addr_key.dst_addr,
                src_port: addr_key.src_port,
                dst_port: addr_key.dst_port,
                nat_port,
            };
            self.cache.insert(addr_key, session).await;
            return Some(session);
        }

        None
    }

    #[allow(dead_code)]
    pub async fn clear(&self) {
        self.cache.invalidate_all();

        {
            let mut mapping = self.mapping.write();
            mapping.clear();
        }
    }

    #[allow(dead_code)]
    pub async fn stats(&self) -> (usize, usize) {
        let mapping_count = self.mapping.read().len();
        (mapping_count, self.cache.entry_count() as usize)
    }

    fn new_cache(
        ttl: Duration,
        mapping: Arc<RwLock<BiMap<SessionKey, u16>>>,
        tx: Option<UnboundedSender<u16>>,
    ) -> Cache<SessionKey, Session> {
        Cache::builder()
            .max_capacity(10000)
            .time_to_idle(ttl)
            .eviction_listener(move |addr_key: Arc<SessionKey>, session: Session, _cause| {
                let mut mapping_guard = mapping.write();
                let _ = mapping_guard.remove_by_left(&*addr_key);
                if let Some(ref tx) = tx {
                    let _ = tx.send(session.nat_port);
                }
            })
            .build()
    }

    fn get_addr_key_by_port_fast(&self, nat_port: &u16) -> Option<SessionKey> {
        let mapping = self.mapping.read();
        mapping.get_by_right(nat_port).copied()
    }

    fn next_ephemeral_port(&self) -> u16 {
        let offset = self.port_counter.fetch_add(1, Ordering::Relaxed) % EPHEMERAL_PORT_RANGE;
        EPHEMERAL_PORT_START + offset
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

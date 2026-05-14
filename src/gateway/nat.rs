use dashmap::DashMap;
use moka::future::Cache;
use std::{
    io::{Error, ErrorKind},
    net::Ipv4Addr,
    sync::{
        Arc,
        atomic::{AtomicU16, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::sync::mpsc::UnboundedSender;

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
const BITMAP_WORDS: usize = (EPHEMERAL_PORT_RANGE as usize + 63) / 64;

pub struct Nat {
    cache: Cache<SessionKey, Session>,
    key_to_session: DashMap<SessionKey, Session>,
    port_to_key: DashMap<u16, SessionKey>,
    bitmap: Arc<[AtomicU64; BITMAP_WORDS]>,
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

        let bitmap = {
            let arr: [AtomicU64; BITMAP_WORDS] = std::array::from_fn(|_| AtomicU64::new(0));
            Arc::new(arr)
        };
        let key_to_session = DashMap::new();
        let port_to_key = DashMap::new();
        let cache = Self::new_cache(ttl, key_to_session.clone(), port_to_key.clone(), bitmap.clone(), tx);

        Self {
            cache,
            key_to_session,
            port_to_key,
            bitmap,
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
        let key = SessionKey {
            src_addr,
            dst_addr,
            src_port,
            dst_port,
        };

        if let Some(session) = self.cache.get(&key).await {
            return Ok(session);
        }

        let session = match self.key_to_session.entry(key) {
            dashmap::mapref::entry::Entry::Occupied(entry) => *entry.get(),
            dashmap::mapref::entry::Entry::Vacant(entry) => {
                let nat_port = self.allocate_port()?;
                let session = Session {
                    src_addr,
                    dst_addr,
                    src_port,
                    dst_port,
                    nat_port,
                };
                self.port_to_key.insert(nat_port, key);
                entry.insert(session);
                session
            }
        };

        self.cache.insert(key, session).await;
        Ok(session)
    }

    pub async fn find(&self, nat_port: u16) -> Option<Session> {
        let addr_key = match self.port_to_key.get(&nat_port) {
            Some(k) => *k.value(),
            None => return None,
        };

        if let Some(session) = self.cache.get(&addr_key).await {
            return Some(session);
        }

        if let Some(session) = self.key_to_session.get(&addr_key) {
            let session = *session.value();
            self.cache.insert(addr_key, session).await;
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
        Some(session)
    }

    #[allow(dead_code)]
    pub async fn clear(&self) {
        self.cache.invalidate_all();

        self.key_to_session.clear();
        self.port_to_key.clear();

        for word in self.bitmap.iter() {
            word.store(0, Ordering::Release);
        }
    }

    #[allow(dead_code)]
    pub async fn stats(&self) -> (usize, usize) {
        (self.key_to_session.len(), self.cache.entry_count() as usize)
    }

    fn allocate_port(&self) -> Result<u16, Error> {
        for _ in 0..EPHEMERAL_PORT_RANGE {
            let offset = self.port_counter.fetch_add(1, Ordering::Relaxed) % EPHEMERAL_PORT_RANGE;
            let word = offset as usize / 64;
            let bit = offset as usize % 64;
            let mask = 1u64 << bit;
            let old = self.bitmap[word].fetch_or(mask, Ordering::AcqRel);
            if old & mask == 0 {
                return Ok(EPHEMERAL_PORT_START + offset);
            }
        }
        Err(Error::new(
            ErrorKind::AddrInUse,
            "No available NAT port: ephemeral range exhausted",
        ))
    }

    fn new_cache(
        ttl: Duration,
        key_to_session: DashMap<SessionKey, Session>,
        port_to_key: DashMap<u16, SessionKey>,
        bitmap: Arc<[AtomicU64; BITMAP_WORDS]>,
        tx: Option<UnboundedSender<u16>>,
    ) -> Cache<SessionKey, Session> {
        Cache::builder()
            .max_capacity(10000)
            .time_to_idle(ttl)
            .eviction_listener(move |key: Arc<SessionKey>, session: Session, _cause| {
                if key_to_session
                    .remove_if(&*key, |_, v| v.nat_port == session.nat_port)
                    .is_some()
                {
                    port_to_key.remove(&session.nat_port);
                    let offset = session.nat_port - EPHEMERAL_PORT_START;
                    let word = offset as usize / 64;
                    let bit = offset as usize % 64;
                    bitmap[word].fetch_and(!(1u64 << bit), Ordering::Release);
                    if let Some(ref tx) = tx {
                        let _ = tx.send(session.nat_port);
                    }
                }
            })
            .build()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

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

    #[tokio::test]
    async fn test_concurrent_port_allocation() {
        let nat = Arc::new(Nat::new(Type::Tcp, None));
        let mut handles = vec![];
        for i in 0..100u16 {
            let nat = nat.clone();
            handles.push(tokio::spawn(async move {
                nat.create(
                    Ipv4Addr::new(10, 0, 0, 1),
                    10000 + i,
                    Ipv4Addr::new(93, 184, 216, 34),
                    80,
                )
                .await
                .unwrap()
            }));
        }
        let results = futures::future::join_all(handles).await;
        let sessions: Vec<Session> = results.into_iter().map(|h| h.unwrap()).collect();
        let nat_ports: HashSet<u16> = sessions.iter().map(|s| s.nat_port).collect();
        assert_eq!(nat_ports.len(), 100, "all NAT ports should be unique");
    }
}

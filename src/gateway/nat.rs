use bimap::BiMap;
use parking_lot::RwLock;
use std::{
    net::{self, Ipv4Addr},
    sync::Arc,
    time::Duration,
};

use moka::sync::Cache;
use rand::random;

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
    pub fn new(nat_type: Type) -> Self {
        let ttl = Duration::from_secs(60 * 10);

        let mapping = Arc::new(RwLock::new(BiMap::new()));
        let cache = Self::new_cache(ttl, mapping.clone());

        Self {
            nat_type,
            cache,
            mapping,
        }
    }

    pub fn create(
        &self,
        src_addr: Ipv4Addr,
        src_port: u16,
        dst_addr: Ipv4Addr,
        dst_port: u16,
    ) -> Session {
        let addr_key = u32::from_be_bytes(src_addr.octets()) + src_port as u32;

        if let Some(session) = self.cache.get(&addr_key) {
            return *session;
        }

        let nat_port = {
            let mapping = self.mapping.read();

            if let Some(&port) = mapping.get_by_left(&addr_key) {
                return Session {
                    src_addr,
                    dst_addr,
                    src_port,
                    dst_port,
                    nat_port: port,
                };
            }

            self.get_available_port()
        };

        let session = Arc::new(Session {
            src_addr,
            dst_addr,
            src_port,
            dst_port,
            nat_port,
        });

        self.cache.insert(addr_key, session.clone());

        {
            let mut mapping = self.mapping.write();
            mapping.insert(addr_key, nat_port);
        }

        *session
    }

    pub fn find(&self, nat_port: u16) -> Option<Session> {
        if let Some(addr_key) = self.get_addr_key_by_port_fast(&nat_port)
            && let Some(session) = self.cache.get(&addr_key)
        {
            return Some(*session);
        }

        None
    }

    #[allow(dead_code)]
    pub fn clear(&self) {
        self.cache.invalidate_all();

        {
            let mut mapping = self.mapping.write();
            mapping.clear();
        }
    }

    #[allow(dead_code)]
    pub fn stats(&self) -> (usize, usize) {
        let mapping_count = self.mapping.read().len();
        (mapping_count, self.cache.entry_count() as usize)
    }

    fn new_cache(ttl: Duration, mapping: Arc<RwLock<BiMap<u32, u16>>>) -> Cache<u32, Arc<Session>> {
        let mapping_clone = mapping.clone();

        let eviction_listener = move |addr_key: Arc<u32>, _session: Arc<Session>, _cause| {
            let mut mapping_guard = mapping_clone.write();
            let _ = mapping_guard.remove_by_left(&*addr_key);
        };

        Cache::builder()
            .max_capacity(5000)
            .time_to_live(ttl)
            .eviction_listener(eviction_listener)
            .build()
    }

    fn get_addr_key_by_port_fast(&self, nat_port: &u16) -> Option<u32> {
        let mapping = self.mapping.read();
        mapping.get_by_right(nat_port).copied()
    }

    fn get_available_port(&self) -> u16 {
        match self.nat_type {
            Type::Tcp => {
                let ln = net::TcpListener::bind("127.0.0.1:0");
                match ln {
                    Ok(listener) => {
                        match listener.local_addr() {
                            Ok(addr) => addr.port(),
                            Err(_) => {
                                // Fallback to a random high port
                                random::<u16>().max(1024)
                            }
                        }
                    }
                    Err(_) => {
                        // Fallback to a random high port
                        random::<u16>().max(1024)
                    }
                }
            }
            Type::Udp => {
                let ln = net::UdpSocket::bind("127.0.0.1:0");
                match ln {
                    Ok(socket) => {
                        match socket.local_addr() {
                            Ok(addr) => addr.port(),
                            Err(_) => {
                                // Fallback to a random high port
                                random::<u16>().max(1024)
                            }
                        }
                    }
                    Err(_) => {
                        // Fallback to a random high port
                        random::<u16>().max(1024)
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let tcp_nat = Nat::new(Type::Tcp);
        let session = tcp_nat.create(
            Ipv4Addr::new(127, 0, 0, 1),
            32,
            Ipv4Addr::new(127, 0, 0, 1),
            80,
        );

        assert_ne!(session.nat_port, 0);

        let session2 = tcp_nat.find(session.nat_port);
        assert!(session2.is_some());
        assert_eq!(session2.unwrap(), session);

        let udp_nat = Nat::new(Type::Udp);
        let session = udp_nat.create(
            Ipv4Addr::new(127, 0, 0, 1),
            32,
            Ipv4Addr::new(127, 0, 0, 1),
            80,
        );
        assert_ne!(session.nat_port, 0);
    }
}

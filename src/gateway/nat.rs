use lru::LruCache;
use std::{
    net::{self, Ipv4Addr},
    sync::RwLock,
};

pub struct Nat {
    nat_type: Type,
    addr_map: RwLock<LruCache<u32, Session>>,
    port_map: RwLock<LruCache<u16, Session>>,
}

pub enum Type {
    Tcp,
    // todo
    #[allow(dead_code)]
    Udp,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Session {
    pub src_addr: Ipv4Addr,
    pub dst_addr: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub nat_port: u16,
}

impl Nat {
    pub fn new(nat_type: Type) -> Self {
        Self {
            nat_type,
            addr_map: RwLock::new(LruCache::new(5000)),
            port_map: RwLock::new(LruCache::new(5000)),
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

        if let Some(session) = self.addr_map.read().unwrap().peek(&addr_key) {
            return session.clone();
        }

        let nat_port = self.get_available_port();

        let session = Session {
            src_addr,
            dst_addr,
            src_port,
            dst_port,
            nat_port,
        };

        self.addr_map
            .write()
            .unwrap()
            .put(addr_key, session.clone());

        self.port_map
            .write()
            .unwrap()
            .put(nat_port, session.clone());

        session
    }

    pub fn find(&self, nat_port: u16) -> Option<Session> {
        self.port_map.read().unwrap().peek(&nat_port).cloned()
    }

    fn get_available_port(&self) -> u16 {
        match self.nat_type {
            Type::Tcp => {
                let ln = net::TcpListener::bind("127.0.0.1:0").unwrap();
                ln.local_addr().unwrap().port()
            }
            Type::Udp => {
                let ln = net::UdpSocket::bind("127.0.0.1:0").unwrap();
                ln.local_addr().unwrap().port()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

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

use std::{
    net::{self, Ipv4Addr},
    sync::Arc,
    time::{Duration, Instant},
};

use moka::sync::Cache;

pub struct Nat {
    nat_type: Type,
    addr_map: Cache<u32, Arc<Session>>,
    port_map: Cache<u16, Arc<Session>>,
}

pub enum Type {
    Tcp,
    // todo
    #[allow(dead_code)]
    Udp,
}

#[derive(Debug, Copy, PartialEq, Eq, Clone)]
pub struct Session {
    pub src_addr: Ipv4Addr,
    pub dst_addr: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub nat_port: u16,

    create_time: Instant,
}

impl Nat {
    pub fn new(nat_type: Type) -> Self {
        let cache_size = 2000;
        let idle = Duration::from_secs(10 * 60);
        Self {
            nat_type,
            addr_map: Cache::builder()
                .max_capacity(cache_size)
                .time_to_idle(idle)
                .build(),
            port_map: Cache::builder()
                .max_capacity(cache_size)
                .time_to_idle(idle)
                .build(),
        }
    }

    pub fn create(
        &self,
        src_addr: Ipv4Addr,
        src_port: u16,
        dst_addr: Ipv4Addr,
        dst_port: u16,
    ) -> Session {
        let now = Instant::now();
        let addr_key = u32::from_be_bytes(src_addr.octets()) + src_port as u32;
        if let Some(mut session) = self.peek(addr_key) {
            if now.duration_since(session.create_time).as_secs() > 10 {
                session.create_time = now;
                self.put(addr_key, Arc::new(session));
            }

            return session;
        }

        let nat_port = self.get_available_port();

        let session = Arc::new(Session {
            src_addr,
            dst_addr,
            src_port,
            dst_port,
            nat_port,
            create_time: now,
        });

        self.put(addr_key, session.clone());

        *session
    }

    pub fn find(&self, nat_port: u16) -> Option<Session> {
        if let Some(v) = self.port_map.get(&nat_port) {
            return Some(*v);
        }
        None
    }

    fn peek(&self, addr_key: u32) -> Option<Session> {
        if let Some(v) = self.addr_map.get(&addr_key) {
            return Some(*v);
        }
        None
    }

    fn put(&self, addr_key: u32, session: Arc<Session>) {
        self.addr_map.insert(addr_key, session.clone());
        self.port_map.insert(session.nat_port, session.clone());
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

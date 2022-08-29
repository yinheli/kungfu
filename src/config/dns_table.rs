use ipnet::IpNet;
use lru::LruCache;
use std::{net::IpAddr, str::FromStr};

#[derive(Debug)]
pub struct DnsTable {
    domain: LruCache<String, Addr>,
    addr: LruCache<IpAddr, Addr>,
    network: IpNet,
    pool_size: usize,
    offset: usize,
}

#[derive(Clone, Debug)]
pub struct Addr {
    pub domain: String,
    pub ip: IpAddr,
    pub target: String,
    pub remark: String,
}

impl Default for DnsTable {
    fn default() -> Self {
        Self {
            domain: LruCache::new(0),
            addr: LruCache::new(0),
            network: Default::default(),
            pool_size: Default::default(),
            offset: Default::default(),
        }
    }
}

impl DnsTable {
    pub fn new(network: &str) -> Self {
        let network = IpNet::from_str(network).unwrap();

        let hosts = network.hosts();
        let pool_size = hosts.count();

        Self {
            domain: LruCache::new(10000),
            addr: LruCache::new(10000),
            network,
            pool_size,
            offset: 0,
        }
    }

    /// apply domain addr
    pub fn apply(&mut self, domain: &str, target: &str, remark: &str) -> Addr {
        if self.domain.contains(domain) {
            let addr = self.domain.peek(domain).unwrap().clone();
            return addr;
        }

        let addr = Addr {
            domain: domain.to_string(),
            ip: self.allocation_addr(),
            target: target.to_string(),
            remark: remark.to_string(),
        };

        self.domain.put(domain.to_string(), addr.clone());
        self.addr.put(addr.ip, addr.clone());

        addr
    }

    /// find addr by ip
    pub fn find(&self, ip: &IpAddr) -> Option<Addr> {
        self.addr.peek(ip).cloned()
    }

    pub fn clear(&mut self) {
        self.domain.clear();
        self.addr.clear();
        self.offset = 0;
    }

    fn allocation_addr(&mut self) -> IpAddr {
        let hosts = self.network.hosts();
        let mut addr;
        loop {
            let n = self.offset % self.pool_size;
            addr = hosts.clone().nth(n).unwrap();
            self.offset += 1;
            if addr == self.network.addr() {
                continue;
            }
            break;
        }
        addr
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;

    use ipnet::IpNet;

    use super::DnsTable;

    #[test]
    fn it_works() {
        let mut table = DnsTable::new("10.89.0.1/24");
        let addr = table.apply("test.com", "", "test");
        assert_eq!(addr.ip, IpAddr::V4(Ipv4Addr::new(10, 89, 0, 2)));

        let addr = table.apply("test.com", "", "test");
        assert_eq!(addr.ip, IpAddr::V4(Ipv4Addr::new(10, 89, 0, 2)));

        let addr = table.apply("test1.com", "", "test");
        assert_eq!(addr.ip, IpAddr::V4(Ipv4Addr::new(10, 89, 0, 3)));
    }

    #[test]
    fn iter() {
        let network = "10.89.0.1/24";
        let hosts = IpNet::from_str(network).unwrap().hosts();

        let mut table = DnsTable::new(network);

        for _ in 0..2 {
            for (i, host) in hosts.skip(1).enumerate() {
                let domain = format!("test{}.com", i);
                let remark = format!("test{}", i);
                let addr = table.apply(&domain, "", &remark);
                assert_eq!(addr.ip, host);
                assert!(table.find(&host).is_some());

                let found = table.find(&host);
                assert!(found.is_some());

                let found = found.unwrap();
                assert_eq!(&found.domain, &domain);
                assert_eq!(&found.remark, &remark);
            }
        }

        let addr = table.apply("test_additional", "", "");
        assert_eq!(addr.ip.to_string(), "10.89.0.2".to_string());
    }
}

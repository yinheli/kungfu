use ipnet::IpNet;
use lru::LruCache;
use std::{
    net::{IpAddr, Ipv4Addr},
    num::NonZeroUsize,
    str::FromStr,
    sync::{Mutex, RwLock},
};
use trust_dns_server::{
    authority::LookupObject,
    proto::rr::{rdata::TXT, RData, Record},
    resolver::Name,
};

#[derive(Debug)]
pub struct DnsTable {
    domain: RwLock<LruCache<String, Option<Addr>>>,
    addr: RwLock<LruCache<IpAddr, Addr>>,
    network: IpNet,
    gateway: IpAddr,
    pool_size: usize,
    offset: Mutex<usize>,
}

#[derive(Clone, Debug)]
pub struct Addr {
    pub domain: String,
    pub ip: Option<IpAddr>,
    pub target: String,
    pub remark: String,

    records: Vec<Record>,
}

const DNS_CACHE_SIZE: usize = 5000;

impl Default for DnsTable {
    fn default() -> Self {
        Self {
            domain: RwLock::new(LruCache::new(NonZeroUsize::new(DNS_CACHE_SIZE).unwrap())),
            addr: RwLock::new(LruCache::new(NonZeroUsize::new(DNS_CACHE_SIZE).unwrap())),
            network: Default::default(),
            gateway: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
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

        let (domain, addr) = DnsTable::new_cache();

        Self {
            domain: RwLock::new(domain),
            addr: RwLock::new(addr),
            network,
            gateway: network.addr(),
            pool_size,
            offset: Mutex::new(0),
        }
    }

    /// apply domain addr
    pub fn apply(&self, domain: &str, target: &str, remark: &str) -> Addr {
        let ip = self.allocate_addr();
        let addr = Addr::new(domain, Some(ip), target, remark);

        self.domain
            .write()
            .unwrap()
            .put(domain.to_string(), Some(addr.clone()));
        self.addr.write().unwrap().put(ip, addr.clone());

        addr
    }

    /// find addr by ip
    pub fn find_by_ip(&self, ip: &IpAddr) -> Option<Addr> {
        self.addr.read().unwrap().peek(ip).cloned()
    }

    pub fn find_by_domain(&self, domain: &str) -> Option<Option<Addr>> {
        let addr = self.domain.read().unwrap().peek(domain).cloned();
        if addr.is_none() {
            self.domain.write().unwrap().put(domain.to_string(), None);
        }
        addr
    }

    pub fn allocate(&self, domain: &str, ip: Option<IpAddr>, remark: &str) -> Addr {
        let addr = Addr::new(domain, ip, "", remark);
        self.domain
            .write()
            .unwrap()
            .put(domain.to_string(), Some(addr.clone()));
        addr
    }

    pub fn clear(&self) {
        *self.offset.lock().unwrap() = 0;

        // directly make new one
        let (domain, addr) = DnsTable::new_cache();
        *self.domain.write().unwrap() = domain;
        *self.addr.write().unwrap() = addr;
    }

    fn allocate_addr(&self) -> IpAddr {
        let hosts = self.network.hosts();
        let mut offset = self.offset.lock().unwrap();
        let mut addr;
        loop {
            let n = *offset % self.pool_size;
            addr = hosts.clone().nth(n).unwrap();
            *offset += 1;
            if addr.eq(&self.gateway) {
                continue;
            }
            break;
        }
        addr
    }

    fn new_cache() -> (LruCache<String, Option<Addr>>, LruCache<IpAddr, Addr>) {
        (
            LruCache::new(NonZeroUsize::new(DNS_CACHE_SIZE).unwrap()),
            LruCache::new(NonZeroUsize::new(DNS_CACHE_SIZE).unwrap()),
        )
    }
}

impl Addr {
    pub fn new(domain: &str, ip: Option<IpAddr>, target: &str, remark: &str) -> Self {
        let mut records = vec![];

        let name = Name::from_str(domain).unwrap();

        if let Some(ip) = ip {
            let record = match ip {
                std::net::IpAddr::V4(v) => Record::from_rdata(name.clone(), 10, RData::A(v)),
                std::net::IpAddr::V6(v) => Record::from_rdata(name.clone(), 10, RData::AAAA(v)),
            };
            records.push(record);
        }

        if !remark.is_empty() {
            records.push(Record::from_rdata(
                name,
                10,
                RData::TXT(TXT::new(vec![remark.to_string()])),
            ));
        }

        Self {
            domain: domain.to_string(),
            ip,
            target: target.to_string(),
            remark: remark.to_string(),
            records,
        }
    }
}

impl LookupObject for Addr {
    fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = &'a Record> + Send + 'a> {
        Box::new(self.records.iter())
    }

    fn take_additionals(&mut self) -> Option<Box<dyn LookupObject>> {
        None
    }
}

#[cfg(test)]
mod tests {
    extern crate test;
    use rayon::prelude::{IntoParallelIterator, ParallelIterator};

    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;
    use test::Bencher;

    use ipnet::IpNet;

    use super::DnsTable;

    #[test]
    fn it_works() {
        let table = DnsTable::new("10.89.0.1/24");
        let addr = table.apply("test.com", "", "test");
        assert_eq!(addr.ip, Some(IpAddr::V4(Ipv4Addr::new(10, 89, 0, 2))));
    }

    #[test]
    fn iter() {
        let network = "10.89.0.1/24";
        let hosts = IpNet::from_str(network).unwrap().hosts();

        let table = DnsTable::new(network);

        for _ in 0..2 {
            for (i, host) in hosts.skip(1).enumerate() {
                let domain = format!("test{}.com", i);
                let remark = format!("test{}", i);
                let addr = table.apply(&domain, "", &remark);
                assert_eq!(addr.ip, Some(host));
                assert!(table.find_by_ip(&host).is_some());

                let found = table.find_by_ip(&host);
                assert!(found.is_some());

                let found = found.unwrap();
                assert_eq!(&found.domain, &domain);
                assert_eq!(&found.remark, &remark);
            }
        }

        let addr = table.apply("test_additional", "", "");
        assert_eq!(addr.ip.unwrap().to_string(), "10.89.0.2".to_string());
    }

    #[bench]
    fn bench_allocate(b: &mut Bencher) {
        let table = DnsTable::new("10.89.0.1/24");

        b.iter(|| {
            table.allocate_addr();
        })
    }

    #[bench]
    fn bench_apply_simple(b: &mut Bencher) {
        let table = DnsTable::new("10.89.0.1/24");

        b.iter(|| {
            table.apply(&format!("example.com"), "", "");
        })
    }

    #[bench]
    fn bench_apply(b: &mut Bencher) {
        let table = DnsTable::new("10.89.0.1/24");

        b.iter(|| {
            (0..100).into_par_iter().for_each(|i| {
                table.apply(&format!("{i}.example.com"), "", "");
            })
        });
    }

    #[bench]
    fn bench_find(b: &mut Bencher) {
        let table = DnsTable::new("10.89.0.1/24");

        (0..100).for_each(|i| {
            table.apply(&format!("{i}.example.com"), "", "");
        });

        b.iter(|| {
            (0..100).into_par_iter().for_each(|i| {
                table.find_by_domain(&format!("{i}.example.com"));
            })
        });
    }
}

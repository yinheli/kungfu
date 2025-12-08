use bimap::BiMap;
use hickory_server::{
    authority::LookupObject,
    proto::rr::{
        RData, Record,
        rdata::{A, AAAA, TXT},
    },
    resolver::Name,
};
use ipnet::IpNet;
use moka::sync::Cache;
use std::{
    fmt::{Display, Formatter},
    net::IpAddr,
    str::FromStr,
    sync::{Arc, Mutex, RwLock},
    time::Duration,
};

#[derive(Debug)]
pub struct DnsTable {
    cache: Cache<String, Arc<Addr>>,
    mapping: Arc<RwLock<BiMap<String, IpAddr>>>,
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

const DNS_CACHE_SIZE: u64 = 2000;

impl Default for DnsTable {
    fn default() -> Self {
        Self::new("10.89.0.1/16")
    }
}

impl DnsTable {
    pub fn new(network: &str) -> Self {
        let network = IpNet::from_str(network).unwrap();

        let hosts = network.hosts();
        let pool_size = hosts.count();

        let mapping: Arc<RwLock<BiMap<String, IpAddr>>> = Default::default();
        let cache = DnsTable::new_cache(mapping.clone());

        Self {
            cache,
            mapping,
            network,
            gateway: network.addr(),
            pool_size,
            offset: Mutex::new(0),
        }
    }

    pub fn apply(&self, domain: &str, target: &str, remark: &str) -> Addr {
        let ip = self.allocate_addr();
        let addr = Arc::new(Addr::new(domain, Some(ip), target, remark));

        self.cache.insert(domain.to_string(), addr.clone());

        let mut mapping = self.mapping.write().unwrap();
        mapping.insert(domain.to_string(), ip);

        (*addr).clone()
    }

    pub fn find_by_ip(&self, ip: &IpAddr) -> Option<Addr> {
        if let Some(domain) = self.get_domain_by_ip_fast(ip)
            && let Some(addr) = self.cache.get(&domain)
        {
            return Some((*addr).clone());
        }

        None
    }

    pub fn find_by_domain(&self, domain: &str) -> Option<Option<Addr>> {
        if let Some(addr) = self.cache.get(domain) {
            return Some(Some((*addr).clone()));
        }

        let mapping = self.mapping.read().unwrap();
        if mapping.contains_left(domain) {
            Some(None)
        } else {
            None
        }
    }

    pub fn allocate(&self, domain: &str, ip: Option<IpAddr>, remark: &str) -> Addr {
        let addr = Arc::new(Addr::new(domain, ip, "", remark));

        self.cache.insert(domain.to_string(), addr.clone());

        if let Some(ip_addr) = ip {
            let mut mapping = self.mapping.write().unwrap();
            mapping.insert(domain.to_string(), ip_addr);
        }

        (*addr).clone()
    }

    pub fn clear(&self) {
        self.cache.invalidate_all();

        let mut mapping = self.mapping.write().unwrap();
        mapping.clear();
    }

    fn allocate_addr(&self) -> IpAddr {
        let mut offset = self.offset.lock().unwrap();
        loop {
            let n = *offset % self.pool_size;
            *offset += 1;

            let addr = self.nth_host_ip(n);

            if addr != self.gateway {
                return addr;
            }
        }
    }

    fn nth_host_ip(&self, n: usize) -> IpAddr {
        match self.network.network() {
            IpAddr::V4(network_addr) => {
                let base = u32::from(network_addr);
                let target = base + 1 + n as u32;
                IpAddr::V4(target.into())
            }
            IpAddr::V6(network_addr) => {
                let base = u128::from(network_addr);
                let target = base + 1 + n as u128;
                IpAddr::V6(target.into())
            }
        }
    }

    fn new_cache(mapping: Arc<RwLock<BiMap<String, IpAddr>>>) -> Cache<String, Arc<Addr>> {
        let idle = Duration::from_secs(60 * 10);
        let mapping_clone = mapping.clone();

        let eviction_listener = move |domain: Arc<String>, _addr: Arc<Addr>, _cause| {
            let mut mapping_guard = mapping_clone.write().unwrap();
            if let Some((_removed_domain, _removed_ip)) = mapping_guard.remove_by_left(&*domain) {}
        };

        Cache::builder()
            .max_capacity(DNS_CACHE_SIZE)
            .time_to_idle(idle)
            .eviction_listener(eviction_listener)
            .build()
    }

    fn get_domain_by_ip_fast(&self, ip: &IpAddr) -> Option<String> {
        let mapping = self.mapping.read().unwrap();
        mapping.get_by_right(ip).cloned()
    }
}

impl Addr {
    pub fn new(domain: &str, ip: Option<IpAddr>, target: &str, remark: &str) -> Self {
        let mut records = vec![];

        let name = Name::from_str(domain).unwrap();

        if let Some(ip) = ip {
            let record = match ip {
                std::net::IpAddr::V4(v) => Record::from_rdata(name.clone(), 10, RData::A(A(v))),
                std::net::IpAddr::V6(v) => {
                    Record::from_rdata(name.clone(), 10, RData::AAAA(AAAA(v)))
                }
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

impl Display for Addr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Addr {{ domain: {}, ip: {:?}, target: {}, remark: {} }}",
            self.domain, self.ip, self.target, self.remark
        )
    }
}

#[cfg(test)]
mod tests {
    extern crate test;
    use rayon::prelude::{IntoParallelIterator, ParallelIterator};

    use std::net::Ipv4Addr;
    use std::str::FromStr;
    use test::Bencher;

    use ipnet::IpNet;

    use super::*;

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
                let domain = format!("test{i}.com");
                let remark = format!("test{i}");
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
            table.apply("example.com", "", "");
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

    #[test]
    fn test_cache_mapping_sync_on_eviction() {
        let table = DnsTable::new("10.89.0.1/24");

        let domains = ["test1.com", "test2.com", "test3.com"];
        let mut ips = vec![];

        for domain in &domains {
            let addr = table.apply(domain, "proxy", "test");
            ips.push(addr.ip.unwrap());

            assert!(table.find_by_domain(domain).is_some());
            assert!(table.find_by_ip(&addr.ip.unwrap()).is_some());
        }

        for domain in &domains {
            table.cache.invalidate(*domain);
        }

        std::thread::sleep(std::time::Duration::from_millis(100));

        for domain in &domains {
            assert!(table.cache.get(*domain).is_none());
        }

        for ip in &ips {
            assert!(table.find_by_ip(ip).is_none());
        }

        for domain in &domains {
            assert!(table.find_by_domain(domain).is_none());
        }
    }

    #[test]
    fn test_default_constructor_mapping_consistency() {
        let table = DnsTable::default();

        let addr = table.allocate(
            "test.com",
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            "test",
        );
        let ip = addr.ip.unwrap();

        assert!(table.cache.get("test.com").is_some());
        assert!(table.find_by_domain("test.com").is_some());
        assert!(table.find_by_ip(&ip).is_some());

        table.cache.invalidate("test.com");
        std::thread::sleep(std::time::Duration::from_millis(100));

        // Verify mapping is also cleared (proves cache and mapping share the same Arc)
        assert!(table.find_by_ip(&ip).is_none());
    }
}

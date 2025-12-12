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
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::RwLock;

#[derive(Debug)]
pub struct DnsTable {
    cache: Cache<String, Arc<Addr>>,
    mapping: Arc<RwLock<BiMap<String, IpAddr>>>,
    network: IpNet,
    gateway: IpAddr,
    pool_size: usize,
    offset: AtomicUsize,
}

#[derive(Clone, Debug)]
pub struct Addr {
    pub domain: String,
    pub ip: Option<IpAddr>,
    pub target: String,
    pub remark: String,

    records: Vec<Record>,
}

const DNS_CACHE_SIZE: u64 = 1000;
const DNS_CACHE_TTL: Duration = Duration::from_mins(5);

impl Default for DnsTable {
    fn default() -> Self {
        Self::new("10.89.0.1/16")
    }
}

impl DnsTable {
    pub fn new(network: &str) -> Self {
        Self::new_with_ttl(network, DNS_CACHE_TTL)
    }

    #[cfg(test)]
    pub fn new_with_short_ttl(network: &str) -> Self {
        Self::new_with_ttl(network, Duration::from_secs(1))
    }

    fn new_with_ttl(network: &str, ttl: Duration) -> Self {
        let network = IpNet::from_str(network).unwrap();

        let hosts = network.hosts();
        let pool_size = hosts.count();

        let mapping = Arc::new(RwLock::new(BiMap::new()));

        let cache = Cache::builder()
            .max_capacity(DNS_CACHE_SIZE)
            .time_to_idle(ttl)
            .eviction_listener({
                let mapping = Arc::clone(&mapping);
                move |domain: Arc<String>, _addr: Arc<Addr>, _cause| {
                    // Use try_write for eviction listener to avoid blocking
                    if let Ok(mut mapping_guard) = mapping.try_write() {
                        mapping_guard.remove_by_left(&*domain);
                    }
                    // If lock is busy, stale entry will be cleaned up on next access
                }
            })
            .build();

        Self {
            cache,
            mapping,
            network,
            gateway: network.addr(),
            pool_size,
            offset: AtomicUsize::new(0),
        }
    }

    pub async fn apply(&self, domain: &str, target: &str, remark: &str) -> Addr {
        let ip = self.allocate_addr();
        let addr = Arc::new(Addr::new(domain, Some(ip), target, remark));

        let domain_owned = domain.to_string();
        self.cache.insert(domain_owned.clone(), addr.clone());

        let mut mapping = self.mapping.write().await;
        mapping.insert(domain_owned, ip);

        (*addr).clone()
    }

    pub async fn find_by_ip(&self, ip: &IpAddr) -> Option<Addr> {
        let domain = {
            let mapping = self.mapping.read().await;
            mapping.get_by_right(ip).cloned()
        };

        if let Some(domain) = domain {
            if let Some(addr) = self.cache.get(&domain) {
                return Some((*addr).clone());
            }
            // Remove stale entry from mapping
            let mut mapping = self.mapping.write().await;
            mapping.remove_by_right(ip);
        }
        None
    }

    pub async fn find_by_domain(&self, domain: &str) -> Option<Option<Addr>> {
        if let Some(addr) = self.cache.get(domain) {
            return Some(Some((*addr).clone()));
        }

        let has_mapping = {
            let mapping = self.mapping.read().await;
            mapping.contains_left(domain)
        };

        if has_mapping {
            // Remove stale entry from mapping
            let mut mapping = self.mapping.write().await;
            mapping.remove_by_left(domain);
        }

        None
    }

    pub async fn allocate(&self, domain: &str, ip: Option<IpAddr>, remark: &str) -> Addr {
        let addr = Arc::new(Addr::new(domain, ip, "", remark));

        let domain_owned = domain.to_string();
        self.cache.insert(domain_owned.clone(), addr.clone());

        if let Some(ip_addr) = ip {
            let mut mapping = self.mapping.write().await;
            mapping.insert(domain_owned, ip_addr);
        }

        (*addr).clone()
    }

    pub async fn clear(&self) {
        self.cache.invalidate_all();

        // Clear the mapping atomically
        let mut mapping = self.mapping.write().await;
        mapping.clear();
    }

    fn allocate_addr(&self) -> IpAddr {
        loop {
            let offset = self.offset.fetch_add(1, Ordering::Relaxed);
            let n = offset % self.pool_size;

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

    use std::net::Ipv4Addr;
    use std::str::FromStr;
    use test::Bencher;

    use ipnet::IpNet;

    use super::*;

    #[tokio::test]
    async fn it_works() {
        let table = DnsTable::new("10.89.0.1/24");
        let addr = table.apply("test.com", "", "test").await;
        assert_eq!(addr.ip, Some(IpAddr::V4(Ipv4Addr::new(10, 89, 0, 2))));
    }

    #[tokio::test]
    async fn iter() {
        let network = "10.89.0.1/24";
        let hosts = IpNet::from_str(network).unwrap().hosts();

        let table = DnsTable::new(network);

        for _ in 0..2 {
            for (i, host) in hosts.skip(1).enumerate() {
                let domain = format!("test{i}.com");
                let remark = format!("test{i}");
                let addr = table.apply(&domain, "", &remark).await;
                assert_eq!(addr.ip, Some(host));
                assert!(table.find_by_ip(&host).await.is_some());

                let found = table.find_by_ip(&host).await;
                assert!(found.is_some());

                let found = found.unwrap();
                assert_eq!(&found.domain, &domain);
                assert_eq!(&found.remark, &remark);
            }
        }

        let addr = table.apply("test_additional", "", "").await;
        assert_eq!(addr.ip.unwrap().to_string(), "10.89.0.2".to_string());
    }

    #[tokio::test]
    async fn test_cache_mapping_sync_on_eviction() {
        let table = DnsTable::new_with_short_ttl("10.89.0.1/24");

        let domains = ["test1.com", "test2.com", "test3.com"];
        let mut ips = vec![];

        for domain in &domains {
            let addr = table.apply(domain, "proxy", "test").await;
            ips.push(addr.ip.unwrap());

            assert!(table.find_by_domain(domain).await.is_some());
            assert!(table.find_by_ip(&addr.ip.unwrap()).await.is_some());
        }

        for domain in &domains {
            table.cache.invalidate(*domain);
        }

        std::thread::sleep(std::time::Duration::from_millis(100));

        for domain in &domains {
            assert!(table.cache.get(*domain).is_none());
        }

        for ip in &ips {
            assert!(table.find_by_ip(ip).await.is_none());
        }

        for domain in &domains {
            assert!(table.find_by_domain(domain).await.is_none());
        }
    }

    #[tokio::test]
    async fn test_default_constructor_mapping_consistency() {
        let table = DnsTable::default();

        let addr = table
            .allocate(
                "test.com",
                Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                "test",
            )
            .await;
        let ip = addr.ip.unwrap();

        assert!(table.cache.get("test.com").is_some());
        assert!(table.find_by_domain("test.com").await.is_some());
        assert!(table.find_by_ip(&ip).await.is_some());

        table.cache.invalidate("test.com");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Verify mapping is also cleared (proves cache and mapping share the same Arc)
        assert!(table.find_by_ip(&ip).await.is_none());
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
        let rt = tokio::runtime::Runtime::new().unwrap();
        let table = DnsTable::new("10.89.0.1/24");

        b.iter(|| {
            rt.block_on(table.apply("example.com", "", ""));
        })
    }

    #[bench]
    fn bench_apply(b: &mut Bencher) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let table = Arc::new(DnsTable::new("10.89.0.1/24"));

        b.iter(|| {
            rt.block_on(async {
                use rayon::prelude::*;
                (0..100).into_par_iter().for_each(|i| {
                    let domain = format!("{i}.example.com");
                    rt.block_on(table.apply(&domain, "", ""));
                });
            });
        });
    }

    #[bench]
    fn bench_find(b: &mut Bencher) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let table = Arc::new(DnsTable::new("10.89.0.1/24"));

        rt.block_on(async {
            for i in 0..100 {
                let domain = format!("{i}.example.com");
                table.apply(&domain, "", "").await;
            }
        });

        b.iter(|| {
            rt.block_on(async {
                use rayon::prelude::*;
                (0..100).into_par_iter().for_each(|i| {
                    let domain = format!("{i}.example.com");
                    rt.block_on(table.find_by_domain(&domain));
                });
            });
        });
    }
}

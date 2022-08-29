use crate::config::{setting::RuleType, Addr, ArcSetting};
use rayon::prelude::*;
use std::{net::IpAddr, str::FromStr, sync::Arc};
use trust_dns_server::{
    authority::{Authority, LookupObject, LookupOptions},
    client::rr::LowerName,
    proto::rr::{rdata::TXT, RData, Record, RecordType},
    resolver::Name,
    store::forwarder::ForwardAuthority,
};

pub(crate) struct DnsHandler {
    upstream: Arc<ForwardAuthority>,
    setting: ArcSetting,
}

impl DnsHandler {
    pub(crate) fn new(upstream: Arc<ForwardAuthority>, setting: ArcSetting) -> Self {
        Self { upstream, setting }
    }

    pub(crate) async fn handle_hosts(&self, domain: &str) -> Option<Box<dyn LookupObject>> {
        let m = self
            .setting
            .hosts_match
            .read()
            .unwrap()
            .match_domain(domain)?;

        let name = Name::from_str(domain).unwrap();

        if let Ok(IpAddr::V4(ip)) = IpAddr::from_str(&m) {
            let record = Record::from_rdata(name.clone(), 60, RData::A(ip));
            let r = DnsLookup {
                records: vec![record],
            };
            return Some(Box::new(r));
        }

        let upstream = self.upstream.clone();
        let r = upstream
            .lookup(
                &LowerName::new(&name),
                RecordType::A,
                LookupOptions::default(),
            )
            .await;
        match r {
            Ok(v) => Some(Box::new(v)),
            Err(_) => None,
        }
    }

    pub(crate) fn apply_before_rules(&self, domain: &str) -> Option<Box<dyn LookupObject>> {
        let rules = {
            let rules = &self.setting.rules.read().unwrap();
            rules
                .iter()
                .filter(|&v| v.rule_type == RuleType::Domain)
                .cloned()
                .collect::<Vec<_>>()
        };

        let result = rules.par_iter().find_map_any(|r| {
            if let Some(m) = r.match_domain(domain) {
                let remark = format!("rule:{:?}, value:{}, target:{}", r.rule_type, m, r.target);

                let addr = self
                    .setting
                    .dns_table
                    .write()
                    .unwrap()
                    .apply(domain, &r.target, &remark);

                return Some(DnsLookup::from(addr));
            }
            None
        });

        match result {
            Some(r) => Some(Box::new(r)),
            None => None,
        }
    }

    pub(crate) fn apply_post_rules(
        &self,
        domain: &str,
        records: &dyn LookupObject,
    ) -> Option<Box<dyn LookupObject>> {
        let rules = {
            let rules = &self.setting.rules.read().unwrap();
            rules
                .iter()
                .filter(|&v| v.rule_type == RuleType::DnsCidr)
                .cloned()
                .collect::<Vec<_>>()
        };

        if rules.is_empty() {
            return None;
        }

        let records = records.iter().cloned().collect::<Vec<_>>();

        let ips = records
            .par_iter()
            .map(|v| {
                if let Some(v) = v.data() {
                    let r = match v {
                        RData::A(v) => Some(IpAddr::V4(*v)),
                        RData::AAAA(v) => Some(IpAddr::V6(*v)),
                        _ => None,
                    };
                    return r;
                }
                None
            })
            .collect::<Vec<_>>();

        let ips = ips.iter().flatten().collect::<Vec<_>>();

        let result = ips.par_iter().find_map_any(|v| {
            rules.par_iter().find_map_any(|r| {
                if let Some(m) = r.match_cidr(v) {
                    let remark =
                        format!("rule:{:?}, value:{}, target:{}", r.rule_type, m, r.target);

                    let addr = self
                        .setting
                        .dns_table
                        .write()
                        .unwrap()
                        .apply(domain, &r.target, &remark);

                    return Some(DnsLookup::from(addr));
                }
                None
            })
        });

        match result {
            Some(r) => Some(Box::new(r)),
            None => None,
        }
    }
}

#[derive(Default)]
struct DnsLookup {
    records: Vec<Record>,
}

impl LookupObject for DnsLookup {
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

impl From<Addr> for DnsLookup {
    fn from(addr: Addr) -> Self {
        let mut records = vec![];

        let name = Name::from_str(&addr.domain).unwrap();

        let record = match addr.ip {
            std::net::IpAddr::V4(ip) => Record::from_rdata(name.clone(), 10, RData::A(ip)),
            std::net::IpAddr::V6(_) => todo!(),
        };
        records.push(record);

        records.push(Record::from_rdata(
            name,
            10,
            RData::TXT(TXT::new(vec![format!("match {}", addr.remark)])),
        ));

        Self { records }
    }
}

impl From<Box<dyn LookupObject>> for DnsLookup {
    fn from(objs: Box<dyn LookupObject>) -> Self {
        if objs.is_empty() {
            return Self::default();
        }

        let records = objs.iter().cloned().collect();
        Self { records }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn feature() {
        let pattern = glob::Pattern::new("*.google.com").unwrap();
        println!("{:?}", pattern.matches("www.google.com"));
    }
}

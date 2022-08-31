use std::{net::IpAddr, str::FromStr, time::Duration};

use log::debug;

use prometheus::{register_int_counter, IntCounter};
use rayon::prelude::*;
use tokio::time;
use trust_dns_server::{
    authority::{AuthorityObject, LookupError, LookupObject, LookupOptions},
    client::rr::LowerName,
    proto::{
        op::ResponseCode,
        rr::{RData, RecordType},
    },
    resolver::Name,
    server::RequestInfo,
};

use crate::config::{setting::RuleType, Addr, ArcSetting};

pub(crate) struct DnsHandler {
    upstream: Box<dyn AuthorityObject>,
    setting: ArcSetting,
}

impl DnsHandler {
    pub(crate) fn new(upstream: Box<dyn AuthorityObject>, setting: ArcSetting) -> Self {
        Self { upstream, setting }
    }

    pub(crate) async fn handle(
        &self,
        request_info: RequestInfo<'_>,
        lookup_options: LookupOptions,
    ) -> Result<Box<dyn LookupObject>, LookupError> {
        let query = request_info.query;
        let should_handle = query.query_type() == RecordType::A;

        let domain = query.name().to_string();
        let domain = domain.strip_suffix('.').unwrap_or("");

        if Name::from_str(domain).is_err() {
            return Err(LookupError::ResponseCode(ResponseCode::BADNAME));
        }

        // metrics
        if self.setting.metrics.is_some() {
            lazy_static! {
                static ref DNS_QUERY: IntCounter =
                    register_int_counter!("dns_query_total", "Number of dns query").unwrap();
            }
            DNS_QUERY.inc();
        }

        let mut matched = false;

        if should_handle {
            let addr = self.setting.dns_table.find_by_domain(domain);
            match addr {
                Some(Some(v)) => {
                    return Ok(Box::new(v));
                }
                None => {
                    debug!("query src: {:?}, domain: {}", request_info.src.ip(), domain);

                    let result = self
                        .handle_hosts(domain)
                        .await
                        .or_else(|| self.apply_before_rules(domain));

                    if let Some(v) = result {
                        return Ok(Box::new(v));
                    }
                }
                _ => matched = true,
            }
        }

        let result = {
            let r = time::timeout(
                Duration::from_secs(2),
                self.upstream.search(request_info, lookup_options),
            )
            .await;
            match r {
                Ok(v) => v,
                Err(_) => {
                    debug!("upstream timeout {}", domain);
                    Err(LookupError::ResponseCode(ResponseCode::ServFail))
                }
            }
        };

        // let result = self.upstream.search(request_info, lookup_options).await;

        if should_handle && !matched {
            match result {
                Ok(r) => {
                    if let Some(v) = self.apply_post_rules(domain, r.as_ref()) {
                        return Ok(Box::new(v));
                    }

                    return Ok(r);
                }
                _ => return result,
            }
        }
        result
    }

    pub(crate) async fn handle_hosts(&self, domain: &str) -> Option<Addr> {
        let m = self
            .setting
            .hosts_match
            .read()
            .unwrap()
            .match_domain(domain)?;

        let name = Name::from_str(domain).unwrap();

        if let Ok(ip) = IpAddr::from_str(&m) {
            return Some(self.setting.dns_table.allocate(domain, Some(ip), "host"));
        }

        let r = self
            .upstream
            .lookup(
                &LowerName::new(&name),
                RecordType::A,
                LookupOptions::default(),
            )
            .await;
        match r {
            Ok(v) => {
                for v in v.iter() {
                    if let Some(v) = v.data() {
                        if let Some(v) = v.as_a() {
                            return Some(self.setting.dns_table.allocate(
                                domain,
                                Some(IpAddr::V4(*v)),
                                "host",
                            ));
                        }
                    }
                }
                None
            }
            Err(_) => None,
        }
    }

    pub(crate) fn apply_before_rules(&self, domain: &str) -> Option<Addr> {
        let rules = {
            let rules = &self.setting.rules.read().unwrap();
            rules
                .iter()
                .filter(|&v| v.rule_type == RuleType::Domain)
                .cloned()
                .collect::<Vec<_>>()
        };

        rules.par_iter().find_map_any(|r| {
            if let Some(m) = r.match_domain(domain) {
                let remark = format!("rule:{:?}, value:{}, target:{}", r.rule_type, m, r.target);

                let addr = self.setting.dns_table.apply(domain, &r.target, &remark);

                return Some(addr);
            }
            None
        })
    }

    pub(crate) fn apply_post_rules(
        &self,
        domain: &str,
        records: &dyn LookupObject,
    ) -> Option<Addr> {
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

        let records = records
            .iter()
            .filter(|v| v.data().is_some() && v.data().unwrap().as_a().is_some())
            .cloned()
            .collect::<Vec<_>>();

        let ips = records
            .par_iter()
            .map(|v| {
                if let Some(v) = v.data() {
                    let r = match v {
                        RData::A(v) => Some(IpAddr::V4(*v)),
                        _ => None,
                    };
                    return r;
                }
                None
            })
            .collect::<Vec<_>>();

        let ips = ips.iter().flatten().collect::<Vec<_>>();

        ips.par_iter().find_map_any(|v| {
            rules.par_iter().find_map_any(|r| {
                if let Some(m) = r.match_cidr(v) {
                    let remark =
                        format!("rule:{:?}, value:{}, target:{}", r.rule_type, m, r.target);
                    let addr = self.setting.dns_table.apply(domain, &r.target, &remark);

                    return Some(addr);
                }
                None
            })
        })
    }
}

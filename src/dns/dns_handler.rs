use hickory_server::{
    authority::{
        AuthLookup, AuthorityObject, LookupError, LookupObject, LookupOptions, LookupRecords,
    },
    proto::{
        op::ResponseCode,
        rr::{LowerName, RData, RecordSet, RecordType, rdata::PTR},
    },
    resolver::Name,
    server::RequestInfo,
};
use log::{debug, error};
use prometheus::{IntCounter, register_int_counter};
use std::{net::IpAddr, str::FromStr, sync::Arc, time::Duration};
use tokio::time::timeout;

use crate::config::Addr;
use crate::runtime::ArcRuntime;

pub(crate) struct DnsHandler {
    upstream: Box<dyn AuthorityObject>,
    runtime: ArcRuntime,
}

impl DnsHandler {
    pub(crate) fn new(upstream: Box<dyn AuthorityObject>, runtime: ArcRuntime) -> Self {
        Self { upstream, runtime }
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
        if self.runtime.setting.metrics.is_some() {
            lazy_static! {
                static ref DNS_QUERY: IntCounter =
                    register_int_counter!("dns_query_total", "Number of dns query").unwrap();
            }
            DNS_QUERY.inc();
        }

        if query.query_type() == RecordType::PTR {
            let domain = domain.replace(".in-addr.arpa", "");
            let ip = domain
                .split('.')
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect::<Vec<_>>()
                .join(".");
            if let Ok(addr) = ip.parse::<std::net::IpAddr>()
                && let Some(v) = self.runtime.dns_table.find_by_ip(&addr)
            {
                let mut records = RecordSet::with_ttl(query.name().into(), RecordType::PTR, 10);
                let ptr = format!("{}.{}", domain, v.domain);
                records.add_rdata(RData::PTR(PTR(Name::from_str(&ptr).unwrap())));
                let answers = LookupRecords::new(Default::default(), Arc::new(records));
                let result = AuthLookup::answers(answers, None);
                return Ok(Box::new(result));
            }
        }

        let mut matching_rules = false;

        if should_handle {
            let addr = self.runtime.dns_table.find_by_domain(domain);
            match addr {
                Some(Some(v)) => {
                    return Ok(Box::new(v));
                }
                None => {
                    debug!("query src: {:?}, domain: {}", request_info.src.ip(), domain);

                    matching_rules = true;

                    let result = self
                        .handle_hosts(domain)
                        .await
                        .or_else(|| self.apply_before_rules(domain));

                    if let Some(v) = result {
                        return Ok(Box::new(v));
                    }
                }
                _ => {}
            }
        }

        let result = timeout(
            Duration::from_secs(2),
            self.upstream.search(request_info, lookup_options),
        )
        .await
        .map_err(|_| LookupError::ResponseCode(ResponseCode::ServFail))?;

        if should_handle && matching_rules {
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
        let m = self.runtime.hosts.read().unwrap().match_domain(domain)?;

        if let Ok(ip) = IpAddr::from_str(&m) {
            return Some(self.runtime.dns_table.allocate(domain, Some(ip), "host"));
        }

        let name = Name::from_str(&m);

        if name.is_err() {
            return None;
        }

        let r = self
            .upstream
            .lookup(
                &LowerName::new(&name.unwrap()),
                RecordType::A,
                LookupOptions::default(),
            )
            .await;

        match r {
            Ok(v) => {
                for v in v.iter() {
                    if let Some(v) = v.data()
                        && let Some(v) = v.as_a()
                    {
                        return Some(self.runtime.dns_table.allocate(
                            domain,
                            Some(IpAddr::V4(**v)),
                            "host",
                        ));
                    }
                }
                None
            }
            Err(e) => {
                error!("{:?}", e);
                None
            }
        }
    }

    pub(crate) fn apply_before_rules(&self, domain: &str) -> Option<Addr> {
        // Check exclude rules first
        if self.runtime.rules.find_exclude_domain(domain) {
            return None;
        }

        // Find domain-based rule
        if let Some(matched) = self.runtime.rules.find_domain_rule(domain) {
            let remark = format!(
                "rule:{:?}, value:{}, target:{}",
                matched.rule_type, matched.matched_value, matched.target
            );

            let addr = self
                .runtime
                .dns_table
                .apply(domain, &matched.target, &remark);

            return Some(addr);
        }

        None
    }

    pub(crate) fn apply_post_rules(
        &self,
        domain: &str,
        records: &dyn LookupObject,
    ) -> Option<Addr> {
        let records = records
            .iter()
            .filter(|v| v.data().is_some() && v.data().unwrap().as_a().is_some())
            .collect::<Vec<_>>();

        for record in records {
            if let Some(data) = record.data() {
                let ip = match data {
                    RData::A(v) => Some(IpAddr::V4(**v)),
                    _ => None,
                };

                if let Some(ip) = ip
                    && let Some(matched) = self.runtime.rules.find_dns_cidr_rule(&ip)
                {
                    let remark = format!(
                        "rule:{:?}, value:{}, target:{}",
                        matched.rule_type, matched.matched_value, matched.target
                    );
                    let addr = self
                        .runtime
                        .dns_table
                        .apply(domain, &matched.target, &remark);

                    return Some(addr);
                }
            }
        }

        None
    }
}

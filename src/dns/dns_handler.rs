use hickory_server::{
    authority::{
        AuthLookup, AuthorityObject, LookupControlFlow, LookupError, LookupObject, LookupOptions,
        LookupRecords,
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
use std::{
    net::{IpAddr, Ipv4Addr},
    str::FromStr,
    sync::Arc,
    time::Duration,
};
use tokio::time::timeout;

use crate::config::Addr;
use crate::runtime::ArcRuntime;

pub(crate) struct DnsHandler {
    runtime: ArcRuntime,
    upstream: Arc<dyn AuthorityObject>,
}

impl DnsHandler {
    pub(crate) fn new(runtime: ArcRuntime, upstream: Arc<dyn AuthorityObject>) -> Self {
        Self { runtime, upstream }
    }

    fn parse_ptr_domain(&self, domain: &str) -> Option<IpAddr> {
        if !domain.ends_with(".in-addr.arpa") {
            return None;
        }

        let addr_part = domain.trim_end_matches(".in-addr.arpa");
        let mut octets = [0u8; 4];
        let mut octet_index = 0;

        for part in addr_part.split('.').rev() {
            if part.is_empty() {
                continue;
            }

            if octet_index >= 4 {
                return None;
            }

            octets[octet_index] = part.parse::<u8>().ok()?;
            octet_index += 1;
        }

        if octet_index != 4 {
            return None;
        }

        Some(IpAddr::V4(Ipv4Addr::from(octets)))
    }

    pub(crate) async fn handle(
        &self,
        request_info: RequestInfo<'_>,
        lookup_options: LookupOptions,
    ) -> Result<Box<dyn LookupObject>, LookupError> {
        let query = request_info.query;
        let should_handle = query.query_type() == RecordType::A;

        let name_str = query.name().to_string();
        let domain = if let Some(trimmed) = name_str.strip_suffix('.') {
            if trimmed.is_empty() {
                &name_str
            } else {
                trimmed
            }
        } else {
            &name_str
        };

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

        if query.query_type() == RecordType::PTR
            && let Some(addr) = self.parse_ptr_domain(domain)
            && let Some(v) = self.runtime.dns_table.find_by_ip(&addr)
        {
            let mut records = RecordSet::with_ttl(query.name().into(), RecordType::PTR, 10);
            let ptr = format!("{}.{}", domain, v.domain);
            if let Ok(name) = Name::from_str(&ptr) {
                records.add_rdata(RData::PTR(PTR(name)));
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

        let search_result = timeout(
            Duration::from_secs(2),
            self.upstream.search(request_info, lookup_options),
        )
        .await
        .map_err(|_| LookupError::ResponseCode(ResponseCode::ServFail))?;

        let result = match search_result {
            LookupControlFlow::Continue(lookup) => lookup,
            LookupControlFlow::Break(lookup) => lookup,
            LookupControlFlow::Skip => Err(LookupError::ResponseCode(ResponseCode::ServFail)),
        };

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
        let m = self.runtime.hosts.read().match_domain(domain)?.into_owned();

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
            LookupControlFlow::Continue(Ok(v)) => {
                for record in v.iter() {
                    let data = record.data();
                    if let Some(a_record) = data.as_a() {
                        return Some(self.runtime.dns_table.allocate(
                            domain,
                            Some(IpAddr::V4(**a_record)),
                            "host",
                        ));
                    }
                }
                None
            }
            LookupControlFlow::Continue(Err(e)) => {
                error!("{:?}", e);
                None
            }
            LookupControlFlow::Break(Ok(v)) => {
                for record in v.iter() {
                    let data = record.data();
                    if let Some(a_record) = data.as_a() {
                        return Some(self.runtime.dns_table.allocate(
                            domain,
                            Some(IpAddr::V4(**a_record)),
                            "host",
                        ));
                    }
                }
                None
            }
            LookupControlFlow::Break(Err(e)) => {
                error!("{:?}", e);
                None
            }
            LookupControlFlow::Skip => None,
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
        for record in records.iter() {
            let ip = match record.data() {
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

        None
    }
}

use anyhow::Error;
use arc_swap::ArcSwap;
use rayon::prelude::*;
use std::net::IpAddr;
use std::sync::Arc;

use super::{MatchedRule, RuleConfig, RuleMatcher, RuleType};

#[derive(Clone)]
struct RulesData {
    exclude_matchers: Vec<Arc<RuleMatcher>>,
    domain_matchers: Vec<Arc<RuleMatcher>>,
    dns_cidr_matchers: Vec<Arc<RuleMatcher>>,
    route_matchers: Vec<Arc<RuleMatcher>>,
}

type CategorizedMatchers = (
    Vec<Arc<RuleMatcher>>, // exclude_matchers
    Vec<Arc<RuleMatcher>>, // domain_matchers
    Vec<Arc<RuleMatcher>>, // dns_cidr_matchers
    Vec<Arc<RuleMatcher>>, // route_matchers
);

pub struct Rules {
    data: ArcSwap<RulesData>,
}

impl Rules {
    pub fn new(configs: Vec<RuleConfig>) -> Result<Self, Error> {
        let (exclude_matchers, domain_matchers, dns_cidr_matchers, route_matchers) =
            Self::categorize_matchers(configs)?;

        let data = RulesData {
            exclude_matchers,
            domain_matchers,
            dns_cidr_matchers,
            route_matchers,
        };

        Ok(Self {
            data: ArcSwap::new(Arc::new(data)),
        })
    }

    pub fn find_exclude_domain(&self, domain: &str) -> bool {
        let data = self.data.load();

        data.exclude_matchers
            .par_iter()
            .any(|m| m.match_domain(domain).is_some())
    }

    pub fn find_domain_rule(&self, domain: &str) -> Option<MatchedRule> {
        let data = self.data.load();

        data.domain_matchers.par_iter().find_map_any(|m| {
            let target = m.target.as_ref()?;
            let matched_value = m.match_domain(domain)?.into_owned();

            Some(MatchedRule {
                target: target.clone(),
                matched_value,
                rule_type: m.rule_type.clone(),
            })
        })
    }

    pub fn find_dns_cidr_rule(&self, ip: &IpAddr) -> Option<MatchedRule> {
        let data = self.data.load();

        data.dns_cidr_matchers.par_iter().find_map_any(|m| {
            let target = m.target.as_ref()?;
            let matched_value = m.match_cidr(ip)?.into_owned();

            Some(MatchedRule {
                target: target.clone(),
                matched_value,
                rule_type: m.rule_type.clone(),
            })
        })
    }

    pub fn find_route_rule(&self, ip: &IpAddr) -> Option<MatchedRule> {
        let data = self.data.load();

        data.route_matchers.par_iter().find_map_any(|m| {
            let target = m.target.as_ref()?;
            let matched_value = m.match_cidr(ip)?.into_owned();

            Some(MatchedRule {
                target: target.clone(),
                matched_value,
                rule_type: m.rule_type.clone(),
            })
        })
    }

    pub fn get_route_rules(&self) -> Vec<String> {
        let data = self.data.load();
        data.route_matchers
            .iter()
            .flat_map(|m| m.values.clone())
            .collect()
    }

    pub fn reload(&self, configs: Vec<RuleConfig>) -> Result<(), Error> {
        let (exclude_matchers, domain_matchers, dns_cidr_matchers, route_matchers) =
            Self::categorize_matchers(configs)?;

        let new_data = RulesData {
            exclude_matchers,
            domain_matchers,
            dns_cidr_matchers,
            route_matchers,
        };

        // Atomic swap - all readers will see the new data immediately
        self.data.store(Arc::new(new_data));
        Ok(())
    }

    fn categorize_matchers(configs: Vec<RuleConfig>) -> Result<CategorizedMatchers, Error> {
        let mut exclude_matchers = Vec::new();
        let mut domain_matchers = Vec::new();
        let mut dns_cidr_matchers = Vec::new();
        let mut route_matchers = Vec::new();

        for config in configs {
            let matcher = RuleMatcher::from_config(config)?;
            let matcher = Arc::new(matcher);

            match matcher.rule_type {
                RuleType::ExcludeDomain => exclude_matchers.push(matcher),
                RuleType::Domain => domain_matchers.push(matcher),
                RuleType::DnsCidr => dns_cidr_matchers.push(matcher),
                RuleType::Route => route_matchers.push(matcher),
                RuleType::DnsGeoIp => {
                    // TODO: Implement GeoIP rule handling
                }
                RuleType::Unknown(_) => {
                    log::warn!("Unknown rule type encountered");
                }
            }
        }

        Ok((
            exclude_matchers,
            domain_matchers,
            dns_cidr_matchers,
            route_matchers,
        ))
    }
}

impl Default for Rules {
    fn default() -> Self {
        let data = RulesData {
            exclude_matchers: vec![],
            domain_matchers: vec![],
            dns_cidr_matchers: vec![],
            route_matchers: vec![],
        };

        Self {
            data: ArcSwap::new(Arc::new(data)),
        }
    }
}

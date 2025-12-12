use anyhow::Error;
use parking_lot::RwLock;
use rayon::prelude::*;
use std::net::IpAddr;
use std::sync::Arc;

use super::{MatchedRule, RuleConfig, RuleMatcher, RuleType};

/// Type alias for categorized matcher collections
type CategorizedMatchers = (
    Vec<Arc<RuleMatcher>>, // exclude_matchers
    Vec<Arc<RuleMatcher>>, // domain_matchers
    Vec<Arc<RuleMatcher>>, // dns_cidr_matchers
    Vec<Arc<RuleMatcher>>, // route_matchers
);

/// Rules management - handles rule matching with high-level API
pub struct Rules {
    exclude_matchers: RwLock<Vec<Arc<RuleMatcher>>>,
    domain_matchers: RwLock<Vec<Arc<RuleMatcher>>>,
    dns_cidr_matchers: RwLock<Vec<Arc<RuleMatcher>>>,
    route_matchers: RwLock<Vec<Arc<RuleMatcher>>>,
}

impl Rules {
    /// Create new Rules from configuration
    pub fn new(configs: Vec<RuleConfig>) -> Result<Self, Error> {
        let (exclude_matchers, domain_matchers, dns_cidr_matchers, route_matchers) =
            Self::categorize_matchers(configs)?;

        Ok(Self {
            exclude_matchers: RwLock::new(exclude_matchers),
            domain_matchers: RwLock::new(domain_matchers),
            dns_cidr_matchers: RwLock::new(dns_cidr_matchers),
            route_matchers: RwLock::new(route_matchers),
        })
    }

    /// Check if domain should be excluded from proxying
    pub fn find_exclude_domain(&self, domain: &str) -> bool {
        let matchers = self.exclude_matchers.read();
        matchers
            .par_iter()
            .any(|m| m.match_domain(domain).is_some())
    }

    /// Find domain-based rule match
    pub fn find_domain_rule(&self, domain: &str) -> Option<MatchedRule> {
        let matchers = self.domain_matchers.read();
        matchers.par_iter().find_map_any(|m| {
            let target = m.target.as_ref()?;
            let matched_value = m.match_domain(domain)?.into_owned();

            Some(MatchedRule {
                target: target.clone(),
                matched_value,
                rule_type: m.rule_type.clone(),
            })
        })
    }

    /// Generic helper to find CIDR-based rule matches
    fn find_cidr_rule(
        &self,
        matchers: &RwLock<Vec<Arc<RuleMatcher>>>,
        ip: &IpAddr,
    ) -> Option<MatchedRule> {
        let matchers = matchers.read();
        matchers.par_iter().find_map_any(|m| {
            let target = m.target.as_ref()?;
            let matched_value = m.match_cidr(ip)?.into_owned();

            Some(MatchedRule {
                target: target.clone(),
                matched_value,
                rule_type: m.rule_type.clone(),
            })
        })
    }

    /// Find DNS CIDR-based rule match
    pub fn find_dns_cidr_rule(&self, ip: &IpAddr) -> Option<MatchedRule> {
        self.find_cidr_rule(&self.dns_cidr_matchers, ip)
    }

    /// Find route-based rule match
    pub fn find_route_rule(&self, ip: &IpAddr) -> Option<MatchedRule> {
        self.find_cidr_rule(&self.route_matchers, ip)
    }

    /// Get all route rule CIDR values (for gateway setup)
    pub fn get_route_rules(&self) -> Vec<String> {
        let matchers = self.route_matchers.read();
        matchers.iter().flat_map(|m| m.values.clone()).collect()
    }

    /// Hot-reload rules from new configuration
    pub fn reload(&self, configs: Vec<RuleConfig>) -> Result<(), Error> {
        let (exclude_matchers, domain_matchers, dns_cidr_matchers, route_matchers) =
            Self::categorize_matchers(configs)?;

        *self.exclude_matchers.write() = exclude_matchers;
        *self.domain_matchers.write() = domain_matchers;
        *self.dns_cidr_matchers.write() = dns_cidr_matchers;
        *self.route_matchers.write() = route_matchers;

        Ok(())
    }

    /// Categorize matchers from rule configurations
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
        Self {
            exclude_matchers: RwLock::new(vec![]),
            domain_matchers: RwLock::new(vec![]),
            dns_cidr_matchers: RwLock::new(vec![]),
            route_matchers: RwLock::new(vec![]),
        }
    }
}

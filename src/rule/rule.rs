use anyhow::Error;
use rayon::prelude::*;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};

use super::{MatchedRule, RuleConfig, RuleMatcher, RuleType};

/// Rules management - handles rule matching with high-level API
pub struct Rules {
    matchers: RwLock<Vec<Arc<RuleMatcher>>>,
}

impl Rules {
    /// Create new Rules from configuration
    pub fn new(configs: Vec<RuleConfig>) -> Result<Self, Error> {
        let mut matchers = Vec::new();
        for config in configs {
            let matcher = RuleMatcher::from_config(config)?;
            matchers.push(Arc::new(matcher));
        }

        Ok(Self {
            matchers: RwLock::new(matchers),
        })
    }

    /// Check if domain should be excluded from proxying
    pub fn find_exclude_domain(&self, domain: &str) -> bool {
        let matchers = self.matchers.read().unwrap();
        let exclude_matchers = matchers
            .iter()
            .filter(|m| m.rule_type == RuleType::ExcludeDomain)
            .collect::<Vec<_>>();

        exclude_matchers
            .par_iter()
            .any(|m| m.match_domain(domain).is_some())
    }

    /// Find domain-based rule match
    pub fn find_domain_rule(&self, domain: &str) -> Option<MatchedRule> {
        let matchers = self.matchers.read().unwrap();
        let domain_matchers = matchers
            .iter()
            .filter(|m| m.rule_type == RuleType::Domain)
            .collect::<Vec<_>>();

        domain_matchers.par_iter().find_map_any(|m| {
            let target = m.target.as_ref()?;
            let matched_value = m.match_domain(domain)?;

            Some(MatchedRule {
                target: target.clone(),
                matched_value,
                rule_type: m.rule_type.clone(),
            })
        })
    }

    /// Find DNS CIDR-based rule match
    pub fn find_dns_cidr_rule(&self, ip: &IpAddr) -> Option<MatchedRule> {
        let matchers = self.matchers.read().unwrap();
        let cidr_matchers = matchers
            .iter()
            .filter(|m| m.rule_type == RuleType::DnsCidr)
            .collect::<Vec<_>>();

        cidr_matchers.par_iter().find_map_any(|m| {
            let target = m.target.as_ref()?;
            let matched_value = m.match_cidr(ip)?;

            Some(MatchedRule {
                target: target.clone(),
                matched_value,
                rule_type: m.rule_type.clone(),
            })
        })
    }

    /// Find route-based rule match
    pub fn find_route_rule(&self, ip: &IpAddr) -> Option<MatchedRule> {
        let matchers = self.matchers.read().unwrap();
        let route_matchers = matchers
            .iter()
            .filter(|m| m.rule_type == RuleType::Route)
            .collect::<Vec<_>>();

        route_matchers.par_iter().find_map_any(|m| {
            let target = m.target.as_ref()?;
            let matched_value = m.match_cidr(ip)?;

            Some(MatchedRule {
                target: target.clone(),
                matched_value,
                rule_type: m.rule_type.clone(),
            })
        })
    }

    /// Get all route rule CIDR values (for gateway setup)
    pub fn get_route_rules(&self) -> Vec<String> {
        let matchers = self.matchers.read().unwrap();
        matchers
            .iter()
            .filter(|m| m.rule_type == RuleType::Route)
            .flat_map(|m| m.values.clone())
            .collect()
    }

    /// Hot-reload rules from new configuration
    pub fn reload(&self, configs: Vec<RuleConfig>) -> Result<(), Error> {
        let mut new_matchers = Vec::new();
        for config in configs {
            let matcher = RuleMatcher::from_config(config)?;
            new_matchers.push(Arc::new(matcher));
        }

        let mut matchers = self.matchers.write().unwrap();
        *matchers = new_matchers;

        Ok(())
    }
}

impl Default for Rules {
    fn default() -> Self {
        Self {
            matchers: RwLock::new(vec![]),
        }
    }
}

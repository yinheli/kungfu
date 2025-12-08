use anyhow::Error;
use ipnet::IpNet;
use rayon::prelude::*;
use std::net::IpAddr;
use std::str::FromStr;

use super::{RuleConfig, RuleType};

/// Compiled rule matcher with pre-parsed patterns and CIDRs
#[derive(Default, Clone, Debug)]
pub struct RuleMatcher {
    pub rule_type: RuleType,
    pub target: Option<String>,
    pub values: Vec<String>,
    patterns: Vec<glob::Pattern>,
    cidrs: Vec<IpNet>,
}

/// Result of a successful rule match
#[derive(Debug, Clone)]
pub struct MatchedRule {
    pub target: String,
    pub matched_value: String,
    pub rule_type: RuleType,
}

impl RuleMatcher {
    /// Build a RuleMatcher from RuleConfig
    pub fn from_config(config: RuleConfig) -> Result<Self, Error> {
        match config.rule_type {
            RuleType::Domain | RuleType::ExcludeDomain => {
                let values = config.values.clone();
                let mut patterns = vec![];
                for x in values.iter() {
                    let pattern = glob::Pattern::new(x)?;
                    patterns.push(pattern);
                }
                Ok(Self {
                    rule_type: config.rule_type,
                    target: config.target,
                    values,
                    patterns,
                    cidrs: vec![],
                })
            }
            RuleType::DnsCidr | RuleType::Route => {
                let values = config.values.clone();
                let mut cidrs = vec![];
                for x in values.iter() {
                    let cidr = IpNet::from_str(x)?;
                    cidrs.push(cidr);
                }
                Ok(Self {
                    rule_type: config.rule_type,
                    target: config.target,
                    values,
                    patterns: vec![],
                    cidrs,
                })
            }
            _ => Ok(Self {
                rule_type: config.rule_type,
                target: config.target,
                values: config.values,
                patterns: vec![],
                cidrs: vec![],
            }),
        }
    }

    /// Match domain against glob patterns (parallel search)
    pub fn match_domain(&self, domain: &str) -> Option<String> {
        let pattern = self.patterns.par_iter().find_any(|&v| v.matches(domain));
        pattern.map(|p| p.to_string())
    }

    /// Match IP address against CIDR ranges (parallel search)
    pub fn match_cidr(&self, ip: &IpAddr) -> Option<String> {
        let cidr = self.cidrs.par_iter().find_any(|&v| v.contains(ip));
        cidr.map(|cidr| cidr.to_string())
    }
}

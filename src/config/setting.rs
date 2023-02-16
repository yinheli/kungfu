use ipnet::IpNet;
use rayon::prelude::*;
use serde::Deserialize;
use std::{net::IpAddr, str::FromStr, sync::RwLock};

use super::{dns_table::DnsTable, hosts::Hosts};

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct Setting {
    pub bind: String,
    pub dns_port: u32,
    pub dns_upstream: Vec<String>,
    pub network: String,
    pub proxy: Vec<Proxy>,
    pub hosts: RwLock<String>,
    pub rules: RwLock<Vec<Rule>>,
    pub metrics: Option<String>,

    #[serde(skip_serializing, skip_deserializing)]
    pub hosts_match: RwLock<Hosts>,

    #[serde(skip_serializing, skip_deserializing)]
    pub dns_table: DnsTable,
}

impl Default for Setting {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0".to_string(),
            dns_port: 53,
            dns_upstream: vec![String::from("1.2.4.8"), String::from("8.8.8.8")],
            network: String::from("10.89.0.1/16"),
            proxy: Default::default(),
            hosts: Default::default(),
            rules: Default::default(),
            metrics: None,
            hosts_match: Default::default(),
            dns_table: Default::default(),
        }
    }
}

#[derive(Default, Debug, Deserialize)]
pub struct Proxy {
    pub name: String,
    pub values: Vec<String>,
}

#[derive(Default, Clone, Debug, Deserialize)]
#[serde(try_from = "InnerRule")]
pub struct Rule {
    #[serde(rename = "type")]
    pub rule_type: RuleType,
    pub target: Option<String>,
    pub values: Vec<String>,
    patterns: Vec<glob::Pattern>,
    cidrs: Vec<IpNet>,
}

#[derive(Default, Clone, Debug, Deserialize)]
struct InnerRule {
    #[serde(rename = "type")]
    pub rule_type: RuleType,
    pub target: Option<String>,
    pub values: Vec<String>,
}

impl TryFrom<InnerRule> for Rule {
    type Error = anyhow::Error;

    fn try_from(value: InnerRule) -> Result<Self, Self::Error> {
        match value.rule_type {
            RuleType::Domain | RuleType::ExcludeDomain => {
                let values = value.values.clone();
                let mut patterns = vec![];
                for x in values.iter() {
                    let pattern = glob::Pattern::new(x)?;
                    patterns.push(pattern);
                }
                Ok(Self {
                    rule_type: value.rule_type,
                    target: value.target,
                    values,
                    patterns,
                    ..Default::default()
                })
            }
            RuleType::DnsCidr | RuleType::Route => {
                let values = value.values.clone();
                let mut cidrs = vec![];
                for x in values.iter() {
                    let cidr = IpNet::from_str(x)?;
                    cidrs.push(cidr);
                }
                Ok(Self {
                    rule_type: value.rule_type,
                    target: value.target,
                    values,
                    cidrs,
                    ..Default::default()
                })
            }
            _ => Ok(Self {
                rule_type: value.rule_type,
                target: value.target,
                values: value.values,
                ..Default::default()
            }),
        }
    }
}

impl Rule {
    pub fn match_domain(&self, domain: &str) -> Option<String> {
        let pattern = self.patterns.par_iter().find_any(|&v| v.matches(domain));
        pattern.map(|p| p.to_string())
    }

    pub fn match_cidr(&self, ip: &IpAddr) -> Option<String> {
        let cidr = self.cidrs.par_iter().find_any(|&v| v.contains(ip));
        cidr.map(|cidr| cidr.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleType {
    Route,
    Domain,
    ExcludeDomain,
    DnsGeoIp,
    DnsCidr,
    Unknown(String),
}

impl<'de> serde::de::Deserialize<'de> for RuleType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?.to_lowercase();

        // spell-checker: disable
        let t = match s.as_str() {
            "route" => RuleType::Route,
            "domain" => RuleType::Domain,
            "excludedomain" => RuleType::ExcludeDomain,
            "dnscidr" => RuleType::DnsCidr,
            "dnsgeoip" => RuleType::DnsGeoIp,
            _ => RuleType::Unknown(s),
        };
        // spell-checker: enable
        Ok(t)
    }
}

impl Default for RuleType {
    fn default() -> Self {
        RuleType::Unknown("unknown".to_string())
    }
}

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

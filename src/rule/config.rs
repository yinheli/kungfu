use serde::Deserialize;

use super::RuleType;

/// Pure configuration data structure deserialized from YAML
#[derive(Default, Debug, Deserialize, Clone)]
pub struct RuleConfig {
    #[serde(rename = "type")]
    pub rule_type: RuleType,
    pub target: Option<String>,
    pub values: Vec<String>,
}

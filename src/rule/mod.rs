mod config;
mod matcher;
#[allow(clippy::module_inception)]
mod rule;
mod r#type;

pub use config::RuleConfig;
pub use matcher::{MatchedRule, RuleMatcher};
pub use rule::Rules;
pub use r#type::RuleType;

use std::sync::{Arc, RwLock};

use crate::config::{DnsTable, Hosts, setting::Setting};
use crate::rule::Rules;

/// Runtime context containing configuration and runtime components
pub struct RuntimeContext {
    pub setting: Arc<Setting>,
    pub rules: Arc<Rules>,
    pub hosts: RwLock<Hosts>,
    pub dns_table: DnsTable,
}

pub type ArcRuntime = Arc<RuntimeContext>;

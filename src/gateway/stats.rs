use crate::runtime::ArcRuntime;
use moka::sync::Cache;
use prometheus::{IntCounterVec, register_int_counter_vec};
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone, Copy)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    fn as_str(&self) -> &'static str {
        match self {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
        }
    }
}

/// Update metrics for traffic relay
pub fn update_metrics(
    runtime: &ArcRuntime,
    protocol: Protocol,
    proxy: &str,
    domain: &str,
    up: u64,
    down: u64,
) {
    if runtime.setting.metrics.is_none() {
        return;
    }

    lazy_static::lazy_static! {
        static ref RELAY_COUNT: IntCounterVec = register_int_counter_vec!(
            "relay_total",
            "Number of bytes relayed by proxy",
            &["protocol", "action", "proxy"]
        )
        .unwrap();

        static ref RELAY_HOST_COUNT: IntCounterVec = register_int_counter_vec!(
            "relay_host_total",
            "Number of bytes relayed by domain (latest 100 domains)",
            &["protocol", "action", "domain"]
        )
        .unwrap();

        static ref RELAY_COUNT_CACHE: Cache<String, u8> = Cache::builder()
            .max_capacity(100)
            .time_to_live(Duration::from_secs(60))
            .eviction_listener(|k: Arc<String>, _, c| {
                if c.was_evicted() {
                    let _ = RELAY_HOST_COUNT.remove_label_values(&["tcp", "upload", &k]);
                    let _ = RELAY_HOST_COUNT.remove_label_values(&["tcp", "download", &k]);
                    let _ = RELAY_HOST_COUNT.remove_label_values(&["udp", "upload", &k]);
                    let _ = RELAY_HOST_COUNT.remove_label_values(&["udp", "download", &k]);
                }
            })
            .build();
    }

    let protocol_str = protocol.as_str();

    RELAY_COUNT
        .with_label_values(&[protocol_str, "upload", proxy])
        .inc_by(up);
    RELAY_COUNT
        .with_label_values(&[protocol_str, "download", proxy])
        .inc_by(down);

    RELAY_HOST_COUNT
        .with_label_values(&[protocol_str, "upload", domain])
        .inc_by(up);
    RELAY_HOST_COUNT
        .with_label_values(&[protocol_str, "download", domain])
        .inc_by(down);

    RELAY_COUNT_CACHE.insert(domain.to_string(), 0);
}

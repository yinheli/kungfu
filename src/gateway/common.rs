use super::nat::Session;
use crate::runtime::ArcRuntime;
use rand::prelude::*;
use std::net::IpAddr;

/// Randomly select a proxy URL from the list
pub fn random_proxy(proxy: &[String]) -> String {
    if proxy.len() == 1 {
        return proxy[0].clone();
    }
    let mut rng = rand::rng();
    proxy
        .choose(&mut rng)
        .cloned()
        .unwrap_or_else(|| proxy[0].clone())
}

/// Find target proxy and address for a session
pub async fn find_target(runtime: ArcRuntime, session: Session) -> Option<(String, String, u16)> {
    if let Some(addr) = runtime.dns_table.find_by_ip(&session.dst_addr.into()).await {
        return Some((addr.target, addr.domain, session.dst_port));
    }

    if let Some(matched) = runtime.rules.find_route_rule(&IpAddr::V4(session.dst_addr)) {
        return Some((
            matched.target,
            session.dst_addr.to_string(),
            session.dst_port,
        ));
    }

    None
}

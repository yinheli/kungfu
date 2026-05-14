use super::nat::Session;
use crate::config::setting::ParsedProxyUrl;
use crate::runtime::ArcRuntime;
use rand::prelude::*;
use std::net::IpAddr;

pub fn random_proxy(proxies: &[ParsedProxyUrl]) -> &ParsedProxyUrl {
    if proxies.len() == 1 {
        return &proxies[0];
    }
    let mut rng = rand::rng();
    proxies.choose(&mut rng).unwrap_or(&proxies[0])
}

pub async fn find_target(runtime: ArcRuntime, session: Session) -> Option<(String, String, u16)> {
    if let Some(addr) = runtime.dns_table.find_by_ip(&session.dst_addr.into()).await {
        return Some((addr.target.clone(), addr.domain.clone(), session.dst_port));
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

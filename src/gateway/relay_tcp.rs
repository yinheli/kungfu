use std::{
    net::IpAddr,
    num::NonZeroUsize,
    sync::{Arc, Mutex},
    time::Duration,
};

use log::warn;
use lru::LruCache;
use prometheus::{register_int_counter_vec, IntCounterVec};
use rand::seq::SliceRandom;
use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};
use tokio::{io::copy_bidirectional, net::TcpListener};

use crate::{
    config::{setting::RuleType, ArcSetting},
    gateway::proxy::open_proxy,
};

use super::nat::{Nat, Session};

pub(crate) struct Relay {
    setting: ArcSetting,
    relay_addr: String,
    nat: Arc<Nat>,
}

impl Relay {
    pub fn new(setting: ArcSetting, relay_addr: String, nat: Arc<Nat>) -> Self {
        Self {
            setting,
            relay_addr,
            nat,
        }
    }

    pub async fn serve(&self) {
        let server = TcpListener::bind(&self.relay_addr).await.unwrap();
        let nat = self.nat.clone();
        let setting = self.setting.clone();

        tokio::spawn(async move {
            while let Ok((stream, remote_addr)) = server.accept().await {
                let nat = nat.clone();
                let setting = setting.clone();

                tokio::spawn(async move {
                    let session = nat.find(remote_addr.port());
                    if session.is_none() {
                        return;
                    }

                    let session = session.unwrap();

                    // proxy (name), target host, target port
                    let target = find_target(setting.clone(), session);

                    if target.is_none() {
                        return;
                    }

                    let target = target.unwrap();

                    let proxy = setting.proxy.iter().find(|&v| v.name == target.0);

                    if proxy.is_none() {
                        warn!("proxy ({}) not found", target.0);
                        return;
                    }

                    let proxy = proxy.unwrap();
                    let proxy_url = random_proxy(&proxy.values);

                    let outbound = open_proxy(proxy_url, &target.1, target.2).await;

                    match outbound {
                        Ok(mut outbound) => {
                            let _ = stream.set_nodelay(true);
                            let mut stream = tokio_io_timeout::TimeoutStream::new(stream);
                            stream.set_read_timeout(Some(Duration::from_secs(30)));
                            let mut stream = Box::pin(stream);

                            let _ = outbound.set_nodelay(true);

                            let result = copy_bidirectional(&mut stream, &mut outbound).await;

                            if let Ok((up, down)) = result {
                                if setting.metrics.is_some() {
                                    lazy_static! {
                                        static ref RELAY_COUNT: IntCounterVec = register_int_counter_vec!(
                                            "relay_total",
                                            "Number of bytes relay by proxy",
                                            &["action", "proxy"]
                                        )
                                        .unwrap();
                                        static ref RELAY_HOST_COUNT: IntCounterVec = register_int_counter_vec!(
                                            "relay_host_total",
                                            "Number of bytes relay by proxy with domain (latest 200 domains for each proxy)",
                                            &["action", "proxy", "domain"]
                                        )
                                        .unwrap();
                                        static ref RELAY_COUNT_CACHE: Mutex<LruCache<String, u8>> =
                                            Mutex::new(LruCache::new(NonZeroUsize::new(200).unwrap()));
                                    }

                                    RELAY_COUNT
                                        .with_label_values(&["upload", &proxy.name])
                                        .inc_by(up);
                                    RELAY_COUNT
                                        .with_label_values(&["download", &proxy.name])
                                        .inc_by(down);

                                    RELAY_HOST_COUNT
                                        .with_label_values(&["upload", &proxy.name, &target.1])
                                        .inc_by(up);
                                    RELAY_HOST_COUNT
                                        .with_label_values(&["download", &proxy.name, &target.1])
                                        .inc_by(down);

                                    if let Some((k, _)) =
                                        RELAY_COUNT_CACHE.lock().unwrap().push(target.1.clone(), 0)
                                    {
                                        if !k.eq(&target.1) {
                                            let _ = RELAY_HOST_COUNT.remove_label_values(&[
                                                "upload",
                                                &proxy.name,
                                                &k,
                                            ]);
                                            let _ = RELAY_HOST_COUNT.remove_label_values(&[
                                                "download",
                                                &proxy.name,
                                                &k,
                                            ]);
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            warn!("open proxy {}, err: {}", &target.0, e);
                        }
                    }
                });
            }
        });
    }
}

fn random_proxy(proxy: &Vec<String>) -> String {
    if proxy.len() == 1 {
        return proxy[0].clone();
    }
    let mut rng = rand::thread_rng();
    proxy.choose(&mut rng).unwrap().clone()
}

fn find_target(setting: ArcSetting, session: Session) -> Option<(String, String, u16)> {
    if let Some(addr) = setting.dns_table.find_by_ip(&session.dst_addr.into()) {
        return Some((addr.target, addr.domain, session.dst_port));
    }

    let rules = setting.rules.read().unwrap();
    let rules = rules.par_iter().filter(|&v| v.rule_type == RuleType::Route);

    rules.find_map_any(|r| {
        if r.match_cidr(&IpAddr::V4(session.dst_addr)).is_some() {
            return Some((
                r.target.clone(),
                session.dst_addr.to_string(),
                session.dst_port,
            ));
        }
        None
    })
}

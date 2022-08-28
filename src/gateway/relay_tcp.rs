use std::{
    net::{IpAddr},
    sync::Arc,
};

use log::{warn};
use rand::seq::SliceRandom;
use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};
use tokio::{
    io::{self, AsyncWriteExt},
    net::TcpListener,
};

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
            while let Ok((mut stream, remote_addr)) = server.accept().await {
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
                    let proxy = random_proxy(&proxy.values);

                    let outbound = open_proxy(proxy, &target.1, target.2).await;

                    match outbound {
                        Ok(mut outbound) => {
                            let (mut ri, mut wi) = stream.split();
                            let (mut ro, mut wo) = outbound.split();

                            let client_to_server = async {
                                io::copy(&mut ri, &mut wo).await?;
                                wo.shutdown().await
                            };

                            let server_to_client = async {
                                io::copy(&mut ro, &mut wi).await?;
                                wi.shutdown().await
                            };

                            let _ = tokio::try_join!(client_to_server, server_to_client);
                        }
                        Err(e) => {
                            warn!("open proxy: {}", e);
                        }
                    }
                });
            }
        });
    }
}

fn random_proxy(proxy: &Vec<String>) -> String {
    let mut rng = rand::thread_rng();
    proxy.choose(&mut rng).unwrap().clone()
}

fn find_target(setting: ArcSetting, session: Session) -> Option<(String, String, u16)> {
    if let Some(addr) = setting
        .dns_table
        .read()
        .unwrap()
        .find(&session.dst_addr.into())
    {
        return Some((addr.target, addr.domain, session.dst_port));
    }

    let rules = {
        let rules = setting.rules.read().unwrap();
        rules
            .iter()
            .filter(|&v| v.rule_type == RuleType::Route)
            .cloned()
            .collect::<Vec<_>>()
    };

    let t = rules.par_iter().find_map_any(|r| {
        if r.match_cidr(&IpAddr::V4(session.dst_addr)).is_some() {
            return Some(r.target.clone());
        }
        None
    });

    if let Some(p) = t {
        return Some((p, session.dst_addr.to_string(), session.dst_port));
    }

    None
}

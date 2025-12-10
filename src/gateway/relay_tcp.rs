use std::{sync::Arc, time::Duration};

use log::warn;
use tokio::{io::copy_bidirectional, net::TcpListener};

use crate::{gateway::proxy::open_proxy, runtime::ArcRuntime};

use super::{
    common,
    nat::Nat,
    stats::{self, Protocol},
};

pub(crate) struct Relay {
    runtime: ArcRuntime,
    relay_addr: String,
    nat: Arc<Nat>,
}

impl Relay {
    pub fn new(runtime: ArcRuntime, relay_addr: String, nat: Arc<Nat>) -> Self {
        Self {
            runtime,
            relay_addr,
            nat,
        }
    }

    pub async fn serve(&self) {
        let server = TcpListener::bind(&self.relay_addr).await.unwrap();
        let nat = self.nat.clone();
        let runtime = self.runtime.clone();

        tokio::spawn(async move {
            while let Ok((stream, remote_addr)) = server.accept().await {
                let nat = nat.clone();
                let runtime = runtime.clone();

                tokio::spawn(async move {
                    let session = nat.find(remote_addr.port());
                    if session.is_none() {
                        warn!("nat not found, {}", remote_addr);
                        return;
                    }

                    let session = session.unwrap();

                    let target = common::find_target(runtime.clone(), session);

                    if target.is_none() {
                        return;
                    }

                    let target = target.unwrap();

                    let proxy = runtime.setting.proxy.iter().find(|&v| v.name == target.0);

                    if proxy.is_none() {
                        warn!("proxy ({}) not found", target.0);
                        return;
                    }

                    let proxy = proxy.unwrap();
                    let proxy_url = common::random_proxy(&proxy.values);

                    let outbound = open_proxy(proxy_url, &target.1, target.2).await;

                    match outbound {
                        Ok(mut outbound) => {
                            let _ = stream.set_nodelay(true);
                            // TODO optimize this with idle timeout
                            let mut stream = tokio_io_timeout::TimeoutStream::new(stream);
                            stream.set_read_timeout(Some(Duration::from_secs(3600 * 2)));
                            let mut stream = Box::pin(stream);

                            let _ = outbound.set_nodelay(true);

                            let result = copy_bidirectional(&mut stream, &mut outbound).await;

                            if let Ok((up, down)) = result {
                                stats::update_metrics(
                                    &runtime,
                                    Protocol::Tcp,
                                    &proxy.name,
                                    &target.1,
                                    up,
                                    down,
                                );
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

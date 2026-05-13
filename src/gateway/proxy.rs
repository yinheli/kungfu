use crate::config::setting::ParsedProxyUrl;
use anyhow::{Error, anyhow};
use fast_socks5::client::{Config, Socks5Stream};
use std::time::Duration;
use tokio::net::TcpStream;

pub async fn open_proxy(
    proxy: &ParsedProxyUrl,
    target: &str,
    target_port: u16,
) -> Result<TcpStream, Error> {
    let mut config = Config::default();
    config.set_connect_timeout(Duration::from_secs(5));
    config.set_skip_auth(false);

    let target_addr = target.to_string();

    let socket = Socks5Stream::connect_with_password(
        &proxy.addr,
        target_addr,
        target_port,
        proxy.username.clone(),
        proxy.password.as_deref().unwrap_or("default").to_string(),
        config,
    )
    .await;

    socket.map(|v| v.get_socket()).map_err(|e| {
        anyhow!(
            "create proxy, proxy: {}, target: {}:{}, err: {}",
            &proxy.addr,
            target,
            target_port,
            e
        )
    })
}

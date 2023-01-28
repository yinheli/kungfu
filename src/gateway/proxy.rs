use anyhow::{anyhow, Error};
use fast_socks5::client::{Config, Socks5Stream};
use tokio::net::TcpStream;
use url::Url;

pub async fn open_proxy(proxy: String, target: &str, target_port: u16) -> Result<TcpStream, Error> {
    let url = Url::parse(&proxy).unwrap();
    let host = url.host().unwrap();
    let port = url.port().map_or(80, |v| v);

    let proxy = format!("{host}:{port}");

    let mut config = Config::default();
    config.set_connect_timeout(5);

    let target_addr = target.to_string();

    let socket = if url.has_authority() {
        config.set_skip_auth(false);

        Socks5Stream::connect_with_password(
            &proxy,
            target_addr,
            target_port,
            url.username().to_string(),
            url.password().map_or("default", |v| v).to_string(),
            config,
        )
        .await
    } else {
        config.set_skip_auth(true);

        Socks5Stream::connect(&proxy, target_addr, target_port, config).await
    };

    socket.map(|v| v.get_socket()).map_err(|e| {
        anyhow!(
            "create proxy, proxy: {}, target: {}:{}, err: {}",
            &proxy,
            target,
            target_port,
            e
        )
    })
}

use super::dns_server;
use crate::config::ArcSetting;

pub async fn serve(setting: ArcSetting) {
    let server = dns_server::build_dns_server(setting.clone()).await;

    if let Ok(mut server) = server {
        server.block_until_done().await.unwrap();
    }
}

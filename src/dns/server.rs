use super::dns_server;
use crate::runtime::ArcRuntime;

pub async fn serve(runtime: ArcRuntime) {
    let server = dns_server::build_dns_server(runtime.clone()).await;

    if let Ok(mut server) = server {
        server.block_until_done().await.unwrap();
    }
}

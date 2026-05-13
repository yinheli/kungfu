use anyhow::Error;
use hickory_server::net::runtime::Time;
use hickory_server::proto::op::ResponseCode;
use hickory_server::proto::rr::TSigResponseContext;
use hickory_server::proto::rr::{LowerName, Name};
use hickory_server::resolver::config::{
    ConnectionConfig, NameServerConfig, ProtocolConfig, ResolveHosts, ResolverOpts,
};
use hickory_server::server::{Request, RequestHandler, RequestInfo, ResponseHandler, ResponseInfo};
use hickory_server::store::forwarder::{ForwardConfig, ForwardZoneHandler};
use hickory_server::{
    Server,
    zone_handler::{
        AuthLookup, AxfrPolicy, Catalog, LookupControlFlow, LookupError, LookupOptions,
        ZoneHandler, ZoneType,
    },
};
use std::net::ToSocketAddrs;
use std::{sync::Arc, time::Duration};
use tokio::{
    net::{TcpListener, UdpSocket},
    time,
};

use super::dns_handler::DnsHandler;
use crate::runtime::ArcRuntime;

fn make_connection_configs(port: u16) -> Vec<ConnectionConfig> {
    let mut udp = ConnectionConfig::new(ProtocolConfig::Udp);
    udp.port = port;
    let mut tcp = ConnectionConfig::new(ProtocolConfig::Tcp);
    tcp.port = port;
    vec![udp, tcp]
}

pub(crate) async fn build_dns_server(runtime: ArcRuntime) -> Result<Server<Handler>, Error> {
    let mut name_servers = Vec::new();
    for upstream in runtime.setting.dns_upstream.iter() {
        let mut upstream = upstream.clone();
        if !upstream.contains(':') {
            upstream.push_str(":53")
        }

        if let Ok(addrs) = &upstream[..].to_socket_addrs() {
            addrs.clone().for_each(|addr| {
                let mut ns = NameServerConfig::udp_and_tcp(addr.ip());
                ns.connections = make_connection_configs(addr.port());
                name_servers.push(ns);
            });
        }
    }

    let mut opts = ResolverOpts::default();
    opts.attempts = 1;
    opts.use_hosts_file = ResolveHosts::Never;
    opts.num_concurrent_reqs = 2;
    opts.try_tcp_on_error = false;
    opts.edns0 = true;
    opts.timeout = Duration::from_secs(2);
    opts.positive_max_ttl = Some(Duration::from_secs(120));
    opts.negative_max_ttl = Some(Duration::from_secs(120));

    let forward_config = ForwardConfig {
        name_servers,
        options: Some(opts),
    };

    let upstream = ForwardZoneHandler::builder_tokio(forward_config)
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to build forward authority: {}", e))?;

    let upstream: Arc<dyn ZoneHandler> = Arc::new(upstream);
    let handler = DnsHandler::new(runtime.clone(), upstream.clone());
    let authority = HijackAuthority::new(upstream.clone(), handler);

    let mut catalog = Catalog::new();
    catalog.upsert(LowerName::from(Name::root()), vec![Arc::new(authority)]);

    let mut server = Server::new(Handler { catalog });
    log::info!("dns listen port: {}", runtime.setting.dns_port);
    server.register_socket(
        UdpSocket::bind(format!(
            "{}:{}",
            runtime.setting.bind, runtime.setting.dns_port
        ))
        .await?,
    );
    server.register_listener(
        TcpListener::bind(format!(
            "{}:{}",
            runtime.setting.bind, runtime.setting.dns_port
        ))
        .await?,
        Duration::from_secs(5),
        1024,
    );

    Ok(server)
}

struct HijackAuthority {
    upstream: Arc<dyn ZoneHandler>,
    handler: DnsHandler,
}

impl HijackAuthority {
    fn new(upstream: Arc<dyn ZoneHandler>, handler: DnsHandler) -> Self {
        Self { upstream, handler }
    }
}

#[async_trait::async_trait]
impl ZoneHandler for HijackAuthority {
    fn zone_type(&self) -> ZoneType {
        self.upstream.zone_type()
    }

    fn axfr_policy(&self) -> AxfrPolicy {
        self.upstream.axfr_policy()
    }

    fn can_validate_dnssec(&self) -> bool {
        self.upstream.can_validate_dnssec()
    }

    fn origin(&self) -> &LowerName {
        self.upstream.origin()
    }

    async fn update(
        &self,
        update: &Request,
        now: u64,
    ) -> (Result<bool, ResponseCode>, Option<TSigResponseContext>) {
        self.upstream.update(update, now).await
    }

    async fn lookup(
        &self,
        name: &LowerName,
        rtype: hickory_server::proto::rr::RecordType,
        request_info: Option<&RequestInfo<'_>>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        self.upstream
            .lookup(name, rtype, request_info, lookup_options)
            .await
    }

    async fn search(
        &self,
        request: &Request,
        lookup_options: LookupOptions,
    ) -> (LookupControlFlow<AuthLookup>, Option<TSigResponseContext>) {
        let future = self.handler.handle(request, lookup_options);

        match time::timeout(Duration::from_millis(2000), future).await {
            Ok(Ok(r)) => (LookupControlFlow::Continue(Ok(r)), None),
            Ok(Err(e)) => (LookupControlFlow::Break(Err(e)), None),
            Err(_) => (
                LookupControlFlow::Break(Err(LookupError::ResponseCode(ResponseCode::ServFail))),
                None,
            ),
        }
    }

    async fn nsec_records(
        &self,
        name: &LowerName,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        self.upstream.nsec_records(name, lookup_options).await
    }

    async fn consult(
        &self,
        name: &LowerName,
        rtype: hickory_server::proto::rr::RecordType,
        request_info: Option<&RequestInfo<'_>>,
        lookup_options: LookupOptions,
        last_result: LookupControlFlow<AuthLookup>,
    ) -> (LookupControlFlow<AuthLookup>, Option<TSigResponseContext>) {
        self.upstream
            .consult(name, rtype, request_info, lookup_options, last_result)
            .await
    }
}

pub struct Handler {
    catalog: Catalog,
}

#[async_trait::async_trait]
impl RequestHandler for Handler {
    async fn handle_request<R: ResponseHandler, T: Time>(
        &self,
        request: &Request,
        response_handle: R,
    ) -> ResponseInfo {
        let now = T::current_time();
        self.catalog
            .lookup(request, None, now, response_handle)
            .await
    }
}

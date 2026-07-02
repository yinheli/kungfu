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
use std::net::{SocketAddr, ToSocketAddrs};
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

fn resolver_opts() -> ResolverOpts {
    let mut opts = ResolverOpts::default();
    opts.attempts = 1;
    opts.use_hosts_file = ResolveHosts::Never;
    opts.num_concurrent_reqs = 2;
    opts.try_tcp_on_error = false;
    opts.edns0 = true;
    opts.timeout = Duration::from_secs(2);
    opts.positive_max_ttl = Some(Duration::from_secs(120));
    opts.negative_max_ttl = Some(Duration::from_secs(120));
    opts
}

fn build_forward_handler(addr: SocketAddr) -> Result<Arc<dyn ZoneHandler>, Error> {
    let mut ns = NameServerConfig::udp_and_tcp(addr.ip());
    ns.connections = make_connection_configs(addr.port());

    let forward_config = ForwardConfig {
        name_servers: vec![ns],
        options: Some(resolver_opts()),
    };

    let upstream = ForwardZoneHandler::builder_tokio(forward_config)
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to build forward authority: {}", e))?;

    Ok(Arc::new(upstream))
}

fn build_upstream_handlers(upstreams: &[String]) -> Result<Vec<Arc<dyn ZoneHandler>>, Error> {
    let mut handlers: Vec<Arc<dyn ZoneHandler>> = Vec::new();

    for upstream in upstreams.iter() {
        let mut upstream = upstream.clone();
        if !upstream.contains(':') {
            upstream.push_str(":53")
        }

        if let Ok(addrs) = &upstream[..].to_socket_addrs() {
            for addr in addrs.clone() {
                handlers.push(build_forward_handler(addr)?);
            }
        }
    }

    if handlers.is_empty() {
        return Err(anyhow::anyhow!("no valid dns upstreams configured"));
    }

    Ok(handlers)
}

fn should_try_next_upstream(result: &LookupControlFlow<AuthLookup>) -> bool {
    match result {
        LookupControlFlow::Skip => true,
        LookupControlFlow::Continue(Err(error)) | LookupControlFlow::Break(Err(error)) => {
            is_retryable_lookup_error(error)
        }
        _ => false,
    }
}

fn is_retryable_lookup_error(error: &LookupError) -> bool {
    if error.is_nx_domain() || error.is_no_records_found() {
        return false;
    }

    !matches!(error, LookupError::NameExists)
}

struct SequentialUpstreams {
    handlers: Vec<Arc<dyn ZoneHandler>>,
}

impl SequentialUpstreams {
    fn new(handlers: Vec<Arc<dyn ZoneHandler>>) -> Self {
        Self { handlers }
    }

    fn first(&self) -> &dyn ZoneHandler {
        self.handlers
            .first()
            .expect("SequentialUpstreams requires at least one handler")
            .as_ref()
    }
}

#[async_trait::async_trait]
impl ZoneHandler for SequentialUpstreams {
    fn zone_type(&self) -> ZoneType {
        self.first().zone_type()
    }

    fn axfr_policy(&self) -> AxfrPolicy {
        self.first().axfr_policy()
    }

    fn can_validate_dnssec(&self) -> bool {
        self.first().can_validate_dnssec()
    }

    fn origin(&self) -> &LowerName {
        self.first().origin()
    }

    async fn update(
        &self,
        update: &Request,
        now: u64,
    ) -> (Result<bool, ResponseCode>, Option<TSigResponseContext>) {
        self.first().update(update, now).await
    }

    async fn lookup(
        &self,
        name: &LowerName,
        rtype: hickory_server::proto::rr::RecordType,
        request_info: Option<&RequestInfo<'_>>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        let mut last_result = LookupControlFlow::Skip;

        for handler in &self.handlers {
            let result = handler
                .lookup(name, rtype, request_info, lookup_options)
                .await;
            if !should_try_next_upstream(&result) {
                return result;
            }
            last_result = result;
        }

        last_result
    }

    async fn search(
        &self,
        request: &Request,
        lookup_options: LookupOptions,
    ) -> (LookupControlFlow<AuthLookup>, Option<TSigResponseContext>) {
        let mut last_result = (LookupControlFlow::Skip, None);

        for handler in &self.handlers {
            let result = handler.search(request, lookup_options).await;
            if !should_try_next_upstream(&result.0) {
                return result;
            }
            last_result = result;
        }

        last_result
    }

    async fn nsec_records(
        &self,
        name: &LowerName,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        let mut last_result = LookupControlFlow::Skip;

        for handler in &self.handlers {
            let result = handler.nsec_records(name, lookup_options).await;
            if !should_try_next_upstream(&result) {
                return result;
            }
            last_result = result;
        }

        last_result
    }
}

pub(crate) async fn build_dns_server(runtime: ArcRuntime) -> Result<Server<Handler>, Error> {
    let mut upstream_handlers = build_upstream_handlers(&runtime.setting.dns_upstream)?;
    let upstream: Arc<dyn ZoneHandler> = if upstream_handlers.len() == 1 {
        upstream_handlers.remove(0)
    } else {
        Arc::new(SequentialUpstreams::new(upstream_handlers))
    };

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

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_server::proto::rr::RecordType;
    use hickory_server::zone_handler::LookupError;
    use std::io;
    use std::str::FromStr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    enum MockOutcome {
        Empty,
        NxDomain,
        Io,
    }

    struct MockHandler {
        origin: LowerName,
        calls: Arc<AtomicUsize>,
        outcome: MockOutcome,
    }

    impl MockHandler {
        fn new(outcome: MockOutcome) -> (Arc<Self>, Arc<AtomicUsize>) {
            let calls = Arc::new(AtomicUsize::new(0));
            (
                Arc::new(Self {
                    origin: LowerName::from(Name::root()),
                    calls: Arc::clone(&calls),
                    outcome,
                }),
                calls,
            )
        }

        fn outcome(&self) -> LookupControlFlow<AuthLookup> {
            match self.outcome {
                MockOutcome::Empty => LookupControlFlow::Continue(Ok(AuthLookup::default())),
                MockOutcome::NxDomain => {
                    LookupControlFlow::Continue(Err(LookupError::from(ResponseCode::NXDomain)))
                }
                MockOutcome::Io => LookupControlFlow::Continue(Err(LookupError::from(
                    io::Error::other("primary unavailable"),
                ))),
            }
        }
    }

    #[async_trait::async_trait]
    impl ZoneHandler for MockHandler {
        fn zone_type(&self) -> ZoneType {
            ZoneType::External
        }

        fn axfr_policy(&self) -> AxfrPolicy {
            AxfrPolicy::Deny
        }

        fn origin(&self) -> &LowerName {
            &self.origin
        }

        async fn lookup(
            &self,
            _name: &LowerName,
            _rtype: RecordType,
            _request_info: Option<&RequestInfo<'_>>,
            _lookup_options: LookupOptions,
        ) -> LookupControlFlow<AuthLookup> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.outcome()
        }

        async fn search(
            &self,
            _request: &Request,
            _lookup_options: LookupOptions,
        ) -> (LookupControlFlow<AuthLookup>, Option<TSigResponseContext>) {
            self.calls.fetch_add(1, Ordering::SeqCst);
            (self.outcome(), None)
        }

        async fn nsec_records(
            &self,
            _name: &LowerName,
            _lookup_options: LookupOptions,
        ) -> LookupControlFlow<AuthLookup> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.outcome()
        }
    }

    fn query_name() -> LowerName {
        LowerName::new(&Name::from_str("example.com.").unwrap())
    }

    #[tokio::test]
    async fn does_not_query_backup_after_dns_negative_response() {
        let (primary, primary_calls) = MockHandler::new(MockOutcome::NxDomain);
        let (backup, backup_calls) = MockHandler::new(MockOutcome::Empty);
        let upstreams = SequentialUpstreams::new(vec![primary, backup]);

        let result = upstreams
            .lookup(
                &query_name(),
                RecordType::AAAA,
                None,
                LookupOptions::default(),
            )
            .await;

        assert!(matches!(
            result,
            LookupControlFlow::Continue(Err(ref error)) if error.is_nx_domain()
        ));
        assert_eq!(primary_calls.load(Ordering::SeqCst), 1);
        assert_eq!(backup_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn queries_backup_after_primary_transport_error() {
        let (primary, primary_calls) = MockHandler::new(MockOutcome::Io);
        let (backup, backup_calls) = MockHandler::new(MockOutcome::Empty);
        let upstreams = SequentialUpstreams::new(vec![primary, backup]);

        let result = upstreams
            .lookup(&query_name(), RecordType::A, None, LookupOptions::default())
            .await;

        assert!(matches!(result, LookupControlFlow::Continue(Ok(_))));
        assert_eq!(primary_calls.load(Ordering::SeqCst), 1);
        assert_eq!(backup_calls.load(Ordering::SeqCst), 1);
    }
}

use parking_lot::RwLock;
use std::{
    io::Error,
    pin::Pin,
    sync::Arc,
    task::Context,
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result};
use log::{debug, warn};
use tokio::{
    io::{AsyncRead, AsyncWrite, copy_bidirectional},
    net::{TcpListener, TcpStream},
    time::timeout,
};

use crate::{gateway::proxy::open_proxy, runtime::ArcRuntime};

use super::{
    common,
    nat::Nat,
    stats::{self, Protocol},
};

const PROXY_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const IDLE_TIMEOUT: Duration = Duration::from_secs(120);

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

    pub async fn serve(&self) -> Result<()> {
        let server = TcpListener::bind(&self.relay_addr)
            .await
            .context("Failed to bind relay server")?;

        let nat = self.nat.clone();
        let runtime = self.runtime.clone();

        tokio::spawn(async move {
            while let Ok((stream, remote_addr)) = server.accept().await {
                let nat = nat.clone();
                let runtime = runtime.clone();

                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, remote_addr, nat, runtime).await {
                        warn!("Connection handling failed: {}", e);
                    }
                });
            }
        });

        Ok(())
    }
}

async fn handle_connection(
    stream: TcpStream,
    remote_addr: std::net::SocketAddr,
    nat: Arc<Nat>,
    runtime: ArcRuntime,
) -> Result<()> {
    let (target_proxy, target_addr, target_port) =
        find_session_target(&nat, &runtime, remote_addr).await?;

    let proxy_config = runtime
        .setting
        .proxy
        .iter()
        .find(|p| p.name == target_proxy)
        .ok_or_else(|| anyhow::anyhow!("Proxy '{}' not found", target_proxy))?;

    let outbound = timeout(
        PROXY_CONNECT_TIMEOUT,
        open_proxy(
            common::random_proxy(&proxy_config.values),
            &target_addr,
            target_port,
        ),
    )
    .await
    .context("Proxy connection timeout")?
    .context("Failed to open proxy connection")?;

    stream.set_nodelay(true)?;
    outbound.set_nodelay(true)?;

    copy_with_idle_timeout(stream, outbound, &runtime, &proxy_config.name, &target_addr).await
}

async fn copy_with_idle_timeout(
    client: TcpStream,
    proxy: TcpStream,
    runtime: &ArcRuntime,
    proxy_name: &str,
    target_addr: &str,
) -> Result<()> {
    let tracker = Arc::new(SharedIdleTracker::new());

    let mut timeout_client = IdleTimeoutStream::new(client, tracker.clone(), IDLE_TIMEOUT);
    let mut timeout_proxy = IdleTimeoutStream::new(proxy, tracker, IDLE_TIMEOUT);

    match copy_bidirectional(&mut timeout_client, &mut timeout_proxy).await {
        Ok((up, down)) => {
            stats::update_metrics(runtime, Protocol::Tcp, proxy_name, target_addr, up, down);
            Ok(())
        }
        Err(e) => {
            // prevent logging timeout errors as warnings
            debug!("TCP relay error: {}", e);
            Ok(())
        }
    }
}

async fn find_session_target(
    nat: &Nat,
    runtime: &ArcRuntime,
    remote_addr: std::net::SocketAddr,
) -> Result<(String, String, u16)> {
    let session = nat
        .find(remote_addr.port())
        .ok_or_else(|| anyhow::anyhow!("NAT session not found for {}", remote_addr))?;

    common::find_target(runtime.clone(), session)
        .ok_or_else(|| anyhow::anyhow!("No target found for session"))
}

struct SharedIdleTracker {
    last_activity: Arc<RwLock<Instant>>,
}

impl SharedIdleTracker {
    fn new() -> Self {
        Self {
            last_activity: Arc::new(RwLock::new(Instant::now())),
        }
    }

    fn update_activity(&self) {
        *self.last_activity.write() = Instant::now();
    }

    fn elapsed(&self) -> Duration {
        self.last_activity.read().elapsed()
    }

    fn is_idle(&self, timeout: Duration) -> bool {
        self.elapsed() > timeout
    }
}

struct IdleTimeoutStream<T> {
    inner: T,
    tracker: Arc<SharedIdleTracker>,
    timeout: Duration,
}

impl<T> IdleTimeoutStream<T> {
    fn new(inner: T, tracker: Arc<SharedIdleTracker>, timeout: Duration) -> Self {
        Self {
            inner,
            tracker,
            timeout,
        }
    }

    fn update_activity(&self) {
        self.tracker.update_activity();
    }

    fn check_idle(&self) -> tokio::io::Result<()> {
        if self.tracker.is_idle(self.timeout) {
            return Err(tokio::io::Error::new(
                tokio::io::ErrorKind::TimedOut,
                "idle timeout - no activity on either side",
            ));
        }
        Ok(())
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for IdleTimeoutStream<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.check_idle()?;

        let initial_filled = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);

        if let std::task::Poll::Ready(Ok(())) = poll
            && buf.filled().len() > initial_filled
        {
            self.update_activity();
        }

        poll
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for IdleTimeoutStream<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, Error>> {
        self.check_idle()?;

        let poll = Pin::new(&mut self.inner).poll_write(cx, buf);

        if let std::task::Poll::Ready(Ok(n)) = poll {
            if n > 0 {
                self.update_activity();
            }
            std::task::Poll::Ready(Ok(n))
        } else {
            poll
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> std::task::Poll<Result<(), Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> std::task::Poll<Result<(), Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

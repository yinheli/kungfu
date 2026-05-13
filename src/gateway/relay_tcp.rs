use std::{
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use anyhow::{Context as _, Result};
use log::debug;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf, copy_bidirectional},
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
const WATCHDOG_INTERVAL: Duration = Duration::from_secs(15);

pub(crate) struct TcpRelay {
    runtime: ArcRuntime,
    relay_listener: Mutex<Option<std::net::TcpListener>>,
    nat: Arc<Nat>,
}

impl TcpRelay {
    pub fn new(runtime: ArcRuntime, relay_listener: std::net::TcpListener, nat: Arc<Nat>) -> Self {
        Self {
            runtime,
            relay_listener: Mutex::new(Some(relay_listener)),
            nat,
        }
    }

    pub async fn serve(&self) -> Result<()> {
        let listener = self
            .relay_listener
            .lock()
            .unwrap()
            .take()
            .context("Relay listener already consumed")?;

        listener
            .set_nonblocking(true)
            .context("Failed to set relay listener to non-blocking")?;

        let server = TcpListener::from_std(listener)
            .context("Failed to convert relay listener to tokio TcpListener")?;

        let nat = self.nat.clone();
        let runtime = self.runtime.clone();

        tokio::spawn(async move {
            while let Ok((stream, remote_addr)) = server.accept().await {
                let nat = nat.clone();
                let runtime = runtime.clone();

                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, remote_addr, nat, runtime).await {
                        debug!("TCP connection failed for {}: {:#}", remote_addr, e);
                    }
                });
            }
        });

        Ok(())
    }
}

async fn handle_connection(
    stream: TcpStream,
    remote_addr: SocketAddr,
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
            common::random_proxy(proxy_config.parsed_values()),
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
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(60))
        .with_interval(Duration::from_secs(10));

    let _ = socket2::SockRef::from(&client).set_tcp_keepalive(&keepalive);
    let _ = socket2::SockRef::from(&proxy).set_tcp_keepalive(&keepalive);

    let last_activity = Arc::new(AtomicU64::new(now_millis()));
    let mut tracked_client = ActivityTracker::new(client, last_activity.clone());
    let mut tracked_proxy = ActivityTracker::new(proxy, last_activity.clone());

    tokio::select! {
        result = copy_bidirectional(&mut tracked_client, &mut tracked_proxy) => {
            match result {
                Ok((up, down)) => {
                    stats::update_metrics(runtime, Protocol::Tcp, proxy_name, target_addr, up, down);
                }
                Err(e) => {
                    debug!("TCP relay error for {}: {}", target_addr, e);
                }
            }
        }
        _ = idle_watchdog(&last_activity) => {
            debug!("TCP relay idle timeout for {} after {:?}", target_addr, IDLE_TIMEOUT);
        }
    }

    Ok(())
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

async fn idle_watchdog(last_activity: &AtomicU64) {
    let timeout_ms = IDLE_TIMEOUT.as_millis() as u64;
    loop {
        tokio::time::sleep(WATCHDOG_INTERVAL).await;
        let elapsed = now_millis().saturating_sub(last_activity.load(Ordering::Relaxed));
        if elapsed >= timeout_ms {
            return;
        }
    }
}

struct ActivityTracker<T> {
    inner: T,
    last_activity: Arc<AtomicU64>,
}

impl<T> ActivityTracker<T> {
    fn new(inner: T, last_activity: Arc<AtomicU64>) -> Self {
        Self {
            inner,
            last_activity,
        }
    }

    fn touch(&self) {
        self.last_activity.store(now_millis(), Ordering::Relaxed);
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for ActivityTracker<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &poll
            && buf.filled().len() > before
        {
            self.touch();
        }
        poll
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for ActivityTracker<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &poll
            && *n > 0
        {
            self.touch();
        }
        poll
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

async fn find_session_target(
    nat: &Nat,
    runtime: &ArcRuntime,
    remote_addr: SocketAddr,
) -> Result<(String, String, u16)> {
    let session = nat
        .find(remote_addr.port())
        .await
        .ok_or_else(|| anyhow::anyhow!("NAT session not found for {}", remote_addr))?;

    common::find_target(runtime.clone(), session)
        .await
        .ok_or_else(|| anyhow::anyhow!("No target found for session"))
}

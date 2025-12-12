use std::{
    io::Error,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, Result};
use log::debug;
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
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

pub(crate) struct TcpRelay {
    runtime: ArcRuntime,
    relay_addr: String,
    nat: Arc<Nat>,
}

impl TcpRelay {
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
                    let _ = handle_connection(stream, remote_addr, nat, runtime).await;
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
            debug!("TCP relay error: {}", e);
            Ok(())
        }
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

struct SharedIdleTracker {
    last_activity: Arc<AtomicU64>,
}

impl SharedIdleTracker {
    fn new() -> Self {
        let now_millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        Self {
            last_activity: Arc::new(AtomicU64::new(now_millis)),
        }
    }

    fn update_activity(&self) {
        let now_millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        self.last_activity.store(now_millis, Ordering::Relaxed);
    }

    fn elapsed(&self) -> Duration {
        let last_millis = self.last_activity.load(Ordering::Relaxed);
        let now_millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        Duration::from_millis(now_millis.saturating_sub(last_millis))
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

    fn is_normal_close(e: &std::io::Error) -> bool {
        matches!(
            e.kind(),
            std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::UnexpectedEof
        )
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for IdleTimeoutStream<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.check_idle()?;

        let initial_filled = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);

        match &poll {
            Poll::Ready(Ok(())) if buf.filled().len() > initial_filled => {
                self.update_activity();
            }
            Poll::Ready(Err(e)) if Self::is_normal_close(e) => {
                return Poll::Ready(Ok(()));
            }
            _ => {}
        }

        poll
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for IdleTimeoutStream<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        self.check_idle()?;

        let poll = Pin::new(&mut self.inner).poll_write(cx, buf);

        match poll {
            Poll::Ready(Ok(n)) => {
                if n > 0 {
                    self.update_activity();
                }
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(e)) if Self::is_normal_close(&e) => {
                // Treat normal close as successful write of all bytes
                Poll::Ready(Ok(buf.len()))
            }
            _ => poll,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

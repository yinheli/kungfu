use std::{net::SocketAddr, str::FromStr};

use bytes::Bytes;
use http_body_util::Full;
use hyper::{server::conn::http1, service::service_fn, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use log::{info, warn};
use prometheus::{Encoder, TextEncoder};
use tokio::{net::TcpListener, spawn};

pub async fn serve(addr: Option<String>) {
    if addr.is_none() {
        return;
    }

    let addr = addr.unwrap();

    let addr = SocketAddr::from_str(&addr).unwrap();

    let listener = TcpListener::bind(addr).await.unwrap();

    info!("metrics server listening on {}", addr);

    loop {
        let (stream, _) = listener.accept().await.unwrap();
        let io = TokioIo::new(stream);
        spawn(async move {
            if let Err(err) = http1::Builder::new()
                .serve_connection(io, service_fn(metrics))
                .await
            {
                warn!("Error serving connection: {:?}", err);
            }
        });
    }
}

async fn metrics(
    req: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    match req.uri().path() {
        "/metrics" => {
            let encoder = TextEncoder::new();
            let metric_families = prometheus::gather();
            let mut buffer = Vec::with_capacity(1024 * 32);
            encoder.encode(&metric_families, &mut buffer).unwrap();

            let body = Full::new(Bytes::from(buffer));

            let response = Response::builder()
                .status(200)
                .header(hyper::header::CONTENT_TYPE, encoder.format_type())
                .body(body)
                .unwrap();

            Ok(response)
        }
        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Default::default())
            .unwrap()),
    }
}

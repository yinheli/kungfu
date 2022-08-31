use std::{convert::Infallible, net::SocketAddr, str::FromStr};

use hyper::{
    service::{make_service_fn, service_fn},
    Body, Request, Response, StatusCode,
};
use log::warn;
use prometheus::{Encoder, TextEncoder};

pub async fn serve(addr: Option<String>) {
    if addr.is_none() {
        return;
    }

    let addr = SocketAddr::from_str(&addr.unwrap()).unwrap();

    let make_svc = make_service_fn(|_| async { Ok::<_, Infallible>(service_fn(metrics)) });

    if let Err(e) = hyper::Server::bind(&addr).serve(make_svc).await {
        warn!("metrics server error: {:?}", e);
    }
}

async fn metrics(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    match req.uri().path() {
        "/metrics" => {
            let encoder = TextEncoder::new();
            let metric_families = prometheus::gather();
            let mut buffer = vec![];
            encoder.encode(&metric_families, &mut buffer).unwrap();

            let response = Response::builder()
                .status(200)
                .header(hyper::header::CONTENT_TYPE, encoder.format_type())
                .body(Body::from(buffer))
                .unwrap();

            Ok(response)
        }
        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::empty())
            .unwrap()),
    }
}

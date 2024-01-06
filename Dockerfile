FROM rust:1.75-bookworm as builder
WORKDIR /workspace
COPY . .
RUN rustup override set nightly
RUN cargo build --release

FROM debian:bookworm-slim
LABEL org.opencontainers.image.authors "yinheli"
LABEL org.opencontainers.image.source https://github.com/yinheli/kungfu
RUN sed -i 's|deb.debian.org|mirrors.ustc.edu.cn|g' /etc/apt/sources.list && \
    sed -i 's|security.debian.org|mirrors.ustc.edu.cn|g' /etc/apt/sources.list && \
    apt-get update && apt-get install -y iptables
RUN apt-get clean autoclean && apt-get autoremove --yes && rm -rf /var/lib/apt/lists/*
RUN mkdir /app
WORKDIR /app
COPY --from=builder /workspace/target/release/kungfu .
COPY --from=builder /workspace/config config
EXPOSE 53/udp 53/tcp
CMD ./kungfu

FROM rust:1.67.1 as builder
WORKDIR /workspace
COPY . .
RUN rustup override set nightly
RUN cargo build --release

FROM debian:11-slim
LABEL org.opencontainers.image.authors="yinheli"
RUN sed -i 's/deb.debian.org/mirrors.ustc.edu.cn/g' /etc/apt/sources.list && \
    sed -i 's|security.debian.org/debian-security|mirrors.ustc.edu.cn/debian-security|g' /etc/apt/sources.list && \
    apt-get update && apt-get install -y iptables
RUN apt-get clean autoclean && apt-get autoremove --yes && rm -rf /var/lib/apt/lists/*
RUN mkdir /app
WORKDIR /app
COPY --from=builder /workspace/target/release/kungfu .
COPY --from=builder /workspace/config config
EXPOSE 53/udp 53/tcp
CMD ./kungfu
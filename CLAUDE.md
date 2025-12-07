# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

kungfu is a flexible DNS hijacking and proxy tool written in Rust. It provides DNS-based transparent proxying with flexible rule matching, hosts file management, and Prometheus metrics support.

**Key capabilities:**
- DNS server with upstream forwarding
- Transparent proxy gateway using TUN/TAP devices
- Rule-based traffic routing (domain patterns, CIDR, GeoIP)
- Host file management with CNAME and glob pattern support
- Prometheus metrics endpoint

## Build and Development Commands

### Requirements
- **Rust Nightly Toolchain**: This project requires nightly Rust due to the `#![feature(test)]` feature flag
- Install with: `rustup toolchain install nightly && rustup default nightly`

### Common Commands

```bash
# Build the project
cargo build

# Build optimized release binary
cargo build --release

# Run tests (includes benchmarks)
cargo test --benches -- --nocapture

# Test configuration files without starting services
cargo run -- --config config/config.yaml --test

# Run with specific config
cargo run -- --config config/config.yaml

# Lint with clippy
cargo clippy

# Format code
cargo fmt
```

### Cross-compilation
The project supports multiple targets (see `.github/workflows/build.yml`):
- Linux: x86_64, aarch64, arm, armv7, i686 (gnu/musl)
- macOS: x86_64, aarch64

Use `cross` for cross-compilation on Linux targets:
```bash
cross build --release --target aarch64-unknown-linux-musl
```

### Docker
```bash
# Build multi-platform image
docker buildx build --platform linux/amd64,linux/arm64 -t kungfu:latest .

# Run container (requires privileged mode for TUN device)
docker run --privileged -v ./config:/app/config kungfu:latest
```

## Architecture

### Module Structure

```
src/
├── main.rs           # Entry point, runtime setup
├── cli.rs            # Command-line argument parsing
├── logger.rs         # Logging initialization
├── metrics.rs        # Prometheus metrics HTTP server
├── config/           # Configuration management
│   ├── mod.rs
│   ├── setting.rs    # Core config structures (Setting, Proxy, Rule)
│   ├── load.rs       # Config file loading and hot-reload
│   ├── dns_table.rs  # IP address allocation for hijacked domains
│   └── hosts.rs      # Host file parsing with CNAME/glob support
├── dns/              # DNS server implementation
│   ├── mod.rs
│   ├── server.rs     # Main DNS server entry point
│   ├── dns_server.rs # hickory-server based DNS protocol handler
│   └── dns_handler.rs # Custom DNS query handler with rule matching
└── gateway/          # Transparent proxy gateway
    ├── mod.rs
    ├── server.rs     # TUN device setup and packet handling
    ├── nat.rs        # NAT table for connection tracking
    ├── proxy.rs      # SOCKS5 proxy connection management
    └── relay_tcp.rs  # TCP relay between TUN and proxy
```

### Core Architecture Patterns

**Three-Service Model**: The application runs three concurrent services via `tokio::join!`:
1. **DNS Server** (`dns::serve`): Intercepts DNS queries, applies rules, allocates hijack IPs
2. **Gateway Server** (`gateway::serve`): Captures packets from TUN device, performs NAT, proxies traffic
3. **Metrics Server** (`metrics::serve`): Exposes Prometheus metrics on HTTP endpoint

**Configuration Hot-Reload**:
- Uses `notify` crate to watch config files
- Rules and hosts can be reloaded without restart
- Static routes (type: route) require restart

**IP Allocation Strategy** (`dns_table.rs`):
- Allocates IPs from configured network pool (e.g., 10.89.0.1/16)
- Maps hijacked domains to unique IPs for routing
- Uses `moka` cache for fast lookups

**Rule Matching Order** (see `setting.rs`):
1. `ExcludeDomain`: Skip proxy for matching domains
2. `Domain`: Glob pattern matching (e.g., `*google*`)
3. `DnsCidr`: Match upstream DNS response IPs
4. `DnsGeoIp`: Match by GeoIP (TODO: not yet implemented)
5. `Route`: Static CIDR routes (e.g., Telegram IP ranges)

### Concurrency Model

- **Tokio Runtime**: Multi-threaded with CPU-count workers
  - Custom stack size: 256KB per thread
  - Thread name: `kungfu-worker`

- **Rayon Thread Pool**: Parallel processing for rule/pattern matching
  - Thread count: `max(2, num_cpus)`
  - Thread name: `kungfu-rayon`
  - Used in `Rule::match_domain()` and `Rule::match_cidr()` with `.par_iter()`

## Configuration

### Main Config File (`config/config.yaml`)

```yaml
bind: 0.0.0.0           # Bind address for services
dns_port: 53            # DNS server port
dns_upstream:           # Upstream DNS servers
  - 1.2.4.8
  - 114.114.114.114
network: 10.89.0.1/16   # IP pool for hijacked domains
proxy:                  # Named proxy targets
  - name: hk
    values:
      - socks5://127.0.0.1:1082
metrics: 0.0.0.0:6080   # Prometheus metrics endpoint
```

### Rule Files (`config/config.d/*.yaml`)

Rules use glob patterns for domains and CIDR notation for IPs:

```yaml
# Domain-based routing (glob patterns)
- type: domain
  target: hk
  values:
    - "*google*"
    - "*facebook.com"

# Domain exclusions
- type: excludeDomain
  values:
    - "www.googletagmanager.com"

# Static IP routes
- type: route
  target: hk
  values:
    - 91.108.56.0/22

# DNS response CIDR matching
- type: dnsCidr
  target: hk
  values:
    - 39.156.69.79/32
```

### Hosts File (`config/config.d/hosts`)

Enhanced hosts file with CNAME and glob support:

```
192.168.1.20                  my-app.com
cdn.my-app.com.a.bdydns.com.  cdn.my-app.com  # CNAME
192.168.8.20                  *-dev.app.com   # glob pattern
```

## Code Style and Conventions

- **Error Handling**: Use `anyhow::Result` for application errors
- **Async Runtime**: All async code uses Tokio
- **Parallelism**: Use Rayon for CPU-bound parallel operations
- **Logging**: Use `log` crate macros (`info!`, `error!`, etc.)
- **Serialization**: Use `serde` with `#[serde(default)]` for config structs

## Testing and Validation

- Configuration validation: `cargo run -- --config <path> --test`
- Benchmarks are included in test suite: `cargo test --benches -- --nocapture`
- CI runs tests on multiple platforms via GitHub Actions

## Performance Considerations

- **Release Profile**: Highly optimized (`opt-level = 'z'`, LTO, single codegen unit)
- **Caching**: Uses `moka` sync cache for DNS table lookups
- **Parallel Matching**: Rule matching parallelized with Rayon
- **Target Performance**: >120k QPS (as measured on AMD 5600G)

## Deployment

### Grafana Dashboard
Prometheus metrics compatible with dashboard: https://grafana.com/grafana/dashboards/16998-kungfu/

### Privileged Mode Required
Gateway mode requires root/CAP_NET_ADMIN for TUN device creation.

## Important Notes

- **Nightly Rust Required**: Do not remove `#![feature(test)]` or suggest stable alternatives
- **Static Routes Not Hot-Reloadable**: `type: route` rules require service restart
- **GeoIP Not Implemented**: `dnsGeoIp` rule type is defined but not yet functional

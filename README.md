# kungfu

[![build](https://github.com/yinheli/kungfu/actions/workflows/build.yml/badge.svg)](https://github.com/yinheli/kungfu/actions/workflows/build.yml)

Flexible DNS hijacking and proxy tool.

## Features

- Flexible rules eg. glob patten domain, static routes, response CIDR
- Host file include /etc/hosts & custom hosts with cname and glob patten supported
- Observable with prometheus supported (checkout `assets/grafana/kungfu.json`)
- Very fast, above 120k QPS (on my develop environment, AMD 5600G)

## Usage

Please checkout `config` to get started.

# s3mm

`s3mm` is a daemon + CLI agent that replicates S3 objects between clusters under a
configurable **policy engine**. It is built in C++20 on top of libcurl and OpenSSL,
logs exclusively to syslog (RFC 5424), runs under systemd, and keeps all state under
`/var/cache/s3mm`.

## Features

- Registry of clusters and credentials (global vs. per-cluster, cluster wins).
- Named policy bundles of ordered rules with a small DSL (`field op value`,
  `and`/`or`/`not`, `source.`/`destination.` prefixes). Built-in bundles
  `drop-all` and `default`.
- Actions: `accept`, `drop`, `quarantine`, `redirect`, `log`, `set`, `propagate`,
  `pass`. First matching rule wins; three result baskets `denied` / `warning` /
  `success`.
- Delta replication via `ListObjects` + a persistent TSV cache, with size/time
  thresholds and optional S3 Inventory.
- Vendor code only in loadable `.so` modules: `minio`, `aws`, `ceph`, `rustfs`.
- Firewall-style CLI (`s3mm`) with one-shot and `--permanent` mutations,
  `flush-config`, `-t` validation, table/json/yaml output.

## Requirements

- Linux, CMake >= 3.20, a C++20 compiler (tested with g++ 13.3)
- libcurl >= 8.0, OpenSSL >= 3.0
- systemd (runtime)

## Build

```sh
cmake -B build
cmake --build build -j
ctest --test-dir build
```

Binaries: `build/s3mmd`, `build/s3mm`, modules in `build/modules/`.

## Install

```sh
cmake --install build
```

Installs to `/usr/bin`, `/usr/lib/s3mm/modules`, `/etc/s3mm`, `/usr/lib/systemd/system`.

## Quick start

1. Copy `etc/s3mm.conf` to `/etc/s3mm/s3mm.conf` and edit clusters/credentials.
2. `s3mmd -t -c /etc/s3mm/s3mm.conf` — validate.
3. `systemctl enable --now s3mmd`
4. `s3mm status`
5. `s3mm add cluster ...`, `s3mm add replication ...`, `s3mm scan`

## License

Apache License 2.0 — see `LICENSE`.

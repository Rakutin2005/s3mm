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
  thresholds. Object listings are streamed page-by-page, and tags / HTTP
  metadata are re-checked every `metadata_every` interval (default `5m`).
- Full object metadata propagation: `Content-Type`, `Content-Encoding`,
  `Content-Language`, `Content-Disposition`, `Cache-Control`, `Expires`,
  `x-amz-storage-class`, user metadata and object tags.
- `delete_propagation on` mirrors object deletes and bucket deletions. A
  deleted bucket is purged of **all** versions and delete markers (including
  versioned destinations) before the bucket itself is removed.
- Account sync uses MinIO/RustFS `export-iam` (plaintext ZIP) to preserve
  secrets and policy mappings, mirrors direct policies and group memberships,
  and never deletes accounts unless `sync-accounts --prune` is requested.
- Vendor code only in loadable `.so` modules: `minio`, `aws`, `ceph`, `rustfs`.
- Firewall-style CLI (`s3mm`) with one-shot and `--permanent` mutations,
  `flush-config`, `-t` validation, table/json/yaml output.

## REST interface (s3mmws)

`s3mmws` is a separate daemon that exposes the main daemon over HTTP REST. It talks to
`s3mmd` through its UNIX control socket and loads REST-only modules (`.so`) that may
change authentication, request processing and add endpoints. It has no GUI.

```text
s3mmws -c /etc/s3mm/s3mmws.conf -l 127.0.0.1 -p 8080
```

Endpoints: `/health`, `/status`, `/modules`, `/replications`, `/rpc` (POST JSON command).

## Replication semantics

```text
replication photos {
    source minio1;
    destination aws1;
    buckets media*,!media/tmp/*;
    accounts team-*;
    policy default;
    delete_propagation on;
    retention 1h;        # optional delay for object and bucket deletes
    scan_every 5m;
    metadata_every 5m;   # re-read tags/HTTP metadata; 0 disables
}
```

- Bearer credentials are replicated first, then buckets/objects. Bucket
  settings (versioning, policy, tags) are only copied when the bucket policy
  contains `propagate settings=true`.
- `retention` delays delete propagation; a missing bucket is remembered on
  disk (`buckets.deleted`) so a restart does not reset the window.
- Scheduled account sync is non-pruning. Destination-only accounts are removed
  only by an explicit `s3mm sync-accounts <replication> --apply --prune`.
- MinIO `/list-users` response bodies are encrypted by madmin. `s3mm` uses
  `export-iam` for both MinIO and RustFS; if `export-iam` is unavailable, a
  plaintext `list-users` response from an older server is still accepted.

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

1. Copy `etc/s3mm/` to `/etc/s3mm/` and edit clusters/credentials (`s3mmd.d/20-clusters.conf`, `s3mmd.d/25-credentials.conf`).
2. `s3mmd -t -c /etc/s3mm/s3mmd.conf` — validate.
3. `systemctl enable --now s3mmd`
4. `s3mm status`
5. `s3mm add cluster ...`, `s3mm add replication ...`, `s3mm scan`

## License

Apache License 2.0 — see `LICENSE`.

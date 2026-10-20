# Architecture

`s3mm` is split into a static core library (`s3mm_core`), two executables (`s3mmd`,
`s3mm`) and four vendor modules (`s3mm_mod_{minio,aws,ceph,rustfs}`) loaded at
runtime with `dlopen`.

## Layering

```
common -> config -> policy -> s3 -> module -> registry -> replication -> daemon/cli
```

- `common`: strings, units, glob, time, JSON-like `Value`, `Result<T>`, crypto,
  secrets, filesystem, logging (syslog RFC 5424 only).
- `config`: nginx-style parser with `include` (wildcards supported).
- `policy`: attribute context, expression AST, rule/bundle, engine.
- `s3`: path-style HTTP client (libcurl) + SigV4 signer (multipart, UNSIGNED-PAYLOAD).
- `module`: `IModule` interface and `Loader`.
- `registry`: clusters, credentials, replications, targets, settings, mutations, dump.
- `replication`: delta cache, targets, baskets, engine, stats, account sync.
- `daemon` / `cli`: control loop and command-line client.

## Configuration

A single `s3mm { ... }` root block. Entity blocks (`cluster`, `credential`,
`policy`, `replication`, `target`) and settings directives live inside it.
`include` directives are expanded at load time and may appear inside the block.
No sqlite/json stores; the only on-disk state is the delta cache under
`/var/cache/s3mm` and sealed secrets under `/etc/s3mm/secrets`.

## Policy engine

A **bundle** is a named set of rules plus per-category defaults and a route table.
Rules carry a mandatory order number; evaluation is first-match-wins, `pass` rules
fall through. Condition DSL: `field op value` with operators
`= == != < <= > >= ~ !~ in exists`, combined with `and`/`or`/`not`/`()`. Fields
may be prefixed with `source.` / `destination.` (aliases `src.` / `dest.`).

Actions: `accept`, `drop`, `quarantine`, `redirect`, `log`, `set`, `propagate`,
`pass` (`pass` conflicts with `accept`/`drop`). Routing: `accept` -> success,
`drop` -> denied, `quarantine` -> warning, `redirect` -> success to a custom
target. Built-in bundles: `drop-all`, `default`.

## Replication

A scheduler ticks every 500 ms: `scanDue` -> `scanQueued` (CAS) -> worker pool.
`worker_count = 0` means one dedicated worker per policy. The first scan of a
bucket is full; later scans are deltas (`ListObjects` + persistent TSV cache under
`/var/cache/s3mm`). Thresholds (queue size/time, min size, max disk) decide when
a batch ships. Delete propagation uses tombstones with retention. A circuit
breaker trips per cluster; queue overflow produces a warning + log.

## Secrets

AES-256-GCM with PBKDF2 (100k iterations), stored as
`-----BEGIN S3MM SECRET-----` PEM blocks. Global credentials are usable on any
cluster; a credential bound to a cluster overrides the global one.

## Daemon / CLI protocol

Newline-delimited JSON over a Unix socket, one request per connection. Responses
are `{"ok":true,"data":...}` or `{"ok":false,"error":...}`. Mutations stop the
engine, apply the change, refresh state and restart it. Audit records go to syslog
with the `audit` topic. `SIGHUP` reloads configuration, `SIGUSR1` kicks a scan.

## Vendor modules

Vendor code lives only in `.so` files implementing `s3mm_module_entry()`.
Feature sets differ: MinIO (full CRUD + admin SigV4 on service `s3`, empty
region), AWS (inventory), Ceph (ACL/versioning), RustFS (bucket policy).
All data-plane traffic is path-style.

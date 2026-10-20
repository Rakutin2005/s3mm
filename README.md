# s3mm — S3 replication, mirroring and migration agent

`s3mm` is a Linux daemon (`s3mmd`) plus a command-line client (`s3mm`) that
continuously replicates objects between S3-compatible storage clusters
(AWS S3, MinIO, Ceph RGW, RustFS — the latter three via loadable modules).

The daemon scans source clusters, classifies everything it finds
(objects, buckets, accounts, deletes) with a rule-based policy, and ships
the results to a destination cluster and/or to audit targets (files,
quarantine, webhooks). Replication is incremental: every bucket keeps a
local snapshot cache, so a scan only transfers what actually changed.

```
source cluster ──scan──▶ snapshot diff ──policy rules──▶ routes
                              │                ├─ success    → destination cluster (1:1 copy)
                              │                ├─ denied     → null / quarantine / audit
                              │                └─ warning    → quarantine / audit
                              └─ delta cache (per bucket, TSV)
```

## Features

- **Replication / mirroring / migration** between S3 clusters, including
  bucket-level and account-level scoping, account (STS user) sync, and
  delete propagation with configurable retention.
- **Rule-based policy engine** — per-replication rule lists with conditions on
  object/bucket/account metadata (`size`, `tags`, `prefix`, `owner`,
  `versioning`, …), negation, `in` lists, `exists` checks and `match`
  glob matching, over actions `accept`, `drop`, `redirect`, `log`,
  `reject`, `quarantine`, `alert`.
- **Flexible targets** for classified records: the destination S3 cluster
  (implicit 1:1 route), append-only JSONL files, JSONL directories,
  HTTP(S) webhooks, or an internal "null" sink. Custom targets are addressed
  from rules via `redirect <target>`.
- **Incremental by design** — per-bucket snapshot cache (TSV), size/delta
  thresholds (`min_size`, `queue` batching by size/time, skip when the
  destination copy is already newer), so re-scans are cheap.
- **Pluggable S3 backends** — native SigV4 client (AWS, MinIO, Ceph, RustFS
  and anything API-compatible) with unsigned-payload support; vendor-specific
  behaviour is isolated in `dlopen`-ed modules (`s3mm_module_entry()`).
- **Secrets at rest** — access keys/secret keys can be stored sealed in the
  config (`-----BEGIN S3MM SECRET-----` PEM blocks), encrypted with
  AES-256-GCM using a master key derived via PBKDF2-HMAC-SHA256.
- **Operations-friendly** — unix-socket control API (newline JSON),
  `s3mm` CLI with human, `--json` and `--yaml` output, Prometheus metrics
  endpoint, RFC 5424 syslog audit records, hot `reload` without dropping
  in-flight work, graceful drain on `SIGTERM`, `--run-once` mode for cron.
- **Safe by default** — atomic config file writes, backups of the previous
  config, audit trail of every mutation, socket permissions 0660.

## Requirements

- Linux
- CMake ≥ 3.20
- g++ with C++20 support (tested with GCC 13)
- libcurl (HTTP/S3 transport)
- OpenSSL (SigV4 signing, AES-GCM secret sealing, SHA-256)
- systemd (optional, for the provided service unit; not required to build)
- pthreads / dl (standard on Linux)

Debian/Ubuntu example:

```sh
sudo apt install build-essential cmake libcurl4-openssl-dev libssl-dev
```

## Building

```sh
cmake -B build
cmake --build build -j
```

Build artifacts:

| Path                       | What it is                                   |
|----------------------------|----------------------------------------------|
| `build/s3mmd`              | the daemon                                   |
| `build/s3mm`               | the CLI client                               |
| `build/modules/*.so`       | S3 backend modules (`minio`, `aws`, `ceph`, `rustfs`) |

Run the test suite:

```sh
ctest --test-dir build
```

Install (daemon, CLI, modules, configs and the systemd unit):

```sh
sudo cmake --install build
```

This installs to `/usr/local` by default; use `CMAKE_INSTALL_PREFIX` to
change it. On a distribution-style install:

```sh
cmake -B build -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_INSTALL_SYSCONFDIR=/etc
sudo cmake --install build
```

## Quick start

1. **Create the config set** (see `etc/` for annotated examples):

   - `etc/s3mm.conf` — daemon settings (socket, cache, metrics, modules);
   - `etc/clusters.conf` — S3 endpoints and credentials;
   - `etc/credentials.conf` — access/secret keys (optionally sealed);
   - `etc/replications.conf` — what replicates where, queues, retention;
   - `etc/policies.conf` — rule bundles (`accept`, `drop`, `redirect` …).

   `s3mm.conf` pulls the other files in with `include` directives — all
   entity blocks (`cluster`, `credential`, `policy`, `replication`, `target`)
   live inside the `s3mm { … }` block.

2. **Start the daemon** (foreground check first):

   ```sh
   build/s3mmd -c etc/s3mm.conf -d /var/cache/s3mm -t
   ```

   `-t` validates the configuration and exits; drop it to run.

3. **Talk to it with the CLI** (works offline against the config files when
   the daemon is not running):

   ```sh
   build/s3mm status                    # daemon + replication state
   build/s3mm replication list          # configured replications
   build/s3mm scan --replication main   # trigger a scan
   build/s3mm config check              # validate the config
   build/s3mm config show -o yaml       # effective registry as YAML
   ```

   Full command reference: [`docs/cli.md`](docs/cli.md).

4. **Install as a service** (after `sudo cmake --install build`):

   ```sh
   sudo systemctl enable --now s3mmd
   ```

5. **Observe it**:

   - `curl http://127.0.0.1:9108/metrics` — Prometheus metrics (`s3mm_*`);
   - `journalctl -u s3mmd` — logs; audit records go to syslog with
     `topic=audit`;
   - `build/s3mm rules test --bundle <name> --kind object --bucket b --key k`
     — dry-run a policy rule against test metadata.

## Documentation

- [`docs/architecture.md`](docs/architecture.md) — components, data flow,
  configuration model, control protocol.
- [`docs/cli.md`](docs/cli.md) — `s3mm` command-line reference.
- [`etc/`](etc/) — annotated example configuration.
- [`systemd/s3mmd.service`](systemd/s3mmd.service) — hardened service unit.

## Configuration at a glance

The config syntax is nginx-like: directives end with `;`, blocks with `{ }`,
comments are `#` or `//`, and `include` supports wildcards. Example —
a complete, minimal replication:

```nginx
s3mm {
    socket  /run/s3mm/s3mm.sock;
    cache_dir /var/cache/s3mm;

    include credentials.conf;
    include clusters.conf;
    include policies.conf;
    include replications.conf;
}
```

```nginx
# credentials.conf
credential minio-creds {
    access_key "minioadmin";
    secret_key "minioadmin";
}

# clusters.conf
cluster minio-src {
    endpoint "http://127.0.0.1:9001";
    region   "us-east-1";
    credential minio-creds;
    tls_verify off;
}

cluster minio-dst {
    endpoint "http://127.0.0.1:9002";
    region   "us-east-1";
    credential minio-creds;
    tls_verify off;
}

# policies.conf
policy all-accept {
    default_action accept;
    default_route  success;
}

# replications.conf
replication main {
    source      minio-src;
    destination minio-dst;
    buckets     "photos", "backups";
    policy      all-accept;
    scan_every  5m;
    queue {
        size     1G;
        time     5m;
        min_size 1M;
    }
}
```

> **Note on layout**: entity blocks must be *inside* `s3mm { … }` (typically
> pulled in by `include`), and `credential` blocks must appear before the
> `cluster` blocks that reference them — credentials are validated when the
> referencing cluster is added.

## License

Apache License 2.0 — see [LICENSE](LICENSE).

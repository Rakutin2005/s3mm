---
name: s3mm Project
description: Work on the s3mm C++20 S3 replication daemon, CLI, REST daemon, cluster client, event broker, modules, and React web UI. Use when building, testing, debugging, or extending this repository.
---

# s3mm project skill

## Overview

`s3mm` is a C++20 daemon + CLI that replicates S3 objects between clusters under a policy engine. Core is a static library `s3mm_core`; vendor code lives only in loadable `.so` modules.

Main components:
- `s3mmd` — daemon (`src/daemon`)
- `s3mm` — CLI client (`src/cli`)
- `s3mmws` — REST daemon (`src/rest`)
- `s3mmc` — cluster client / peer mesh (`s3mmc/`)
- `s3mme` — event broker client (`s3mme/`) with Kafka/RabbitMQ modules
- modules: `modules/{minio,aws,ceph,rustfs,kafka,rabbitmq}`
- web UI: `/home/aigol/WebstormProjects/s3mmui` (React 19 + Vite + Ant Design)

## Build

```sh
cmake -B build
cmake --build build -j
ctest --test-dir build
```

Binaries: `build/s3mmd`, `build/s3mm`, `build/s3mmws`, `build/s3mmc`, modules in `build/modules/`. `s3mme` is built as `build/s3mme`.

Dependencies: CMake >= 3.20, C++20, libcurl >= 8.0, OpenSSL >= 3.0, argon2, zlib, Threads. Logging is syslog RFC 5424 only.

## Architecture and layering

`common -> config -> policy -> s3 -> module -> registry -> replication -> daemon/cli/rest/cluster`

- Config: nginx-style parser with `include` (wildcards), single `s3mm { ... }` root.
- Policy engine: bundles of ordered rules, first-match-wins, `pass` falls through; DSL `field op value`, `and/or/not`, `source.`/`destination.` prefixes. Built-ins `drop-all`, `default`.
- S3 client: libcurl path-style + SigV4.
- Modules: implement `IModule` / `IAdminProvider`; vendor specifics only in `.so`.
- State/cache: `/var/cache/s3mm` (delta TSV cache, deleted buckets). No SQLite/JSON stores.

## Conventions

- Headers in `include/s3mm/...`; implementation in `src/...`.
- Use `Result<T>` and `Value` from common.
- English only in code, CLI, and logs.
- Firewall-style CLI mutations: one-shot by default; `--permanent` persists; `flush-config` writes runtime config.
- Daemon/CLI protocol: newline-delimited JSON over Unix socket.

## Tests

- Unit: `tests/unit/` (engine, policy, config, cache, sigv4, etc.)
- E2E: `tests/e2e/` (fake S3 server)
- Run: `ctest --test-dir build`

## Known build issues (as of review)

- Build is green; s3mme is integrated.
- `etc/secrets/*` contains committed keys/certs; treat as test fixtures only.

## Web UI

Path: `/home/aigol/WebstormProjects/s3mmui`. Stack: React 19, Vite 8, Ant Design 6, React Query, Zustand, ReactFlow, Oxlint. No TypeScript. Dev: `npm run dev`, build: `npm run build`, lint: `npm run lint`.

## Useful commands

```sh
s3mmd -t -c /etc/s3mm/s3mm.conf   # validate
s3mmd -c /etc/s3mm/s3mm.conf -d   # daemonize
s3mm status
s3mm -t
```

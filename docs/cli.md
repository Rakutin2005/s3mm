# CLI reference

`s3mm` is a one-shot client by default; it connects to the daemon over a Unix
socket. Configuration commands (`add`/`edit`/`rm`/`rule`) also work offline by
writing directly to the configuration files (with a warning on stderr).

## Global options

| Option | Meaning |
|---|---|
| `-c, --config <file>` | configuration file (default `/etc/s3mm/s3mmd.conf`) |
| `-s, --socket <path>` | control socket (`$S3MM_SOCKET`, then the config `socket`, then `/run/s3mm/s3mm.sock`) |
| `-o, --output <fmt>` | `table` (default), `json`, `yaml` |
| `--permanent` | write changes back to the configuration files |
| `-t, --test` | validate the configuration and exit |
| `-h, --help` | help |
| `-V, --version` | version |

Exit codes: `0` success, `1` error, `2` usage error.

## Commands

- `status`, `ping`, `modules`
- `list <kind> [policy]` — `cluster|credential|replication|target|policy|rule|settings`
- `show <kind> <name>`
- `add <kind> <name> [key=value ...]`
- `edit <kind> <name> [key=value ...]`
- `rm <kind> <name>`
- `rule list <policy>` / `rule add <policy> <rule>` (`--before`/`--after <ref>`) /
  `rule edit <policy> <ref> <rule>` / `rule rm <policy> <ref>`
- `policy list|show|add|edit|rm ...` (shorthand)
- `replication list|show`, `replication period <name> <dur>`,
  `replication queue [name]`, `replication scan|flush [name]`
- `stat [replica]`, `queues [replica]`, `routes [replica] [--limit N]`
  (`routes` shows the policy-routing decisions of the local engine — success/
  denied/warning outcomes; cluster mesh routing lives in s3mmc, not here)
- `scan [replica] [--async|--force]`, `flush [replica]`
- `sync-accounts <replication> [--apply] [--prune]` (dry-run unless `--apply`).
  Without `--prune` accounts are only created/updated; `--prune` also removes
  destination-only accounts. Scheduled replication account sync never prunes.
- `rescan [replica]`, `reset-stats [replica]`, `reload`
- `validate`, `flush-config`
- `check [cluster]` — availability of the clusters: every `addr` gets a
  ListBuckets with the cluster credential (OK / AUTH/ERROR / DOWN), every
  `admin_endpoint` of a managed cluster is checked for an HTTP answer. Asks
  s3mmd; when it is not running the check runs locally from the configuration.
  Exit status 1 when a cluster has no working data endpoint.

## S3 client

`s3mm s3 ...` talks to a cluster of the configuration directly (endpoints and
credentials are read from the config file, s3mmd is not needed):

| Command | |
|---|---|
| `s3 info <cluster> [--no-count]` | availability, buckets, object counts and sizes |
| `s3 ls <cluster>` | buckets |
| `s3 ls <cluster> <bucket>[/<prefix>] [-r] [--limit N]` | objects (`-r`: recursive) |
| `s3 stat <cluster> <bucket>/<key>` | object metadata |
| `s3 get <cluster> <bucket>/<key> [<file>\|-]` | download (default `./<basename>`, `-` = stdout) |
| `s3 put <cluster> <file> <bucket>[/<key>] [--content-type T]` | upload (multipart above `part_size`) |
| `s3 rm <cluster> <bucket>/<key>` | delete an object |
| `s3 mb <cluster> <bucket>` / `s3 rb <cluster> <bucket> [--force]` | create / delete a bucket (`--force` empties it first) |

## Rule syntax

```
[order] [name=<rule>] [acl|bucket|object] <condition> action <actions...>
```

Example: `100 name=big object source.size >= 1M action accept log`

Conditions use `= == != < <= > >= ~ !~ in exists`, `and`/`or`/`not`, `()`,
and `source.`/`destination.` prefixes. Actions: `accept drop quarantine redirect
log set propagate pass`.

## Daemon

`s3mmd -c <config> [-d] [-t] [--run-once] [-h] [-V]`.

- `-d` daemonizes.
- `-t` validates and exits.
- `--run-once` runs a single replication cycle and exits.
- `SIGHUP` reloads configuration; `SIGUSR1` kicks a scan.

## Metrics

When `metrics` is set, `GET /metrics` on that address returns Prometheus text
(`s3mm_*`). `stat`/`queues`/`routes` accept `--replica`, `--cluster`, `--json`.

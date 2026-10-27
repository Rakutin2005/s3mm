#pragma once
// s3mmc.conf parsing — reuses the core nginx-style config parser.
//
//   node zeta1;                       # optional; default: CN of the cert / hostname
//   run_dir /var/run/s3mmc;
//   core_socket /run/s3mm/s3mm.sock;  # s3mmd control socket
//   listen 0.0.0.0:9443;              # peer mTLS endpoint ("*" allowed for any)
//   tls {                             # mTLS material for all peer sessions
//       cert /etc/s3mmc/tls/node.crt;
//       key  /etc/s3mmc/tls/node.key;
//       ca   /etc/s3mmc/tls/ca.crt;   # empty => verification off (tests only)
//   }
//   inventory push|pull;              # periodic exchange model for state snapshots
//                                     # ("both" is accepted as a no-op alias:
//                                     #  the channel is always logically bidirectional)
//   poll_interval 60s;                # polling cadence
//   poll_timeout 15s;
//   core_timeout 300s;
//   spool_threshold 1MiB;
//   managed s3c-2;                    # node(s) allowed to manage this one: patch our
//                                     # config, request credentials. Comma-separated
//                                     # list, "*", or "none" (default). Identity of a
//                                     # manager = CN of its mTLS certificate == peer id.
//   expose_credentials on;            # additionally let ANY connected peer pull S3
//                                     # credentials over the cluster channel (off by
//                                     # default; managers may pull them regardless)
//   log {                             # optional syslog settings (RFC 5424)
//       level info;                   # debug | info | notice | warning | error | crit
//       facility daemon;
//       socket /dev/log;
//   }
//   peer omega {                      # id == remote cluster namespace of that node
//       address 10.0.0.2:9443;
//       connect on;                   # on: WE dial it (we are the initiator);
//                                     # off: it dials us (passive side)
//   }
#include <optional>
#include <string>
#include <vector>

#include "s3mm/clusterclient.hpp"
#include "s3mm/common/log.hpp"
#include "s3mm/common/result.hpp"

namespace s3mm::s3mmc {

/// When `logOut` is given and the configuration has a `log { }` block, it
/// receives the resulting syslog options (ident "s3mmc").
Result<void> applyConfigText(ClusterClient& client, const std::string& text,
                             const std::string& filename,
                             std::optional<log::Options>* logOut = nullptr);
Result<void> applyConfigFile(ClusterClient& client, const std::string& path,
                             std::optional<log::Options>* logOut = nullptr);

/// Parse a `managed` value ("none" | "*" | comma/space separated ids) into a
/// normalised list. "*" => ["*"], "none"/empty => [].
Result<std::vector<std::string>> parseManagedList(const std::string& spec);

} // namespace s3mm::s3mmc

#pragma once
#include <string>

#include "s3mm/common/result.hpp"
#include "s3mm/rest/daemon.hpp"

namespace s3mm::rest {

/// Standalone parser for the s3mmws configuration file.
///
/// s3mmws must NOT read /etc/s3mm/s3mm.conf (that belongs to s3mmd). It has
/// its own nginx-style file, by default /etc/s3mm/s3mmws.conf:
///
///   s3mmws {
///       socket      /run/s3mm/s3mmd.sock;     # core daemon control socket
///       modules_dir /usr/lib/s3mm/modules;    # REST modules (.so) directory
///       listen      127.0.0.1;                # HTTP bind address
///       port        8080;                     # HTTP port
///
///       auth_enabled on;
///       session_ttl  3600;
///       rbac_store   /var/cache/s3mm/s3mmws_rbac.json;
///       users_file   /var/cache/s3mm/s3mmws_users.json;
///
///       auth {
///           local    { enabled on; users_file ...; }
///           ldap     { enabled off; url ...; bind_dn ...; ... }
///           keycloak { enabled off; issuer ...; client_id ...; ... }
///       }
///
///       wscluster {
///           enabled on; bind 0.0.0.0; port 9443;
///           use_mtls on; certs_dir /etc/s3mm/secrets/cluster;
///           cluster_secret ...;
///       }
///   }
///
/// Command-line options always win over file values (CLI overrides what is
/// explicitly set; file fills in the rest). `include` directives are expanded
/// recursively, same as in the core config format.
class WsConfig {
public:
    /// Parse the given file and apply it onto `options` (without clobbering
    /// values that were already set from the command line). On success returns
    /// the resolved options; on failure returns a human readable error.
    static Result<Options> apply(const std::string& path, const Options& base);

    /// Validate only: parse + report errors, no side effects.
    static Result<bool> validate(const std::string& path);
};

}  // namespace s3mm::rest

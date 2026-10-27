#pragma once
#include <string>
#include <vector>

#include "s3mm/cli/commands.hpp"

namespace s3mm::cli {

/// `s3mm s3 <ls|stat|get|put|rm|mb|rb|info> ...`: direct S3 access to a
/// cluster of the configuration (credentials and endpoints from the config).
int runS3(const Options& opts, const std::vector<std::string>& rest);

/// `s3mm check [cluster]`: availability check through s3mmd, or directly from
/// the configuration when the daemon is not running.
int runCheck(const Options& opts, const std::vector<std::string>& rest, const std::string& socket);

} // namespace s3mm::cli

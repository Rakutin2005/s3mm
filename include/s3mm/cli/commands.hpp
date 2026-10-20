#pragma once
#include <string>
#include <vector>

#include "s3mm/cli/render.hpp"

namespace s3mm::cli {

/// Global options collected before the command is parsed.
struct Options {
    std::string config = "/etc/s3mm/s3mm.conf";
    std::string socket; // empty: $S3MM_SOCKET → config settings.socket → default
    Format format = Format::Table;
    bool permanent = false; // ask the daemon to write changes back to config
    bool test = false;      // -t: validate configuration and exit
};

/// Runs one command line (global options already stripped).
/// Returns the process exit code; throws UsageError/Error on failure.
int runCommand(const Options& opts, const std::vector<std::string>& args);

/// Complete help text (English).
std::string usage();

} // namespace s3mm::cli

#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace s3mm::str {

std::string trim(std::string_view s);
std::string ltrim(std::string_view s);
std::string rtrim(std::string_view s);

/// Split on a single delimiter, no quoting awareness.
std::vector<std::string> split(std::string_view s, char delim, bool keepEmpty = true);
/// Split on any whitespace; respects single and double quotes (quotes removed).
std::vector<std::string> splitWS(std::string_view s);
/// Split "a,b,c" honouring quotes; used for CLI list flags.
std::vector<std::string> splitList(std::string_view s);
/// Tokenize a command line: shell-like quoting with ' " and backslash escapes.
std::vector<std::string> tokenize(std::string_view s);

std::string join(const std::vector<std::string>& parts, std::string_view sep);

std::string toLower(std::string_view s);
std::string toUpper(std::string_view s);

bool startsWith(std::string_view s, std::string_view prefix);
bool endsWith(std::string_view s, std::string_view suffix);
bool iequals(std::string_view a, std::string_view b);

std::string replaceAll(std::string s, std::string_view from, std::string_view to);

/// Escape a string as a JSON string body (without surrounding quotes).
std::string escapeJson(std::string_view s);
/// Quote a string for shell-like output (round-trips through tokenize()).
std::string quoteShell(std::string_view s);
/// Escape for a YAML double-quoted scalar.
std::string escapeYaml(std::string_view s);

/// Left-pad to width (table rendering).
std::string padRight(std::string_view s, size_t width);
std::string padLeft(std::string_view s, size_t width);

std::optional<int64_t> parseInt64(std::string_view s);
std::optional<double> parseDouble(std::string_view s);

/// Expand ${VAR} and $VAR from the environment. Unknown variables expand to empty.
std::string expandEnv(std::string_view s);

} // namespace s3mm::str

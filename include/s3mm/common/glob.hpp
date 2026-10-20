#pragma once
#include <string>
#include <string_view>
#include <vector>

namespace s3mm::glob {

/// Shell-style glob with '*' and '?' (no character classes, no path semantics).
bool match(std::string_view pattern, std::string_view value);

/// Any of the patterns matches. Patterns starting with '!' are negations:
/// returns false if a negation matches, otherwise true if at least one positive
/// pattern matches (or there are no positive patterns at all).
bool matchFilter(const std::vector<std::string>& patterns, std::string_view value);

/// Convenience: split "a,b,!c*" into filter list.
bool matchFilterList(std::string_view patterns, std::string_view value);

/// Expand a glob against the filesystem; returns sorted paths.
std::vector<std::string> expand(std::string_view pattern);

} // namespace s3mm::glob

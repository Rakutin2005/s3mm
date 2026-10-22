#pragma once
#include <optional>
#include <string>
#include <vector>

#include "s3mm/common/result.hpp"

namespace s3mm::config {

/// One directive or block from an nginx-style configuration file.
///
///   cluster s3-cluster-1 {          <- block (name="cluster", args=["s3-cluster-1"])
///       addr https://10.0.0.1:9000; <- directive (name="addr", args=["https://..."])
///       include clusters.d/*.conf;  <- include directive, expanded at load time
///   }
class Node {
public:
    std::string name;
    std::vector<std::string> args;
    std::vector<Node> children;
    std::string file;
    int line = 0;
    bool block = false;

    bool hasArg(size_t i) const { return i < args.size(); }
    const std::string& arg(size_t i) const;
    /// Argument or empty string.
    std::string argOr(size_t i, const std::string& fallback = {}) const;
    /// Argument or ConfigError.
    std::string argRequired(size_t i) const;
    size_t argCount() const { return args.size(); }

    const Node* find(const std::string& childName) const;
    std::vector<const Node*> findAll(const std::string& childName) const;
    /// First child directive with the given name and enough args.
    const Node* findWith(const std::string& childName, size_t minArgs) const;

    /// Single-valued helper: value of `name <value>;` inside this block.
    std::string value(const std::string& directive, const std::string& fallback = {}) const;
    /// Same but throws ConfigError when missing.
    std::string valueRequired(const std::string& directive) const;
    bool boolValue(const std::string& directive, bool fallback) const;
    /// Parse this directive's own first argument as a boolean flag
    /// (`path_style off;`, `delete_propagation on;`, ...).
    bool boolFlag(bool fallback) const;
    int64_t int64Value(const std::string& directive, int64_t fallback) const;

    /// Re-render this subtree back into s3mm.conf syntax (used by `s3mm flush-config`).
    std::string dump(int indent = 0) const;
    /// "name arg1 arg2"
    std::string str() const;

    bool findName(const std::string& childName) const { return find(childName) != nullptr; }
};

/// Parsed configuration of the whole process (one root "s3mm" block plus any
/// top-level directives that were inlined by include).
class Config {
public:
    /// Load a file, expanding `include` directives recursively.
    static Result<Config> load(const std::string& path);
    /// Parse from memory (tests / stdin).
    static Result<Config> parse(const std::string& text, const std::string& filename = "<memory>");

    const Node* s3mm() const { return s3mm_; }
    /// All top-level nodes (the "s3mm" root plus included fragments).
    const std::vector<Node>& roots() const { return roots_; }

    /// Validate well-formedness: known directives per block, unique names, references.
    /// Returns human readable errors; empty vector means OK.
    std::vector<std::string> validate() const;

    /// Serialize the whole configuration back to text.
    std::string dump() const;

    const std::string& path() const { return path_; }

private:
    std::vector<Node> roots_;
    const Node* s3mm_ = nullptr;
    std::string path_;
};

} // namespace s3mm::config

#pragma once
#include <string>
#include <vector>

#include "s3mm/common/value.hpp"
#include "s3mm/policy/rule.hpp"
#include "s3mm/registry/registry.hpp"

namespace s3mm::registry {

// ---------------------------------------------------------------- fields ----
// Helpers that read a field from a JSON request (`req`) or its nested
// `"fields"` object. Values may be JSON scalars or plain strings; strings are
// parsed lazily (units, durations, booleans, comma lists).

const Value& fieldsOf(const Value& req);
bool has(const Value& f, const std::string& k);
std::string fstr(const Value& f, const std::string& k, const std::string& def = {});
bool fbool(const Value& f, const std::string& k, bool def);
int64_t fint(const Value& f, const std::string& k, int64_t def);
double fdouble(const Value& f, const std::string& k, double def);
/// Size with unit suffixes: "512k", "10M", "1g".
uint64_t fsize(const Value& f, const std::string& k, uint64_t def);
/// Duration in seconds: "30s", "5m", "1h".
int64_t fdur(const Value& f, const std::string& k, int64_t defSec);
/// Scalar or JSON array or comma list.
std::vector<std::string> flist(const Value& f, const std::string& k);

/// Plural/synonym kind names: clusters→cluster, policies→policy, bundles→policy …
std::string normKind(std::string k);

/// One action from text: `name [positional] [key=value ...]`.
policy::Action parseActionText(const std::string& text);

/// Build a Value object from `key=value` strings (CLI arguments).
Value parseFields(const std::vector<std::string>& kv);

// ----------------------------------------------------------- serialisation ---

Value clusterValue(const Cluster& c);
Value credentialValue(const Credential& c);
Value replicationValue(const Replication& r);
Value targetValue(const Target& t);
Value settingsValue(const Settings& s);
Value actionValue(const policy::Action& a);
Value ruleValue(const policy::Rule& r);
Value bundleValue(const policy::Bundle& b, bool withRules);

// -------------------------------------------------------------- mutations ----

/// Apply one `add`/`edit`/`rm` mutation (`kindRaw` is normalised via normKind).
/// Credential secrets are materialised into <secretsDir>/<name> (0400), sealed
/// with the master key when one is configured.
/// Throws Error/UsageError; returns the resulting entity, or {"removed":true}.
Value mutateEntity(Registry& r, const std::string& cmd, const std::string& kindRaw,
                   const std::string& name, const Value& fields);

/// Apply a `rule` command: action=list returns the bundle's rules, add/edit/rm
/// mutate it (add/edit need `line`, add honours before/after; edit/rm need
/// `ref`). Throws Error/UsageError.
Value applyRule(Registry& r, const std::string& action, const std::string& bundleName,
                const std::string& ref, const std::string& line, const std::string& before,
                const std::string& after);

} // namespace s3mm::registry

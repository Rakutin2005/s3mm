#pragma once
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "s3mme/broker.hpp"
#include "s3mm/common/result.hpp"

namespace s3mme {
template<class T> using Result = s3mm::Result<T>;

/// dlopen-based loader for broker modules (s3mme_mod_*.so). Same idea as the
/// core vendor-module loader, but resolves `s3mme_broker_entry` instead of
/// `s3mm_module_entry`.
class BrokerLoader {
public:
    BrokerLoader() = default;
    ~BrokerLoader();
    BrokerLoader(const BrokerLoader&) = delete;
    BrokerLoader& operator=(const BrokerLoader&) = delete;

    Result<void> loadFile(const std::string& path);
    /// Load every *.so in a directory (non-recursive).
    Result<void> loadDir(const std::string& dir);
    /// $S3MME_MODULE_PATH, /usr/lib/s3mme/modules, /usr/local/lib/s3mme/modules, ./modules.
    Result<void> loadDefaults();

    IBroker* find(const std::string& name) const;
    std::vector<std::string> names() const;

private:
    std::map<std::string, IBroker*> byName_;
    std::vector<std::pair<void*, IBroker*>> loaded_; // handle -> broker
};

} // namespace s3mme

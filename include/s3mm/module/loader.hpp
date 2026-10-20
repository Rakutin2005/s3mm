#pragma once
#include <map>
#include <string>
#include <vector>

#include "s3mm/common/result.hpp"
#include "s3mm/module/module.hpp"

namespace s3mm::module {

/// dlopen-based module registry.
class Loader {
public:
    Loader() = default;
    ~Loader();
    Loader(const Loader&) = delete;
    Loader& operator=(const Loader&) = delete;

    /// Load every *.so in a directory (non-recursive).
    Result<void> loadDir(const std::string& dir);
    Result<void> loadFile(const std::string& path);
    /// Load from the default search path: $S3MM_MODULE_PATH, /usr/lib/s3mm/modules,
    /// /usr/local/lib/s3mm/modules and ./modules.
    Result<void> loadDefaults();

    IModule* find(const std::string& name) const;
    std::vector<IModule*> modules() const;
    std::vector<std::string> names() const;

private:
    std::map<std::string, IModule*> byName_;
    std::vector<std::pair<void*, IModule*>> loaded_; // handle -> module
};

} // namespace s3mm::module

#pragma once
#include <map>
#include <string>
#include <vector>

#include "s3mm/common/result.hpp"
#include "s3mm/rest/module.hpp"

namespace s3mm::rest {

class RestModuleLoader {
public:
    ~RestModuleLoader();
    /// Load the module `name` from `path`, or from <modulesDir>/s3mmws_mod_<name>.so.
    Result<IRestModule*> loadModule(const std::string& name, const std::string& path, const std::string& modulesDir);
    Result<void> loadFile(const std::string& path);
    std::vector<IRestModule*> modules() const;
private:
    std::vector<std::pair<void*, IRestModule*>> loaded_;
};

} // namespace s3mm::rest

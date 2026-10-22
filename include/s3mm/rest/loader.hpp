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
    Result<void> loadDir(const std::string& dir);
    Result<void> loadFile(const std::string& path);
    std::vector<IRestModule*> modules() const;
private:
    std::vector<std::pair<void*, IRestModule*>> loaded_;
};

} // namespace s3mm::rest

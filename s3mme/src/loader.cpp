#include "s3mme/loader.hpp"

#include <cstdlib>
#include <dlfcn.h>

#include "s3mm/common/fs.hpp"
#include "s3mm/common/log.hpp"
#include "s3mm/common/str.hpp"

namespace s3mme {

BrokerLoader::~BrokerLoader() {
    for (auto& [handle, broker] : loaded_) {
        delete broker;
        if (handle) dlclose(handle);
    }
}

Result<void> BrokerLoader::loadFile(const std::string& path) {
    void* handle = dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (!handle) return Result<void>::failure("cannot load broker module " + path + ": " + dlerror());
    auto entry = reinterpret_cast<CreateBrokerFn>(dlsym(handle, "s3mme_broker_entry"));
    if (!entry) {
        dlclose(handle);
        return Result<void>::failure("module " + path + " has no s3mme_broker_entry() symbol");
    }
    IBroker* broker = entry();
    if (!broker) {
        dlclose(handle);
        return Result<void>::failure("module " + path + " returned null");
    }
    std::string name = broker->name() ? broker->name() : "unknown";
    if (byName_.count(name)) {
        delete broker;
        dlclose(handle);
        return Result<void>::failure("broker '" + name + "' already loaded (" + path + ")");
    }
    byName_[name] = broker;
    loaded_.emplace_back(handle, broker);
    LOG_INFO("loaded broker module ", name, " from ", path);
    return Result<void>::success();
}

Result<void> BrokerLoader::loadDir(const std::string& dir) {
    std::string lastError;
    bool any = false;
    for (const auto& entry : fs::listDir(dir)) {
        if (!str::endsWith(entry, ".so")) continue;
        auto res = loadFile(fs::joinPath(dir, entry));
        if (!res) {
            lastError = res.error();
            LOG_WARN("broker load failed: ", res.error());
            continue;
        }
        any = true;
    }
    if (!any && !lastError.empty()) return Result<void>::failure(lastError);
    return Result<void>::success();
}

Result<void> BrokerLoader::loadDefaults() {
    std::vector<std::string> dirs;
    if (const char* env = std::getenv("S3MME_MODULE_PATH")) dirs.push_back(env);
    dirs.push_back("/usr/lib/s3mme/modules");
    dirs.push_back("/usr/local/lib/s3mme/modules");
    dirs.push_back("./modules");
    std::string lastError;
    bool any = false;
    for (const auto& d : dirs) {
        if (!fs::exists(d)) continue;
        auto res = loadDir(d);
        if (res) any = true;
        else lastError = res.error();
    }
    if (!any && !lastError.empty()) return Result<void>::failure(lastError);
    return Result<void>::success();
}

IBroker* BrokerLoader::find(const std::string& name) const {
    auto it = byName_.find(name);
    return it == byName_.end() ? nullptr : it->second;
}

std::vector<std::string> BrokerLoader::names() const {
    std::vector<std::string> out;
    for (const auto& [n, b] : byName_) out.push_back(n);
    return out;
}

} // namespace s3mme

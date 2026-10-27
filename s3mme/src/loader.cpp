#include "s3mme/loader.hpp"

#include <cstdlib>
#include <dlfcn.h>

#include "s3mm/common/fs.hpp"
#include "s3mm/common/log.hpp"
#include "s3mm/common/str.hpp"

namespace s3mme {

BrokerLoader::~BrokerLoader() {
    for (auto& [handle, broker] : loaded_) {
        LOG_DEBUG("unloading broker module ", broker && broker->name() ? broker->name() : "?");
        delete broker;
        if (handle) dlclose(handle);
    }
}

Result<void> BrokerLoader::loadFile(const std::string& path) {
    LOG_DEBUG("dlopen ", path);
    void* handle = dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        std::string why = dlerror();
        LOG_ERROR("dlopen ", path, " failed: ", why);
        return Result<void>::failure("cannot load broker module " + path + ": " + why);
    }
    LOG_DEBUG("dlopen ", path, " ok, resolving s3mme_broker_entry");
    auto entry = reinterpret_cast<CreateBrokerFn>(dlsym(handle, "s3mme_broker_entry"));
    if (!entry) {
        const char* why = dlerror();
        LOG_ERROR("module ", path, " has no s3mme_broker_entry() symbol: ", why ? why : "(null)");
        dlclose(handle);
        return Result<void>::failure("module " + path + " has no s3mme_broker_entry() symbol");
    }
    IBroker* broker = entry();
    if (!broker) {
        LOG_ERROR("module ", path, ": s3mme_broker_entry() returned null");
        dlclose(handle);
        return Result<void>::failure("module " + path + " returned null");
    }
    std::string name = broker->name() ? broker->name() : "unknown";
    if (byName_.count(name)) {
        LOG_WARN("broker '", name, "' from ", path, " already loaded, skipping duplicate");
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
    LOG_DEBUG("scanning broker module dir ", dir);
    std::string lastError;
    bool any = false;
    size_t candidates = 0;
    for (const auto& entry : s3mm::fs::listDir(dir)) {
        if (!s3mm::str::endsWith(entry, ".so")) continue;
        ++candidates;
        auto res = loadFile(s3mm::fs::joinPath(dir, entry));
        if (!res) {
            lastError = res.error();
            LOG_WARN("broker load failed: ", res.error());
            continue;
        }
        any = true;
    }
    LOG_DEBUG("module dir ", dir, ": ", candidates, " candidate(s), ", any ? "some" : "none", " loaded");
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
        if (!s3mm::fs::exists(d)) { LOG_DEBUG("module search path ", d, " does not exist, skipped"); continue; }
        LOG_DEBUG("module search path ", d);
        auto res = loadDir(d);
        if (res) any = true;
        else lastError = res.error();
    }
    if (byName_.empty()) LOG_WARN("no broker modules found in default search paths");
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

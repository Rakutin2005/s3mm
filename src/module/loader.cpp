#include "s3mm/module/loader.hpp"

#include <cstdlib>
#include <dlfcn.h>

#include "s3mm/common/fs.hpp"
#include "s3mm/common/log.hpp"
#include "s3mm/common/str.hpp"

namespace s3mm::module {

Loader::~Loader() {
    for (auto& [handle, module] : loaded_) {
        delete module;
        if (handle) dlclose(handle);
    }
}

Result<void> Loader::loadFile(const std::string& path) {
    void* handle = dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (!handle) return Result<void>::failure("cannot load module " + path + ": " + dlerror());
    auto entry = reinterpret_cast<CreateModuleFn>(dlsym(handle, "s3mm_module_entry"));
    if (!entry) {
        dlclose(handle);
        return Result<void>::failure("module " + path + " has no s3mm_module_entry() symbol");
    }
    IModule* module = entry();
    if (!module) {
        dlclose(handle);
        return Result<void>::failure("module " + path + " returned null");
    }
    ModuleInfo info = module->info();
    std::string name = info.name ? info.name : "unknown";
    if (byName_.count(name)) {
        delete module;
        dlclose(handle);
        return Result<void>::failure("module '" + name + "' already loaded (" + path + ")");
    }
    byName_[name] = module;
    loaded_.emplace_back(handle, module);
    LOG_INFO("loaded module ", name, " v", info.version ? info.version : "?", " (vendor ", info.vendor ? info.vendor : "?",
             ") from ", path);
    return Result<void>::success();
}

Result<void> Loader::loadDir(const std::string& dir) {
    std::string lastError;
    bool any = false;
    for (const auto& entry : fs::listDir(dir)) {
        if (!str::endsWith(entry, ".so")) continue;
        auto res = loadFile(fs::joinPath(dir, entry));
        if (!res) {
            lastError = res.error();
            LOG_WARN("module load failed: ", res.error());
            continue;
        }
        any = true;
    }
    if (!any && !lastError.empty()) return Result<void>::failure(lastError);
    return Result<void>::success();
}

Result<void> Loader::loadDefaults() {
    std::vector<std::string> dirs;
    if (const char* env = std::getenv("S3MM_MODULE_PATH")) {
        for (const auto& d : str::split(env, ':')) dirs.push_back(d);
    }
    dirs.push_back("/usr/lib/s3mm/modules");
    dirs.push_back("/usr/local/lib/s3mm/modules");
    dirs.push_back("modules");
    dirs.push_back("./build/modules");
    std::string lastError;
    bool any = false;
    for (const auto& d : dirs) {
        if (!fs::isDir(d)) continue;
        auto res = loadDir(d);
        if (!res) lastError = res.error();
        else if (!modules().empty()) any = true;
    }
    if (!any && !lastError.empty()) return Result<void>::failure(lastError);
    return Result<void>::success();
}

IModule* Loader::find(const std::string& name) const {
    auto it = byName_.find(name);
    return it == byName_.end() ? nullptr : it->second;
}

std::vector<IModule*> Loader::modules() const {
    std::vector<IModule*> out;
    for (const auto& [name, module] : byName_) out.push_back(module);
    return out;
}

std::vector<std::string> Loader::names() const {
    std::vector<std::string> out;
    for (const auto& [name, module] : byName_) out.push_back(name);
    return out;
}

} // namespace s3mm::module

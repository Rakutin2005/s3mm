#include "s3mm/module/loader.hpp"

#include <cstdlib>
#include <dlfcn.h>

#include "s3mm/common/fs.hpp"
#include "s3mm/common/log.hpp"
#include "s3mm/common/str.hpp"

namespace s3mm::module {

Loader::~Loader() {
    if (!loaded_.empty()) LOG_DEBUG("modules: unloading ", loaded_.size(), " module(s)");
    for (auto& [handle, module] : loaded_) {
        delete module;
        if (handle) dlclose(handle);
    }
}

Result<void> Loader::loadFile(const std::string& path) {
    log::Stopwatch sw;
    LOG_DEBUG("modules: dlopen ", path);
    void* handle = dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        std::string err = dlerror();
        LOG_ERROR("modules: dlopen ", path, " failed: ", err);
        return Result<void>::failure("cannot load module " + path + ": " + err);
    }
    LOG_DEBUG("modules: dlopen ", path, " ok, resolving s3mm_module_entry");
    dlerror();
    auto entry = reinterpret_cast<CreateModuleFn>(dlsym(handle, "s3mm_module_entry"));
    if (!entry) {
        const char* err = dlerror();
        LOG_ERROR("modules: ", path, ": symbol s3mm_module_entry not found: ", err ? err : "null symbol");
        dlclose(handle);
        return Result<void>::failure("module " + path + " has no s3mm_module_entry() symbol");
    }
    IModule* module = entry();
    if (!module) {
        LOG_ERROR("modules: ", path, ": s3mm_module_entry() returned null");
        dlclose(handle);
        return Result<void>::failure("module " + path + " returned null");
    }
    ModuleInfo info = module->info();
    std::string name = info.name ? info.name : "unknown";
    if (!info.name) LOG_WARN("modules: ", path, " reports no name, registering as 'unknown'");
    if (byName_.count(name)) {
        LOG_WARN("modules: '", name, "' from ", path, " is already loaded, skipping");
        delete module;
        dlclose(handle);
        return Result<void>::failure("module '" + name + "' already loaded (" + path + ")");
    }
    byName_[name] = module;
    loaded_.emplace_back(handle, module);
    LOG_INFO("loaded module ", name, " v", info.version ? info.version : "?", " (vendor ", info.vendor ? info.vendor : "?",
             ") from ", path, " in ", sw.ms(), " ms");
    return Result<void>::success();
}

Result<void> Loader::loadDir(const std::string& dir) {
    std::string lastError;
    bool any = false;
    LOG_DEBUG("modules: scanning ", dir);
    for (const auto& entry : fs::listDir(dir)) {
        if (!str::endsWith(entry, ".so")) {
            LOG_DEBUG("modules: skipping ", entry, " in ", dir, " (not a .so)");
            continue;
        }
        auto res = loadFile(fs::joinPath(dir, entry));
        if (!res) {
            lastError = res.error();
            LOG_WARN("module load failed: ", res.error());
            continue;
        }
        any = true;
    }
    LOG_DEBUG("modules: scanned ", dir, ": ", loaded_.size(), " module(s) loaded in total");
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
    LOG_DEBUG("modules: search path ", str::join(dirs, ":"));
    for (const auto& d : dirs) {
        if (!fs::isDir(d)) {
            LOG_DEBUG("modules: ", d, " is not a directory, skipped");
            continue;
        }
        auto res = loadDir(d);
        if (!res) lastError = res.error();
        else if (!modules().empty()) any = true;
    }
    if (!any && !lastError.empty()) return Result<void>::failure(lastError);
    if (modules().empty()) LOG_WARN("modules: no module found in ", str::join(dirs, ":"));
    return Result<void>::success();
}

IModule* Loader::find(const std::string& name) const {
    auto it = byName_.find(name);
    if (it == byName_.end()) {
        LOG_DEBUG("modules: no module named '", name, "'");
        return nullptr;
    }
    return it->second;
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

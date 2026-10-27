#include "s3mm/rest/loader.hpp"
#include <filesystem>

#include <dlfcn.h>

#include "s3mm/common/log.hpp"

namespace s3mm::rest {

RestModuleLoader::~RestModuleLoader() {
    for (auto& [handle, module] : loaded_) {
        LOG_DEBUG("rest modules: unloading ", module ? module->info().name : std::string("<null>"));
        delete module;
        if (handle) dlclose(handle);
    }
}

Result<void> RestModuleLoader::loadFile(const std::string& path) {
    LOG_DEBUG("rest modules: dlopen ", path);
    void* handle = dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        std::string err = dlerror();
        LOG_ERROR("rest modules: dlopen ", path, " failed: ", err);
        return Result<void>::failure(std::string("dlopen: ") + err);
    }
    auto fn = reinterpret_cast<CreateRestModuleFn>(dlsym(handle, "s3mm_rest_module_entry"));
    if (!fn) {
        LOG_DEBUG("rest modules: ", path, " has no s3mm_rest_module_entry (not a REST module)");
        dlclose(handle);
        return Result<void>::failure("missing s3mm_rest_module_entry in " + path);
    }
    IRestModule* module = fn();
    if (!module) {
        LOG_ERROR("rest modules: entry point of ", path, " returned null");
        dlclose(handle);
        return Result<void>::failure("module entry returned null in " + path);
    }
    auto info = module->info();
    LOG_INFO("rest modules: loaded '", info.name, "' version ", info.version, " (", info.vendor, ") from ", path);
    loaded_.emplace_back(handle, module);
    return Result<void>::success();
}

Result<void> RestModuleLoader::loadDir(const std::string& dir) {
    std::error_code ec;
    LOG_DEBUG("rest modules: scanning directory ", dir);
    if (!std::filesystem::exists(dir, ec)) {
        LOG_WARN("rest modules: directory not found: ", dir, ec ? " (" + ec.message() + ")" : std::string());
        return Result<void>::failure("modules directory not found: " + dir);
    }
    size_t candidates = 0;
    for (const auto& entry : std::filesystem::directory_iterator(dir, ec)) {
        if (!entry.is_regular_file()) continue;
        if (entry.path().extension() != ".so") {
            LOG_DEBUG("rest modules: skipping ", entry.path().string(), " (not a .so)");
            continue;
        }
        ++candidates;
        // The directory is shared with the storage modules (s3mm_mod_*.so),
        // which have no REST entry point: skip them, and keep going past a
        // broken module instead of dropping every module after it.
        auto loaded = loadFile(entry.path().string());
        if (!loaded && loaded.error().rfind("missing s3mm_rest_module_entry", 0) != 0)
            LOG_WARN("rest modules: skipping ", entry.path().string(), ": ", loaded.error());
    }
    if (ec) LOG_WARN("rest modules: error while iterating ", dir, ": ", ec.message());
    LOG_INFO("rest modules: scanned ", dir, ": ", candidates, " shared objects, ", loaded_.size(), " REST modules loaded");
    return Result<void>::success();
}

std::vector<IRestModule*> RestModuleLoader::modules() const {
    std::vector<IRestModule*> out;
    for (const auto& [handle, module] : loaded_) out.push_back(module);
    return out;
}

} // namespace s3mm::rest

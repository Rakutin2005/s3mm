#include "s3mm/rest/loader.hpp"

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

Result<IRestModule*> RestModuleLoader::loadModule(const std::string& name, const std::string& path,
                                                 const std::string& modulesDir) {
    std::string file = path.empty() ? modulesDir + "/s3mmws_mod_" + name + ".so" : path;
    LOG_INFO("rest modules: loading module '", name, "' from ", file);
    auto loaded = loadFile(file);
    if (!loaded) return Result<IRestModule*>::failure("module '" + name + "': " + loaded.error());
    IRestModule* module = loaded_.back().second;
    if (module->info().name != name)
        LOG_WARN("rest modules: ", file, " identifies itself as '", module->info().name, "', configured as '", name, "'");
    return module;
}

std::vector<IRestModule*> RestModuleLoader::modules() const {
    std::vector<IRestModule*> out;
    for (const auto& [handle, module] : loaded_) out.push_back(module);
    return out;
}

} // namespace s3mm::rest

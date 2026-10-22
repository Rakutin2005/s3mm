#include "s3mm/rest/loader.hpp"
#include <filesystem>

#include <dlfcn.h>

namespace s3mm::rest {

RestModuleLoader::~RestModuleLoader() {
    for (auto& [handle, module] : loaded_) {
        delete module;
        if (handle) dlclose(handle);
    }
}

Result<void> RestModuleLoader::loadFile(const std::string& path) {
    void* handle = dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (!handle) return Result<void>::failure(std::string("dlopen: ") + dlerror());
    auto fn = reinterpret_cast<CreateRestModuleFn>(dlsym(handle, "s3mm_rest_module_entry"));
    if (!fn) {
        dlclose(handle);
        return Result<void>::failure("missing s3mm_rest_module_entry in " + path);
    }
    IRestModule* module = fn();
    if (!module) {
        dlclose(handle);
        return Result<void>::failure("module entry returned null in " + path);
    }
    loaded_.emplace_back(handle, module);
    return Result<void>::success();
}

Result<void> RestModuleLoader::loadDir(const std::string& dir) {
    std::error_code ec;
    if (!std::filesystem::exists(dir, ec)) return Result<void>::failure("modules directory not found: " + dir);
    for (const auto& entry : std::filesystem::directory_iterator(dir, ec)) {
        if (!entry.is_regular_file()) continue;
        if (entry.path().extension() != ".so") continue;
        auto loaded = loadFile(entry.path().string());
        if (!loaded) return loaded;
    }
    return Result<void>::success();
}

std::vector<IRestModule*> RestModuleLoader::modules() const {
    std::vector<IRestModule*> out;
    for (const auto& [handle, module] : loaded_) out.push_back(module);
    return out;
}

} // namespace s3mm::rest

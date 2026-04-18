#pragma once

#include <filesystem>
#include <string>
#include <vector>

#include <ember/common/annotations.hpp>
#include <ember/common/error.hpp>

namespace ember {

class Binary;

// Passing one of these to ScriptRuntime exposes the `project.*` mutation API
// to scripts. `commit()` merges pending writes into `loaded` and writes back
// to `path`.
struct ProjectContext {
    std::filesystem::path path;
    Annotations           loaded{};
};

class ScriptRuntime {
public:
    explicit ScriptRuntime(const Binary& binary,
                           ProjectContext* project = nullptr) noexcept;
    ScriptRuntime(const ScriptRuntime&)            = delete;
    ScriptRuntime& operator=(const ScriptRuntime&) = delete;
    ~ScriptRuntime();

    // Call before run_file / eval.
    void set_argv(std::vector<std::string> argv);

    Result<void> run_file(const std::filesystem::path& path);
    Result<void> eval(std::string source, std::string name);

private:
    struct Impl;
    Impl* impl_;
};

}  // namespace ember

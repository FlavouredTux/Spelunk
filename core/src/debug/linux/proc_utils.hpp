#pragma once

#include <string>
#include <sys/types.h>
#include <vector>

#include <ember/debug/target.hpp>

namespace ember::debug::linux_detail {

// Owns the null-terminated string array passed to execvpe. The strings are
// released only when exec fails; a successful exec replaces the process image.
struct OwnedArgv {
    OwnedArgv() = default;
    OwnedArgv(const OwnedArgv&) = delete;
    OwnedArgv& operator=(const OwnedArgv&) = delete;
    OwnedArgv(OwnedArgv&& other) noexcept;
    OwnedArgv& operator=(OwnedArgv&& other) noexcept;
    ~OwnedArgv();

    std::vector<char*> ptrs;
};

[[nodiscard]] OwnedArgv
build_argv(const std::string& program, const std::vector<std::string>& args);

[[nodiscard]] OwnedArgv build_envp(const std::vector<std::string>& env);

[[nodiscard]] std::vector<LoadedImage> read_proc_maps(pid_t pid);

[[nodiscard]] std::vector<pid_t> read_task_tids(pid_t pid);

}  // namespace ember::debug::linux_detail

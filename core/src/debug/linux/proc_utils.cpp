// Shared launch-argument and /proc discovery helpers for the Linux debugger
// backends. Backend-specific process control remains in *_proc.cpp.

#include "proc_utils.hpp"

#include <cstdio>
#include <cstdlib>
#include <dirent.h>
#include <string.h>
#include <string_view>
#include <utility>

#include <ember/common/types.hpp>

namespace ember::debug::linux_detail {

namespace {

// Parse one hex address from the start of a string; stops at the first
// non-hex character. Returns 0 on a leading non-hex byte.
addr_t parse_hex(std::string_view text) {
    addr_t value = 0;
    for (char c : text) {
        const int digit = (c >= '0' && c <= '9') ? c - '0'
                        : (c >= 'a' && c <= 'f') ? c - 'a' + 10
                        : (c >= 'A' && c <= 'F') ? c - 'A' + 10
                        : -1;
        if (digit < 0) break;
        value = (value << 4) | static_cast<addr_t>(digit);
    }
    return value;
}

void free_strings(std::vector<char*>& ptrs) {
    for (char* ptr : ptrs) {
        if (ptr) std::free(ptr);
    }
}

}  // namespace

OwnedArgv::OwnedArgv(OwnedArgv&& other) noexcept
    : ptrs(std::move(other.ptrs)) {
    other.ptrs.clear();
}

OwnedArgv& OwnedArgv::operator=(OwnedArgv&& other) noexcept {
    if (this == &other) return *this;
    free_strings(ptrs);
    ptrs = std::move(other.ptrs);
    other.ptrs.clear();
    return *this;
}

OwnedArgv::~OwnedArgv() {
    free_strings(ptrs);
}

OwnedArgv build_argv(const std::string& program,
                     const std::vector<std::string>& args) {
    OwnedArgv argv;
    argv.ptrs.reserve(args.size() + 2);
    argv.ptrs.push_back(::strdup(program.c_str()));
    for (const auto& arg : args) argv.ptrs.push_back(::strdup(arg.c_str()));
    argv.ptrs.push_back(nullptr);
    return argv;
}

OwnedArgv build_envp(const std::vector<std::string>& env) {
    OwnedArgv envp;
    envp.ptrs.reserve(env.size() + 1);
    for (const auto& entry : env) envp.ptrs.push_back(::strdup(entry.c_str()));
    envp.ptrs.push_back(nullptr);
    return envp;
}

// One LoadedImage per unique path with at least one file-backed mapping.
// Base is the lowest mapping start for that path. For an ELF, the kernel maps
// the lowest-vaddr PT_LOAD there, so the base lands on the ELF header.
std::vector<LoadedImage> read_proc_maps(pid_t pid) {
    std::vector<LoadedImage> images;
    char path[64];
    std::snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE* file = std::fopen(path, "r");
    if (!file) return images;

    char line[4096];
    while (std::fgets(line, sizeof(line), file)) {
        std::string_view text(line);
        const auto path_pos = text.find('/');
        if (path_pos == std::string_view::npos) continue;

        const auto dash = text.find('-');
        if (dash == std::string_view::npos) continue;

        const addr_t start = parse_hex(text.substr(0, dash));
        if (start == 0) continue;

        std::string file_path(text.substr(path_pos));
        while (!file_path.empty() &&
               (file_path.back() == ' ' || file_path.back() == '\t' ||
                file_path.back() == '\r' || file_path.back() == '\n')) {
            file_path.pop_back();
        }

        bool found = false;
        for (auto& image : images) {
            if (image.path == file_path) {
                if (start < image.base) image.base = start;
                found = true;
                break;
            }
        }
        if (!found) images.push_back({file_path, start});
    }
    std::fclose(file);
    return images;
}

// Walk /proc/<pid>/task, the kernel's current thread-membership snapshot.
std::vector<pid_t> read_task_tids(pid_t pid) {
    std::vector<pid_t> tids;
    char path[64];
    std::snprintf(path, sizeof(path), "/proc/%d/task", pid);

    DIR* dir = ::opendir(path);
    if (!dir) return tids;
    while (auto* entry = ::readdir(dir)) {
        if (entry->d_name[0] < '0' || entry->d_name[0] > '9') continue;
        tids.push_back(static_cast<pid_t>(std::atoi(entry->d_name)));
    }
    ::closedir(dir);
    return tids;
}

}  // namespace ember::debug::linux_detail

// Memory read/write for the perf backend. Identical mechanism to
// ptrace_mem.cpp: /proc/<pid>/mem opened once, lazily, used for every
// access. The perf backend never had a ptrace tracer to begin with, so
// the access path is exactly the same - short reads at unmapped pages
// surface as a partial returned count, not an error.

#include "perf_target.hpp"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>

#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>

namespace ember::debug::linux_perf {

namespace {

[[nodiscard]] Error errno_io(const char* op) {
    return Error::io(std::string(op) + ": " + std::strerror(errno));
}

[[nodiscard]] int ensure_mem_fd(PerfTarget& t) {
    int& fd = PerfMemFdAccess::fd_of(t);
    if (fd >= 0) return fd;
    char path[64];
    std::snprintf(path, sizeof(path), "/proc/%u/mem", t.pid());
    fd = ::open(path, O_RDWR | O_CLOEXEC);
    return fd;
}

}  // namespace

Result<std::size_t>
PerfTarget::read_mem(addr_t va, std::span<std::byte> out) {
    const int fd = ensure_mem_fd(*this);
    if (fd < 0) return std::unexpected(errno_io("open /proc/.../mem"));

    std::size_t total = 0;
    while (total < out.size()) {
        const ssize_t n = ::pread(
            fd, out.data() + total, out.size() - total,
            static_cast<off_t>(va + total));
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EIO || errno == EFAULT) break;
            return std::unexpected(errno_io("pread /proc/.../mem"));
        }
        if (n == 0) break;
        total += static_cast<std::size_t>(n);
    }
    return total;
}

Result<std::size_t>
PerfTarget::write_mem(addr_t va, std::span<const std::byte> in) {
    const int fd = ensure_mem_fd(*this);
    if (fd < 0) return std::unexpected(errno_io("open /proc/.../mem"));

    std::size_t total = 0;
    while (total < in.size()) {
        const ssize_t n = ::pwrite(
            fd, in.data() + total, in.size() - total,
            static_cast<off_t>(va + total));
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EIO || errno == EFAULT) break;
            return std::unexpected(errno_io("pwrite /proc/.../mem"));
        }
        if (n == 0) break;
        total += static_cast<std::size_t>(n);
    }
    return total;
}

}  // namespace ember::debug::linux_perf

// Memory read/write for the Linux ptrace backend. We use /proc/<pid>/mem
// rather than PTRACE_PEEKDATA / PTRACE_POKEDATA: it's word-granular,
// returns short reads cleanly at unmapped boundaries (EIO), and a
// single open() amortises across thousands of accesses.

#include "ptrace_target.hpp"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>

#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>

namespace ember::debug::linux_ {

namespace {

[[nodiscard]] Error errno_io(const char* op) {
    return Error::io(std::string(op) + ": " + std::strerror(errno));
}

[[nodiscard]] int ensure_mem_fd(LinuxTarget& t) {
    int& fd = MemFdAccess::fd_of(t);
    if (fd >= 0) return fd;
    char path[64];
    std::snprintf(path, sizeof(path), "/proc/%u/mem", t.pid());
    fd = ::open(path, O_RDWR | O_CLOEXEC);
    return fd;
}

}  // namespace

Result<std::size_t>
LinuxTarget::read_mem(addr_t va, std::span<std::byte> out) {
    const int fd = ensure_mem_fd(*this);
    if (fd < 0) return std::unexpected(errno_io("open /proc/.../mem"));

    std::size_t total = 0;
    while (total < out.size()) {
        const ssize_t n = ::pread(
            fd, out.data() + total, out.size() - total,
            static_cast<off_t>(va + total));
        if (n < 0) {
            if (errno == EINTR) continue;
            // Crossing into an unmapped page is a short read, not an
            // error — caller already inspects the returned count.
            if (errno == EIO || errno == EFAULT) break;
            return std::unexpected(errno_io("pread /proc/.../mem"));
        }
        if (n == 0) break;
        total += static_cast<std::size_t>(n);
    }
    return total;
}

Result<std::size_t>
LinuxTarget::write_mem(addr_t va, std::span<const std::byte> in) {
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

}  // namespace ember::debug::linux_

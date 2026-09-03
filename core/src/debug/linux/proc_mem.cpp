// Shared /proc/<pid>/mem access for the Linux debugger backends. A single
// lazy fd is reused; EIO/EFAULT at unmapped boundaries return a partial count.

#include "proc_mem.hpp"

#include <cerrno>
#include <cstdio>
#include <expected>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>

#include "errno_io.hpp"

namespace ember::debug::linux_detail {

int ensure_proc_mem_fd(ProcessId pid, int& fd) {
    if (fd >= 0) return fd;

    char path[64];
    std::snprintf(path, sizeof(path), "/proc/%u/mem", pid);
    fd = ::open(path, O_RDWR | O_CLOEXEC);
    return fd;
}

Result<std::size_t>
read_proc_mem(ProcessId pid, int& fd, addr_t va,
              std::span<std::byte> out) {
    const int mem_fd = ensure_proc_mem_fd(pid, fd);
    if (mem_fd < 0) {
        return std::unexpected(errno_io("open /proc/.../mem"));
    }

    std::size_t total = 0;
    while (total < out.size()) {
        const ssize_t n = ::pread(
            mem_fd, out.data() + total, out.size() - total,
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
write_proc_mem(ProcessId pid, int& fd, addr_t va,
               std::span<const std::byte> in) {
    const int mem_fd = ensure_proc_mem_fd(pid, fd);
    if (mem_fd < 0) {
        return std::unexpected(errno_io("open /proc/.../mem"));
    }

    std::size_t total = 0;
    while (total < in.size()) {
        const ssize_t n = ::pwrite(
            mem_fd, in.data() + total, in.size() - total,
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

}  // namespace ember::debug::linux_detail

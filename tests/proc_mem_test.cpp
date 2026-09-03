#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>
#include <sys/mman.h>
#include <unistd.h>

#include "proc_mem.hpp"

#define CHECK(cond, msg)                                                   \
    do {                                                                   \
        if (!(cond)) {                                                     \
            std::fprintf(stderr,                                           \
                         "FAIL: %s (line %d)\n", (msg), __LINE__);         \
            return 1;                                                      \
        }                                                                  \
    } while (0)

int main() {
    const long page_size_raw = ::sysconf(_SC_PAGESIZE);
    CHECK(page_size_raw > 0, "sysconf(_SC_PAGESIZE)");
    const auto page_size = static_cast<std::size_t>(page_size_raw);

    void* mapping = ::mmap(nullptr, page_size * 2,
                           PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(mapping != MAP_FAILED, "mmap");
    auto* const bytes = static_cast<std::byte*>(mapping);
    std::fill(bytes, bytes + page_size, std::byte{0x5a});

    int mem_fd = -1;
    const auto pid = static_cast<ember::debug::ProcessId>(::getpid());
    errno = 0;
    const int opened_fd =
        ember::debug::linux_detail::ensure_proc_mem_fd(pid, mem_fd);
    if (opened_fd < 0 && (errno == EACCES || errno == EPERM)) {
        const int open_errno = errno;
        (void)::munmap(mapping, page_size * 2);
        std::fprintf(stderr,
                     "SKIP: /proc/self/mem access denied (errno %d)\n",
                     open_errno);
        return 77;
    }
    CHECK(opened_fd >= 0, "open /proc/self/mem");
    CHECK(mem_fd == opened_fd, "lazy open stores fd");
    CHECK(ember::debug::linux_detail::ensure_proc_mem_fd(pid, mem_fd) ==
              opened_fd,
          "lazy open reuses fd");

    constexpr std::size_t kProbeSize = 16;
    std::array<std::byte, kProbeSize> readback{};
    const auto base = static_cast<ember::addr_t>(
        reinterpret_cast<std::uintptr_t>(bytes));
    auto read_result = ember::debug::linux_detail::read_proc_mem(
        pid, mem_fd, base, std::span<std::byte>{readback});
    CHECK(read_result.has_value(), "read mapped memory");
    CHECK(*read_result == readback.size(), "full mapped read count");
    CHECK(std::ranges::all_of(readback,
                              [](std::byte b) { return b == std::byte{0x5a}; }),
          "mapped read contents");

    std::array<std::byte, kProbeSize> payload{};
    payload.fill(std::byte{0xa5});
    auto write_result = ember::debug::linux_detail::write_proc_mem(
        pid, mem_fd, base, std::span<const std::byte>{payload});
    CHECK(write_result.has_value(), "write mapped memory");
    CHECK(*write_result == payload.size(), "full mapped write count");
    CHECK(std::equal(payload.begin(), payload.end(), bytes),
          "mapped write contents");

    std::fill(bytes + page_size - kProbeSize, bytes + page_size,
              std::byte{0x3c});
    CHECK(::munmap(bytes + page_size, page_size) == 0,
          "munmap boundary page");

    const ember::addr_t boundary =
        base + static_cast<ember::addr_t>(page_size - kProbeSize);
    std::array<std::byte, kProbeSize * 2> boundary_read{};
    read_result = ember::debug::linux_detail::read_proc_mem(
        pid, mem_fd, boundary, std::span<std::byte>{boundary_read});
    CHECK(read_result.has_value(), "read across unmapped boundary");
    CHECK(*read_result == kProbeSize, "partial boundary read count");
    CHECK(std::ranges::all_of(
              boundary_read.begin(), boundary_read.begin() + kProbeSize,
              [](std::byte b) { return b == std::byte{0x3c}; }),
          "partial boundary read contents");

    std::array<std::byte, kProbeSize * 2> boundary_payload{};
    boundary_payload.fill(std::byte{0xc3});
    write_result = ember::debug::linux_detail::write_proc_mem(
        pid, mem_fd, boundary,
        std::span<const std::byte>{boundary_payload});
    CHECK(write_result.has_value(), "write across unmapped boundary");
    CHECK(*write_result == kProbeSize, "partial boundary write count");
    CHECK(std::equal(boundary_payload.begin(),
                     boundary_payload.begin() + kProbeSize,
                     bytes + page_size - kProbeSize),
          "partial boundary write contents");

    CHECK(::close(mem_fd) == 0, "close /proc/self/mem");
    CHECK(::munmap(mapping, page_size) == 0, "munmap data page");
    return 0;
}

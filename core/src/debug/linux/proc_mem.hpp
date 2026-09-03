#pragma once

#include <cstddef>
#include <span>

#include <ember/common/error.hpp>
#include <ember/common/types.hpp>
#include <ember/debug/types.hpp>

namespace ember::debug::linux_detail {

[[nodiscard]] int ensure_proc_mem_fd(ProcessId pid, int& fd);

[[nodiscard]] Result<std::size_t>
read_proc_mem(ProcessId pid, int& fd, addr_t va, std::span<std::byte> out);

[[nodiscard]] Result<std::size_t>
write_proc_mem(ProcessId pid, int& fd, addr_t va,
               std::span<const std::byte> in);

}  // namespace ember::debug::linux_detail

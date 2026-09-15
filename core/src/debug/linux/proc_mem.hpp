#pragma once

#include <cstddef>
#include <span>

#include <spelunk/common/error.hpp>
#include <spelunk/common/types.hpp>
#include <spelunk/debug/types.hpp>

namespace spelunk::debug::linux_detail {

[[nodiscard]] int ensure_proc_mem_fd(ProcessId pid, int& fd);

[[nodiscard]] Result<std::size_t>
read_proc_mem(ProcessId pid, int& fd, addr_t va, std::span<std::byte> out);

[[nodiscard]] Result<std::size_t>
write_proc_mem(ProcessId pid, int& fd, addr_t va,
               std::span<const std::byte> in);

}  // namespace spelunk::debug::linux_detail

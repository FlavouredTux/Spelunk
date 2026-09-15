#include "proc_mem.hpp"
#include "ptrace_target.hpp"

namespace spelunk::debug::linux_ {

Result<std::size_t>
LinuxTarget::read_mem(addr_t va, std::span<std::byte> out) {
    return linux_detail::read_proc_mem(
        pid(), MemFdAccess::fd_of(*this), va, out);
}

Result<std::size_t>
LinuxTarget::write_mem(addr_t va, std::span<const std::byte> in) {
    return linux_detail::write_proc_mem(
        pid(), MemFdAccess::fd_of(*this), va, in);
}

}  // namespace spelunk::debug::linux_

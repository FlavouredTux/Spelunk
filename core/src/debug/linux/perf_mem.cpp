#include "perf_target.hpp"
#include "proc_mem.hpp"

namespace ember::debug::linux_perf {

Result<std::size_t>
PerfTarget::read_mem(addr_t va, std::span<std::byte> out) {
    return linux_detail::read_proc_mem(
        pid(), PerfMemFdAccess::fd_of(*this), va, out);
}

Result<std::size_t>
PerfTarget::write_mem(addr_t va, std::span<const std::byte> in) {
    return linux_detail::write_proc_mem(
        pid(), PerfMemFdAccess::fd_of(*this), va, in);
}

}  // namespace ember::debug::linux_perf

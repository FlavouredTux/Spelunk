// Syscall catchpoints. PTRACE_O_TRACESYSGOOD marks syscall-stops as
// SIGTRAP|0x80; when catching is on, cont() / step() route through
// PTRACE_SYSCALL and wait_event decodes orig_rax into EvSyscallStop.

#include "ptrace_target.hpp"

namespace ember::debug::linux_ {

Result<void>
LinuxTarget::set_syscall_catch(bool catch_all, std::span<const u32> nrs) {
    syscall_catching_  = catch_all || !nrs.empty();
    syscall_catch_all_ = catch_all;
    syscall_nrs_.clear();
    for (auto n : nrs) syscall_nrs_.insert(n);
    return {};
}

Result<void> LinuxTarget::clear_syscall_catch() {
    syscall_catching_  = false;
    syscall_catch_all_ = false;
    syscall_nrs_.clear();
    // Don't reset per-thread in_syscall — the kernel still tracks
    // entry/exit alternation across re-arm.
    return {};
}

}  // namespace ember::debug::linux_

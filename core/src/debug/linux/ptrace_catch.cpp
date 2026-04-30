// Syscall catchpoints for the Linux ptrace backend.
//
// PTRACE_SYSCALL stops the tracee at every syscall entry and exit
// (with PTRACE_O_TRACESYSGOOD set in ptrace_proc, the stop signal is
// SIGTRAP | 0x80 so we can distinguish from int3 or DR-watch hits).
// Catching is a target-wide flag plus an optional number filter:
// when active, cont() / step() route through PTRACE_SYSCALL instead
// of PTRACE_CONT, and wait_event() decodes the syscall-stop into
// EvSyscallStop. With a non-empty filter we silently re-issue
// PTRACE_SYSCALL on stops whose nr isn't of interest, which keeps
// the user's view focused without forcing them to re-arm the
// catch on every uninteresting nr.

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
    // Per-thread in_syscall stays as-is; the kernel still tracks
    // entry/exit alternation, so the next time the user re-arms
    // catching we'll be in sync. Resetting the flag here would
    // mis-label the very next stop after a re-arm.
    return {};
}

}  // namespace ember::debug::linux_

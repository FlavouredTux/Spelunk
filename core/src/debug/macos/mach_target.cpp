// Class scaffold + getters for the macOS Mach backend. Verb impls
// live in mach_proc / mach_mem / mach_regs / mach_break / mach_event,
// so this file stays small and only deals with the bookkeeping that
// has no Mach API dependency.

#include "mach_target.hpp"

#include <algorithm>

#include <mach/mach.h>
#include <mach/mach_port.h>

namespace ember::debug::mach_ {

MachOTarget::~MachOTarget() {
    // Mirrors LinuxTarget's policy: detach()/kill() are the user's
    // job. The destructor only releases the Mach port references we
    // still hold so we don't leak send/receive rights into a tracee
    // we never explicitly disconnected from.
    if (exc_port_ != 0) {
        ::mach_port_destroy(::mach_task_self(), exc_port_);
        exc_port_ = 0;
    }
    if (task_port_ != 0) {
        ::mach_port_deallocate(::mach_task_self(), task_port_);
        task_port_ = 0;
    }
}

void MachOTarget::add_thread(ThreadId tid) {
    thread_state_.try_emplace(tid);
}

void MachOTarget::drop_thread(ThreadId tid) {
    thread_state_.erase(tid);
}

std::vector<ThreadId> MachOTarget::threads() const {
    std::vector<ThreadId> out;
    out.reserve(thread_state_.size());
    for (const auto& [tid, _] : thread_state_) out.push_back(tid);
    return out;
}

ThreadState& MachOTarget::thread_state(ThreadId tid) {
    return thread_state_[tid];
}

const ThreadState* MachOTarget::thread_state_lookup(ThreadId tid) const {
    auto it = thread_state_.find(tid);
    return it == thread_state_.end() ? nullptr : &it->second;
}

SoftwareBreakpoint* MachOTarget::find_bp_at(addr_t va) {
    for (auto& [_, bp] : bps_) {
        if (bp.info.addr == va) return &bp;
    }
    return nullptr;
}

SoftwareBreakpoint* MachOTarget::find_bp_id(BreakpointId id) {
    auto it = bps_.find(id);
    return it == bps_.end() ? nullptr : &it->second;
}

std::vector<Breakpoint> MachOTarget::breakpoints() const {
    std::vector<Breakpoint> out;
    out.reserve(bps_.size());
    for (const auto& [_, bp] : bps_) out.push_back(bp.info);
    std::ranges::sort(out, {}, &Breakpoint::id);
    return out;
}

}  // namespace ember::debug::mach_

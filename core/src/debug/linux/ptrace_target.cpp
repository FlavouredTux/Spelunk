#include "ptrace_target.hpp"

#include <algorithm>

#include <unistd.h>

namespace ember::debug::linux_ {

LinuxTarget::~LinuxTarget() {
    // detach()/kill() are the user's responsibility; if they didn't
    // call either, the kernel will tear the tracee down when this
    // process exits. We do not synthesise a detach here because that
    // would silently leave the tracee running on destructor unwind,
    // hiding bugs that should surface as a missed call.
    if (mem_fd_ >= 0) ::close(mem_fd_);
}

void LinuxTarget::add_thread(ThreadId tid) {
    thread_state_.try_emplace(tid);
}

void LinuxTarget::drop_thread(ThreadId tid) {
    thread_state_.erase(tid);
}

std::vector<ThreadId> LinuxTarget::threads() const {
    std::vector<ThreadId> out;
    out.reserve(thread_state_.size());
    for (const auto& [tid, _] : thread_state_) out.push_back(tid);
    return out;  // std::map keeps keys sorted
}

ThreadState& LinuxTarget::thread_state(ThreadId tid) {
    return thread_state_[tid];
}

const ThreadState* LinuxTarget::thread_state_lookup(ThreadId tid) const {
    auto it = thread_state_.find(tid);
    return it == thread_state_.end() ? nullptr : &it->second;
}

SoftwareBreakpoint* LinuxTarget::find_bp_at(addr_t va) {
    for (auto& [_, bp] : bps_) {
        if (bp.info.addr == va) return &bp;
    }
    return nullptr;
}

SoftwareBreakpoint* LinuxTarget::find_bp_id(BreakpointId id) {
    auto it = bps_.find(id);
    return it == bps_.end() ? nullptr : &it->second;
}

std::vector<Breakpoint> LinuxTarget::breakpoints() const {
    std::vector<Breakpoint> out;
    out.reserve(bps_.size());
    for (const auto& [_, bp] : bps_) out.push_back(bp.info);
    std::ranges::sort(out, {}, &Breakpoint::id);
    return out;
}

}  // namespace ember::debug::linux_

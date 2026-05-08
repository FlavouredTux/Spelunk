// Skeleton for the perf_event_open backend's PerfTarget class:
// destructor, slot lookup helpers, thread-state map, breakpoint /
// watchpoint accessors. The interesting kernel work lives in
// perf_proc.cpp (launch+attach), perf_break/watch.cpp (DR slots),
// perf_event.cpp (poll loop + sample parsing), perf_regs.cpp
// (cached-sample register read), and perf_mem.cpp (/proc/<pid>/mem).

#include "perf_target.hpp"

#include <algorithm>

#include <unistd.h>
#include <sys/mman.h>

namespace ember::debug::linux_perf {

void close_slot(PerfSlot& s) {
    if (s.ring && s.ring_bytes) ::munmap(s.ring, s.ring_bytes);
    if (s.fd >= 0) ::close(s.fd);
    s = PerfSlot{};
}

PerfTarget::~PerfTarget() {
    for (auto& s : slots_) close_slot(s);
    if (mem_fd_ >= 0) ::close(mem_fd_);
    if (pidfd_  >= 0) ::close(pidfd_);
}

std::vector<ThreadId> PerfTarget::threads() const {
    std::vector<ThreadId> out;
    out.reserve(thread_state_.size());
    for (const auto& [tid, _] : thread_state_) out.push_back(tid);
    return out;  // std::map keeps keys sorted
}

PerfThreadState& PerfTarget::thread_state(ThreadId tid) {
    return thread_state_[tid];
}

const PerfThreadState* PerfTarget::thread_state_lookup(ThreadId tid) const {
    auto it = thread_state_.find(tid);
    return it == thread_state_.end() ? nullptr : &it->second;
}

int PerfTarget::find_free_slot() const {
    for (int i = 0; i < kMaxSlots; ++i) {
        if (slots_[i].fd < 0) return i;
    }
    return -1;
}

int PerfTarget::find_bp_slot(BreakpointId id) const {
    for (int i = 0; i < kMaxSlots; ++i) {
        const auto& s = slots_[i];
        if (s.fd >= 0 && !s.is_watch && s.bp_info.id == id) return i;
    }
    return -1;
}

int PerfTarget::find_wp_slot(WatchpointId id) const {
    for (int i = 0; i < kMaxSlots; ++i) {
        const auto& s = slots_[i];
        if (s.fd >= 0 && s.is_watch && s.wp_info.id == id) return i;
    }
    return -1;
}

int PerfTarget::find_slot_by_fd(int fd) const {
    for (int i = 0; i < kMaxSlots; ++i) {
        if (slots_[i].fd == fd) return i;
    }
    return -1;
}

std::vector<Breakpoint> PerfTarget::breakpoints() const {
    std::vector<Breakpoint> out;
    for (const auto& s : slots_) {
        if (s.fd >= 0 && !s.is_watch) out.push_back(s.bp_info);
    }
    std::ranges::sort(out, {}, &Breakpoint::id);
    return out;
}

std::vector<Watchpoint> PerfTarget::watchpoints() const {
    std::vector<Watchpoint> out;
    for (const auto& s : slots_) {
        if (s.fd >= 0 && s.is_watch) out.push_back(s.wp_info);
    }
    std::ranges::sort(out, {}, &Watchpoint::id);
    return out;
}

void PerfTarget::clear_all_after_exec() {
    // execve drops every perf_event_open fd attached to the previous
    // task. Tear down our slot bookkeeping so set_breakpoint /
    // set_watchpoint don't try to reuse fds the kernel already closed.
    for (auto& s : slots_) close_slot(s);
    for (auto& [_, ts] : thread_state_) {
        ts.paused     = false;
        ts.has_sample = false;
        ts.cached     = Registers{};
    }
}

}  // namespace ember::debug::linux_perf

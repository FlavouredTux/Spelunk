// Register access for the perf backend. The kernel only exposes
// register state to userspace through perf samples — there is no
// out-of-band PEEK/POKE_USER equivalent without ptrace. wait_event
// caches the most recent sample's GPR snapshot per thread; get_regs
// returns that cached value, with PresentGpr set when at least one
// sample has been seen for the thread, and present == 0 otherwise.
//
// FP / SIMD / DR slots are intentionally absent from the cached
// snapshot: PERF_SAMPLE_REGS_USER is GPR-only on x86-64. set_regs
// has no kernel surface here at all and returns Error::unsupported.

#include "perf_target.hpp"

namespace ember::debug::linux_perf {

Result<Registers> PerfTarget::get_regs(ThreadId tid) {
    const auto* ts = thread_state_lookup(tid);
    if (!ts) {
        // Thread we've never seen. Return zero state so the REPL can
        // show "0x0" without stopping the session — matches the
        // ptrace backend's behaviour for un-sampled threads (which
        // it can read) versus an explicit error.
        return Registers{};
    }
    return ts->cached;
}

Result<void> PerfTarget::set_regs(ThreadId, const Registers&) {
    return std::unexpected(Error::unsupported(
        "debugger: register write is not available on the perf backend "
        "(no PTRACE_SETREGS surface — use the ptrace backend if you need it)"));
}

}  // namespace ember::debug::linux_perf

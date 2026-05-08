#pragma once

// Internal header for the Linux perf_event_open debugger backend.
// Mirrors the shape of ptrace_target.hpp but the underlying kernel
// surface is completely different — no PTRACE_*, no PEEK/POKE_USER,
// no `waitpid` semantics. Communication with the tracee happens via:
//
//   * /proc/<pid>/mem            — bulk read/write
//   * perf_event_open(BREAKPOINT) — HW BP/WP (4 DR slots, shared)
//   * perf mmap ring buffer       — sample (PC + regs + tid) on hit
//   * pidfd_open(2) + poll(2)     — process-exit notification
//   * SIGSTOP / SIGCONT           — fake "stopped" semantics for the
//                                   REPL after a HW hit
//
// Capability gaps relative to ptrace_target are intentional and are
// surfaced as Error::unsupported at the API:
//
//   - software breakpoints       (no INT3 SIGTRAP catcher without ptrace)
//   - single-step                (no TF flag access from outside)
//   - on-demand register read    (kernel won't sample regs except on
//                                 a perf event — we cache the last
//                                 sample per thread instead)
//   - register write             (no SETREGS without ptrace)
//   - syscall catch              (would need uprobes, deferred)

#include <cstddef>
#include <deque>
#include <map>
#include <memory>
#include <set>
#include <span>
#include <vector>

#include <ember/common/error.hpp>
#include <ember/common/types.hpp>
#include <ember/debug/target.hpp>

namespace ember::debug::linux_perf {

// Per-thread state. The cached sample is populated by the event loop
// every time a HW BP/WP fires for that tid. get_regs() returns the
// cached snapshot — `present` carries the GPR-only bit since perf
// SAMPLE_REGS_USER doesn't reach into FP/SIMD/DR state.
struct PerfThreadState {
    bool      paused      = false;     // tracks SIGSTOP/SIGCONT we drove
    bool      has_sample  = false;     // any prior PERF_RECORD_SAMPLE seen
    Registers cached{};                // last sample regs
};

// One DR slot programmed via perf_event_open(PERF_TYPE_BREAKPOINT).
// fd is the perf handle, ring is the mmap'd ring buffer (data_pages
// + 1 metadata page). bp_id and wp_id are mutually exclusive — the
// non-zero one identifies the slot's kind for event dispatch.
struct PerfSlot {
    int           fd         = -1;
    void*         ring       = nullptr;     // (kRingDataPages + 1) * page_size
    std::size_t   ring_bytes = 0;
    bool          is_watch   = false;
    addr_t        addr       = 0;
    Breakpoint    bp_info{};                // valid when !is_watch
    Watchpoint    wp_info{};                // valid when  is_watch
};

inline constexpr int kMaxSlots      = 4;    // x86 has 4 DRs; kernel mirrors
inline constexpr int kRingDataPages = 4;    // 16 KiB sample buffer per slot

// One record peeled out of a perf mmap ring. data_tail has already
// been advanced past it by the time it's queued here, so the kernel
// won't redeliver. slot_idx records which DR slot it came from
// (samples are scoped to the fd they were generated on, but the
// kernel doesn't put that into the record itself).
struct PendingRecord {
    u32             type      = 0;
    int             slot_idx  = -1;
    std::vector<u8> body;            // bytes after the header
};

class PerfTarget final : public Target {
public:
    explicit PerfTarget(ProcessId pid, int pidfd, bool spawned) noexcept
        : pid_v_(pid), pidfd_(pidfd), spawned_(spawned) {}
    ~PerfTarget() override;

    [[nodiscard]] ProcessId             pid()     const noexcept override { return pid_v_; }
    [[nodiscard]] std::vector<ThreadId> threads() const override;
    [[nodiscard]] std::vector<LoadedImage> images() const override;

    [[nodiscard]] Result<void> detach() override;
    [[nodiscard]] Result<void> kill()   override;

    [[nodiscard]] Result<std::size_t> read_mem (addr_t va, std::span<std::byte>       out) override;
    [[nodiscard]] Result<std::size_t> write_mem(addr_t va, std::span<const std::byte> in)  override;

    [[nodiscard]] Result<Registers> get_regs(ThreadId tid) override;
    [[nodiscard]] Result<void>      set_regs(ThreadId tid, const Registers& r) override;

    [[nodiscard]] Result<BreakpointId>   set_breakpoint  (addr_t va) override;
    [[nodiscard]] Result<void>           clear_breakpoint(BreakpointId id) override;
    [[nodiscard]] std::vector<Breakpoint> breakpoints() const override;

    void clear_all_after_exec() override;

    [[nodiscard]] Result<WatchpointId>    set_watchpoint  (addr_t va, u8 size, WatchMode mode) override;
    [[nodiscard]] Result<void>            clear_watchpoint(WatchpointId id) override;
    [[nodiscard]] std::vector<Watchpoint> watchpoints() const override;

    [[nodiscard]] Result<void>
        set_syscall_catch(bool catch_all, std::span<const u32> nrs) override;
    [[nodiscard]] Result<void> clear_syscall_catch() override;
    [[nodiscard]] bool         is_syscall_catching() const override { return false; }
    [[nodiscard]] std::set<u32> syscall_catch_filter() const override { return {}; }
    [[nodiscard]] bool         syscall_catch_all() const override { return false; }

    [[nodiscard]] Result<void>  step      (ThreadId tid) override;
    [[nodiscard]] Result<void>  cont      ()             override;
    [[nodiscard]] Result<void>  interrupt ()             override;
    [[nodiscard]] Result<Event> wait_event()             override;

    // ---- Internal helpers (used by linux/perf_*.cpp impls) -----------
    [[nodiscard]] int  pidfd()   const noexcept { return pidfd_;   }
    [[nodiscard]] bool spawned() const noexcept { return spawned_; }

    [[nodiscard]] PerfSlot* slot(int idx) {
        return idx >= 0 && idx < kMaxSlots ? &slots_[idx] : nullptr;
    }
    [[nodiscard]] const PerfSlot* slot(int idx) const {
        return idx >= 0 && idx < kMaxSlots ? &slots_[idx] : nullptr;
    }

    // Locate a free slot or return -1 when all four DRs are in use.
    [[nodiscard]] int find_free_slot() const;

    // Find by id — bp_id when is_watch == false, wp_id otherwise.
    [[nodiscard]] int find_bp_slot(BreakpointId id) const;
    [[nodiscard]] int find_wp_slot(WatchpointId id) const;
    [[nodiscard]] int find_slot_by_fd(int fd) const;

    [[nodiscard]] BreakpointId next_bp_id() { return next_bp_id_++; }
    [[nodiscard]] WatchpointId next_wp_id() { return next_wp_id_++; }

    [[nodiscard]] PerfThreadState& thread_state(ThreadId tid);
    [[nodiscard]] const PerfThreadState* thread_state_lookup(ThreadId tid) const;
    [[nodiscard]] std::map<ThreadId, PerfThreadState>&       thread_state_map()       { return thread_state_; }
    [[nodiscard]] const std::map<ThreadId, PerfThreadState>& thread_state_map() const { return thread_state_; }

    void mark_dead() { dead_ = true; }
    [[nodiscard]] bool dead() const noexcept { return dead_; }

private:
    ProcessId    pid_v_   = 0;
    int          pidfd_   = -1;
    bool         spawned_ = false;     // launch_perf path → we're parent, can waitpid()
    bool         dead_    = false;     // EvExited/EvTerminated already emitted
    int          mem_fd_  = -1;        // /proc/<pid>/mem, lazy-opened by perf_mem.cpp

    PerfSlot     slots_[kMaxSlots]{};
    BreakpointId next_bp_id_ = 1;
    WatchpointId next_wp_id_ = 1;
    std::map<ThreadId, PerfThreadState> thread_state_;
    // Records drained from the kernel rings but not yet consumed by
    // wait_event(). One poll() wake-up may deliver many samples; the
    // public API hands back one event per call, so the rest queue
    // here until the next invocation.
    std::deque<PendingRecord> pending_records_;

    friend void perf_drain_into_target(PerfTarget&, int slot_idx, std::size_t page);

    friend class PerfMemFdAccess;
};

// File-local accessor so perf_mem.cpp can touch mem_fd_ without
// promoting it to the public surface (mirrors LinuxTarget pattern).
class PerfMemFdAccess {
public:
    [[nodiscard]] static int& fd_of(PerfTarget& t) { return t.mem_fd_; }
};

[[nodiscard]] Result<std::unique_ptr<Target>> launch_perf(const LaunchOptions&);
[[nodiscard]] Result<std::unique_ptr<Target>> attach_perf(ProcessId);

// ---- Slot installation primitives, shared between break/watch/event ----
//
// install_perf_event opens a perf_event_open(PERF_TYPE_BREAKPOINT) fd
// for the target pid, mmaps its ring buffer, and parks it in the
// first free slot. Returns the slot index on success. The caller
// fills in bp_info/wp_info, is_watch, and addr for the slot before
// the next event-loop iteration.
//
// bp_type: HW_BREAKPOINT_X | HW_BREAKPOINT_W | HW_BREAKPOINT_RW
// len_bytes: 1 (X), or 1/2/4/8 (W/RW)
[[nodiscard]] Result<int>
    install_perf_event(PerfTarget& t, addr_t addr, u32 bp_type, u8 len_bytes);

void close_slot(PerfSlot& s);

// Drain the mmap ring for slot_idx into the target's pending queue.
// Friended on PerfTarget so wait_event's helper has access without
// exposing the queue on the public surface.
void perf_drain_into_target(PerfTarget& t, int slot_idx, std::size_t page);

}  // namespace ember::debug::linux_perf

#pragma once

#include <cstddef>
#include <map>
#include <memory>
#include <set>
#include <span>
#include <unordered_map>
#include <vector>

#include <ember/common/error.hpp>
#include <ember/common/types.hpp>
#include <ember/debug/target.hpp>

namespace ember::debug::linux_ {

// Per-breakpoint bookkeeping kept alongside the public Breakpoint
// view — we need the original code byte to restore on clear and
// during step-over.
struct SoftwareBreakpoint {
    Breakpoint info{};
    u8         orig_byte = 0;
};

// Per-thread step-over state machine. The event loop owns these
// transitions; cont()/step() schedule, wait_event() resolves.
//
//   None                   running, or paused with no pending action
//   SteppingOverForCont    bp disabled, single-step issued; on
//                          completion, re-enable bp and PTRACE_CONT
//   SteppingOverForStep    same as above but surface EvSingleStep
//                          to the caller instead of resuming
//   Stepping               plain user single-step (no bp involved);
//                          on completion, surface EvSingleStep
enum class StepState : u8 {
    None,
    SteppingOverForCont,
    SteppingOverForStep,
    Stepping,
};

struct ThreadState {
    bool         paused         = true;
    BreakpointId parked_at_bp   = 0;     // 0 = not parked at any bp
    StepState    step_state     = StepState::None;
    addr_t       step_over_addr = 0;     // bp addr being stepped over
    int          pending_signal = 0;     // forwarded on next cont/step (0 = none)
    bool         in_syscall     = false; // toggles per syscall-stop: false→entry, true→exit
};

class LinuxTarget final : public Target {
public:
    explicit LinuxTarget(ProcessId pid_) noexcept : pid_v_(pid_) {}
    ~LinuxTarget() override;

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
    [[nodiscard]] bool         is_syscall_catching() const override
        { return syscall_catching_; }
    [[nodiscard]] std::set<u32> syscall_catch_filter() const override
        { return syscall_nrs_; }
    [[nodiscard]] bool         syscall_catch_all() const override
        { return syscall_catch_all_; }

    [[nodiscard]] Result<void>  step      (ThreadId tid) override;
    [[nodiscard]] Result<void>  cont      ()             override;
    [[nodiscard]] Result<void>  interrupt ()             override;
    [[nodiscard]] Result<Event> wait_event()             override;

    // Internal helpers used by the linux/*.cpp impl files.
    void add_thread   (ThreadId tid);
    void drop_thread  (ThreadId tid);
    void mark_attached(bool v)                        { attached_ = v; }
    [[nodiscard]] bool is_attached() const noexcept   { return attached_; }

    // Breakpoint table accessors. The .cpp files implementing event
    // handling and step-over need to consult these.
    [[nodiscard]] SoftwareBreakpoint* find_bp_at(addr_t va);
    [[nodiscard]] SoftwareBreakpoint* find_bp_id(BreakpointId id);
    [[nodiscard]] const std::unordered_map<BreakpointId, SoftwareBreakpoint>&
        bp_table() const { return bps_; }

    // Hardware-watchpoint slot table. Index 0..3 maps directly to DR0..DR3;
    // an empty slot has id == 0. ptrace_event.cpp consults this on each
    // SIGTRAP to decode DR6 hits into EvWatchpointHit.
    struct WpSlot {
        WatchpointId id   = 0;
        Watchpoint   info{};
    };
    [[nodiscard]] WpSlot* wp_slot(int idx) { return idx >= 0 && idx < 4 ? &wp_[idx] : nullptr; }
    [[nodiscard]] const WpSlot* wp_slot(int idx) const { return idx >= 0 && idx < 4 ? &wp_[idx] : nullptr; }

    // Thread state — exposed for ptrace_event.cpp's loop to consult
    // and update without duplicating the bookkeeping.
    [[nodiscard]] ThreadState&       thread_state(ThreadId tid);
    [[nodiscard]] const ThreadState* thread_state_lookup(ThreadId tid) const;
    [[nodiscard]] std::map<ThreadId, ThreadState>&       thread_state_map()       { return thread_state_; }
    [[nodiscard]] const std::map<ThreadId, ThreadState>& thread_state_map() const { return thread_state_; }

private:
    ProcessId                pid_v_ = 0;
    std::map<ThreadId, ThreadState> thread_state_;
    std::unordered_map<BreakpointId, SoftwareBreakpoint> bps_;
    BreakpointId             next_bp_id_ = 1;
    WpSlot                   wp_[4]{};
    WatchpointId             next_wp_id_ = 1;
    bool                     syscall_catching_  = false;
    bool                     syscall_catch_all_ = false;
    std::set<u32>            syscall_nrs_;
    bool                     attached_   = false;
    // Lazily opened by ptrace_mem.cpp. Closed by the destructor and
    // by detach()/kill(). -1 means "not yet opened".
    int                      mem_fd_     = -1;
    friend class MemFdAccess;
};

// File-local helper used by ptrace_mem.cpp to touch the otherwise-
// private mem_fd_ without making it part of the public surface.
class MemFdAccess {
public:
    [[nodiscard]] static int& fd_of(LinuxTarget& t) { return t.mem_fd_; }
};

[[nodiscard]] Result<std::unique_ptr<Target>> launch_linux(const LaunchOptions&);
[[nodiscard]] Result<std::unique_ptr<Target>> attach_linux(ProcessId);

// Breakpoint primitives shared between ptrace_break.cpp (set/clear)
// and ptrace_event.cpp (step-over). Both poke a single byte via the
// target's write_mem; disable_bp restores the original instruction
// byte, enable_bp re-arms with 0xCC.
[[nodiscard]] Result<void> disable_bp(LinuxTarget& t, addr_t va, u8 orig_byte);
[[nodiscard]] Result<void> enable_bp (LinuxTarget& t, addr_t va);

// Hardware-watchpoint helpers exposed to ptrace_event.cpp / ptrace_proc.cpp.
// dr6_consume_hit returns 0..3 if a DR-watch fired (clearing DR6),
// or -1 otherwise. rearm_watchpoints_on_new_thread re-applies the
// active DR slots to a freshly-cloned thread (best-effort).
int  dr6_consume_hit(ThreadId tid);
void rearm_watchpoints_on_new_thread(LinuxTarget& t, ThreadId tid);

}  // namespace ember::debug::linux_

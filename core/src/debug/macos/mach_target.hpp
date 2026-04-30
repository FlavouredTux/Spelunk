#pragma once

// macOS / Darwin debugger backend, x86-64 only.
//
// Mirrors core/src/debug/linux/ptrace_target.hpp 1:1 in terms of the
// surface it exposes. The implementation is built on Mach IPC: the
// kernel-supplied `task_for_pid` gateway gives us a port that
// represents the tracee's address space, registers, threads, and
// exception delivery. ptrace plays no role here beyond the optional
// PT_TRACE_ME signal-routing variant — every primitive uses
// mach_vm_* / thread_get_state / mach_msg.

#include <cstddef>
#include <map>
#include <memory>
#include <span>
#include <unordered_map>
#include <vector>

#include <ember/common/error.hpp>
#include <ember/common/types.hpp>
#include <ember/debug/target.hpp>

namespace ember::debug::mach_ {

struct SoftwareBreakpoint {
    Breakpoint info{};
    u8         orig_byte = 0;
};

// Same step-over machine as the Linux backend; the only difference
// is who holds the "currently parked" thread between cont/step
// (Mach-side it's the pending exception reply that gates resumption).
enum class StepState : u8 {
    None,
    SteppingOverForCont,
    SteppingOverForStep,
    Stepping,
};

// Per-thread state. Beyond the shared bookkeeping, Mach also needs
// us to retain the exception-message header bits so cont()/step()
// can construct a reply that the kernel routes back to the tracee
// to actually resume it.
struct ThreadState {
    bool         paused         = true;
    BreakpointId parked_at_bp   = 0;
    StepState    step_state     = StepState::None;
    addr_t       step_over_addr = 0;
    int          pending_signal = 0;

    // Held verbatim from the most recent exception_raise message so
    // the resume reply has the matching remote-port + msgh_id + bits.
    bool reply_pending     = false;
    u32  reply_remote_port = 0;   // mach_port_t (mach_port_name_t is u32)
    u32  reply_local_port  = 0;
    u32  reply_msgh_bits   = 0;
    int  reply_msgh_id     = 0;
};

class MachOTarget final : public Target {
public:
    // task_port and exc_port are mach_port_name_t — u32 in our task's
    // port-name space. We pass them as u32 to keep this header free
    // of <mach/mach.h>; the impl translates back at call sites.
    MachOTarget(ProcessId pid_v, u32 task_port_v, u32 exc_port_v) noexcept
        : pid_v_(pid_v), task_port_(task_port_v), exc_port_(exc_port_v) {}
    ~MachOTarget() override;

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

    [[nodiscard]] Result<WatchpointId>    set_watchpoint  (addr_t va, u8 size, WatchMode mode) override;
    [[nodiscard]] Result<void>            clear_watchpoint(WatchpointId id) override;
    [[nodiscard]] std::vector<Watchpoint> watchpoints() const override;

    [[nodiscard]] Result<void>  step      (ThreadId tid) override;
    [[nodiscard]] Result<void>  cont      ()             override;
    [[nodiscard]] Result<void>  interrupt ()             override;
    [[nodiscard]] Result<Event> wait_event()             override;

    // Internal helpers used by the macos/*.cpp impl files.
    void add_thread   (ThreadId tid);
    void drop_thread  (ThreadId tid);
    void mark_attached(bool v)                        { attached_ = v; }
    [[nodiscard]] bool is_attached() const noexcept   { return attached_; }

    [[nodiscard]] u32 task_port() const noexcept { return task_port_; }
    [[nodiscard]] u32 exc_port()  const noexcept { return exc_port_;  }
    void clear_task_port() { task_port_ = 0; }
    void clear_exc_port()  { exc_port_  = 0; }

    [[nodiscard]] SoftwareBreakpoint* find_bp_at(addr_t va);
    [[nodiscard]] SoftwareBreakpoint* find_bp_id(BreakpointId id);
    [[nodiscard]] const std::unordered_map<BreakpointId, SoftwareBreakpoint>&
        bp_table() const { return bps_; }

    [[nodiscard]] ThreadState&       thread_state(ThreadId tid);
    [[nodiscard]] const ThreadState* thread_state_lookup(ThreadId tid) const;
    [[nodiscard]] std::map<ThreadId, ThreadState>&       thread_state_map()       { return thread_state_; }
    [[nodiscard]] const std::map<ThreadId, ThreadState>& thread_state_map() const { return thread_state_; }

private:
    ProcessId pid_v_     = 0;
    u32       task_port_ = 0;   // task_for_pid result; mach_port_deallocate on dtor
    u32       exc_port_  = 0;   // receive-right port; mach_port_destroy on dtor
    std::map<ThreadId, ThreadState>                      thread_state_;
    std::unordered_map<BreakpointId, SoftwareBreakpoint> bps_;
    BreakpointId next_bp_id_ = 1;
    bool         attached_   = false;
};

[[nodiscard]] Result<std::unique_ptr<Target>> launch_macos(const LaunchOptions&);
[[nodiscard]] Result<std::unique_ptr<Target>> attach_macos(ProcessId);

// Breakpoint primitives shared between mach_break.cpp (set/clear)
// and mach_event.cpp (step-over). Same shape as the Linux helpers.
[[nodiscard]] Result<void> disable_bp(MachOTarget& t, addr_t va, u8 orig_byte);
[[nodiscard]] Result<void> enable_bp (MachOTarget& t, addr_t va);

}  // namespace ember::debug::mach_

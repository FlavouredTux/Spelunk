#pragma once

#include <cstddef>
#include <memory>
#include <set>
#include <span>
#include <string>
#include <vector>

#include <ember/common/error.hpp>
#include <ember/common/types.hpp>
#include <ember/debug/breakpoint.hpp>
#include <ember/debug/event.hpp>
#include <ember/debug/regs.hpp>
#include <ember/debug/types.hpp>

namespace ember::debug {

struct LaunchOptions {
    std::string              program;        // path to the executable
    std::vector<std::string> args;           // argv excluding argv[0]
    std::vector<std::string> env;            // empty → inherit parent's environ
    std::string              cwd;            // empty → inherit
    bool                     stop_at_entry = true;  // first wait_event() yields EvStopped at the first user instruction
};

struct LoadedImage {
    std::string path;
    addr_t      base = 0;     // runtime load address (slide already applied)
};

class Target {
public:
    virtual ~Target() = default;

    Target() = default;
    Target(const Target&)            = delete;
    Target& operator=(const Target&) = delete;
    Target(Target&&)                 = delete;
    Target& operator=(Target&&)      = delete;

    [[nodiscard]] virtual ProcessId             pid()     const noexcept = 0;
    [[nodiscard]] virtual std::vector<ThreadId> threads() const          = 0;
    [[nodiscard]] virtual std::vector<LoadedImage> images() const        = 0;

    [[nodiscard]] virtual Result<void> detach() = 0;
    [[nodiscard]] virtual Result<void> kill()   = 0;

    // Bytes actually transferred is returned; short reads/writes are not
    // an error (they happen at unmapped-page boundaries).
    [[nodiscard]] virtual Result<std::size_t> read_mem (addr_t va, std::span<std::byte>       out) = 0;
    [[nodiscard]] virtual Result<std::size_t> write_mem(addr_t va, std::span<const std::byte> in)  = 0;

    [[nodiscard]] virtual Result<Registers> get_regs(ThreadId tid)                       = 0;
    [[nodiscard]] virtual Result<void>      set_regs(ThreadId tid, const Registers& r)   = 0;

    [[nodiscard]] virtual Result<BreakpointId>   set_breakpoint  (addr_t va)             = 0;
    [[nodiscard]] virtual Result<void>           clear_breakpoint(BreakpointId id)       = 0;
    [[nodiscard]] virtual std::vector<Breakpoint> breakpoints() const                    = 0;

    // Drop all kernel-side breakpoint / watchpoint state without
    // attempting to restore the original instruction byte. Used after
    // PTRACE_EVENT_EXEC where the previous address space is gone and
    // the int3 patches went with it; touching the recorded VAs would
    // either fail or, worse, corrupt unrelated bytes in the new image
    // that happened to land at the same address.
    virtual void clear_all_after_exec() = 0;

    // Hardware data watchpoints (DR0..DR3 on x86; up to 4 active).
    // size must be 1, 2, 4, or 8; addr must be aligned to size.
    [[nodiscard]] virtual Result<WatchpointId>    set_watchpoint  (addr_t va, u8 size, WatchMode mode) = 0;
    [[nodiscard]] virtual Result<void>            clear_watchpoint(WatchpointId id) = 0;
    [[nodiscard]] virtual std::vector<Watchpoint> watchpoints() const = 0;

    // Syscall catchpoint. When active, every `syscall` raises
    // EvSyscallStop on entry and exit. catch_all=true catches all;
    // otherwise only the numbers in `nrs` surface (others fall
    // through to the next PTRACE_SYSCALL silently).
    [[nodiscard]] virtual Result<void>
    set_syscall_catch(bool catch_all, std::span<const u32> nrs) = 0;
    [[nodiscard]] virtual Result<void> clear_syscall_catch()    = 0;
    [[nodiscard]] virtual bool         is_syscall_catching() const = 0;
    [[nodiscard]] virtual std::set<u32> syscall_catch_filter() const = 0;
    [[nodiscard]] virtual bool         syscall_catch_all() const = 0;

    [[nodiscard]] virtual Result<void>  step      (ThreadId tid) = 0;
    [[nodiscard]] virtual Result<void>  cont      ()             = 0;
    [[nodiscard]] virtual Result<void>  interrupt ()             = 0;
    [[nodiscard]] virtual Result<Event> wait_event()             = 0;
};

// Platform dispatch. Linux: ptrace. macOS/Windows: NotImplemented for v0.
[[nodiscard]] Result<std::unique_ptr<Target>> launch(const LaunchOptions&);
[[nodiscard]] Result<std::unique_ptr<Target>> attach(ProcessId pid);

}  // namespace ember::debug

#pragma once

#include <cstddef>
#include <memory>
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

    [[nodiscard]] virtual Result<void>  step      (ThreadId tid) = 0;
    [[nodiscard]] virtual Result<void>  cont      ()             = 0;
    [[nodiscard]] virtual Result<void>  interrupt ()             = 0;
    [[nodiscard]] virtual Result<Event> wait_event()             = 0;
};

// Platform dispatch. Linux: ptrace. macOS/Windows: NotImplemented for v0.
[[nodiscard]] Result<std::unique_ptr<Target>> launch(const LaunchOptions&);
[[nodiscard]] Result<std::unique_ptr<Target>> attach(ProcessId pid);

}  // namespace ember::debug

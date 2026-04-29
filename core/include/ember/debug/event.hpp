#pragma once

#include <variant>

#include <ember/common/types.hpp>
#include <ember/debug/breakpoint.hpp>
#include <ember/debug/types.hpp>

namespace ember::debug {

// Hit a software breakpoint we placed. PC is already adjusted back to
// the breakpoint instruction (ptrace stops one byte past the int3).
struct EvBreakpointHit { ThreadId tid; BreakpointId id; addr_t pc; };

// Single-step finished — used by step() and the breakpoint step-over.
struct EvSingleStep    { ThreadId tid; addr_t pc; };

// Tracee received a signal we don't intercept (SIGSEGV, SIGFPE, …).
// The signal is held; cont() forwards it back unless the caller clears
// it via set_regs / explicit suppress (deferred for v0).
struct EvSignal        { ThreadId tid; int signo; };

// Generic stop with no cause we recognised — used after attach() and
// at launch entry when stop_at_entry=true.
struct EvStopped       { ThreadId tid; addr_t pc; };

// A new thread appeared (PTRACE_EVENT_CLONE). Already attached and
// stopped; the next cont() resumes it alongside its siblings.
struct EvThreadCreated { ThreadId tid; };
struct EvThreadExited  { ThreadId tid; int code; };

// A new image entered the address space. v0 emits this once at launch
// for the main executable; dynamic loader instrumentation comes later.
struct EvImageLoaded   { addr_t base; };

struct EvExited        { int code; };
struct EvTerminated    { int signo; };

using Event = std::variant<
    EvBreakpointHit,
    EvSingleStep,
    EvSignal,
    EvStopped,
    EvThreadCreated,
    EvThreadExited,
    EvImageLoaded,
    EvExited,
    EvTerminated
>;

}  // namespace ember::debug

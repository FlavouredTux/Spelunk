#pragma once

#include <variant>

#include <ember/common/types.hpp>
#include <ember/debug/breakpoint.hpp>
#include <ember/debug/types.hpp>

namespace ember::debug {

// Hit a software breakpoint we placed. PC is already adjusted back to
// the breakpoint instruction (ptrace stops one byte past the int3).
struct EvBreakpointHit { ThreadId tid; BreakpointId id; addr_t pc; };

// A hardware data watchpoint fired. PC is the *next* instruction
// (data watches trap after the access completes), `addr` is the
// watched VA from the DR slot that fired, `slot` is 0..3 — useful
// when the user wants to know which DR caught the hit.
struct EvWatchpointHit {
    ThreadId     tid;
    WatchpointId id;
    addr_t       pc;
    addr_t       addr;
    u8           slot;
};

// Tracee is paused at a `syscall` instruction (entry or exit) by the
// catchpoint mechanism. `nr` is the original syscall number from
// orig_rax (preserved across both stops). PC points at the syscall
// instruction on entry, at the instruction after it on exit.
struct EvSyscallStop {
    ThreadId tid;
    u32      nr;
    addr_t   pc;
    bool     entry;  // true = about to execute syscall; false = it just returned
};

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

// The tracee called execve(2). The address space has been replaced —
// every breakpoint and watchpoint set in the previous image now
// points into stale (or freshly-mapped, semantically unrelated)
// memory. Caller is expected to drop kernel-side bp/wp state via
// the target's clear_*_after_exec helpers, recompute slides, and
// re-arm anything it wants persisted across the exec boundary.
// The thread is left paused at the new entry point so the caller
// gets a chance to re-arm before the new program runs.
struct EvExec         { ThreadId tid; addr_t pc; };

struct EvExited        { int code; };
struct EvTerminated    { int signo; };

using Event = std::variant<
    EvBreakpointHit,
    EvWatchpointHit,
    EvSyscallStop,
    EvSingleStep,
    EvSignal,
    EvStopped,
    EvThreadCreated,
    EvThreadExited,
    EvImageLoaded,
    EvExec,
    EvExited,
    EvTerminated
>;

}  // namespace ember::debug

// Event loop + execution control for the Linux ptrace backend.
//
// The state machine for breakpoint step-over lives here. cont() and
// step() schedule (mark per-thread step_state, possibly issue a
// PTRACE_SINGLESTEP); wait_event() resolves (decodes the next stop,
// re-enables the bp if we were mid step-over, decides whether to
// surface the event or loop internally).

#include "ptrace_target.hpp"

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <string>

#include <signal.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>

namespace ember::debug::linux_ {

namespace {

[[nodiscard]] Error errno_io(const char* op) {
    return Error::io(std::string(op) + ": " + std::strerror(errno));
}

[[nodiscard]] void* sig_data(int sig) {
    return reinterpret_cast<void*>(static_cast<std::uintptr_t>(sig));
}

[[nodiscard]] addr_t read_rip(pid_t kt) {
    user_regs_struct ur{};
    if (::ptrace(PTRACE_GETREGS, kt, nullptr, &ur) < 0) return 0;
    return ur.rip;
}

}  // namespace

Result<void> LinuxTarget::step(ThreadId tid) {
    const pid_t kt = static_cast<pid_t>(tid);
    ThreadState& ts = thread_state(tid);
    if (!ts.paused) {
        return std::unexpected(Error::invalid_format(
            "debugger: step: thread is not paused"));
    }

    if (ts.parked_at_bp != 0) {
        auto* bp = find_bp_id(ts.parked_at_bp);
        if (!bp) {
            return std::unexpected(Error::invalid_format(
                "debugger: step: parked-at-bp id no longer exists"));
        }
        if (auto rv = disable_bp(*this, bp->info.addr, bp->orig_byte); !rv) {
            return std::unexpected(std::move(rv).error());
        }
        ts.step_over_addr = bp->info.addr;
        ts.step_state     = StepState::SteppingOverForStep;
    } else {
        ts.step_state = StepState::Stepping;
    }

    const int sig = ts.pending_signal;
    ts.pending_signal = 0;
    if (::ptrace(PTRACE_SINGLESTEP, kt, nullptr, sig_data(sig)) < 0) {
        return std::unexpected(errno_io("singlestep"));
    }
    ts.paused = false;
    return {};
}

Result<void> LinuxTarget::cont() {
    for (auto& [tid, ts] : thread_state_map()) {
        if (!ts.paused) continue;
        const pid_t kt = static_cast<pid_t>(tid);

        if (ts.parked_at_bp != 0) {
            auto* bp = find_bp_id(ts.parked_at_bp);
            if (bp) {
                if (auto rv = disable_bp(*this, bp->info.addr, bp->orig_byte); !rv) {
                    return std::unexpected(std::move(rv).error());
                }
                ts.step_over_addr = bp->info.addr;
                ts.step_state     = StepState::SteppingOverForCont;
                const int sig = ts.pending_signal;
                ts.pending_signal = 0;
                if (::ptrace(PTRACE_SINGLESTEP, kt, nullptr, sig_data(sig)) < 0) {
                    return std::unexpected(errno_io("singlestep (cont/step-over)"));
                }
                ts.paused = false;
                continue;
            }
            // bp vanished from the table while we were parked — nothing
            // to step over, just resume.
            ts.parked_at_bp   = 0;
            ts.step_over_addr = 0;
            ts.step_state     = StepState::None;
        }

        const int sig = ts.pending_signal;
        ts.pending_signal = 0;
        if (::ptrace(PTRACE_CONT, kt, nullptr, sig_data(sig)) < 0) {
            return std::unexpected(errno_io("cont"));
        }
        ts.paused = false;
    }
    return {};
}

Result<void> LinuxTarget::interrupt() {
    for (auto& [tid, ts] : thread_state_map()) {
        if (ts.paused) continue;
        if (::ptrace(PTRACE_INTERRUPT, static_cast<pid_t>(tid),
                     nullptr, nullptr) < 0) {
            if (errno != ESRCH) return std::unexpected(errno_io("interrupt"));
        }
    }
    return {};
}

Result<Event> LinuxTarget::wait_event() {
    while (true) {
        int status = 0;
        const pid_t kt = ::waitpid(-1, &status, __WALL);
        if (kt < 0) {
            if (errno == EINTR) continue;
            return std::unexpected(errno_io("waitpid"));
        }
        const ThreadId tid = static_cast<ThreadId>(kt);

        if (WIFEXITED(status)) {
            const int code = WEXITSTATUS(status);
            const bool was_main = (static_cast<pid_t>(pid()) == kt);
            drop_thread(tid);
            if (was_main) {
                mark_attached(false);
                return Event{EvExited{code}};
            }
            return Event{EvThreadExited{tid, code}};
        }
        if (WIFSIGNALED(status)) {
            const int sig = WTERMSIG(status);
            const bool was_main = (static_cast<pid_t>(pid()) == kt);
            drop_thread(tid);
            if (was_main) {
                mark_attached(false);
                return Event{EvTerminated{sig}};
            }
            return Event{EvThreadExited{tid, -sig}};
        }
        if (!WIFSTOPPED(status)) {
            // WIFCONTINUED or some unknown status — drop and loop.
            continue;
        }

        ThreadState& ts = thread_state(tid);
        ts.paused = true;

        const int stopsig   = WSTOPSIG(status);
        const int eventcode = (status >> 16) & 0xFFFF;

        // ---- ptrace events (CLONE / FORK / VFORK / EXEC / EXIT / STOP) ----
        if (stopsig == SIGTRAP && eventcode != 0) {
            if (eventcode == PTRACE_EVENT_CLONE ||
                eventcode == PTRACE_EVENT_FORK  ||
                eventcode == PTRACE_EVENT_VFORK) {
                unsigned long new_id = 0;
                ::ptrace(PTRACE_GETEVENTMSG, kt, nullptr, &new_id);
                if (::ptrace(PTRACE_CONT, kt, nullptr, nullptr) == 0) {
                    ts.paused = false;
                }
                if (eventcode == PTRACE_EVENT_CLONE) {
                    // The new thread is part of our process. The kernel
                    // already attached it via PTRACE_O_TRACECLONE; we'll
                    // see its initial stop next time around the loop.
                    const auto new_tid = static_cast<ThreadId>(new_id);
                    add_thread(new_tid);
                    // Cloned thread starts with empty DR state; mirror
                    // the parent's active watchpoints so cross-thread
                    // coverage matches the user's expectation.
                    rearm_watchpoints_on_new_thread(*this, new_tid);
                    return Event{EvThreadCreated{new_tid}};
                }
                // FORK/VFORK spawn separate processes that we don't track.
                continue;
            }
            if (eventcode == PTRACE_EVENT_EXEC) {
                if (::ptrace(PTRACE_CONT, kt, nullptr, nullptr) == 0) {
                    ts.paused = false;
                }
                return Event{EvImageLoaded{0}};
            }
            if (eventcode == PTRACE_EVENT_EXIT) {
                // Thread is on its way out; resume so it can finish and
                // then we'll see WIFEXITED on the next round.
                if (::ptrace(PTRACE_CONT, kt, nullptr, nullptr) == 0) {
                    ts.paused = false;
                }
                continue;
            }
            if (eventcode == PTRACE_EVENT_STOP) {
                // PTRACE_INTERRUPT or initial seize-stop. PC = current rip.
                return Event{EvStopped{tid, read_rip(kt)}};
            }
            // Unrecognised event — fall through to generic signal.
            return Event{EvSignal{tid, stopsig}};
        }

        // ---- regular SIGTRAP: int3 hit OR step completion ----
        if (stopsig == SIGTRAP) {
            switch (ts.step_state) {
                case StepState::SteppingOverForCont: {
                    const addr_t va = ts.step_over_addr;
                    if (auto rv = enable_bp(*this, va); !rv) {
                        ts.step_state = StepState::None;
                        return std::unexpected(std::move(rv).error());
                    }
                    ts.parked_at_bp   = 0;
                    ts.step_over_addr = 0;
                    ts.step_state     = StepState::None;
                    if (::ptrace(PTRACE_CONT, kt, nullptr, nullptr) < 0) {
                        return std::unexpected(errno_io("cont (post step-over)"));
                    }
                    ts.paused = false;
                    continue;  // wait for the next real event
                }
                case StepState::SteppingOverForStep: {
                    const addr_t va = ts.step_over_addr;
                    if (auto rv = enable_bp(*this, va); !rv) {
                        ts.step_state = StepState::None;
                        return std::unexpected(std::move(rv).error());
                    }
                    ts.parked_at_bp   = 0;
                    ts.step_over_addr = 0;
                    ts.step_state     = StepState::None;
                    return Event{EvSingleStep{tid, read_rip(kt)}};
                }
                case StepState::Stepping: {
                    ts.step_state = StepState::None;
                    return Event{EvSingleStep{tid, read_rip(kt)}};
                }
                case StepState::None:
                    break;
            }

            // Hardware-watchpoint hit? DR6's B0..B3 stick when a DR
            // slot fires. Check before falling through to the int3
            // path, since a watch hit's PC isn't `rip-1` and never
            // matches a software bp address.
            if (const int slot = dr6_consume_hit(tid); slot >= 0) {
                if (const auto* w = wp_slot(slot); w && w->id != 0) {
                    user_regs_struct ur{};
                    addr_t pc = 0;
                    if (::ptrace(PTRACE_GETREGS, kt, nullptr, &ur) == 0) pc = ur.rip;
                    return Event{EvWatchpointHit{
                        tid, w->id, pc, w->info.addr,
                        static_cast<u8>(slot)}};
                }
            }

            // No step in flight — must be a fresh int3 hit.
            user_regs_struct ur{};
            if (::ptrace(PTRACE_GETREGS, kt, nullptr, &ur) == 0) {
                const addr_t hit_pc = ur.rip - 1;
                if (auto* bp = find_bp_at(hit_pc)) {
                    ur.rip = hit_pc;
                    ::ptrace(PTRACE_SETREGS, kt, nullptr, &ur);
                    ts.parked_at_bp = bp->info.id;
                    return Event{EvBreakpointHit{tid, bp->info.id, hit_pc}};
                }
                return Event{EvSignal{tid, stopsig}};
            }
            return Event{EvSignal{tid, stopsig}};
        }

        // ---- other signal (SIGSEGV/SIGBUS/SIGINT/etc.) ----
        // Hold for forwarding on the next cont/step so the tracee
        // observes the signal it would have received without us.
        ts.pending_signal = stopsig;
        return Event{EvSignal{tid, stopsig}};
    }
}

}  // namespace ember::debug::linux_

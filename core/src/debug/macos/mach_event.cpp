// Event loop + execution control for the macOS Mach backend.
//
// Mach delivers traps as IPC messages on the receive port we
// registered via task_set_exception_ports. wait_event() blocks on
// mach_msg(MACH_RCV_MSG, ...); when a message arrives we parse the
// canonical exception_raise layout to recover thread / exception /
// code, translate to our Event variant, and stash the reply header
// in the per-thread state so cont()/step() can resume the tracee
// by sending back a KERN_SUCCESS reply (or a larger msgh_id-101 for
// "we did NOT handle it, send to next handler" — unused here).
//
// Step on x86-64 is done by setting the TF (single-step) bit in
// RFLAGS via thread_set_state, then sending the resume reply. The
// next instruction completes and the kernel raises EXC_BREAKPOINT
// with subcode EXC_I386_SGL.
//
// Step-over a software breakpoint mirrors the Linux state machine:
//   * disable bp byte
//   * set TF, schedule one of {SteppingOverForCont,
//     SteppingOverForStep}
//   * resume via reply
//   * next exception is the single-step trap → re-enable bp byte,
//     clear TF if cont, surface EvSingleStep if step.

#include "mach_target.hpp"

#include <cstddef>
#include <cstring>
#include <format>
#include <string>

#include <signal.h>
#include <sys/types.h>

#include <mach/mach.h>
#include <mach/exception_types.h>
#include <mach/i386/exception.h>
#include <mach/mach_port.h>
#include <mach/task.h>
#include <mach/thread_act.h>
#include <mach/thread_state.h>
#include <mach/i386/thread_status.h>

namespace ember::debug::mach_ {

namespace {

[[nodiscard]] Error mach_io(const char* op, kern_return_t kr) {
    return Error::io(std::format("{}: {}", op, ::mach_error_string(kr)));
}

constexpr u64 kRflagsTF = 0x100;   // single-step trap flag

// Layout of the message we receive when EXCEPTION_DEFAULT is the
// behaviour. From mach/exc.defs (canonical IPC interface). We don't
// pull in MIG-generated headers so we hand-define the layout.
//
// Two ports come inline (out-of-line port descriptors): the thread
// that raised the exception and the task. Then the typed payload.
// codeCnt for x86-64 is 2 (subcode + address).
#pragma pack(push, 4)
struct exc_request_msg_t {
    mach_msg_header_t          Head;
    mach_msg_body_t            msgh_body;
    mach_msg_port_descriptor_t thread;
    mach_msg_port_descriptor_t task;
    NDR_record_t               NDR;
    exception_type_t           exception;
    mach_msg_type_number_t     codeCnt;
    int64_t                    code[2];
    // Trailer follows; size depends on what we requested in mach_msg
    char                       trailer[64];
};

struct exc_reply_msg_t {
    mach_msg_header_t Head;
    NDR_record_t      NDR;
    kern_return_t     RetCode;
};
#pragma pack(pop)

constexpr int kExcRequestId = 2401;   // mach_exc_server msgh_id for exception_raise
constexpr int kExcReplyId   = 2501;   // 2401 + 100 (Mach reply convention)

void stash_reply_header(ThreadState& ts, const mach_msg_header_t& h) {
    ts.reply_remote_port = h.msgh_remote_port;
    ts.reply_local_port  = h.msgh_local_port;
    ts.reply_msgh_bits   = h.msgh_bits;
    ts.reply_msgh_id     = h.msgh_id;
    ts.reply_pending     = true;
}

[[nodiscard]] Result<void>
send_reply(ThreadState& ts, kern_return_t ret_code) {
    if (!ts.reply_pending) return {};

    exc_reply_msg_t reply{};
    reply.Head.msgh_bits = MACH_MSGH_BITS(
        MACH_MSGH_BITS_REMOTE(ts.reply_msgh_bits), 0);
    reply.Head.msgh_size        = sizeof(reply);
    reply.Head.msgh_remote_port = ts.reply_remote_port;
    reply.Head.msgh_local_port  = MACH_PORT_NULL;
    reply.Head.msgh_id          = kExcReplyId;
    reply.NDR                   = NDR_record;
    reply.RetCode               = ret_code;

    kern_return_t kr = ::mach_msg(
        &reply.Head,
        MACH_SEND_MSG | MACH_SEND_TIMEOUT,
        sizeof(reply),
        0,
        MACH_PORT_NULL,
        0,
        MACH_PORT_NULL);
    ts.reply_pending = false;
    if (kr != MACH_MSG_SUCCESS) {
        return std::unexpected(mach_io("mach_msg (reply)", kr));
    }
    return {};
}

[[nodiscard]] addr_t read_rip(thread_act_t th) {
    x86_thread_state64_t s{};
    mach_msg_type_number_t cnt = x86_THREAD_STATE64_COUNT;
    if (::thread_get_state(th, x86_THREAD_STATE64,
            reinterpret_cast<thread_state_t>(&s), &cnt) != KERN_SUCCESS) {
        return 0;
    }
    return s.__rip;
}

[[nodiscard]] Result<void> set_tf(thread_act_t th, bool enable) {
    x86_thread_state64_t s{};
    mach_msg_type_number_t cnt = x86_THREAD_STATE64_COUNT;
    kern_return_t kr = ::thread_get_state(th, x86_THREAD_STATE64,
        reinterpret_cast<thread_state_t>(&s), &cnt);
    if (kr != KERN_SUCCESS) return std::unexpected(mach_io("thread_get_state (TF)", kr));
    if (enable) s.__rflags |= kRflagsTF;
    else        s.__rflags &= ~kRflagsTF;
    kr = ::thread_set_state(th, x86_THREAD_STATE64,
        reinterpret_cast<thread_state_t>(&s), x86_THREAD_STATE64_COUNT);
    if (kr != KERN_SUCCESS) return std::unexpected(mach_io("thread_set_state (TF)", kr));
    return {};
}

[[nodiscard]] Result<void> rewind_rip(thread_act_t th, addr_t to) {
    x86_thread_state64_t s{};
    mach_msg_type_number_t cnt = x86_THREAD_STATE64_COUNT;
    kern_return_t kr = ::thread_get_state(th, x86_THREAD_STATE64,
        reinterpret_cast<thread_state_t>(&s), &cnt);
    if (kr != KERN_SUCCESS) return std::unexpected(mach_io("thread_get_state (rewind)", kr));
    s.__rip = to;
    kr = ::thread_set_state(th, x86_THREAD_STATE64,
        reinterpret_cast<thread_state_t>(&s), x86_THREAD_STATE64_COUNT);
    if (kr != KERN_SUCCESS) return std::unexpected(mach_io("thread_set_state (rewind)", kr));
    return {};
}

}  // namespace

Result<void> MachOTarget::step(ThreadId tid) {
    ThreadState& ts = thread_state(tid);
    if (!ts.paused) {
        return std::unexpected(Error::invalid_format(
            "debugger: step: thread is not paused"));
    }
    const thread_act_t th = static_cast<thread_act_t>(tid);

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
    if (auto rv = set_tf(th, true); !rv) return rv;
    if (auto rv = send_reply(ts, KERN_SUCCESS); !rv) return rv;
    ts.paused = false;
    return {};
}

Result<void> MachOTarget::cont() {
    for (auto& [tid, ts] : thread_state_map()) {
        if (!ts.paused) continue;
        const thread_act_t th = static_cast<thread_act_t>(tid);

        if (ts.parked_at_bp != 0) {
            auto* bp = find_bp_id(ts.parked_at_bp);
            if (bp) {
                if (auto rv = disable_bp(*this, bp->info.addr, bp->orig_byte); !rv) {
                    return std::unexpected(std::move(rv).error());
                }
                ts.step_over_addr = bp->info.addr;
                ts.step_state     = StepState::SteppingOverForCont;
                if (auto rv = set_tf(th, true); !rv) return rv;
                if (auto rv = send_reply(ts, KERN_SUCCESS); !rv) return rv;
                ts.paused = false;
                continue;
            }
            ts.parked_at_bp   = 0;
            ts.step_over_addr = 0;
            ts.step_state     = StepState::None;
        }

        if (auto rv = send_reply(ts, KERN_SUCCESS); !rv) return rv;
        ts.paused = false;
    }
    return {};
}

Result<void> MachOTarget::interrupt() {
    // task_suspend bumps the kernel suspend count; threads stop on
    // the next user-mode instruction. We don't synthesize an
    // EvStopped here — the next wait_event sees the suspended
    // threads via the standard message path (kernel doesn't deliver
    // a Mach exception for plain task_suspend, so callers should be
    // aware: an interrupt() on Mach is NOT symmetric with the Linux
    // PTRACE_INTERRUPT path that always yields a stop event).
    if (task_port_ == 0) return {};
    if (auto kr = ::task_suspend(task_port_); kr != KERN_SUCCESS) {
        return std::unexpected(mach_io("task_suspend", kr));
    }
    for (auto& [_, ts] : thread_state_map()) ts.paused = true;
    return {};
}

Result<Event> MachOTarget::wait_event() {
    if (exc_port_ == 0) {
        return std::unexpected(Error::io("wait_event: no exception port"));
    }
    while (true) {
        exc_request_msg_t msg{};
        kern_return_t kr = ::mach_msg(
            &msg.Head,
            MACH_RCV_MSG | MACH_RCV_LARGE,
            0,
            sizeof(msg),
            exc_port_,
            MACH_MSG_TIMEOUT_NONE,
            MACH_PORT_NULL);
        if (kr != MACH_MSG_SUCCESS) {
            return std::unexpected(mach_io("mach_msg (wait_event)", kr));
        }
        if (msg.Head.msgh_id != kExcRequestId) {
            // Unknown message; deallocate ports and loop.
            ::mach_port_deallocate(::mach_task_self(), msg.thread.name);
            ::mach_port_deallocate(::mach_task_self(), msg.task.name);
            continue;
        }

        const auto tid_port = msg.thread.name;
        const auto exc_type = msg.exception;
        const auto sub_code = msg.code[0];
        const auto fault_va = static_cast<addr_t>(msg.code[1]);
        const ThreadId tid  = static_cast<ThreadId>(tid_port);

        // We don't need the task port reference — release it.
        ::mach_port_deallocate(::mach_task_self(), msg.task.name);

        ThreadState& ts = thread_state(tid);
        ts.paused = true;
        stash_reply_header(ts, msg.Head);

        // ---- breakpoints + single-step ----
        // EXC_BREAKPOINT carries one of EXC_I386_BPT (int3 hit) or
        // EXC_I386_SGL (TF single-step). The bare numeric values are
        // 1 (SGL) and 3 (BPT) on x86-64; we use the macros if the
        // header pulls them in.
        if (exc_type == EXC_BREAKPOINT) {
            switch (ts.step_state) {
                case StepState::SteppingOverForCont: {
                    const addr_t va = ts.step_over_addr;
                    if (auto rv = enable_bp(*this, va); !rv) {
                        ts.step_state = StepState::None;
                        return std::unexpected(std::move(rv).error());
                    }
                    set_tf(static_cast<thread_act_t>(tid), false);
                    ts.parked_at_bp   = 0;
                    ts.step_over_addr = 0;
                    ts.step_state     = StepState::None;
                    if (auto rv = send_reply(ts, KERN_SUCCESS); !rv) return rv;
                    ts.paused = false;
                    continue;
                }
                case StepState::SteppingOverForStep: {
                    const addr_t va = ts.step_over_addr;
                    if (auto rv = enable_bp(*this, va); !rv) {
                        ts.step_state = StepState::None;
                        return std::unexpected(std::move(rv).error());
                    }
                    set_tf(static_cast<thread_act_t>(tid), false);
                    ts.parked_at_bp   = 0;
                    ts.step_over_addr = 0;
                    ts.step_state     = StepState::None;
                    return Event{EvSingleStep{tid,
                        read_rip(static_cast<thread_act_t>(tid))}};
                }
                case StepState::Stepping: {
                    set_tf(static_cast<thread_act_t>(tid), false);
                    ts.step_state = StepState::None;
                    return Event{EvSingleStep{tid,
                        read_rip(static_cast<thread_act_t>(tid))}};
                }
                case StepState::None:
                    break;
            }

            // Fresh int3 hit. Mach delivers the exception with RIP
            // already pointing AT the bp address (unlike ptrace which
            // points one past). subcode tells us — EXC_I386_SGL means
            // single-step (no rewind), EXC_I386_BPT means int3 (RIP
            // is already correct on macOS, no -1 dance needed).
            if (sub_code == EXC_I386_SGL) {
                return Event{EvSingleStep{tid,
                    read_rip(static_cast<thread_act_t>(tid))}};
            }
            const addr_t pc = read_rip(static_cast<thread_act_t>(tid));
            if (auto* bp = find_bp_at(pc)) {
                ts.parked_at_bp = bp->info.id;
                return Event{EvBreakpointHit{tid, bp->info.id, pc}};
            }
            // Unknown bp at PC. fault_va is the int3 site per Mach
            // convention; trust it as a fallback.
            if (auto* bp = find_bp_at(fault_va)) {
                rewind_rip(static_cast<thread_act_t>(tid), fault_va);
                ts.parked_at_bp = bp->info.id;
                return Event{EvBreakpointHit{tid, bp->info.id, fault_va}};
            }
            // Not a debugger-placed breakpoint — try the int3
            // resolver callback if one is registered.
            if (const auto& resolver = int3_resolver()) {
                auto resolution = resolver(pc);
                return Event{EvInt3Trap{tid, pc, std::move(resolution)}};
            }
            return Event{EvSignal{tid, SIGTRAP}};
        }

        // ---- other exception types ----
        switch (exc_type) {
            case EXC_BAD_ACCESS:
                return Event{EvSignal{tid, SIGSEGV}};
            case EXC_BAD_INSTRUCTION:
                return Event{EvSignal{tid, SIGILL}};
            case EXC_ARITHMETIC:
                return Event{EvSignal{tid, SIGFPE}};
            case EXC_SOFTWARE:
                // Mach re-routes Unix signals via EXC_SOFTWARE with
                // subcode EXC_SOFT_SIGNAL; code[1] holds the signo.
                if (sub_code == EXC_SOFT_SIGNAL) {
                    return Event{EvSignal{tid, static_cast<int>(fault_va)}};
                }
                return Event{EvSignal{tid, SIGTRAP}};
            case EXC_CRASH:
                return Event{EvTerminated{SIGABRT}};
            default:
                return Event{EvSignal{tid, SIGTRAP}};
        }
    }
}

}  // namespace ember::debug::mach_

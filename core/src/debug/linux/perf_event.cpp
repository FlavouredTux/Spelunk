// Event loop, execution control, and ring-buffer sample parsing for
// the perf backend.
//
// This file replaces the role ptrace_event.cpp plays in the ptrace
// backend, but the underlying mechanism is completely different.
// Instead of waitpid()-ing on tracee stops, we poll(2) over:
//
//   * pidfd       - wakes when the target task exits
//   * each slot.fd - wakes when its perf_event_open BP/WP fires
//
// On a perf wake-up we drain the slot's mmap ring buffer. Records
// of interest:
//
//   PERF_RECORD_SAMPLE   - BP/WP fired. Carries IP, TID, and the
//                          full GPR snapshot at the trap point.
//   PERF_RECORD_FORK     - kernel is telling us a new task entered
//                          the inheritance tree (a clone'd thread,
//                          since we set attr.inherit=1).
//   PERF_RECORD_EXIT     - task left.
//   PERF_RECORD_LOST     - ring overflowed; we surface a diagnostic
//                          but keep going.
//
// The sample is the only path by which the perf backend ever gets
// register state, so we cache it per-thread for get_regs to read.
// We deliberately do NOT SIGSTOP the target on a hit - staying
// quiet is the whole point of this backend (the ptrace backend
// already stops everything; users pick perf when they want to be
// invisible). interrupt() is the explicit "stop now" hook for cases
// where the user does want to freeze the target.

#include "perf_target.hpp"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <linux/perf_event.h>
#include <poll.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace ember::debug::linux_perf {

namespace {

[[nodiscard]] Error errno_io(const char* op) {
    return Error::io(std::string(op) + ": " + std::strerror(errno));
}

// PERF_SAMPLE_REGS_USER on x86-64 emits regs in PERF_REG_X86_* enum
// order (low bit to high). The kernel rejects DS/ES/FS/GS in
// sample_regs_user on 64-bit (validator returns EINVAL), so our
// mask drops bits 12..15 and the resulting sample carries 20 u64s:
//
//   [0]  AX     [10] CS
//   [1]  BX     [11] SS
//   [2]  CX     [12] R8
//   [3]  DX     [13] R9
//   [4]  SI     [14] R10
//   [5]  DI     [15] R11
//   [6]  BP     [16] R12
//   [7]  SP     [17] R13
//   [8]  IP     [18] R14
//   [9]  FLAGS  [19] R15
constexpr int kSampledRegs = 20;

void install_sample_regs(Registers& r, const u64 regs[kSampledRegs]) {
    r.rax    = regs[0];
    r.rbx    = regs[1];
    r.rcx    = regs[2];
    r.rdx    = regs[3];
    r.rsi    = regs[4];
    r.rdi    = regs[5];
    r.rbp    = regs[6];
    r.rsp    = regs[7];
    r.rip    = regs[8];
    r.rflags = regs[9];
    r.cs     = regs[10];
    r.ss     = regs[11];
    r.r8     = regs[12];
    r.r9     = regs[13];
    r.r10    = regs[14];
    r.r11    = regs[15];
    r.r12    = regs[16];
    r.r13    = regs[17];
    r.r14    = regs[18];
    r.r15    = regs[19];
    r.present = Registers::PresentGpr;
}

}  // namespace

// Drain every record currently in slot_idx's mmap ring; appends
// owned copies to the target's pending queue, tagged with the slot
// they came from. Updates data_tail with a release fence so the
// kernel can reuse the bytes. Friended on PerfTarget so it can
// reach pending_records_ without exposing it to the public surface.
void perf_drain_into_target(PerfTarget& tgt, int slot_idx, std::size_t page) {
    PerfSlot* slot = tgt.slot(slot_idx);
    if (!slot || !slot->ring) return;

    auto* mp = static_cast<perf_event_mmap_page*>(slot->ring);
    const std::size_t data_size = static_cast<std::size_t>(slot->ring_bytes - page);
    auto* data_base = static_cast<u8*>(slot->ring) + page;

    const u64 head = __atomic_load_n(&mp->data_head, __ATOMIC_ACQUIRE);
    u64 tail = mp->data_tail;

    while (tail < head) {
        const std::size_t off = static_cast<std::size_t>(tail % data_size);

        perf_event_header h{};
        const std::size_t hdr_left = data_size - off;
        if (hdr_left >= sizeof(h)) {
            std::memcpy(&h, data_base + off, sizeof(h));
        } else {
            std::memcpy(&h, data_base + off, hdr_left);
            std::memcpy(reinterpret_cast<u8*>(&h) + hdr_left,
                        data_base, sizeof(h) - hdr_left);
        }

        if (h.size < sizeof(h) || h.size > data_size) break;  // corrupt - bail

        PendingRecord rec;
        rec.type     = h.type;
        rec.slot_idx = slot_idx;
        const std::size_t body_n = h.size - sizeof(h);
        rec.body.resize(body_n);
        const std::size_t body_off  = (off + sizeof(h)) % data_size;
        const std::size_t body_left = data_size - body_off;
        if (body_left >= body_n) {
            std::memcpy(rec.body.data(), data_base + body_off, body_n);
        } else {
            std::memcpy(rec.body.data(), data_base + body_off, body_left);
            std::memcpy(rec.body.data() + body_left, data_base, body_n - body_left);
        }

        tgt.pending_records_.push_back(std::move(rec));
        tail += h.size;
    }

    __atomic_store_n(&mp->data_tail, tail, __ATOMIC_RELEASE);
}

namespace {

// PERF_RECORD_SAMPLE body layout for our sample_type
// (PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_REGS_USER):
//
//   u64 ip
//   u32 pid; u32 tid
//   u64 abi
//   u64 regs[kSampledRegs]
struct ParsedSample {
    addr_t   ip   = 0;
    ProcessId pid = 0;
    ThreadId tid  = 0;
    u64      abi  = 0;
    u64      regs[kSampledRegs]{};
};

bool parse_sample(const PendingRecord& rec, ParsedSample& out) {
    constexpr std::size_t need =
        sizeof(u64) +                  // ip
        sizeof(u32) * 2 +              // pid, tid
        sizeof(u64) +                  // abi
        sizeof(u64) * kSampledRegs;    // regs
    if (rec.body.size() < need) return false;

    const u8* p = rec.body.data();
    std::memcpy(&out.ip, p, sizeof(u64));         p += sizeof(u64);
    u32 pid = 0, tid = 0;
    std::memcpy(&pid, p, sizeof(u32));            p += sizeof(u32);
    std::memcpy(&tid, p, sizeof(u32));            p += sizeof(u32);
    out.pid = pid;
    out.tid = tid;
    std::memcpy(&out.abi, p, sizeof(u64));        p += sizeof(u64);
    std::memcpy(out.regs, p, sizeof(u64) * kSampledRegs);
    return true;
}

// PERF_RECORD_FORK / EXIT body: u32 pid; u32 ppid; u32 tid; u32 ptid; u64 time
struct ParsedTask {
    ProcessId pid = 0, ppid = 0;
    ThreadId  tid = 0, ptid = 0;
};

bool parse_task(const PendingRecord& rec, ParsedTask& out) {
    constexpr std::size_t need = sizeof(u32) * 4 + sizeof(u64);
    if (rec.body.size() < need) return false;
    const u8* p = rec.body.data();
    u32 a = 0, b = 0, c = 0, d = 0;
    std::memcpy(&a, p, 4); p += 4;
    std::memcpy(&b, p, 4); p += 4;
    std::memcpy(&c, p, 4); p += 4;
    std::memcpy(&d, p, 4);
    out.pid = a; out.ppid = b; out.tid = c; out.ptid = d;
    return true;
}

}  // namespace

Result<void> PerfTarget::cont() {
    if (dead_) return {};
    bool any_paused = false;
    for (auto& [_, ts] : thread_state_) {
        if (ts.paused) { any_paused = true; ts.paused = false; }
    }
    if (any_paused) {
        if (::kill(static_cast<pid_t>(pid_v_), SIGCONT) < 0 && errno != ESRCH) {
            return std::unexpected(errno_io("kill SIGCONT"));
        }
    }
    return {};
}

Result<void> PerfTarget::interrupt() {
    if (dead_) return {};
    if (::kill(static_cast<pid_t>(pid_v_), SIGSTOP) < 0 && errno != ESRCH) {
        return std::unexpected(errno_io("kill SIGSTOP"));
    }
    for (auto& [_, ts] : thread_state_) ts.paused = true;
    return {};
}

Result<void> PerfTarget::step(ThreadId) {
    return std::unexpected(Error::unsupported(
        "debugger: single-step is not available on the perf backend "
        "(no TF flag access without ptrace) - switch to the ptrace "
        "backend, or set a HW BP at the next instruction"));
}

Result<void>
PerfTarget::set_syscall_catch(bool, std::span<const u32>) {
    return std::unexpected(Error::unsupported(
        "debugger: syscall catch is not implemented on the perf "
        "backend - switch to the ptrace backend"));
}

Result<void> PerfTarget::clear_syscall_catch() {
    return std::unexpected(Error::unsupported(
        "debugger: syscall catch is not implemented on the perf backend"));
}

Result<Event> PerfTarget::wait_event() {
    if (dead_) {
        return std::unexpected(Error::invalid_format(
            "debugger: wait_event called after target exited"));
    }

    const long page_l = ::sysconf(_SC_PAGESIZE);
    const std::size_t page = page_l > 0 ? static_cast<std::size_t>(page_l) : 4096u;

    while (true) {
        // Peel one event off the queue first - multiple samples can
        // arrive in a single poll wake-up, and the public API hands
        // back one event per call.
        while (!pending_records_.empty()) {
            PendingRecord rec = std::move(pending_records_.front());
            pending_records_.pop_front();

            switch (rec.type) {
                case PERF_RECORD_SAMPLE: {
                    ParsedSample s{};
                    if (!parse_sample(rec, s)) continue;
                    auto& ts = thread_state(s.tid);
                    install_sample_regs(ts.cached, s.regs);
                    ts.has_sample = true;

                    const auto* hit = slot(rec.slot_idx);
                    if (!hit || hit->fd < 0) {
                        return Event{EvSignal{s.tid, SIGTRAP}};
                    }
                    if (hit->is_watch) {
                        return Event{EvWatchpointHit{
                            s.tid, hit->wp_info.id, s.ip, hit->wp_info.addr,
                            static_cast<u8>(rec.slot_idx)}};
                    }
                    return Event{EvBreakpointHit{s.tid, hit->bp_info.id, s.ip}};
                }
                case PERF_RECORD_FORK: {
                    ParsedTask tk{};
                    if (!parse_task(rec, tk)) continue;
                    if (tk.tid == 0) continue;
                    if (thread_state_.find(tk.tid) == thread_state_.end()) {
                        (void)thread_state(tk.tid);
                        return Event{EvThreadCreated{tk.tid}};
                    }
                    continue;
                }
                case PERF_RECORD_EXIT: {
                    ParsedTask tk{};
                    if (!parse_task(rec, tk)) continue;
                    if (tk.tid == 0) continue;
                    thread_state_.erase(tk.tid);
                    return Event{EvThreadExited{tk.tid, 0}};
                }
                case PERF_RECORD_LOST: {
                    // Body: u64 id; u64 lost. Ring overflowed - samples
                    // were dropped. Surface to stderr so the user knows
                    // their breakpoint sequence has gaps; the alternative
                    // (silent skip) makes the perf backend appear flaky.
                    if (rec.body.size() >= 16) {
                        u64 lost = 0;
                        std::memcpy(&lost, rec.body.data() + 8, 8);
                        std::fprintf(stderr,
                            "ember: perf ring overflow - %llu sample(s) lost\n",
                            static_cast<unsigned long long>(lost));
                    }
                    continue;
                }
                default:
                    continue;
            }
        }

        // Queue empty: poll until either the target dies or one of
        // its open slots fires a sample.
        std::vector<pollfd> pfds;
        pfds.reserve(1 + kMaxSlots);
        pfds.push_back({pidfd_, POLLIN, 0});
        std::vector<int> slot_indices;        // pfds[1+i] → slot index in slots_
        slot_indices.reserve(kMaxSlots);
        for (int i = 0; i < kMaxSlots; ++i) {
            if (slots_[i].fd >= 0) {
                pfds.push_back({slots_[i].fd, POLLIN, 0});
                slot_indices.push_back(i);
            }
        }

        const int rc = ::poll(pfds.data(), pfds.size(), -1);
        if (rc < 0) {
            if (errno == EINTR) continue;
            return std::unexpected(errno_io("poll"));
        }

        // Process death takes priority over pending samples.
        if (pfds[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            int code = 0, sig = 0;
            if (spawned_) {
                int status = 0;
                if (::waitpid(static_cast<pid_t>(pid_v_), &status, WNOHANG) > 0) {
                    if (WIFEXITED(status))   code = WEXITSTATUS(status);
                    if (WIFSIGNALED(status)) sig  = WTERMSIG(status);
                }
            }
            dead_ = true;
            for (auto& s : slots_) close_slot(s);
            pending_records_.clear();
            if (sig) return Event{EvTerminated{sig}};
            return Event{EvExited{code}};
        }

        for (std::size_t i = 0; i < slot_indices.size(); ++i) {
            if (!(pfds[1 + i].revents & POLLIN)) continue;
            perf_drain_into_target(*this, slot_indices[i], page);
        }
        // Loop - the next iteration peels from pending_records_.
    }
}

}  // namespace ember::debug::linux_perf

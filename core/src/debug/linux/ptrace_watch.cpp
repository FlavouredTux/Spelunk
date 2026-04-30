// Hardware data watchpoints for the Linux ptrace backend (DR0..DR3,
// programmed per-thread via PTRACE_POKEUSER). DR0..DR3 hold linear
// addresses, DR7 holds enable/length/type per slot, DR6 reports
// B0..B3 when the slot fires. PTRACE_EVENT_CLONE delivers fresh
// threads with empty DR state, so ptrace_event re-arms each one
// via rearm_watchpoints_on_new_thread before resuming.

#include "ptrace_target.hpp"

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>

#include <sys/ptrace.h>
#include <sys/user.h>

namespace ember::debug::linux_ {

namespace {

[[nodiscard]] Error errno_io(const char* op) {
    return Error::io(std::string(op) + ": " + std::strerror(errno));
}

constexpr std::size_t kDrBase   = offsetof(struct user, u_debugreg[0]);
constexpr std::size_t kDrStride = sizeof(reinterpret_cast<struct user*>(0)->u_debugreg[0]);

[[nodiscard]] std::size_t dr_off(int idx) {
    return kDrBase + static_cast<std::size_t>(idx) * kDrStride;
}

[[nodiscard]] Result<void>
poke_dr(ThreadId tid, int idx, u64 value) {
    errno = 0;
    if (::ptrace(PTRACE_POKEUSER, static_cast<pid_t>(tid),
                 reinterpret_cast<void*>(dr_off(idx)),
                 reinterpret_cast<void*>(static_cast<std::uintptr_t>(value))) < 0) {
        return std::unexpected(errno_io("pokeuser (dr)"));
    }
    return {};
}

[[nodiscard]] Result<u64>
peek_dr(ThreadId tid, int idx) {
    errno = 0;
    const long v = ::ptrace(PTRACE_PEEKUSER, static_cast<pid_t>(tid),
                            reinterpret_cast<void*>(dr_off(idx)), nullptr);
    if (v == -1 && errno != 0) return std::unexpected(errno_io("peekuser (dr)"));
    return static_cast<u64>(v);
}

// DR7 length encoding. The two-bit field is intentionally non-monotonic:
// 00=1, 01=2, 11=4, 10=8 (Intel SDM Vol 3, table 17-2).
[[nodiscard]] u8 encode_len(u8 size_bytes) {
    switch (size_bytes) {
        case 1: return 0b00;
        case 2: return 0b01;
        case 4: return 0b11;
        case 8: return 0b10;
        default: return 0xFF;
    }
}

[[nodiscard]] u8 encode_type(WatchMode m) {
    return m == WatchMode::Write ? 0b01 : 0b11;
}

// Compose DR7 from the four-slot table. We always set Local Exact (LE)
// so the CPU isn't relaxed about pipelining writes that would otherwise
// race the trap. Global slots are never used — the kernel resets DR7
// across exec() and we want the same behaviour anyway.
[[nodiscard]] u64 compose_dr7(const LinuxTarget& t) {
    u64 dr7 = 0;
    for (int i = 0; i < 4; ++i) {
        const auto* w = t.wp_slot(i);
        if (!w || w->id == 0 || !w->info.enabled) continue;
        const u8 len  = encode_len(w->info.size);
        const u8 type = encode_type(w->info.mode);
        if (len == 0xFF) continue;
        dr7 |= (1ULL << (i * 2));                                 // Lx
        dr7 |= (static_cast<u64>(type) << (16 + 4 * i));          // type
        dr7 |= (static_cast<u64>(len)  << (18 + 4 * i));          // len
    }
    if (dr7 != 0) dr7 |= (1ULL << 8);  // LE
    return dr7;
}

[[nodiscard]] Result<void> apply_to_thread(LinuxTarget& t, ThreadId tid) {
    for (int i = 0; i < 4; ++i) {
        const auto* w = t.wp_slot(i);
        const u64 va = (w && w->id) ? static_cast<u64>(w->info.addr) : 0;
        if (auto rv = poke_dr(tid, i, va); !rv) return rv;
    }
    // DR6 is the trap-status word — clear stale bits before re-arming
    // so a leftover B0..B3 from a previous run can't be misread.
    if (auto rv = poke_dr(tid, 6, 0); !rv) return rv;
    if (auto rv = poke_dr(tid, 7, compose_dr7(t)); !rv) return rv;
    return {};
}

[[nodiscard]] Result<void> apply_all(LinuxTarget& t) {
    for (const auto& [tid, _] : t.thread_state_map()) {
        if (auto rv = apply_to_thread(t, tid); !rv) return rv;
    }
    return {};
}

}  // namespace

Result<WatchpointId>
LinuxTarget::set_watchpoint(addr_t va, u8 size, WatchMode mode) {
    if (size != 1 && size != 2 && size != 4 && size != 8) {
        return std::unexpected(Error::invalid_format(
            "debugger: wp: size must be 1, 2, 4, or 8"));
    }
    if ((va & (size - 1)) != 0) {
        return std::unexpected(Error::invalid_format(
            "debugger: wp: address must be aligned to size"));
    }
    int slot_idx = -1;
    for (int i = 0; i < 4; ++i) {
        if (wp_[i].id == 0) { slot_idx = i; break; }
    }
    if (slot_idx < 0) {
        return std::unexpected(Error::invalid_format(
            "debugger: wp: all 4 hardware slots in use; delete one first"));
    }
    WpSlot& slot = wp_[slot_idx];
    slot.id            = next_wp_id_++;
    slot.info.id       = slot.id;
    slot.info.addr     = va;
    slot.info.size     = size;
    slot.info.mode     = mode;
    slot.info.enabled  = true;

    if (auto rv = apply_all(*this); !rv) {
        slot = WpSlot{};
        return std::unexpected(std::move(rv).error());
    }
    return slot.id;
}

Result<void> LinuxTarget::clear_watchpoint(WatchpointId id) {
    int slot_idx = -1;
    for (int i = 0; i < 4; ++i) {
        if (wp_[i].id == id) { slot_idx = i; break; }
    }
    if (slot_idx < 0) {
        return std::unexpected(Error::invalid_format(
            "debugger: wp: unknown watchpoint id"));
    }
    wp_[slot_idx] = WpSlot{};
    return apply_all(*this);
}

std::vector<Watchpoint> LinuxTarget::watchpoints() const {
    std::vector<Watchpoint> out;
    out.reserve(4);
    for (int i = 0; i < 4; ++i) {
        if (wp_[i].id != 0) out.push_back(wp_[i].info);
    }
    return out;
}

// Called from ptrace_event.cpp on every SIGTRAP to decide whether the
// stop was a hardware-watch hit. Returns the slot index (0..3) and
// clears that bit in DR6; returns -1 when no watch fired. The caller
// then maps slot → WatchpointId to surface EvWatchpointHit.
int dr6_consume_hit(ThreadId tid) {
    auto v = peek_dr(tid, 6);
    if (!v) return -1;
    const u64 dr6 = *v;
    int slot = -1;
    for (int i = 0; i < 4; ++i) {
        if (dr6 & (1ULL << i)) { slot = i; break; }
    }
    if (slot < 0) return -1;
    // Clear the slot bit (and BS/BD/BT, which are non-watch causes we
    // don't use). Writing 0 wipes the trap-status register cleanly so
    // a follow-up SIGTRAP on a different cause doesn't see stale bits.
    [[maybe_unused]] auto _ = poke_dr(tid, 6, 0);
    return slot;
}

// Best-effort re-arm on the CLONE-event path; an error here just
// means the new thread runs without watches, not a debugger fault.
void rearm_watchpoints_on_new_thread(LinuxTarget& t, ThreadId tid) {
    [[maybe_unused]] auto _ = apply_to_thread(t, tid);
}

}  // namespace ember::debug::linux_

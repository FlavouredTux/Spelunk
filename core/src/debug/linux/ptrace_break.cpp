// Software breakpoints for the Linux ptrace backend.
// One byte at the target VA is replaced with 0xCC (int3); the
// original byte is parked in the SoftwareBreakpoint table so we can
// restore it on clear or during step-over.

#include "ptrace_target.hpp"

#include <cstddef>

namespace ember::debug::linux_ {

namespace {

constexpr u8 kInt3 = 0xCC;

[[nodiscard]] Result<u8> read_byte(LinuxTarget& t, addr_t va) {
    std::byte buf[1] = {};
    auto rv = t.read_mem(va, buf);
    if (!rv) return std::unexpected(std::move(rv).error());
    if (*rv != 1) return std::unexpected(Error::out_of_bounds(
        "debugger: bp address is unmapped"));
    return static_cast<u8>(buf[0]);
}

[[nodiscard]] Result<void> write_byte(LinuxTarget& t, addr_t va, u8 b) {
    const std::byte buf[1] = { static_cast<std::byte>(b) };
    auto rv = t.write_mem(va, buf);
    if (!rv) return std::unexpected(std::move(rv).error());
    if (*rv != 1) return std::unexpected(Error::out_of_bounds(
        "debugger: bp address is unmapped for write"));
    return {};
}

}  // namespace

Result<BreakpointId> LinuxTarget::set_breakpoint(addr_t va) {
    if (auto* existing = find_bp_at(va)) {
        // Idempotent — same address yields the same id, regardless of
        // whether the underlying byte is currently armed.
        return existing->info.id;
    }

    auto orig = read_byte(*this, va);
    if (!orig) return std::unexpected(std::move(orig).error());

    if (auto rv = write_byte(*this, va, kInt3); !rv) {
        return std::unexpected(std::move(rv).error());
    }

    SoftwareBreakpoint bp;
    bp.info.id      = next_bp_id_++;
    bp.info.addr    = va;
    bp.info.kind    = BreakpointKind::Software;
    bp.info.enabled = true;
    bp.orig_byte    = *orig;
    const BreakpointId id = bp.info.id;
    bps_.emplace(id, bp);
    return id;
}

Result<void> LinuxTarget::clear_breakpoint(BreakpointId id) {
    auto* bp = find_bp_id(id);
    if (!bp) {
        return std::unexpected(Error::invalid_format(
            "debugger: unknown breakpoint id"));
    }
    if (bp->info.enabled) {
        if (auto rv = write_byte(*this, bp->info.addr, bp->orig_byte); !rv) {
            return std::unexpected(std::move(rv).error());
        }
    }
    bps_.erase(id);
    return {};
}

Result<void> disable_bp(LinuxTarget& t, addr_t va, u8 orig_byte) {
    return write_byte(t, va, orig_byte);
}

Result<void> enable_bp(LinuxTarget& t, addr_t va) {
    return write_byte(t, va, kInt3);
}

}  // namespace ember::debug::linux_

namespace ember::debug::linux_ {

// Drop kernel-bound state after PTRACE_EVENT_EXEC. Software bp
// patches are gone with the dead address space and DR slots were
// auto-cleared by exec. Syscall-catch settings are NOT reset —
// they're a tracing mode, not address-space-bound, and we want
// `catch syscall` to follow execve into the new image.
void LinuxTarget::clear_all_after_exec() {
    bps_.clear();
    for (int i = 0; i < 4; ++i) wp_[i] = WpSlot{};
    for (auto& [_, ts] : thread_state_) {
        ts.parked_at_bp   = 0;
        ts.step_over_addr = 0;
        ts.step_state     = StepState::None;
        ts.in_syscall     = false;
    }
}

}  // namespace ember::debug::linux_

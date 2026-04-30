// Software breakpoints for the macOS Mach backend.
//
// Same logical shape as core/src/debug/linux/ptrace_break.cpp:
// patch a 0xCC int3 byte over the target VA, save the original
// byte for restore, idempotent on duplicate set. The actual
// memory modification (and the RX→RWX→RX protection dance) is
// handled inside MachOTarget::write_mem, so this file stays
// platform-symmetric with the Linux implementation.

#include "mach_target.hpp"

#include <cstddef>

namespace ember::debug::mach_ {

namespace {

constexpr u8 kInt3 = 0xCC;

[[nodiscard]] Result<u8> read_byte(MachOTarget& t, addr_t va) {
    std::byte buf[1] = {};
    auto rv = t.read_mem(va, buf);
    if (!rv) return std::unexpected(std::move(rv).error());
    if (*rv != 1) return std::unexpected(Error::out_of_bounds(
        "debugger: bp address is unmapped"));
    return static_cast<u8>(buf[0]);
}

[[nodiscard]] Result<void> write_byte(MachOTarget& t, addr_t va, u8 b) {
    const std::byte buf[1] = { static_cast<std::byte>(b) };
    auto rv = t.write_mem(va, buf);
    if (!rv) return std::unexpected(std::move(rv).error());
    if (*rv != 1) return std::unexpected(Error::out_of_bounds(
        "debugger: bp address is unmapped for write"));
    return {};
}

}  // namespace

Result<BreakpointId> MachOTarget::set_breakpoint(addr_t va) {
    if (auto* existing = find_bp_at(va)) {
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

Result<void> MachOTarget::clear_breakpoint(BreakpointId id) {
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

Result<void> disable_bp(MachOTarget& t, addr_t va, u8 orig_byte) {
    return write_byte(t, va, orig_byte);
}

Result<void> enable_bp(MachOTarget& t, addr_t va) {
    return write_byte(t, va, kInt3);
}

Result<WatchpointId>
MachOTarget::set_watchpoint(addr_t /*va*/, u8 /*size*/, WatchMode /*mode*/) {
    return std::unexpected(Error::not_implemented(
        "debugger: hardware watchpoints not yet implemented on macOS"));
}

Result<void> MachOTarget::clear_watchpoint(WatchpointId /*id*/) {
    return std::unexpected(Error::not_implemented(
        "debugger: hardware watchpoints not yet implemented on macOS"));
}

std::vector<Watchpoint> MachOTarget::watchpoints() const {
    return {};
}

Result<void> MachOTarget::set_syscall_catch(bool /*all*/, std::span<const u32> /*nrs*/) {
    return std::unexpected(Error::not_implemented(
        "debugger: syscall catchpoints not yet implemented on macOS"));
}

Result<void> MachOTarget::clear_syscall_catch() { return {}; }

}  // namespace ember::debug::mach_

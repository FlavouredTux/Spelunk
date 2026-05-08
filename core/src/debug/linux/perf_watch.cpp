// Hardware data watchpoints for the perf backend. Same kernel
// surface as perf_break.cpp — the only differences are bp_type
// (HW_BREAKPOINT_W vs _RW vs _X) and the user-visible Watchpoint
// shape. The four DR slots are pooled across BPs and WPs; the
// kernel returns ENOSPC and we surface that as a clear error.
//
// x86 cannot do read-only watches at the hardware level — DR7's
// length/type field has no "read-only" encoding, only "write only"
// or "read/write". Users asking for read fire on writes too; we
// follow the existing Watchpoint::Mode contract from breakpoint.hpp.

#include "perf_target.hpp"

#include <linux/hw_breakpoint.h>

namespace ember::debug::linux_perf {

namespace {

[[nodiscard]] u32 kernel_bp_type(WatchMode mode) {
    return mode == WatchMode::Write ? HW_BREAKPOINT_W : HW_BREAKPOINT_RW;
}

}  // namespace

Result<WatchpointId>
PerfTarget::set_watchpoint(addr_t va, u8 size, WatchMode mode) {
    if (size != 1 && size != 2 && size != 4 && size != 8) {
        return std::unexpected(Error::invalid_format(
            "debugger: watchpoint size must be 1, 2, 4, or 8 bytes"));
    }
    if (va % size != 0) {
        return std::unexpected(Error::invalid_format(
            "debugger: watchpoint addr must be aligned to size"));
    }

    auto idx = install_perf_event(*this, va, kernel_bp_type(mode), size);
    if (!idx) return std::unexpected(std::move(idx).error());

    auto* s = slot(*idx);
    if (!s) {
        return std::unexpected(Error::io(
            "debugger: internal — install_perf_event returned bad slot index"));
    }
    s->is_watch        = true;
    s->wp_info.id      = next_wp_id();
    s->wp_info.addr    = va;
    s->wp_info.size    = size;
    s->wp_info.mode    = mode;
    s->wp_info.enabled = true;
    return s->wp_info.id;
}

Result<void> PerfTarget::clear_watchpoint(WatchpointId id) {
    const int idx = find_wp_slot(id);
    if (idx < 0) {
        return std::unexpected(Error::invalid_format(
            "debugger: unknown watchpoint id"));
    }
    close_slot(*slot(idx));
    return {};
}

}  // namespace ember::debug::linux_perf

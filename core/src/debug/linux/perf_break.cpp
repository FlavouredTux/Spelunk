// Hardware execute breakpoints for the perf backend. Each BP burns
// one of the four x86 DR slots (DR0..DR3) — the same physical
// resource the watchpoint code uses, so the slot pool is shared.
// The kernel reports ENOSPC when all four are in use; we surface
// that as Error::out_of_bounds with a message the REPL can show.
//
// We open one perf_event_open(PERF_TYPE_BREAKPOINT) fd per slot.
// The fd carries a small mmap'd ring buffer that perf_event.cpp
// drains in wait_event(). Sample contents include IP + TID + the
// full GPR snapshot at hit time (PERF_SAMPLE_REGS_USER), which is
// the only way to read regs in this backend.

#include "perf_target.hpp"

#include <cerrno>
#include <cstring>
#include <string>

#include <asm/perf_regs.h>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

namespace ember::debug::linux_perf {

namespace {

[[nodiscard]] Error errno_io(const char* op) {
    return Error::io(std::string(op) + ": " + std::strerror(errno));
}

[[nodiscard]] long sys_perf_event_open(perf_event_attr* attr, pid_t pid,
                                       int cpu, int group_fd, unsigned long flags) {
    return ::syscall(SYS_perf_event_open, attr, pid, cpu, group_fd, flags);
}

// Bitmask of the user-mode registers we want in every sample. On
// x86-64 the kernel rejects the segment selectors DS/ES/FS/GS in
// sample_regs_user (they're meaningless in 64-bit mode and the
// validator returns EINVAL when set). Everything else 0..23 in the
// PERF_REG_X86_* enum is fair game.
constexpr u64 user_regs_mask() {
    u64 m = 0;
    for (unsigned i = 0; i < PERF_REG_X86_64_MAX; ++i) m |= (1ULL << i);
    m &= ~((1ULL << PERF_REG_X86_DS) |
           (1ULL << PERF_REG_X86_ES) |
           (1ULL << PERF_REG_X86_FS) |
           (1ULL << PERF_REG_X86_GS));
    return m;
}

}  // namespace

[[nodiscard]] Result<int>
install_perf_event(PerfTarget& t, addr_t addr, u32 bp_type, u8 len_bytes) {
    const int idx = t.find_free_slot();
    if (idx < 0) {
        return std::unexpected(Error::out_of_bounds(
            "debugger: no free HW debug slot (4 max — release a "
            "breakpoint or watchpoint first)"));
    }

    perf_event_attr attr{};
    attr.type             = PERF_TYPE_BREAKPOINT;
    attr.size             = sizeof(attr);
    attr.bp_type          = bp_type;
    attr.bp_addr          = static_cast<u64>(addr);
    attr.bp_len           = len_bytes;
    attr.sample_period    = 1;
    attr.sample_type      = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_REGS_USER;
    attr.sample_regs_user = user_regs_mask();
    attr.wakeup_events    = 1;     // wake poll() on every sample
    attr.disabled         = 0;
    // No inherit / task tracking on HW BP: those flags are mutually
    // exclusive with PERF_TYPE_BREAKPOINT on most kernels and surface
    // as EINVAL. Thread discovery is best-effort via /proc/<pid>/task
    // at attach time and lazily through samples themselves.

    const long fd_l = sys_perf_event_open(
        &attr, static_cast<pid_t>(t.pid()), -1, -1, 0);
    if (fd_l < 0) {
        if (errno == ENOSPC) {
            return std::unexpected(Error::out_of_bounds(
                "debugger: kernel reports no free HW debug slot for "
                "this task (anti-cheat or other tracer may be using them)"));
        }
        if (errno == EACCES || errno == EPERM) {
            return std::unexpected(Error::unsupported(
                "debugger: perf_event_open denied — set "
                "/proc/sys/kernel/perf_event_paranoid to 1 (or below), "
                "or grant CAP_PERFMON to ember"));
        }
        if (errno == EINVAL) {
            return std::unexpected(Error::unsupported(
                "debugger: perf_event_open rejected HW breakpoint/watchpoint "
                "configuration on this kernel or container host"));
        }
        return std::unexpected(errno_io("perf_event_open"));
    }
    const int fd = static_cast<int>(fd_l);

    const long page_l = ::sysconf(_SC_PAGESIZE);
    const std::size_t page = page_l > 0 ? static_cast<std::size_t>(page_l) : 4096u;
    const std::size_t bytes = (kRingDataPages + 1) * page;

    void* ring = ::mmap(nullptr, bytes, PROT_READ | PROT_WRITE,
                        MAP_SHARED, fd, 0);
    if (ring == MAP_FAILED) {
        const int saved = errno;
        ::close(fd);
        errno = saved;
        return std::unexpected(errno_io("mmap (perf ring)"));
    }

    auto* sl = t.slot(idx);
    if (!sl) {
        ::munmap(ring, bytes);
        ::close(fd);
        return std::unexpected(Error::io(
            "debugger: internal — find_free_slot returned out-of-range index"));
    }
    sl->fd         = fd;
    sl->ring       = ring;
    sl->ring_bytes = bytes;
    sl->addr       = addr;
    return idx;
}

Result<BreakpointId> PerfTarget::set_breakpoint(addr_t va) {
    // Idempotent: same address yields the same id.
    for (int i = 0; i < kMaxSlots; ++i) {
        const auto& s = slots_[i];
        if (s.fd >= 0 && !s.is_watch && s.addr == va) {
            return s.bp_info.id;
        }
    }

    auto idx = install_perf_event(*this, va, HW_BREAKPOINT_X, 1);
    if (!idx) return std::unexpected(std::move(idx).error());

    auto* s = slot(*idx);
    if (!s) {
        return std::unexpected(Error::io(
            "debugger: internal — install_perf_event returned bad slot index"));
    }
    s->is_watch        = false;
    s->bp_info.id      = next_bp_id();
    s->bp_info.addr    = va;
    s->bp_info.kind    = BreakpointKind::Software;  // closest enum we have
    s->bp_info.enabled = true;
    return s->bp_info.id;
}

Result<void> PerfTarget::clear_breakpoint(BreakpointId id) {
    const int idx = find_bp_slot(id);
    if (idx < 0) {
        return std::unexpected(Error::invalid_format(
            "debugger: unknown breakpoint id"));
    }
    close_slot(*slot(idx));
    return {};
}

}  // namespace ember::debug::linux_perf

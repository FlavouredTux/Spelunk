// Drives the Linux perf_event_open backend end-to-end against the
// `dbg_target` fixture. Exercises the same shape as dbg_smoke_test.cpp
// but through BackendKind::Perf - HW execute breakpoint, HW data
// watchpoint, and the cached-register-from-sample read path.
//
// Skip semantics: perf_event_open(PERF_TYPE_BREAKPOINT) is gated by
// /proc/sys/kernel/perf_event_paranoid (>=2 denies for non-root) and
// by CAP_PERFMON. When the kernel returns EACCES/EPERM the backend
// surfaces Error::unsupported; we treat that as a skip (exit 77,
// matching CMake's SKIP_RETURN_CODE convention) so the test passes
// in restricted environments where the perf path simply isn't usable.

#include <cstdio>
#include <filesystem>
#include <system_error>
#include <utility>
#include <variant>

#include <ember/binary/binary.hpp>
#include <ember/binary/symbol.hpp>
#include <ember/common/error.hpp>
#include <ember/debug/event.hpp>
#include <ember/debug/target.hpp>

#define CHECK(cond, msg)                                                   \
    do {                                                                   \
        if (!(cond)) {                                                     \
            std::fprintf(stderr,                                           \
                         "FAIL: %s (line %d)\n", (msg), __LINE__);         \
            return 1;                                                      \
        }                                                                  \
    } while (0)

namespace {

ember::addr_t compute_slide(ember::debug::Target& tgt,
                            const ember::Binary& bin,
                            const std::string& bin_path) {
    const auto images = tgt.images();
    if (images.empty()) return 0;
    constexpr ember::addr_t kPage = 0x1000;
    const ember::addr_t pref = bin.preferred_load_base() & ~(kPage - 1);

    namespace fs = std::filesystem;
    std::error_code ec;
    std::string canon = bin_path;
    if (auto p = fs::canonical(bin_path, ec); !ec) canon = p.string();

    for (const auto& img : images) {
        if (img.path == bin_path || img.path == canon) {
            return (img.base & ~(kPage - 1)) - pref;
        }
    }
    return (images.front().base & ~(kPage - 1)) - pref;
}

bool is_perf_denial(const ember::Error& e) {
    return e.kind_name() == std::string_view("unsupported");
}

template <typename TargetPtr>
int skip_perf(TargetPtr& t, const char* what, const ember::Error& e) {
    std::fprintf(stderr, "SKIP: %s (%s)\n", what, e.message.c_str());
    (void)t->kill();
    return 77;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: %s <binary>\n", argv[0]);
        return 99;
    }

    auto bin = ember::load_binary(argv[1]);
    CHECK(bin.has_value(), "load_binary");

    const auto* marker = (*bin)->find_by_name("dbg_marker");
    CHECK(marker != nullptr,            "find dbg_marker");
    const auto* slot   = (*bin)->find_by_name("watch_slot");
    CHECK(slot   != nullptr,            "find watch_slot");

    ember::debug::LaunchOptions opts;
    opts.program       = argv[1];
    opts.stop_at_entry = true;
    opts.backend       = ember::debug::BackendKind::Perf;
    auto t_r = ember::debug::launch(opts);
    if (!t_r) {
        if (is_perf_denial(t_r.error())) {
            std::fprintf(stderr,
                "SKIP: perf backend denied (%s) - set "
                "/proc/sys/kernel/perf_event_paranoid <= 1 or run as root\n",
                t_r.error().message.c_str());
            return 77;
        }
        std::fprintf(stderr,
            "FAIL: launch (perf): %s: %s\n",
            std::string(t_r.error().kind_name()).c_str(),
            t_r.error().message.c_str());
        return 1;
    }
    auto t = std::move(*t_r);

    const ember::addr_t slide   = compute_slide(*t, **bin, argv[1]);
    const ember::addr_t bp_va   = marker->addr + slide;
    const ember::addr_t slot_va = slot->addr   + slide;

    auto bp_r = t->set_breakpoint(bp_va);
    if (!bp_r) {
        if (is_perf_denial(bp_r.error())) {
            return skip_perf(t, "HW breakpoint allocation unavailable",
                             bp_r.error());
        }
        std::fprintf(stderr, "FAIL: set_breakpoint: %s\n",
                     bp_r.error().message.c_str());
        (void)t->kill();
        return 1;
    }
    const auto bp_id = *bp_r;

    auto wp_r = t->set_watchpoint(slot_va, 8, ember::debug::WatchMode::Write);
    if (!wp_r) {
        if (is_perf_denial(wp_r.error())) {
            return skip_perf(t, "HW watchpoint allocation unavailable",
                             wp_r.error());
        }
        std::fprintf(stderr, "FAIL: set_watchpoint: %s\n",
                     wp_r.error().message.c_str());
        (void)t->kill();
        return 1;
    }
    const auto wp_id = *wp_r;

    // step() must report unsupported.
    {
        const auto step_r = t->step(0);
        CHECK(!step_r.has_value(),  "step should be unsupported");
        CHECK(step_r.error().kind_name() == std::string_view("UnsupportedFormat"),
              "step error kind == unsupported");
    }
    // set_regs must report unsupported.
    {
        ember::debug::Registers r{};
        const auto sr = t->set_regs(0, r);
        CHECK(!sr.has_value(),  "set_regs should be unsupported");
    }
    // syscall catch must report unsupported.
    {
        const auto sc = t->set_syscall_catch(true, {});
        CHECK(!sc.has_value(), "syscall catch should be unsupported");
    }

    // Resume: SIGCONT wakes the child. Two HW slots are armed; we
    // expect EvBreakpointHit for dbg_marker, then EvWatchpointHit
    // for the store to watch_slot, then EvExited{42}.
    CHECK(t->cont().has_value(), "cont 1");

    auto ev_r = t->wait_event();
    CHECK(ev_r.has_value(),                                  "wait_event 1");
    const auto* hit = std::get_if<ember::debug::EvBreakpointHit>(&*ev_r);
    CHECK(hit != nullptr,                                    "expected EvBreakpointHit");
    CHECK(hit->id == bp_id,                                  "bp id mismatch");

    // Cached regs at hit must populate at least PresentGpr; rip
    // should land on the breakpoint address (HW BP is trap-before-
    // execute, so the sample IP is the BP VA itself).
    {
        auto regs = t->get_regs(hit->tid);
        CHECK(regs.has_value(),                          "get_regs (cached)");
        CHECK((regs->present & ember::debug::Registers::PresentGpr) != 0,
              "PresentGpr after sample");
        CHECK(regs->rip == bp_va,                        "cached rip == bp_va");
    }

    ev_r = t->wait_event();
    CHECK(ev_r.has_value(),                                  "wait_event 2");
    const auto* whit = std::get_if<ember::debug::EvWatchpointHit>(&*ev_r);
    CHECK(whit != nullptr,                                   "expected EvWatchpointHit");
    CHECK(whit->id == wp_id,                                 "wp id mismatch");
    CHECK(whit->addr == slot_va,                             "wp addr mismatch");
    CHECK(whit->slot < 4,                                    "wp slot in range");

    // Memory-read works on a live (non-stopped) process: read the
    // current value of watch_slot. Since the watchpoint trapped after
    // the store completed (x86 data-watch semantics), it should now
    // hold the constant the fixture writes.
    {
        std::byte buf[8] = {};
        auto rrv = t->read_mem(slot_va, std::span<std::byte>{buf});
        CHECK(rrv.has_value() && *rrv == sizeof(buf),       "read_mem watch_slot");
        ember::u64 v = 0;
        for (int i = 0; i < 8; ++i) {
            v |= static_cast<ember::u64>(static_cast<unsigned char>(buf[i])) << (i * 8);
        }
        CHECK(v == 0xdeadbeefcafebabeULL,                    "watch_slot post-store value");
    }

    ev_r = t->wait_event();
    CHECK(ev_r.has_value(), "wait_event final");
    const auto* exited = std::get_if<ember::debug::EvExited>(&*ev_r);
    CHECK(exited != nullptr,    "expected EvExited");
    CHECK(exited->code == 42,   "exit code");

    std::printf("OK (slide=0x%llx)\n", static_cast<unsigned long long>(slide));
    return 0;
}

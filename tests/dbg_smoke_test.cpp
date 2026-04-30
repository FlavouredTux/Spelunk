// Drives the Linux ptrace backend end-to-end against the
// `dbg_target` fixture. Computes the runtime slide via the same
// preferred_load_base / images() math the REPL uses, so the test
// passes for both non-PIE and PIE fixtures (slide degenerates to 0
// for the non-PIE case).

#include <cstdio>
#include <filesystem>
#include <system_error>
#include <utility>
#include <variant>

#include <ember/binary/binary.hpp>
#include <ember/binary/symbol.hpp>
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

// Mirror of cli/src/dbg.cpp's compute_slide so the test exercises
// the same shape without importing CLI-private code.
ember::addr_t compute_slide(ember::debug::Target& tgt,
                            const ember::Binary& bin,
                            const std::string& bin_path) {
    const auto images = tgt.images();
    if (images.empty()) return 0;
    const ember::addr_t pref = bin.preferred_load_base();

    namespace fs = std::filesystem;
    std::error_code ec;
    std::string canon = bin_path;
    if (auto p = fs::canonical(bin_path, ec); !ec) canon = p.string();

    for (const auto& img : images) {
        if (img.path == bin_path || img.path == canon) {
            return img.base - pref;
        }
    }
    return images.front().base - pref;
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
    CHECK(marker != nullptr, "find dbg_marker");
    CHECK(marker->addr != 0, "dbg_marker addr");

    ember::debug::LaunchOptions opts;
    opts.program       = argv[1];
    opts.stop_at_entry = true;
    auto t_r = ember::debug::launch(opts);
    CHECK(t_r.has_value(), "launch");
    auto t = std::move(*t_r);

    const ember::addr_t slide = compute_slide(*t, **bin, argv[1]);
    const ember::addr_t bp_va = marker->addr + slide;

    auto bp_r = t->set_breakpoint(bp_va);
    CHECK(bp_r.has_value(), "set_breakpoint");
    const auto bp_id = *bp_r;

    CHECK(t->cont().has_value(), "cont 1");

    auto ev_r = t->wait_event();
    CHECK(ev_r.has_value(), "wait_event 1");
    const auto* hit = std::get_if<ember::debug::EvBreakpointHit>(&*ev_r);
    CHECK(hit != nullptr,         "expected EvBreakpointHit");
    CHECK(hit->id == bp_id,       "bp id mismatch");
    CHECK(hit->pc == bp_va,       "bp pc mismatch");

    // Register read/write round-trip — exercises the same get_regs /
    // set_regs path that backs the REPL's `set` command. Read, mutate
    // a callee-saved-but-unused register, write back, read again to
    // verify it stuck. Restore before continuing so the tracee's
    // state isn't disturbed.
    {
        const auto tids = t->threads();
        CHECK(!tids.empty(), "threads empty at bp");
        const auto tid = tids.front();
        auto regs1 = t->get_regs(tid);
        CHECK(regs1.has_value(), "get_regs at bp");
        const auto saved_r12 = regs1->r12;
        constexpr ember::u64 kTestPattern = 0xfeedface'cafebabeULL;
        auto regs_w = *regs1;
        regs_w.r12 = kTestPattern;
        CHECK(t->set_regs(tid, regs_w).has_value(), "set_regs round-trip");
        auto regs2 = t->get_regs(tid);
        CHECK(regs2.has_value(), "get_regs after set");
        CHECK(regs2->r12 == kTestPattern, "r12 readback after set");
        regs_w.r12 = saved_r12;
        CHECK(t->set_regs(tid, regs_w).has_value(), "set_regs restore");
    }

    // Memory read/write round-trip — exercises the same write_mem /
    // read_mem path the REPL's `poke` / `x` commands use. The bp
    // overwrote the first byte at bp_va with a 0xCC trap; round-trip
    // a single byte through a stack-resident scratch slot instead so
    // we don't fight the breakpoint's own bookkeeping.
    {
        const auto tids = t->threads();
        const auto tid = tids.front();
        auto regs = t->get_regs(tid);
        CHECK(regs.has_value(), "get_regs for stack");
        // Pick a slot a few bytes below RSP — within the red zone the
        // SysV ABI guarantees the kernel won't trample. Read it,
        // verify, then write a fresh pattern, verify, then restore.
        const ember::addr_t scratch = regs->rsp - 16;
        std::byte original[8] = {};
        auto rrv = t->read_mem(scratch, std::span<std::byte>{original});
        CHECK(rrv.has_value() && *rrv == sizeof(original),
              "read_mem scratch (initial)");
        constexpr ember::u8 kPattern[8] = {
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
        std::byte payload[8];
        for (std::size_t i = 0; i < sizeof(payload); ++i) {
            payload[i] = std::byte{kPattern[i]};
        }
        auto wrv = t->write_mem(scratch, std::span<const std::byte>{payload});
        CHECK(wrv.has_value() && *wrv == sizeof(payload), "write_mem scratch");
        std::byte readback[8] = {};
        rrv = t->read_mem(scratch, std::span<std::byte>{readback});
        CHECK(rrv.has_value() && *rrv == sizeof(readback),
              "read_mem scratch (verify)");
        for (std::size_t i = 0; i < sizeof(readback); ++i) {
            CHECK(readback[i] == payload[i], "scratch readback mismatch");
        }
        CHECK(t->write_mem(scratch, std::span<const std::byte>{original}).has_value(),
              "write_mem restore");
    }

    // Hardware watchpoint round-trip — exercises the DR0..DR3 path.
    // Arm a write-watch on `watch_slot`, drop the bp at dbg_marker so
    // we don't re-hit it, continue, expect the store in main() to
    // trip the watchpoint, then continue to exit.
    {
        const auto* slot_sym = (*bin)->find_by_name("watch_slot");
        CHECK(slot_sym != nullptr,    "find watch_slot");
        CHECK(slot_sym->addr != 0,    "watch_slot addr");
        const ember::addr_t slot_va = slot_sym->addr + slide;
        auto wp = t->set_watchpoint(slot_va, 8, ember::debug::WatchMode::Write);
        CHECK(wp.has_value(),         "set_watchpoint");
        const auto wp_id = *wp;

        CHECK(t->clear_breakpoint(bp_id).has_value(), "clear bp before resume");

        CHECK(t->cont().has_value(), "cont 2 (to wp)");
        ev_r = t->wait_event();
        CHECK(ev_r.has_value(),                     "wait_event after wp arm");
        const auto* whit = std::get_if<ember::debug::EvWatchpointHit>(&*ev_r);
        CHECK(whit != nullptr,                      "expected EvWatchpointHit");
        CHECK(whit->id == wp_id,                    "wp id mismatch");
        CHECK(whit->addr == slot_va,                "wp addr mismatch");
        CHECK(whit->slot < 4,                       "wp slot in range");

        CHECK(t->clear_watchpoint(wp_id).has_value(), "clear watchpoint");
    }

    CHECK(t->cont().has_value(), "cont 3");

    ev_r = t->wait_event();
    CHECK(ev_r.has_value(), "wait_event final");
    const auto* exited = std::get_if<ember::debug::EvExited>(&*ev_r);
    CHECK(exited != nullptr,  "expected EvExited");
    CHECK(exited->code == 42, "exit code");

    std::printf("OK (slide=0x%llx)\n", static_cast<unsigned long long>(slide));
    return 0;
}

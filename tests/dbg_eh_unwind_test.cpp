// Drives the .eh_frame unwinder against a -fomit-frame-pointer
// build of the dbg_target fixture. RBP-walk would return only the
// innermost frame because the prologue doesn't push RBP; the CFI
// unwinder must produce a multi-frame trace anchored at dbg_marker.

#include <cstdio>
#include <filesystem>
#include <system_error>
#include <utility>
#include <variant>

#include <spelunk/binary/binary.hpp>
#include <spelunk/binary/symbol.hpp>
#include <spelunk/debug/event.hpp>
#include <spelunk/debug/target.hpp>
#include <spelunk/debug/unwind.hpp>

#include "dbg_test_util.hpp"

#define CHECK(cond, msg)                                                   \
    do {                                                                   \
        if (!(cond)) {                                                     \
            std::fprintf(stderr,                                           \
                         "FAIL: %s (line %d)\n", (msg), __LINE__);         \
            return 1;                                                      \
        }                                                                  \
    } while (0)

namespace {

spelunk::addr_t compute_slide(spelunk::debug::Target& tgt,
                            const spelunk::Binary& bin,
                            const std::string& bin_path) {
    const auto images = tgt.images();
    if (images.empty()) return 0;
    const spelunk::addr_t pref = bin.preferred_load_base();

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

    auto bin = spelunk::load_binary(argv[1]);
    CHECK(bin.has_value(), "load_binary");

    const auto* marker = (*bin)->find_by_name("dbg_marker");
    CHECK(marker != nullptr, "find dbg_marker");

    spelunk::debug::LaunchOptions opts;
    opts.program       = argv[1];
    opts.stop_at_entry = true;
    auto t_r = spelunk::debug::launch(opts);
    if (!t_r) {
        if (spelunk_dbg_unavailable(t_r.error())) {
            return spelunk_dbg_skip("ptrace launch unavailable", t_r.error());
        }
        std::fprintf(stderr, "FAIL: launch: %s\n", t_r.error().message.c_str());
        return 1;
    }
    auto t = std::move(*t_r);

    const spelunk::addr_t slide = compute_slide(*t, **bin, argv[1]);
    const spelunk::addr_t bp_va = marker->addr + slide;

    auto bp_r = t->set_breakpoint(bp_va);
    CHECK(bp_r.has_value(), "set_breakpoint");

    CHECK(t->cont().has_value(), "cont 1");

    auto ev_r = t->wait_event();
    CHECK(ev_r.has_value(), "wait_event 1");
    const auto* hit = std::get_if<spelunk::debug::EvBreakpointHit>(&*ev_r);
    CHECK(hit != nullptr, "expected EvBreakpointHit");
    CHECK(hit->pc == bp_va, "bp pc mismatch");

    const spelunk::debug::ThreadId tid = hit->tid;

    // RBP-walk fails on -fomit-frame-pointer past frame 0. We don't
    // assert exactly 1 (the prologue may save RBP for other reasons
    // even with -fomit-frame-pointer), but it should be much shorter
    // than the .eh_frame trace.
    auto rbp_frames = spelunk::debug::unwind_rbp(*t, tid);
    CHECK(rbp_frames.has_value(), "rbp unwind");

    auto eh_frames = spelunk::debug::unwind_eh_frame(*t, tid, **bin, slide);
    CHECK(eh_frames.has_value(), "eh unwind");

    // Anchored at dbg_marker.
    CHECK(!eh_frames->empty(), "eh frames non-empty");
    CHECK(eh_frames->front().pc == bp_va, "eh frame 0 == bp_va");

    // The .eh_frame trace must reach into main - i.e. produce at
    // least 2 frames. RBP-walk must NOT outrun it (the whole point
    // of CFI is to be at least as good).
    CHECK(eh_frames->size() >= 2, "eh frames >= 2");
    CHECK(eh_frames->size() >= rbp_frames->size(),
          "eh trace at least as long as rbp trace");

    CHECK(t->kill().has_value(), "kill");
    std::printf("OK (rbp=%zu eh=%zu slide=0x%llx)\n",
                rbp_frames->size(), eh_frames->size(),
                static_cast<unsigned long long>(slide));
    return 0;
}

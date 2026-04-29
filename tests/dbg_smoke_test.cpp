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

    CHECK(t->cont().has_value(), "cont 2");

    ev_r = t->wait_event();
    CHECK(ev_r.has_value(), "wait_event 2");
    const auto* exited = std::get_if<ember::debug::EvExited>(&*ev_r);
    CHECK(exited != nullptr,  "expected EvExited");
    CHECK(exited->code == 42, "exit code");

    std::printf("OK (slide=0x%llx)\n", static_cast<unsigned long long>(slide));
    return 0;
}

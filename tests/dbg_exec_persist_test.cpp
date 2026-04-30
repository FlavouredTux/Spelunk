// Drives the debugger through an execve(2) boundary to verify that
// watchpoints set against a symbolic spec re-arm in the new image.
//
// Sequence:
//   1. Launch parent fixture, paused at entry.
//   2. Resolve `marker` and `preexec_marker` symbols in the parent.
//   3. Set software bp at preexec_marker, watchpoint on parent's
//      &marker (8 bytes, write).
//   4. Continue, expect bp hit at preexec_marker.
//   5. Continue, expect EvExec (kernel raised PTRACE_EVENT_EXEC).
//   6. Mirror the CLI's re-arm logic: drop kernel state, reload the
//      child binary, resolve the child's `marker` symbol, re-set the
//      watchpoint at the new VA.
//   7. Continue, expect EvWatchpointHit at the child's
//      child_writer+offset (the store inside child_writer that
//      mutates marker).
//   8. Continue, expect process exit code 0.

#include <cstdio>
#include <filesystem>
#include <utility>
#include <variant>

#include <ember/binary/binary.hpp>
#include <ember/binary/symbol.hpp>
#include <ember/debug/event.hpp>
#include <ember/debug/target.hpp>

#define CHECK(cond, msg)                                                \
    do {                                                                \
        if (!(cond)) {                                                  \
            std::fprintf(stderr, "FAIL: %s (line %d)\n", (msg), __LINE__); \
            return 1;                                                   \
        }                                                               \
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

}  // namespace

int main(int argc, char** argv) {
    if (argc < 3) {
        std::fprintf(stderr, "usage: %s <parent> <child>\n", argv[0]);
        return 99;
    }
    const std::string parent_path = argv[1];
    const std::string child_path  = argv[2];

    auto parent_bin = ember::load_binary(parent_path);
    CHECK(parent_bin.has_value(), "load parent binary");
    const auto* preexec = (*parent_bin)->find_by_name("preexec_marker");
    const auto* marker_p = (*parent_bin)->find_by_name("marker");
    CHECK(preexec  && preexec->addr  != 0, "parent preexec_marker symbol");
    CHECK(marker_p && marker_p->addr != 0, "parent marker symbol");

    ember::debug::LaunchOptions opts;
    opts.program       = parent_path;
    opts.args          = { child_path };
    opts.stop_at_entry = true;
    auto t_r = ember::debug::launch(opts);
    CHECK(t_r.has_value(), "launch parent");
    auto t = std::move(*t_r);

    const ember::addr_t parent_slide =
        compute_slide(*t, **parent_bin, parent_path);

    auto bp_r = t->set_breakpoint(preexec->addr + parent_slide);
    CHECK(bp_r.has_value(), "set bp on preexec_marker");

    auto wp_r = t->set_watchpoint(marker_p->addr + parent_slide, 8,
                                  ember::debug::WatchMode::Write);
    CHECK(wp_r.has_value(), "set watchpoint on parent marker");

    // 1. Reach preexec_marker.
    CHECK(t->cont().has_value(), "cont 1");
    auto ev = t->wait_event();
    CHECK(ev.has_value(), "wait 1");
    CHECK(std::holds_alternative<ember::debug::EvBreakpointHit>(*ev),
          "expected bp hit at preexec_marker");

    // 2. Continue past the printf+execve. Either the watchpoint
    //    fires first (printf path could write through marker; -O0
    //    keeps the load-only printf safe so usually we get straight
    //    to EvExec) or EvExec fires first. Loop until we see Exec.
    bool saw_exec = false;
    ember::addr_t exec_pc = 0;
    while (!saw_exec) {
        CHECK(t->cont().has_value(), "cont toward exec");
        ev = t->wait_event();
        CHECK(ev.has_value(), "wait toward exec");
        if (auto* ex = std::get_if<ember::debug::EvExec>(&*ev); ex) {
            saw_exec = true;
            exec_pc  = ex->pc;
            break;
        }
        // Anything else (including a stray watch fire from glibc's
        // libc-printf optimisations on the marker store) is fine —
        // just continue.
    }
    CHECK(saw_exec,    "EvExec received");
    CHECK(exec_pc != 0, "exec_pc reasonable");

    // 3. Drop the dead bp/wp state and re-arm against the child.
    t->clear_all_after_exec();
    auto child_bin = ember::load_binary(child_path);
    CHECK(child_bin.has_value(), "load child binary");
    const auto* marker_c = (*child_bin)->find_by_name("marker");
    const auto* writer_c = (*child_bin)->find_by_name("child_writer");
    CHECK(marker_c && marker_c->addr != 0, "child marker symbol");
    CHECK(writer_c && writer_c->addr != 0, "child child_writer symbol");

    const ember::addr_t child_slide =
        compute_slide(*t, **child_bin, child_path);
    auto wp2 = t->set_watchpoint(marker_c->addr + child_slide, 8,
                                 ember::debug::WatchMode::Write);
    CHECK(wp2.has_value(), "re-arm watchpoint in child");
    const auto wp2_id = *wp2;

    // 4. Continue; expect the watchpoint to fire inside child_writer.
    CHECK(t->cont().has_value(), "cont after re-arm");
    ev = t->wait_event();
    CHECK(ev.has_value(), "wait for watch fire");
    const auto* whit =
        std::get_if<ember::debug::EvWatchpointHit>(&*ev);
    CHECK(whit != nullptr,                  "expected watchpoint hit in child");
    CHECK(whit->id == wp2_id,               "watchpoint id mismatch");
    CHECK(whit->addr == marker_c->addr + child_slide,
                                            "watchpoint addr mismatch");
    // PC should be inside child_writer (post-store, so child_writer + small offset).
    const ember::addr_t writer_lo = writer_c->addr + child_slide;
    const ember::addr_t writer_hi = writer_lo + (writer_c->size ? writer_c->size : 0x40);
    CHECK(whit->pc >= writer_lo && whit->pc < writer_hi,
          "wp fire PC inside child_writer");
    const ember::addr_t wp_fire_pc = whit->pc;  // saved before next wait

    // 5. Run to completion.
    CHECK(t->clear_watchpoint(wp2_id).has_value(), "clear wp before exit");
    CHECK(t->cont().has_value(), "cont to exit");
    ev = t->wait_event();
    CHECK(ev.has_value(), "wait exit");
    const auto* exited = std::get_if<ember::debug::EvExited>(&*ev);
    CHECK(exited != nullptr,  "expected EvExited");
    CHECK(exited->code == 0,  "child exit code");

    std::printf("OK (parent_slide=0x%llx child_slide=0x%llx wp_pc=0x%llx)\n",
                static_cast<unsigned long long>(parent_slide),
                static_cast<unsigned long long>(child_slide),
                static_cast<unsigned long long>(wp_fire_pc));
    return 0;
}

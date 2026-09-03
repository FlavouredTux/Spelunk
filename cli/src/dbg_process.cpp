// Launch/attach, continue/step and post-exec re-arming.

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <map>
#include <print>
#include <set>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <variant>
#include <vector>

#include <ember/binary/binary.hpp>
#include <ember/common/types.hpp>
#include <ember/debug/event.hpp>
#include <ember/debug/target.hpp>
#include <ember/debug/types.hpp>

#include "args.hpp"
#include "dbg_internal.hpp"

namespace ember::cli::dbg {

namespace {

void rearm_after_exec(ReplState& rs) {
    rs.tgt->clear_all_after_exec();

    // /proc/pid/exe follows execve to the new binary path; reload if
    // it changed so symbol lookups hit the new image's table.
    char proc_exe[64];
    std::snprintf(proc_exe, sizeof proc_exe, "/proc/%u/exe", rs.tgt->pid());
    namespace fs = std::filesystem;
    std::error_code ec;
    if (auto target_path = fs::read_symlink(proc_exe, ec); !ec) {
        const std::string new_path = target_path.string();
        const std::string old_canon = [&] {
            std::error_code e;
            auto p = fs::canonical(rs.bin_path, e);
            return e ? rs.bin_path : p.string();
        }();
        if (new_path != old_canon) {
            if (auto reloaded = ember::load_binary(new_path); reloaded) {
                g_post_exec_bin = std::move(*reloaded);
                rs.bin            = g_post_exec_bin.get();
                rs.bin_path       = new_path;
                rs.bin_short_name = short_name_for(new_path);
                std::println("exec into new binary: {} (primary reloaded)", new_path);
            } else {
                std::println(stderr,
                    "ember-dbg: re-arm: failed to reload new primary {}: {}",
                    new_path, reloaded.error().message);
            }
        }
    }

    rs.slide = (rs.bin && !rs.bin_path.empty())
        ? compute_slide(*rs.tgt, *rs.bin, rs.bin_path) : 0;
    for (auto& aux : rs.aux_bins) {
        if (auto s = compute_aux_slide(*rs.tgt, aux); s) {
            aux.slide = *s;
            aux.slide_resolved = true;
        } else {
            aux.slide = 0;
            aux.slide_resolved = false;
        }
    }

    auto saved_bps = std::move(rs.bp_specs);
    auto saved_wps = std::move(rs.wp_specs);
    rs.bp_specs.clear();
    rs.wp_specs.clear();

    std::size_t bp_kept = 0, bp_lost = 0;
    for (const auto& [_, desc] : saved_bps) {
        auto spec = parse_addr_spec_multi(desc.spec, rs);
        if (!spec) {
            std::println(stderr,
                "ember-dbg: re-arm: bp '{}' no longer resolves; dropped", desc.spec);
            ++bp_lost;
            continue;
        }
        const addr_t va = resolve_runtime_multi(*spec);
        auto id = rs.tgt->set_breakpoint(va);
        if (!id) {
            std::println(stderr,
                "ember-dbg: re-arm: bp '{}' at {}: {}", desc.spec,
                fmt_addr(va), id.error().message);
            ++bp_lost;
            continue;
        }
        rs.bp_specs[*id] = desc;
        ++bp_kept;
    }
    std::size_t wp_kept = 0, wp_lost = 0;
    for (const auto& [_, desc] : saved_wps) {
        auto spec = parse_addr_spec_multi(desc.spec, rs);
        if (!spec) {
            std::println(stderr,
                "ember-dbg: re-arm: wp '{}' no longer resolves; dropped", desc.spec);
            ++wp_lost;
            continue;
        }
        const addr_t va = resolve_runtime_multi(*spec);
        auto id = rs.tgt->set_watchpoint(va, desc.size, desc.mode);
        if (!id) {
            std::println(stderr,
                "ember-dbg: re-arm: wp '{}' at {}: {}", desc.spec,
                fmt_addr(va), id.error().message);
            ++wp_lost;
            continue;
        }
        rs.wp_specs[*id] = desc;
        ++wp_kept;
    }
    if (bp_kept || wp_kept || bp_lost || wp_lost) {
        std::println("Re-armed across exec: {} bp ({} dropped), {} wp ({} dropped).",
                     bp_kept, bp_lost, wp_kept, wp_lost);
    }
}

}  // namespace

BackendChoice parse_debug_backend(std::string_view s) {
    if (s.empty() || s == "ptrace") return {debug::BackendKind::Ptrace,  false};
    if (s == "perf")                return {debug::BackendKind::Perf,    false};
    if (s == "auto")                return {debug::BackendKind::Perf,    true};
    std::println(stderr,
        "ember-dbg: --debug-backend: unknown value '{}' (expected ptrace|perf|auto) - using ptrace",
        s);
    return {debug::BackendKind::Ptrace, false};
}

int cmd_run(ReplState& rs, const Args& args) {
    if (rs.live) {
        std::println("Already running. Use `kill` then `run` to restart.");
        return 0;
    }
    if (args.binary.empty()) {
        std::println(stderr, "ember-dbg: run: no binary path (re-launch ember with --debug PATH)");
        return 1;
    }
    debug::LaunchOptions opts;
    opts.program = args.binary;
    opts.args    = args.debug_args;
    opts.stop_at_entry = true;
    opts.backend = rs.backend_kind;
    auto t = debug::launch(opts);
    if (!t && rs.backend_allow_fallback &&
        rs.backend_kind == debug::BackendKind::Perf) {
        std::println("Backend `perf` failed ({}: {}); falling back to `ptrace`.",
                     t.error().kind_name(), t.error().message);
        opts.backend = debug::BackendKind::Ptrace;
        t = debug::launch(opts);
    }
    if (!t) { print_error(t.error()); return 1; }
    rs.tgt = std::move(*t);
    on_target_acquired(rs);
    return 0;
}

int cmd_attach(ReplState& rs, std::string_view pid_str) {
    if (rs.live) {
        std::println("Already attached. Use `detach` first.");
        return 0;
    }
    auto pid = parse_int(pid_str);
    if (!pid) {
        std::println(stderr, "ember-dbg: attach: bad pid '{}'", pid_str);
        return 1;
    }
    auto t = debug::attach(static_cast<debug::ProcessId>(*pid),
                           rs.backend_kind);
    if (!t && rs.backend_allow_fallback &&
        rs.backend_kind == debug::BackendKind::Perf) {
        std::println("Backend `perf` failed ({}: {}); falling back to `ptrace`.",
                     t.error().kind_name(), t.error().message);
        t = debug::attach(static_cast<debug::ProcessId>(*pid),
                          debug::BackendKind::Ptrace);
    }
    if (!t) { print_error(t.error()); return 1; }
    rs.tgt = std::move(*t);
    on_target_acquired(rs);
    return 0;
}

int cmd_detach(ReplState& rs) {
    if (!rs.live) { std::println("Not attached."); return 0; }
    if (auto rv = rs.tgt->detach(); !rv) print_error(rv.error());
    on_target_released(rs);
    return 0;
}

int cmd_kill(ReplState& rs) {
    if (!rs.live) { std::println("Not attached."); return 0; }
    if (auto rv = rs.tgt->kill(); !rv) print_error(rv.error());
    on_target_released(rs);
    return 0;
}

bool wait_and_print(ReplState& rs) {
    while (true) {
        auto ev = rs.tgt->wait_event();
        if (!ev) { print_error(ev.error()); return true; }
        // Dynamic linker may have mapped libc / libstdc++ since
        // attach. Refresh any aux that wasn't yet resolved.
        refresh_unresolved_aux_slides(rs);

        // Fault-class signals at known-recovered PCs: silently forward
        // and keep waiting. The Linux backend stashed `pending_signal`
        // when it built the EvSignal; cont() forwards it back through
        // PTRACE_CONT's data argument, so the tracee's own handler
        // gets called and simret's past as it normally would.
        if (auto* sig = std::get_if<debug::EvSignal>(&*ev);
            sig && is_fault_signal(sig->signo) &&
            !rs.ignored_faults.empty()) {
            if (auto regs = rs.tgt->get_regs(sig->tid); regs) {
                const addr_t pc_runtime = regs->rip;
                const auto hit = find_bin_for_pc(rs, pc_runtime);
                const addr_t pc_static =
                    pc_runtime - (hit ? hit->slide : rs.slide);
                if (rs.ignored_faults.contains(pc_static)) {
                    if (auto rv = rs.tgt->cont(); !rv) {
                        print_error(rv.error());
                        return true;
                    }
                    continue;
                }
            }
        }

        if (auto* ex = std::get_if<debug::EvExec>(&*ev); ex) {
            rearm_after_exec(rs);
            std::println("execve completed; tracee paused at new entry {}{} in thread {}",
                         fmt_addr(ex->pc), sym_at_runtime(ex->pc, rs), ex->tid);
            return false;
        }

        if (print_event(*ev, rs)) {
            on_target_released(rs);
            return true;
        }
        return false;
    }
}

int cmd_cont(ReplState& rs) {
    if (!rs.live) { std::println("Not attached."); return 0; }
    if (auto rv = rs.tgt->cont(); !rv) { print_error(rv.error()); return 1; }
    wait_and_print(rs);
    return 0;
}

int cmd_step(ReplState& rs) {
    if (!rs.live) { std::println("Not attached."); return 0; }
    if (auto rv = rs.tgt->step(rs.current_tid); !rv) {
        print_error(rv.error());
        return 1;
    }
    wait_and_print(rs);
    return 0;
}

}  // namespace ember::cli::dbg

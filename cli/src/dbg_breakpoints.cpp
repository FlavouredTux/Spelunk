// Breakpoints, watchpoints and syscall catchpoints.

#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <optional>
#include <print>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <ember/analysis/pipeline.hpp>
#include <ember/analysis/syscalls.hpp>
#include <ember/common/types.hpp>
#include <ember/debug/breakpoint.hpp>
#include <ember/decompile/emit_options.hpp>

#include "dbg_internal.hpp"

namespace ember::cli::dbg {

namespace {

// `<bin>:<sym>` - restrict the symbol lookup to the named binary.
// The bin name is the basename of the path (no extension); primary
// uses basename(args.binary). Returns true on a hit (bp set or
// error reported); false to fall through.
bool try_break_qualified(ReplState& rs, std::string_view tok) {
    const auto colon = tok.find(':');
    if (colon == std::string_view::npos) return false;
    const std::string_view bin_tok = tok.substr(0, colon);
    const std::string_view sym_tok = tok.substr(colon + 1);
    if (bin_tok.empty() || sym_tok.empty()) return false;

    auto h = find_symbol_qualified(rs, bin_tok, sym_tok);
    if (!h) return false;

    const addr_t va = h->addr + h->slide;
    auto id = rs.tgt->set_breakpoint(va);
    if (!id) { print_error(id.error()); return true; }
    std::println("Breakpoint #{} at {}  ({}:{} → static {})",
                 *id, fmt_addr(va), bin_tok, sym_tok, fmt_addr(h->addr));
    return true;
}

// Reverse-lookup a Linux x86-64 syscall name → nr. Linear over the
// kernel's table; ~400 entries, called once per `catch syscall` token.
[[nodiscard]] std::optional<u32> syscall_nr_from_name(std::string_view name) {
    for (u32 i = 0; i < 512; ++i) {
        const auto n = linux_x64_syscall_name(i);
        if (!n.empty() && n == name) return i;
    }
    return std::nullopt;
}

[[nodiscard]] std::string syscall_label(u32 nr) {
    const auto n = linux_x64_syscall_name(nr);
    return n.empty() ? std::string{"?"} : std::string{n};
}

}  // namespace

// `<symbol>:<line>` - resolve to the runtime PC of the smallest IR
// source_addr whose emit lands on the requested pseudo-C line, then
// set a breakpoint there. Returns true on a match (breakpoint set or
// error already reported); false to fall through to plain addr / sym
// handling.
bool try_break_at_pseudo_line(ReplState& rs, std::string_view tok) {
    const auto colon = tok.find(':');
    if (colon == std::string_view::npos) return false;
    if (!rs.bin && rs.aux_bins.empty()) return false;

    const std::string_view sym_tok  = tok.substr(0, colon);
    const std::string_view line_tok = tok.substr(colon + 1);
    if (sym_tok.empty() || line_tok.empty()) return false;

    auto pl = parse_int(line_tok);
    if (!pl) return false;  // not a line number; caller falls through

    auto sh = find_symbol(rs, sym_tok);
    if (!sh) {
        std::println(stderr, "ember-dbg: b: symbol '{}' not found", sym_tok);
        return true;
    }
    auto win = ember::resolve_function_at(*sh->bin, sh->addr);
    if (!win) {
        std::println(stderr, "ember-dbg: b: cannot resolve {}", sym_tok);
        return true;
    }

    LineMap line_map;
    EmitOptions opts;
    opts.line_map = &line_map;
    auto pseudo = ember::format_struct(*sh->bin, *win, /*pseudo*/true,
                                       /*ann*/nullptr, opts);
    if (!pseudo) { print_error(pseudo.error()); return true; }
    const std::string& text = *pseudo;

    const auto target_line = static_cast<u32>(*pl);
    addr_t best = 0;
    bool   found = false;
    for (const auto& h : line_map.hits) {
        const auto ln = static_cast<u32>(1 + std::count(
            text.begin(),
            text.begin() + static_cast<std::ptrdiff_t>(h.byte_offset),
            '\n'));
        if (ln != target_line) continue;
        if (!found || h.source_addr < best) {
            best  = h.source_addr;
            found = true;
        }
    }
    if (!found) {
        std::println(stderr, "ember-dbg: b: no IR statement on line {} of {}",
                     target_line, sym_tok);
        return true;
    }

    const addr_t va = best + sh->slide;
    auto id = rs.tgt->set_breakpoint(va);
    if (!id) { print_error(id.error()); return true; }
    std::println("Breakpoint #{} at {}  ({}:{} → static {})",
                 *id, fmt_addr(va), sym_tok, target_line, fmt_addr(best));
    return true;
}

int cmd_break(ReplState& rs, std::string_view tok) {
    if (!rs.live) { std::println("Not attached."); return 0; }
    if (try_break_at_pseudo_line(rs, tok)) {
        // try_break_at_pseudo_line owns its own messaging and ID
        // assignment; persist via the bp table after the fact so
        // sym:line breakpoints survive exec just like the rest.
        const auto bps = rs.tgt->breakpoints();
        if (!bps.empty()) rs.bp_specs[bps.back().id] = BpSpec{std::string{tok}};
        return 0;
    }
    if (try_break_qualified(rs, tok)) {
        const auto bps = rs.tgt->breakpoints();
        if (!bps.empty()) rs.bp_specs[bps.back().id] = BpSpec{std::string{tok}};
        return 0;
    }
    auto spec = parse_addr_spec_multi(tok, rs);
    if (!spec) {
        std::println(stderr, "ember-dbg: b: '{}' is neither hex, a known symbol, nor sym:line", tok);
        return 1;
    }
    const addr_t va = resolve_runtime_multi(*spec);
    auto id = rs.tgt->set_breakpoint(va);
    if (!id) { print_error(id.error()); return 1; }
    rs.bp_specs[*id] = BpSpec{std::string{tok}};
    if (spec->was_symbol && va != spec->addr) {
        std::println("Breakpoint #{} at {}  ({} +slide {})",
                     *id, fmt_addr(va), fmt_addr(spec->addr),
                     fmt_addr(va - spec->addr));
    } else {
        std::println("Breakpoint #{} at {}", *id, fmt_addr(va));
    }
    return 0;
}

int cmd_bp_list(ReplState& rs) {
    if (!rs.live) { std::println("Not attached."); return 0; }
    const auto bps = rs.tgt->breakpoints();
    if (bps.empty()) { std::println("No breakpoints."); return 0; }
    for (const auto& bp : bps) {
        std::println("  #{:<3} {}  {}", bp.id, fmt_addr(bp.addr),
                     bp.enabled ? "enabled" : "disabled");
    }
    return 0;
}

int cmd_delete(ReplState& rs, std::string_view tok) {
    if (!rs.live) { std::println("Not attached."); return 0; }
    auto id = parse_int(tok);
    if (!id) {
        std::println(stderr, "ember-dbg: d: bad bp id '{}'", tok);
        return 1;
    }
    const auto bp_id = static_cast<debug::BreakpointId>(*id);
    if (auto rv = rs.tgt->clear_breakpoint(bp_id); !rv) {
        print_error(rv.error());
        return 1;
    }
    rs.bp_specs.erase(bp_id);
    return 0;
}

int cmd_catch(ReplState& rs, std::span<const std::string> toks) {
    if (!rs.live) { std::println("Not attached."); return 0; }
    if (toks.empty()) {
        std::println(stderr,
            "ember-dbg: catch: usage: catch syscall [<nr|name> ...]");
        return 1;
    }
    if (toks[0] != "syscall") {
        std::println(stderr,
            "ember-dbg: catch: only `catch syscall [args]` is supported");
        return 1;
    }
    if (toks.size() == 1) {
        // `catch syscall` with no args = catch every syscall.
        if (auto rv = rs.tgt->set_syscall_catch(true, std::span<const u32>{}); !rv) {
            print_error(rv.error()); return 1;
        }
        std::println("Catching every syscall.");
        return 0;
    }
    std::vector<u32> nrs;
    nrs.reserve(toks.size() - 1);
    for (std::size_t i = 1; i < toks.size(); ++i) {
        const auto& t = toks[i];
        if (auto n = parse_int(t); n && *n >= 0) {
            nrs.push_back(static_cast<u32>(*n));
            continue;
        }
        if (auto n = syscall_nr_from_name(t); n) {
            nrs.push_back(*n);
            continue;
        }
        std::println(stderr,
            "ember-dbg: catch: unknown syscall '{}' (use a decimal nr or Linux x64 name)", t);
        return 1;
    }
    if (auto rv = rs.tgt->set_syscall_catch(false, std::span<const u32>{nrs}); !rv) {
        print_error(rv.error()); return 1;
    }
    std::print("Catching syscalls:");
    for (auto n : nrs) std::print(" {}({})", syscall_label(n), n);
    std::println("");
    return 0;
}

int cmd_dcatch(ReplState& rs) {
    if (!rs.live) { std::println("Not attached."); return 0; }
    if (auto rv = rs.tgt->clear_syscall_catch(); !rv) {
        print_error(rv.error()); return 1;
    }
    std::println("Syscall catchpoint cleared.");
    return 0;
}

// `watch <addr> [r|w|rw] [size]`. Default mode = rw, default size = 8.
// Mode `r` is accepted but realised as ReadWrite at the architectural
// level - x86 has no read-only watchpoint mode. Emit a one-line note
// so the user knows their `r` request also fires on writes.
int cmd_watch(ReplState& rs, std::span<const std::string> toks) {
    if (!rs.live) { std::println("Not attached."); return 0; }
    if (toks.empty()) {
        std::println(stderr,
            "ember-dbg: watch: usage: watch <addr> [r|w|rw] [size]");
        return 1;
    }
    auto spec = parse_addr_spec_multi(toks[0], rs);
    if (!spec) {
        std::println(stderr, "ember-dbg: watch: bad address '{}'", toks[0]);
        return 1;
    }
    debug::WatchMode mode = debug::WatchMode::ReadWrite;
    bool requested_read_only = false;
    u8 size = 8;
    for (std::size_t i = 1; i < toks.size(); ++i) {
        const auto& t = toks[i];
        if (t == "r")       { mode = debug::WatchMode::ReadWrite; requested_read_only = true; }
        else if (t == "w")  { mode = debug::WatchMode::Write; }
        else if (t == "rw") { mode = debug::WatchMode::ReadWrite; }
        else if (auto n = parse_int(t); n && (*n == 1 || *n == 2 || *n == 4 || *n == 8)) {
            size = static_cast<u8>(*n);
        } else {
            std::println(stderr,
                "ember-dbg: watch: unknown mode/size '{}' (expected r|w|rw or 1/2/4/8)", t);
            return 1;
        }
    }
    const addr_t va = resolve_runtime_multi(*spec);
    auto id = rs.tgt->set_watchpoint(va, size, mode);
    if (!id) { print_error(id.error()); return 1; }
    rs.wp_specs[*id] = WpSpec{std::string{toks[0]}, size, mode};
    std::println("Watchpoint #{} at {} (size {}, {})",
                 *id, fmt_addr(va), size,
                 mode == debug::WatchMode::Write ? "write" : "read+write");
    if (requested_read_only) {
        std::println("note: x86 has no read-only watch mode - armed as read+write "
                     "(it'll fire on reads as you wanted; it'll also fire on writes).");
    }
    return 0;
}

int cmd_wp_list(ReplState& rs) {
    if (!rs.live) { std::println("Not attached."); return 0; }
    const auto wps = rs.tgt->watchpoints();
    if (wps.empty()) { std::println("No watchpoints."); return 0; }
    for (const auto& w : wps) {
        std::println("  #{:<3} {}  size={}  {}",
                     w.id, fmt_addr(w.addr), w.size,
                     w.mode == debug::WatchMode::Write ? "write" : "read+write");
    }
    return 0;
}

int cmd_dwp(ReplState& rs, std::string_view tok) {
    if (!rs.live) { std::println("Not attached."); return 0; }
    auto id = parse_int(tok);
    if (!id) {
        std::println(stderr, "ember-dbg: dwp: bad watchpoint id '{}'", tok);
        return 1;
    }
    const auto wp_id = static_cast<debug::WatchpointId>(*id);
    if (auto rv = rs.tgt->clear_watchpoint(wp_id); !rv) {
        print_error(rv.error());
        return 1;
    }
    rs.wp_specs.erase(wp_id);
    return 0;
}

}  // namespace ember::cli::dbg

#include "dbg.hpp"

#include <atomic>
#include <charconv>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <print>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <ember/analysis/pipeline.hpp>
#include <ember/binary/binary.hpp>
#include <ember/binary/symbol.hpp>
#include <ember/common/error.hpp>
#include <ember/debug/event.hpp>
#include <ember/debug/regs.hpp>
#include <ember/debug/target.hpp>
#include <ember/debug/unwind.hpp>
#include <ember/decompile/emit_options.hpp>

#include "args.hpp"

namespace ember::cli {

namespace {

// Active target for the SIGINT forwarder. The debugger blocks on
// wait_event() inside cont/step; Ctrl+C otherwise has nowhere to go
// but kill the REPL (and via PTRACE_O_EXITKILL, the tracee). With
// this hook, Ctrl+C calls interrupt() so the tracee yields control
// back to the prompt instead.
std::atomic<debug::Target*> g_active_target{nullptr};

extern "C" void sigint_forward(int) {
    auto* t = g_active_target.load(std::memory_order_acquire);
    if (t) (void)t->interrupt();
}

// ---- formatting helpers -------------------------------------------

std::string fmt_addr(addr_t a) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%016llx",
                  static_cast<unsigned long long>(a));
    return buf;
}

std::string fmt_signal(int sig) {
    switch (sig) {
        case SIGINT:  return "SIGINT";
        case SIGTERM: return "SIGTERM";
        case SIGSEGV: return "SIGSEGV";
        case SIGBUS:  return "SIGBUS";
        case SIGFPE:  return "SIGFPE";
        case SIGILL:  return "SIGILL";
        case SIGABRT: return "SIGABRT";
        case SIGTRAP: return "SIGTRAP";
        case SIGSTOP: return "SIGSTOP";
        case SIGCONT: return "SIGCONT";
        case SIGCHLD: return "SIGCHLD";
        default:      return std::string("SIG?(") + std::to_string(sig) + ")";
    }
}

// Returns " <symname>" if `runtime_pc` lands on a symbol in `bin`,
// after un-sliding by the cached PIE/ASLR offset. Empty string when
// no binary is loaded or no symbol matches.
std::string sym_at_runtime(addr_t runtime_pc, const Binary* bin, addr_t slide) {
    if (!bin) return {};
    const addr_t static_pc = runtime_pc - slide;
    for (const auto& s : bin->symbols()) {
        if (s.addr == static_pc) return " <" + s.name + ">";
    }
    return {};
}

// Returns true when the event ends the session (process exited or
// terminated). Caller should leave the REPL.
bool print_event(const debug::Event& ev, const Binary* bin, addr_t slide) {
    auto sym_at = [&](addr_t a) { return sym_at_runtime(a, bin, slide); };

    return std::visit([&](const auto& e) -> bool {
        using T = std::decay_t<decltype(e)>;
        if constexpr (std::is_same_v<T, debug::EvBreakpointHit>) {
            std::println("Breakpoint #{} hit at {}{} in thread {}",
                         e.id, fmt_addr(e.pc), sym_at(e.pc), e.tid);
        } else if constexpr (std::is_same_v<T, debug::EvSingleStep>) {
            std::println("Stepped to {}{} in thread {}",
                         fmt_addr(e.pc), sym_at(e.pc), e.tid);
        } else if constexpr (std::is_same_v<T, debug::EvSignal>) {
            std::println("Signal {} ({}) in thread {} — held for forward on next cont",
                         fmt_signal(e.signo), e.signo, e.tid);
        } else if constexpr (std::is_same_v<T, debug::EvStopped>) {
            std::println("Stopped at {}{} in thread {}",
                         fmt_addr(e.pc), sym_at(e.pc), e.tid);
        } else if constexpr (std::is_same_v<T, debug::EvThreadCreated>) {
            std::println("Thread {} created", e.tid);
        } else if constexpr (std::is_same_v<T, debug::EvThreadExited>) {
            std::println("Thread {} exited (code={})", e.tid, e.code);
        } else if constexpr (std::is_same_v<T, debug::EvImageLoaded>) {
            std::println("Image loaded at {}", fmt_addr(e.base));
        } else if constexpr (std::is_same_v<T, debug::EvExited>) {
            std::println("Process exited (code={})", e.code);
            return true;
        } else if constexpr (std::is_same_v<T, debug::EvTerminated>) {
            std::println("Process terminated by signal {} ({})",
                         fmt_signal(e.signo), e.signo);
            return true;
        }
        return false;
    }, ev);
}

void print_error(const Error& e) {
    std::println(stderr, "ember-dbg: {}: {}", e.kind_name(), e.message);
}

// Two flavours of address: a hex literal (already a runtime VA — no
// slide) versus a symbol resolved from the loaded Binary (a static /
// linker VA — needs the runtime slide added before use against PIE
// or ASLR-loaded images).
struct AddrSpec {
    addr_t addr       = 0;
    bool   was_symbol = false;
};

std::optional<AddrSpec>
parse_addr_spec(std::string_view tok, const Binary* bin) {
    if (tok.empty()) return std::nullopt;

    std::string_view t = tok;
    if (t.starts_with("0x") || t.starts_with("0X")) t.remove_prefix(2);
    bool all_hex = !t.empty();
    for (char c : t) {
        const bool is_hex = (c >= '0' && c <= '9') ||
                            (c >= 'a' && c <= 'f') ||
                            (c >= 'A' && c <= 'F');
        if (!is_hex) { all_hex = false; break; }
    }
    if (all_hex) {
        addr_t v = 0;
        for (char c : t) {
            const int d = (c >= '0' && c <= '9') ? c - '0'
                        : (c >= 'a' && c <= 'f') ? c - 'a' + 10
                        : c - 'A' + 10;
            v = (v << 4) | static_cast<addr_t>(d);
        }
        return AddrSpec{v, false};
    }

    if (bin) {
        if (auto* s = bin->find_by_name(tok); s && s->addr != 0) {
            return AddrSpec{s->addr, true};
        }
    }
    return std::nullopt;
}

// PIE / ASLR slide: distance between the runtime base of the main
// binary's mapping and the linker's preferred load base. Non-PIE
// loaded at its preferred address falls out as 0, so symbol-based
// breakpoints just work without the user knowing the difference.
addr_t compute_slide(debug::Target& tgt, const Binary& bin,
                     const std::string& bin_path) {
    const auto images = tgt.images();
    if (images.empty()) return 0;
    const addr_t pref = bin.preferred_load_base();

    namespace fs = std::filesystem;
    std::error_code ec;
    std::string canon = bin_path;
    if (auto p = fs::canonical(bin_path, ec); !ec) canon = p.string();

    // Match by path first; the kernel maps the main binary first
    // after exec so the front of the list is a safe fallback.
    for (const auto& img : images) {
        if (img.path == bin_path || img.path == canon) {
            return img.base - pref;
        }
    }
    return images.front().base - pref;
}

addr_t resolve_runtime(const AddrSpec& spec, debug::Target& tgt,
                       const Binary* bin, const std::string& bin_path) {
    if (!spec.was_symbol || !bin) return spec.addr;
    return spec.addr + compute_slide(tgt, *bin, bin_path);
}

std::optional<int> parse_int(std::string_view s) {
    int v = 0;
    auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
    if (ec != std::errc{} || p != s.data() + s.size()) return std::nullopt;
    return v;
}

std::vector<std::string> tokenize(const std::string& line) {
    std::vector<std::string> out;
    std::istringstream is(line);
    std::string tok;
    while (is >> tok) out.push_back(std::move(tok));
    return out;
}

// ---- command implementations --------------------------------------

struct ReplState {
    std::unique_ptr<debug::Target> tgt;
    debug::ThreadId                current_tid = 0;
    bool                           live        = false;
    const Binary*                  bin         = nullptr;
    std::string                    bin_path;   // for compute_slide path-matching
    addr_t                         slide       = 0;  // PIE/ASLR slide; 0 for non-PIE
};

void on_target_acquired(ReplState& rs) {
    g_active_target.store(rs.tgt.get(), std::memory_order_release);
    rs.live = true;
    if (auto threads = rs.tgt->threads(); !threads.empty()) {
        rs.current_tid = threads.front();
    }
    rs.slide = (rs.bin && !rs.bin_path.empty())
        ? compute_slide(*rs.tgt, *rs.bin, rs.bin_path) : 0;

    std::println("Process {} attached, {} thread(s){}.",
                 rs.tgt->pid(), rs.tgt->threads().size(),
                 rs.slide ? std::format(" — slide {}", fmt_addr(rs.slide))
                          : std::string{});
    if (auto regs = rs.tgt->get_regs(rs.current_tid); regs) {
        std::println("Thread {} paused at {}.", rs.current_tid, fmt_addr(regs->rip));
    }
}

void on_target_released(ReplState& rs) {
    g_active_target.store(nullptr, std::memory_order_release);
    rs.tgt.reset();
    rs.live = false;
    rs.current_tid = 0;
    rs.slide = 0;
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
    auto t = debug::launch(opts);
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
    auto t = debug::attach(static_cast<debug::ProcessId>(*pid));
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

// `<symbol>:<line>` — resolve to the runtime PC of the smallest IR
// source_addr whose emit lands on the requested pseudo-C line, then
// set a breakpoint there. Returns true on a match (breakpoint set or
// error already reported); false to fall through to plain addr / sym
// handling.
bool try_break_at_pseudo_line(ReplState& rs, std::string_view tok) {
    const auto colon = tok.find(':');
    if (colon == std::string_view::npos) return false;
    if (!rs.bin) return false;

    const std::string_view sym_tok  = tok.substr(0, colon);
    const std::string_view line_tok = tok.substr(colon + 1);
    if (sym_tok.empty() || line_tok.empty()) return false;

    auto pl = parse_int(line_tok);
    if (!pl) return false;  // not a line number; caller falls through

    const auto* sym = rs.bin->find_by_name(sym_tok);
    if (!sym || sym->addr == 0) {
        std::println(stderr, "ember-dbg: b: symbol '{}' not found", sym_tok);
        return true;
    }
    auto win = ember::resolve_function_at(*rs.bin, sym->addr);
    if (!win) {
        std::println(stderr, "ember-dbg: b: cannot resolve {}", sym_tok);
        return true;
    }

    LineMap line_map;
    EmitOptions opts;
    opts.line_map = &line_map;
    auto pseudo = ember::format_struct(*rs.bin, *win, /*pseudo*/true,
                                       /*ann*/nullptr, std::move(opts));
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

    const addr_t va = best + rs.slide;
    auto id = rs.tgt->set_breakpoint(va);
    if (!id) { print_error(id.error()); return true; }
    std::println("Breakpoint #{} at {}  ({}:{} → static {})",
                 *id, fmt_addr(va), sym_tok, target_line, fmt_addr(best));
    return true;
}

int cmd_break(ReplState& rs, std::string_view tok) {
    if (!rs.live) { std::println("Not attached."); return 0; }
    if (try_break_at_pseudo_line(rs, tok)) return 0;
    auto spec = parse_addr_spec(tok, rs.bin);
    if (!spec) {
        std::println(stderr, "ember-dbg: b: '{}' is neither hex, a known symbol, nor sym:line", tok);
        return 1;
    }
    const addr_t va = resolve_runtime(*spec, *rs.tgt, rs.bin, rs.bin_path);
    auto id = rs.tgt->set_breakpoint(va);
    if (!id) { print_error(id.error()); return 1; }
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
    if (auto rv = rs.tgt->clear_breakpoint(static_cast<debug::BreakpointId>(*id)); !rv) {
        print_error(rv.error());
        return 1;
    }
    return 0;
}

bool wait_and_print(ReplState& rs) {
    auto ev = rs.tgt->wait_event();
    if (!ev) { print_error(ev.error()); return true; }
    if (print_event(*ev, rs.bin, rs.slide)) {
        on_target_released(rs);
        return true;
    }
    return false;
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

void print_zmm(const debug::Registers::ZmmReg& z, int width) {
    // width = 16 (XMM), 32 (YMM), 64 (ZMM)
    for (int i = width - 1; i >= 0; --i) {
        std::print("{:02x}", z.bytes[i]);
    }
}

int cmd_regs(ReplState& rs, bool full) {
    if (!rs.live) { std::println("Not attached."); return 0; }
    auto regs = rs.tgt->get_regs(rs.current_tid);
    if (!regs) { print_error(regs.error()); return 1; }
    const auto& r = *regs;

    std::println("rax={}  rbx={}  rcx={}  rdx={}",
                 fmt_addr(r.rax), fmt_addr(r.rbx), fmt_addr(r.rcx), fmt_addr(r.rdx));
    std::println("rsi={}  rdi={}  rbp={}  rsp={}",
                 fmt_addr(r.rsi), fmt_addr(r.rdi), fmt_addr(r.rbp), fmt_addr(r.rsp));
    std::println("r8 ={}  r9 ={}  r10={}  r11={}",
                 fmt_addr(r.r8), fmt_addr(r.r9), fmt_addr(r.r10), fmt_addr(r.r11));
    std::println("r12={}  r13={}  r14={}  r15={}",
                 fmt_addr(r.r12), fmt_addr(r.r13), fmt_addr(r.r14), fmt_addr(r.r15));
    std::println("rip={}  rflags={}",
                 fmt_addr(r.rip), fmt_addr(r.rflags));
    std::println("cs={:04x} ds={:04x} es={:04x} fs={:04x} gs={:04x} ss={:04x}",
                 r.cs, r.ds, r.es, r.fs, r.gs, r.ss);
    std::println("fs_base={}  gs_base={}", fmt_addr(r.fs_base), fmt_addr(r.gs_base));

    if (!full) return 0;

    if (r.present & debug::Registers::PresentX87) {
        std::println("--- x87 ---");
        std::println("fcw={:04x} fsw={:04x} ftw={:02x} fop={:04x} fip={} fdp={}",
                     r.fcw, r.fsw, r.ftw, r.fop, fmt_addr(r.fip), fmt_addr(r.fdp));
        for (int i = 0; i < 8; ++i) {
            std::print("st{}=", i);
            for (int b = 9; b >= 0; --b) std::print("{:02x}", r.st[i].bytes[b]);
            std::print("  ");
            if ((i & 1) == 1) std::println();
        }
    }
    if (r.present & debug::Registers::PresentSse) {
        std::println("--- sse ---  mxcsr={:08x} mask={:08x}", r.mxcsr, r.mxcsr_mask);
        for (int i = 0; i < 16; ++i) {
            std::print("xmm{:<2}=", i);
            print_zmm(r.zmm[i], 16);
            std::println();
        }
    }
    if (r.present & debug::Registers::PresentAvx) {
        std::println("--- avx (ymm high halves) ---");
        for (int i = 0; i < 16; ++i) {
            std::print("ymm{:<2}=", i);
            print_zmm(r.zmm[i], 32);
            std::println();
        }
    }
    if (r.present & debug::Registers::PresentAvx512) {
        std::println("--- avx-512 ---");
        for (int i = 0; i < 8; ++i) {
            std::println("k{}={:016x}", i, r.k[i]);
        }
        for (int i = 0; i < 32; ++i) {
            std::print("zmm{:<2}=", i);
            print_zmm(r.zmm[i], 64);
            std::println();
        }
    }
    if (r.present & debug::Registers::PresentDr) {
        std::println("--- debug ---");
        std::println("dr0={}  dr1={}  dr2={}  dr3={}",
                     fmt_addr(r.dr[0]), fmt_addr(r.dr[1]),
                     fmt_addr(r.dr[2]), fmt_addr(r.dr[3]));
        std::println("dr6={}  dr7={}", fmt_addr(r.dr[6]), fmt_addr(r.dr[7]));
    }
    return 0;
}

int cmd_xmem(ReplState& rs, std::string_view addr_tok, std::string_view count_tok) {
    if (!rs.live) { std::println("Not attached."); return 0; }
    auto spec = parse_addr_spec(addr_tok, rs.bin);
    if (!spec) {
        std::println(stderr, "ember-dbg: x: bad address '{}'", addr_tok);
        return 1;
    }
    const addr_t va_runtime = resolve_runtime(*spec, *rs.tgt, rs.bin, rs.bin_path);
    int count = 16;
    if (!count_tok.empty()) {
        if (auto n = parse_int(count_tok)) count = *n;
    }
    if (count <= 0) count = 16;

    std::vector<std::byte> buf(static_cast<std::size_t>(count));
    auto rv = rs.tgt->read_mem(va_runtime, buf);
    if (!rv) { print_error(rv.error()); return 1; }

    const std::size_t got = *rv;
    for (std::size_t i = 0; i < got; i += 16) {
        std::print("{}: ", fmt_addr(va_runtime + i));
        const std::size_t row = std::min<std::size_t>(16, got - i);
        for (std::size_t j = 0; j < row; ++j) {
            std::print("{:02x} ", static_cast<unsigned>(buf[i + j]));
        }
        for (std::size_t j = row; j < 16; ++j) std::print("   ");
        std::print(" ");
        for (std::size_t j = 0; j < row; ++j) {
            const auto c = static_cast<unsigned char>(buf[i + j]);
            std::print("{}", (c >= 32 && c < 127) ? static_cast<char>(c) : '.');
        }
        std::println();
    }
    if (got < buf.size()) {
        std::println("(read short — {} of {} requested bytes)", got, buf.size());
    }
    return 0;
}

int cmd_bt(ReplState& rs) {
    if (!rs.live) { std::println("Not attached."); return 0; }

    // Try .eh_frame first when we have a binary to consult. CFI
    // unwinds correctly through `-fomit-frame-pointer` code where
    // RBP-walk would fall over after the innermost frame. If CFI
    // gives nothing useful (no binary, no .eh_frame, or stalled at
    // frame 0), fall back to RBP-walk.
    std::vector<debug::Frame> frames;
    bool used_eh = false;
    if (rs.bin) {
        if (auto eh = debug::unwind_eh_frame(*rs.tgt, rs.current_tid,
                                             *rs.bin, rs.slide); eh) {
            frames  = std::move(*eh);
            used_eh = frames.size() >= 2;
        }
    }
    if (!used_eh) {
        auto rbp = debug::unwind_rbp(*rs.tgt, rs.current_tid);
        if (!rbp) { print_error(rbp.error()); return 1; }
        if (rbp->size() > frames.size()) frames = std::move(*rbp);
    }

    int idx = 0;
    for (const auto& f : frames) {
        std::println("#{:<2} {}{}", idx++, fmt_addr(f.pc),
                     sym_at_runtime(f.pc, rs.bin, rs.slide));
    }
    if (used_eh) std::println("  (via .eh_frame)");
    return 0;
}

int cmd_code(ReplState& rs) {
    if (!rs.live) { std::println("Not attached."); return 0; }
    if (!rs.bin) {
        std::println(stderr, "ember-dbg: code: no binary loaded");
        return 1;
    }
    auto regs = rs.tgt->get_regs(rs.current_tid);
    if (!regs) { print_error(regs.error()); return 1; }

    const addr_t pc_runtime = regs->rip;
    const addr_t pc_static  = pc_runtime - rs.slide;

    auto cf = ember::containing_function(*rs.bin, pc_static);
    if (!cf) {
        std::println("No function covers {} (static {}).",
                     fmt_addr(pc_runtime), fmt_addr(pc_static));
        return 0;
    }
    auto win = ember::resolve_function_at(*rs.bin, cf->entry);
    if (!win) {
        std::println(stderr, "ember-dbg: code: failed to resolve {}", cf->name);
        return 1;
    }

    LineMap line_map;
    EmitOptions opts;
    opts.line_map = &line_map;
    auto pseudo = ember::format_struct(*rs.bin, *win, /*pseudo*/true,
                                       /*ann*/nullptr, std::move(opts));
    if (!pseudo) { print_error(pseudo.error()); return 1; }
    const std::string& text = *pseudo;

    // Two-tier match: prefer the hit with the largest source_addr <=
    // pc_static (the IR currently in flight). If we're sitting inside
    // a region that the emitter folded away (prologue, dead code), no
    // such hit exists — fall back to the first emitted IR after pc, so
    // the user sees the next visible statement marked instead of no
    // mark at all.
    const LineMap::Hit* best = nullptr;
    const LineMap::Hit* first_after = nullptr;
    for (const auto& h : line_map.hits) {
        if (h.source_addr <= pc_static) {
            if (!best || h.source_addr > best->source_addr) best = &h;
        } else {
            if (!first_after || h.source_addr < first_after->source_addr) {
                first_after = &h;
            }
        }
    }
    const LineMap::Hit* picked = best ? best : first_after;

    u32 marked_line = 0;
    if (picked) {
        marked_line = 1 + static_cast<u32>(std::count(
            text.begin(),
            text.begin() + static_cast<std::ptrdiff_t>(picked->byte_offset),
            '\n'));
    }

    std::println("// {}  entry={}  size={}  pc-offset=0x{:x}",
                 cf->name, fmt_addr(cf->entry), cf->size, cf->offset_within);

    // Print with arrow on the marked line.
    u32 line_no = 1;
    std::size_t i = 0;
    while (i < text.size()) {
        const auto nl = text.find('\n', i);
        const auto end = (nl == std::string::npos) ? text.size() : nl;
        std::println("{} {:>4} | {}",
                     (line_no == marked_line ? "->" : "  "),
                     line_no,
                     std::string_view(text).substr(i, end - i));
        if (nl == std::string::npos) break;
        i = nl + 1;
        ++line_no;
    }
    if (picked == first_after && first_after) {
        std::println("(pc {} is in folded-away code; arrow shows next visible IR at {})",
                     fmt_addr(pc_static), fmt_addr(first_after->source_addr));
    }
    return 0;
}

int cmd_threads(ReplState& rs) {
    if (!rs.live) { std::println("Not attached."); return 0; }
    for (auto tid : rs.tgt->threads()) {
        std::println("  {}{}", (tid == rs.current_tid ? "* " : "  "), tid);
    }
    return 0;
}

int cmd_thread_switch(ReplState& rs, std::string_view tok) {
    if (!rs.live) { std::println("Not attached."); return 0; }
    auto v = parse_int(tok);
    if (!v) {
        std::println(stderr, "ember-dbg: thread: bad tid '{}'", tok);
        return 1;
    }
    rs.current_tid = static_cast<debug::ThreadId>(*v);
    std::println("Switched to thread {}", rs.current_tid);
    return 0;
}

void print_help() {
    std::println(R"(commands:
  run                       launch the binary (uses --debug PATH and -- args)
  attach <pid>              attach to a running process
  detach                    detach from the tracee (it keeps running)
  kill                      send SIGKILL to the tracee
  b <addr|sym|sym:line>     set a software breakpoint
                            sym:line resolves a pseudo-C line for the
                            named function (run `code` to see the lines)
  bp                        list breakpoints
  d <id>                    delete a breakpoint
  c                         continue all paused threads
  s                         single-step the current thread
  regs [all]                show registers ('all' for x87/SSE/AVX/AVX-512/DR)
  x <addr> [n]              read n bytes (default 16) and hex-dump
  bt | where                backtrace (.eh_frame; RBP-walk fallback)
  code | list | l           pseudo-C of the function containing the current PC
  threads                   list threads (* marks current)
  thread <tid>              switch current thread
  help                      this message
  q | quit | exit           leave the REPL
)");
}

}  // namespace

int run_debug(const Args& args, const Binary* bin) {
    ReplState rs;
    rs.bin      = bin;
    rs.bin_path = args.binary;

    std::signal(SIGINT, sigint_forward);

    // Auto-launch / auto-attach when invoked with usable arguments.
    if (!args.attach_pid.empty()) {
        cmd_attach(rs, args.attach_pid);
    } else if (!args.binary.empty()) {
        cmd_run(rs, args);
    } else {
        std::println("ember-dbg: no binary path and no --attach-pid; use `run` or `attach`.");
    }

    std::string line;
    while (true) {
        std::print("(ember) ");
        std::fflush(stdout);
        if (!std::getline(std::cin, line)) { std::println(); break; }
        const auto toks = tokenize(line);
        if (toks.empty()) continue;
        const auto& cmd = toks[0];

        if      (cmd == "q" || cmd == "quit" || cmd == "exit") break;
        else if (cmd == "help" || cmd == "?")                  print_help();
        else if (cmd == "run"  || cmd == "r")                  cmd_run(rs, args);
        else if (cmd == "attach" && toks.size() > 1)           cmd_attach(rs, toks[1]);
        else if (cmd == "detach")                              cmd_detach(rs);
        else if (cmd == "kill")                                cmd_kill(rs);
        else if ((cmd == "b" || cmd == "break") && toks.size() > 1)
                                                               cmd_break(rs, toks[1]);
        else if (cmd == "bp" || cmd == "info-break")           cmd_bp_list(rs);
        else if (cmd == "d"  && toks.size() > 1)               cmd_delete(rs, toks[1]);
        else if (cmd == "c"  || cmd == "cont")                 cmd_cont(rs);
        else if (cmd == "s"  || cmd == "step")                 cmd_step(rs);
        else if (cmd == "regs")
            cmd_regs(rs, toks.size() > 1 && toks[1] == "all");
        else if (cmd == "x"  && toks.size() > 1)
            cmd_xmem(rs, toks[1], toks.size() > 2 ? toks[2] : std::string_view{});
        else if (cmd == "bt" || cmd == "where")                cmd_bt(rs);
        else if (cmd == "code" || cmd == "list" || cmd == "l") cmd_code(rs);
        else if (cmd == "threads")                             cmd_threads(rs);
        else if (cmd == "thread" && toks.size() > 1)           cmd_thread_switch(rs, toks[1]);
        else std::println(stderr, "ember-dbg: unknown command '{}' (try `help`)", cmd);
    }

    if (rs.live) {
        // Tracee is still attached on REPL exit. PTRACE_O_EXITKILL
        // means it dies with us; detach() if the user wanted to leave
        // it running, otherwise this is fine.
        (void)rs.tgt->detach();
        on_target_released(rs);
    }
    std::signal(SIGINT, SIG_DFL);
    return 0;
}

}  // namespace ember::cli

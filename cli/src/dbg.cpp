// REPL state, dispatch loop and run_debug.

#include "dbg.hpp"

#include <atomic>
#include <charconv>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <format>
#include <iostream>
#include <optional>
#include <print>
#include <set>
#include <signal.h>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#include <spelunk/analysis/pipeline.hpp>
#include <spelunk/analysis/syscalls.hpp>
#include <spelunk/binary/binary.hpp>
#include <spelunk/common/error.hpp>
#include <spelunk/common/types.hpp>
#include <spelunk/debug/event.hpp>
#include <spelunk/debug/target.hpp>

#include "dbg_internal.hpp"

namespace spelunk::cli::dbg {

namespace {

extern "C" void sigint_forward(int) {
    auto* t = g_active_target.load(std::memory_order_acquire);
    if (t) (void)t->interrupt();
}

std::string fmt_signal(int sig) {
    switch (sig) {
        case SIGINT:  return "SIGINT";
        case SIGTERM: return "SIGTERM";
        case SIGSEGV: return "SIGSEGV";
        case SIGFPE:  return "SIGFPE";
        case SIGILL:  return "SIGILL";
        case SIGABRT: return "SIGABRT";
#if !defined(_WIN32)
        case SIGBUS:  return "SIGBUS";
        case SIGTRAP: return "SIGTRAP";
        case SIGSTOP: return "SIGSTOP";
        case SIGCONT: return "SIGCONT";
        case SIGCHLD: return "SIGCHLD";
#endif
        default:      return std::string("SIG?(") + std::to_string(sig) + ")";
    }
}

std::vector<std::string> tokenize(const std::string& line) {
    std::vector<std::string> out;
    std::istringstream is(line);
    std::string tok;
    while (is >> tok) out.push_back(std::move(tok));
    return out;
}

// `aux <path>` (or `aux <path>@<hex>`): load a Binary at runtime as
// an extra symbol oracle. Useful when the tracee mmaps a fresh
// non-ELF blob mid-session that wasn't known at --debug time.
int cmd_aux(ReplState& rs, std::string_view tok) {
    if (tok.empty()) {
        if (rs.aux_bins.empty()) {
            std::println("No aux binaries loaded.");
            return 0;
        }
        for (const auto& aux : rs.aux_bins) {
            std::println("  [{}]  {}  {}{}", aux.short_name, aux.path,
                         aux.slide_resolved
                             ? fmt_addr(aux.bin->preferred_load_base() + aux.slide)
                             : std::string("(unresolved)"),
                         aux.manual_base ? " (manual)" : "");
        }
        return 0;
    }
    std::string path(tok);
    std::optional<addr_t> manual;
    if (auto at = path.find('@'); at != std::string::npos) {
        std::string_view va_tok(path);
        va_tok.remove_prefix(at + 1);
        if (va_tok.starts_with("0x") || va_tok.starts_with("0X")) {
            va_tok.remove_prefix(2);
        }
        addr_t v = 0;
        bool ok = !va_tok.empty();
        for (char c : va_tok) {
            const int d = (c >= '0' && c <= '9') ? c - '0'
                : (c >= 'a' && c <= 'f') ? c - 'a' + 10
                : (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1;
            if (d < 0) { ok = false; break; }
            v = (v << 4) | static_cast<addr_t>(d);
        }
        if (!ok) {
            std::println(stderr, "spelunk-dbg: aux: bad hex base in '{}'", tok);
            return 1;
        }
        manual = v;
        path.resize(at);
    }
    auto loaded = spelunk::load_binary(path);
    if (!loaded) { print_error(loaded.error()); return 1; }
    rs.aux_storage.push_back(std::move(*loaded));
    AuxBin aux;
    aux.bin         = rs.aux_storage.back().get();
    aux.short_name  = short_name_for(path);
    aux.path        = std::move(path);
    aux.manual_base = manual;
    if (rs.live) {
        if (auto s = compute_aux_slide(*rs.tgt, aux); s) {
            aux.slide          = *s;
            aux.slide_resolved = true;
            std::println("aux: {} loaded at {}{}", aux.path,
                         fmt_addr(aux.bin->preferred_load_base() + aux.slide),
                         aux.manual_base ? " (manual)" : " (auto)");
        } else {
            std::println(stderr,
                "aux: {} loaded but slide unresolved (size {} not unique in /proc/<pid>/maps)",
                aux.path, aux.bin->mapped_size());
        }
    }
    rs.aux_bins.push_back(std::move(aux));
    return 0;
}

int cmd_ignore(ReplState& rs, std::string_view tok) {
    if (tok.empty()) {
        if (rs.ignored_faults.empty()) {
            std::println("No ignored-fault PCs.");
            return 0;
        }
        std::println("Ignored fault PCs ({}):", rs.ignored_faults.size());
        for (addr_t a : rs.ignored_faults) std::println("  {}", fmt_addr(a));
        return 0;
    }
    auto h = parse_hex_addr(tok);
    if (!h) {
        std::println(stderr, "spelunk-dbg: ignore: bad hex '{}'", tok);
        return 1;
    }
    if (rs.ignored_faults.insert(*h).second) {
        std::println("Ignoring faults at {}", fmt_addr(*h));
    } else {
        std::println("Already ignoring {}", fmt_addr(*h));
    }
    return 0;
}

int cmd_unignore(ReplState& rs, std::string_view tok) {
    auto h = parse_hex_addr(tok);
    if (!h) {
        std::println(stderr, "spelunk-dbg: unignore: bad hex '{}'", tok);
        return 1;
    }
    if (rs.ignored_faults.erase(*h) > 0) {
        std::println("Removed {} from ignored-fault set", fmt_addr(*h));
    } else {
        std::println("{} was not in the set", fmt_addr(*h));
    }
    return 0;
}

int cmd_ignore_file(ReplState& rs, std::string_view tok) {
    if (tok.empty()) {
        std::println(stderr, "spelunk-dbg: ignore-file: usage: ignore-file <path>");
        return 1;
    }
    const std::size_t added = load_ignored_faults_file(
        std::string(tok), rs.ignored_faults);
    std::println("Loaded {} new fault PCs from {} (total {})",
                 added, tok, rs.ignored_faults.size());
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
  b <bin>:<sym>             restrict a symbol lookup to one Binary; <bin>
                            is the basename(path) of either the primary
                            or an aux. Useful when both define `main` etc.
  bp                        list breakpoints
  d <id>                    delete a breakpoint
  watch <addr> [r|w|rw] [N] hardware data watchpoint at <addr>; N=1/2/4/8 byte
                            window (default 8); default mode rw. `r` is
                            accepted but armed as rw - x86 has no read-only
                            mode at the architectural level. Up to 4 watches
                            active at once (DR0..DR3).
  wp                        list watchpoints
  dwp <id>                  delete a watchpoint
  catch syscall [<nr|name>...]
                            stop on every `syscall` instruction (entry+exit).
                            With no args, catches every syscall; otherwise
                            catches only the listed ones (decimal nr or
                            Linux x86-64 name, e.g. `catch syscall execve
                            exit_group`). Pairs with --list-syscalls (which
                            maps the static known sites): the catch covers
                            CFF-buried sites that walker can't resolve.
  dcatch                    clear the syscall catchpoint
  c                         continue all paused threads
  s                         single-step the current thread
  regs [all]                show registers ('all' for x87/SSE/AVX/AVX-512/DR)
  set <reg> <value>         write a GPR / RIP / RFLAGS / segment register.
                            <reg> is rax/rbx/.../r15/rip/rflags/cs/ds/...
                            <value> accepts hex (0xVA), decimal, or any
                            address-spec the `b` command accepts (sym,
                            sym+ofs, bin:sym). Use to skip past a faulting
                            instruction (`set rip <next>`), zero a return
                            register (`set rax 0`), etc.
  x <addr> [n]              read n bytes (default 16) and hex-dump
  poke <addr> <hex>...      write hex bytes to memory. Each byte is one
                            or two hex digits; multiple bytes are space-
                            separated (`poke 0x401234 c3` to write a RET,
                            `poke <a> 90 90 90` to nop-out 3 bytes).
                            Pairs naturally with `set rip` for skip-past-
                            trap workflows that previously needed gdb.
  bt | where                backtrace (.eh_frame; RBP-walk fallback)
  code | list | l           pseudo-C of the function containing the current PC
  aux                       list loaded aux symbol oracles
  aux <path>[@hex]          load a Binary as an aux oracle; auto-detect slide
                            (or pin it with @hex). Used for non-ELF code in
                            the tracee - e.g. Mach-O blobs mmap'd by an
                            in-process userspace loader.
  ignored                   list known-recovered fault PCs (silently passed
                            back to the tracee's own handler)
  ignore <addr>             add a static (un-slid) PC to the ignored-fault set
  unignore <addr>           remove a PC from the set
  ignore-file <path>        load addrs from a file (hex per line, '#' comments)
  threads                   list threads (* marks current)
  thread <tid>              switch current thread
  help                      this message
  q | quit | exit           leave the REPL
)");
}

}  // namespace

// ---- formatting helpers -------------------------------------------
std::string fmt_addr(addr_t a) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%016llx",
                  static_cast<unsigned long long>(a));
    return buf;
}

// Try a single (bin, slide) pair: un-slide `runtime_pc` and label it.
// Exact symbol match → " <name>". Otherwise consult containing_function
// so non-entry PCs (return addresses, mid-body breakpoints, scavenged
// frames) still render as " <name+0xOFFSET>" instead of naked hex.
// Returns "" only when no Binary covers the PC.
std::string sym_at_in_bin(addr_t runtime_pc, const Binary* bin, addr_t slide) {
    if (!bin) return {};
    const addr_t static_pc = runtime_pc - slide;
    for (const auto& s : bin->symbols()) {
        if (s.addr == static_pc) return " <" + s.name + ">";
    }
    if (auto cf = spelunk::containing_function(*bin, static_pc); cf) {
        return std::format(" <{}+{:#x}>", cf->name, cf->offset_within);
    }
    return {};
}

// Returns true when the event ends the session (process exited or
// terminated). Caller should leave the REPL.
bool print_event(const debug::Event& ev, const ReplState& rs) {
    auto sym_at = [&](addr_t a) { return sym_at_runtime(a, rs); };

    return std::visit([&](const auto& e) -> bool {
        using T = std::decay_t<decltype(e)>;
        if constexpr (std::is_same_v<T, debug::EvBreakpointHit>) {
            std::println("Breakpoint #{} hit at {}{} in thread {}",
                         e.id, fmt_addr(e.pc), sym_at(e.pc), e.tid);
        } else if constexpr (std::is_same_v<T, debug::EvWatchpointHit>) {
            std::println("Watchpoint #{} (DR{}) hit: data {} touched at PC {}{} in thread {}",
                         e.id, e.slot, fmt_addr(e.addr),
                         fmt_addr(e.pc), sym_at(e.pc), e.tid);
        } else if constexpr (std::is_same_v<T, debug::EvSyscallStop>) {
            const auto nm = linux_x64_syscall_name(e.nr);
            std::println("Syscall {} {}({}) at PC {}{} in thread {}",
                         e.entry ? "ENTRY" : "EXIT ",
                         nm.empty() ? "?" : std::string(nm),
                         e.nr, fmt_addr(e.pc), sym_at(e.pc), e.tid);
        } else if constexpr (std::is_same_v<T, debug::EvSingleStep>) {
            std::println("Stepped to {}{} in thread {}",
                         fmt_addr(e.pc), sym_at(e.pc), e.tid);
        } else if constexpr (std::is_same_v<T, debug::EvSignal>) {
            std::println("Signal {} ({}) in thread {} - held for forward on next cont",
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
        } else if constexpr (std::is_same_v<T, debug::EvExec>) {
            // wait_and_print intercepts EvExec for the re-arm path;
            // this branch only fires if some other caller routes the
            // event through print_event directly.
            std::println("execve at PC {}{} in thread {}",
                         fmt_addr(e.pc), sym_at(e.pc), e.tid);
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
    std::println(stderr, "spelunk-dbg: {}: {}", e.kind_name(), e.message);
}

// Parse hex literal first; if not hex, look up `tok` as a symbol in
// the given Binary and return its static address. Caller decides how
// to slide-correct. Used for cases where only one Binary is in scope
// (e.g. parsing inside try_break_at_pseudo_line for the function's
// own binary).
std::optional<AddrSpec>
parse_addr_spec_in_bin(std::string_view tok, const Binary* bin) {
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
        return AddrSpec{v, false, nullptr, 0};
    }

    if (bin) {
        if (auto* s = bin->find_by_name(tok); s && s->addr != 0) {
            return AddrSpec{s->addr, true, bin, 0};
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
    // Page-align both sides before subtracting. PT_LOAD's `vaddr` can
    // be unaligned (FlipVM's first segment starts at 0x1000a), but the
    // kernel always mmaps from the page boundary covering it; without
    // alignment we'd report a 10-byte negative slide for an EXEC
    // binary that didn't actually slide at all, and every static_pc
    // we computed for unwinding / scavenge / labelling would be off
    // by the same amount.
    constexpr addr_t kPage = 0x1000;
    const addr_t pref = bin.preferred_load_base() & ~(kPage - 1);

    namespace fs = std::filesystem;
    std::error_code ec;
    std::string canon = bin_path;
    if (auto p = fs::canonical(bin_path, ec); !ec) canon = p.string();

    // Match by path first; the kernel maps the main binary first
    // after exec so the front of the list is a safe fallback.
    for (const auto& img : images) {
        if (img.path == bin_path || img.path == canon) {
            return (img.base & ~(kPage - 1)) - pref;
        }
    }
    return (images.front().base & ~(kPage - 1)) - pref;
}

std::optional<int> parse_int(std::string_view s) {
    int v = 0;
    auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
    if (ec != std::errc{} || p != s.data() + s.size()) return std::nullopt;
    return v;
}

}  // namespace spelunk::cli::dbg

namespace spelunk::cli {

using namespace dbg;

int run_debug(const Args& args, const Binary* bin,
              std::span<const AuxBinarySpec> aux) {
    ReplState rs;
    rs.bin      = bin;
    rs.bin_path = args.binary;
    if (!args.binary.empty()) rs.bin_short_name = short_name_for(args.binary);
    rs.aux_bins.reserve(aux.size());
    for (const auto& a : aux) {
        AuxBin slot;
        slot.bin         = a.bin;
        slot.path        = a.path;
        slot.short_name  = short_name_for(a.path);
        slot.manual_base = a.manual_base;
        rs.aux_bins.push_back(std::move(slot));
    }
    // Seed the ignored-fault set from CLI flags.
    for (const auto& tok : args.ignore_fault_addrs) {
        if (auto h = parse_hex_addr(tok); h) {
            rs.ignored_faults.insert(*h);
        } else {
            std::println(stderr,
                "spelunk-dbg: --ignore-fault-at: bad hex '{}'", tok);
        }
    }
    for (const auto& path : args.ignore_fault_files) {
        const std::size_t added =
            load_ignored_faults_file(path, rs.ignored_faults);
        std::println("Loaded {} fault PCs from {}", added, path);
    }
    if (!rs.ignored_faults.empty()) {
        std::println("{} ignored-fault PC(s) configured.",
                     rs.ignored_faults.size());
    }

    {
        const auto choice = parse_debug_backend(args.debug_backend);
        rs.backend_kind           = choice.kind;
        rs.backend_allow_fallback = choice.allow_fallback;
    }

    // Warn at startup if any short names collide. Lookups still pick
    // the first match; the user can rename with --aux-binary or use
    // `<full-path-stem>:<sym>` if collisions are unavoidable.
    {
        std::vector<std::string> seen;
        if (!rs.bin_short_name.empty()) seen.push_back(rs.bin_short_name);
        for (const auto& a : rs.aux_bins) {
            for (const auto& s : seen) {
                if (s == a.short_name) {
                    std::println(stderr,
                        "spelunk-dbg: warning: short name '{}' collides between "
                        "primary and aux - `<bin>:<sym>` will pick the first match",
                        a.short_name);
                    break;
                }
            }
            seen.push_back(a.short_name);
        }
    }

    std::signal(SIGINT, sigint_forward);

    // Auto-launch / auto-attach when invoked with usable arguments.
    if (!args.attach_pid.empty()) {
        cmd_attach(rs, args.attach_pid);
    } else if (!args.binary.empty()) {
        cmd_run(rs, args);
    } else {
        std::println("spelunk-dbg: no binary path and no --attach-pid; use `run` or `attach`.");
    }

    std::string line;
    while (true) {
        std::print("(spelunk) ");
        std::fflush(stdout);
        if (!std::getline(std::cin, line)) { std::print("\n"); break; }
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
        else if ((cmd == "watch" || cmd == "wp") && toks.size() > 1)
            cmd_watch(rs, std::span<const std::string>{toks.data() + 1, toks.size() - 1});
        else if (cmd == "watch" || cmd == "wp")                cmd_wp_list(rs);
        else if (cmd == "dwp" && toks.size() > 1)              cmd_dwp(rs, toks[1]);
        else if (cmd == "catch" && toks.size() > 1)
            cmd_catch(rs, std::span<const std::string>{toks.data() + 1, toks.size() - 1});
        else if (cmd == "dcatch")                              cmd_dcatch(rs);
        else if (cmd == "c"  || cmd == "cont")                 cmd_cont(rs);
        else if (cmd == "s"  || cmd == "step")                 cmd_step(rs);
        else if (cmd == "regs")
            cmd_regs(rs, toks.size() > 1 && toks[1] == "all");
        else if (cmd == "set" && toks.size() > 2)
            cmd_set_reg(rs, toks[1], toks[2]);
        else if (cmd == "x"  && toks.size() > 1)
            cmd_xmem(rs, toks[1], toks.size() > 2 ? toks[2] : std::string_view{});
        else if (cmd == "poke" && toks.size() > 2)
            cmd_poke(rs, toks[1],
                     std::span<const std::string>{toks.data() + 2, toks.size() - 2});
        else if (cmd == "bt" || cmd == "where")                cmd_bt(rs);
        else if (cmd == "code" || cmd == "list" || cmd == "l") cmd_code(rs);
        else if (cmd == "aux")
            cmd_aux(rs, toks.size() > 1 ? std::string_view(toks[1]) : std::string_view{});
        else if (cmd == "ignored")
            cmd_ignore(rs, std::string_view{});
        else if (cmd == "ignore" && toks.size() > 1)
            cmd_ignore(rs, toks[1]);
        else if (cmd == "unignore" && toks.size() > 1)
            cmd_unignore(rs, toks[1]);
        else if (cmd == "ignore-file" && toks.size() > 1)
            cmd_ignore_file(rs, toks[1]);
        else if (cmd == "threads")                             cmd_threads(rs);
        else if (cmd == "thread" && toks.size() > 1)           cmd_thread_switch(rs, toks[1]);
        else std::println(stderr, "spelunk-dbg: unknown command '{}' (try `help`)", cmd);
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

}  // namespace spelunk::cli

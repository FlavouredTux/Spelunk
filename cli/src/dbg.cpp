#include "dbg.hpp"

#include <algorithm>
#include <atomic>
#include <charconv>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <map>
#include <print>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <ember/analysis/pipeline.hpp>
#include <ember/analysis/syscalls.hpp>
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
    if (auto cf = ember::containing_function(*bin, static_pc); cf) {
        return std::format(" <{}+{:#x}>", cf->name, cf->offset_within);
    }
    return {};
}

struct ReplState;
[[nodiscard]] std::string sym_at_runtime(addr_t pc, const ReplState& rs);

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
    std::println(stderr, "ember-dbg: {}: {}", e.kind_name(), e.message);
}

// Two flavours of address: a hex literal (already a runtime VA — no
// slide) versus a symbol resolved from one of the loaded Binaries
// (a static / linker VA — needs that bin's slide added). When the
// match is a symbol, `bin` and `slide` carry the source so the
// caller can apply the right slide without re-searching.
struct AddrSpec {
    addr_t        addr       = 0;
    bool          was_symbol = false;
    const Binary* bin        = nullptr;
    addr_t        slide      = 0;
};

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

std::vector<std::string> tokenize(const std::string& line) {
    std::vector<std::string> out;
    std::istringstream is(line);
    std::string tok;
    while (is >> tok) out.push_back(std::move(tok));
    return out;
}

// ---- command implementations --------------------------------------

// Aux symbol oracle: a Binary whose code is mapped into the tracee
// outside of any ELF segment we'd see via /proc/<pid>/maps' file
// path field (typical example: a Mach-O blob mmap'd as anon-rwx by a
// userspace loader, then mprotect'd to per-segment final prots).
// Slide is either pinned via `--aux-binary PATH@HEX` or auto-detected
// after attach by size-matching the binary's mapped extent against an
// anon region whose first 4 bytes match the binary's format magic.
struct AuxBin {
    const Binary*         bin = nullptr;
    std::string           path;
    std::string           short_name;       // basename(path) — e.g. "engine"
    addr_t                slide = 0;
    bool                  slide_resolved = false;
    std::optional<addr_t> manual_base;
};

// Whatever the user typed to `b` / `watch` — replayed through
// parse_addr_spec_multi after exec to re-arm against the new image.
struct BpSpec  { std::string spec; };
struct WpSpec  { std::string spec; u8 size; debug::WatchMode mode; };

struct ReplState {
    std::unique_ptr<debug::Target> tgt;
    debug::ThreadId                current_tid = 0;
    bool                           live        = false;
    const Binary*                  bin         = nullptr;
    std::string                    bin_path;   // for compute_slide path-matching
    std::string                    bin_short_name; // basename(bin_path) for `<bin>:<sym>` qualifier
    addr_t                         slide       = 0;  // PIE/ASLR slide; 0 for non-PIE
    std::vector<AuxBin>            aux_bins;
    std::vector<std::unique_ptr<Binary>> aux_storage;  // owns runtime-loaded `aux` binaries
    std::map<debug::BreakpointId, BpSpec> bp_specs;    // for re-arm across exec
    std::map<debug::WatchpointId, WpSpec> wp_specs;    // for re-arm across exec
    // Static-address (un-slid) PCs at which a fault-class signal
    // (SIGSEGV/SIGBUS/SIGFPE/SIGILL) is known to be recovered by the
    // tracee's own handler. wait_and_print silently forwards the
    // signal back instead of stopping. Slide-correction happens at
    // match time using whichever Binary owns the live PC.
    std::set<addr_t>               ignored_faults;
};

// Strip directories and the trailing extension from a path; the
// resulting "short name" is what the `<bin>:<sym>` syntax matches.
[[nodiscard]] std::string short_name_for(const std::string& path) {
    std::filesystem::path p(path);
    auto stem = p.stem().string();
    return stem.empty() ? p.filename().string() : stem;
}

// Parse a hex string with optional 0x prefix, returning the addr or
// nullopt on bad input. Empty strings reject too.
[[nodiscard]] std::optional<addr_t> parse_hex_addr(std::string_view s) {
    if (s.starts_with("0x") || s.starts_with("0X")) s.remove_prefix(2);
    if (s.empty()) return std::nullopt;
    addr_t v = 0;
    for (char c : s) {
        const int d = (c >= '0' && c <= '9') ? c - '0'
                    : (c >= 'a' && c <= 'f') ? c - 'a' + 10
                    : (c >= 'A' && c <= 'F') ? c - 'A' + 10
                    : -1;
        if (d < 0) return std::nullopt;
        v = (v << 4) | static_cast<addr_t>(d);
    }
    return v;
}

// Load addresses from a file. Format: one hex addr per line, '#'
// starts a comment, anything after the first whitespace token is
// ignored (so the user can annotate `0x100394124  # cb_invoke`).
std::size_t load_ignored_faults_file(const std::string& path,
                                     std::set<addr_t>& out) {
    FILE* f = std::fopen(path.c_str(), "r");
    if (!f) {
        std::println(stderr, "ember-dbg: ignore-file: {}: {}",
                     path, std::strerror(errno));
        return 0;
    }
    char line[1024];
    std::size_t added = 0;
    while (std::fgets(line, sizeof(line), f)) {
        std::string_view sv(line);
        if (auto h = sv.find('#'); h != std::string_view::npos) {
            sv.remove_suffix(sv.size() - h);
        }
        while (!sv.empty() &&
               (sv.front() == ' ' || sv.front() == '\t')) {
            sv.remove_prefix(1);
        }
        while (!sv.empty() &&
               (sv.back() == '\n' || sv.back() == '\r' ||
                sv.back() == ' '  || sv.back() == '\t')) {
            sv.remove_suffix(1);
        }
        if (sv.empty()) continue;
        // Take just the leading token — comments after whitespace.
        if (auto sp = sv.find_first_of(" \t"); sp != std::string_view::npos) {
            sv.remove_suffix(sv.size() - sp);
        }
        if (auto h = parse_hex_addr(sv); h) {
            if (out.insert(*h).second) ++added;
        } else {
            std::println(stderr, "ember-dbg: ignore-file: {}: bad hex '{}'",
                         path, std::string(sv));
        }
    }
    std::fclose(f);
    return added;
}

[[nodiscard]] bool is_fault_signal(int signo) {
    return signo == SIGSEGV ||
#if !defined(_WIN32)
           signo == SIGBUS  ||
#endif
           signo == SIGFPE  || signo == SIGILL;
}

// PC → which (Binary, slide) covers it. Tries primary first, then
// aux. Coverage is "static_pc lands in [preferred_load_base,
// preferred_load_base + mapped_size)".
struct BinHit {
    const Binary* bin   = nullptr;
    addr_t        slide = 0;
};

[[nodiscard]] std::optional<BinHit>
find_bin_for_pc(const ReplState& rs, addr_t runtime_pc) {
    auto in_bin = [&](const Binary* b, addr_t slide) -> bool {
        if (!b) return false;
        const addr_t base = b->preferred_load_base();
        const addr_t size = b->mapped_size();
        const addr_t spc  = runtime_pc - slide;
        return size > 0 && spc >= base && spc < base + size;
    };
    if (in_bin(rs.bin, rs.slide)) return BinHit{rs.bin, rs.slide};
    for (const auto& aux : rs.aux_bins) {
        if (aux.slide_resolved && in_bin(aux.bin, aux.slide)) {
            return BinHit{aux.bin, aux.slide};
        }
    }
    return std::nullopt;
}

// Symbol name → first (Binary, static addr, slide) match, scanning
// primary then aux in registration order. When the same name resolves
// in more than one bin we still pick the first hit (so the call is
// O(1) at use sites) but emit a one-line warning to stderr so the
// user knows to disambiguate via `<bin>:<sym>`.
struct SymHit {
    const Binary* bin    = nullptr;
    addr_t        addr   = 0;
    addr_t        slide  = 0;
};
[[nodiscard]] std::optional<SymHit>
find_symbol(const ReplState& rs, std::string_view name) {
    std::optional<SymHit> first;
    std::vector<std::string> also_in;
    auto try_bin = [&](const Binary* b, addr_t slide, std::string_view tag) {
        if (!b) return;
        if (auto* s = b->find_by_name(name); s && s->addr != 0) {
            if (!first) first = SymHit{b, s->addr, slide};
            else        also_in.emplace_back(tag);
        }
    };
    try_bin(rs.bin, rs.slide, rs.bin_short_name);
    for (const auto& aux : rs.aux_bins) {
        try_bin(aux.bin, aux.slide, aux.short_name);
    }
    if (first && !also_in.empty()) {
        std::string tags = also_in.front();
        for (std::size_t i = 1; i < also_in.size(); ++i) {
            tags += ", ";
            tags += also_in[i];
        }
        std::println(stderr,
            "ember-dbg: warning: '{}' resolves in {} bins; using first match — qualify with <bin>:<sym> to pick (also: {})",
            name, also_in.size() + 1, tags);
    }
    return first;
}

// `<bin>:<sym>` lookup. Returns nullopt when the colon-prefix doesn't
// name a known bin so the caller can fall back to a plain global
// symbol search.
[[nodiscard]] std::optional<SymHit>
find_symbol_qualified(const ReplState& rs,
                      std::string_view bin_tok,
                      std::string_view sym_tok) {
    auto try_bin = [&](const Binary* b, addr_t slide,
                       std::string_view tag) -> std::optional<SymHit> {
        if (!b) return std::nullopt;
        if (tag != bin_tok) return std::nullopt;
        if (auto* s = b->find_by_name(sym_tok); s && s->addr != 0) {
            return SymHit{b, s->addr, slide};
        }
        return std::nullopt;
    };
    if (auto h = try_bin(rs.bin, rs.slide, rs.bin_short_name); h) return h;
    for (const auto& aux : rs.aux_bins) {
        if (auto h = try_bin(aux.bin, aux.slide, aux.short_name); h) return h;
    }
    return std::nullopt;
}

// Multi-binary version of parse_addr_spec: hex literal first, then
// symbol search across primary + aux. Carries the matched binary's
// slide so resolve_runtime_multi doesn't need to re-search.
std::optional<AddrSpec>
parse_addr_spec_multi(std::string_view tok, const ReplState& rs) {
    if (auto spec = parse_addr_spec_in_bin(tok, nullptr); spec) return spec;
    if (auto sh = find_symbol(rs, tok); sh) {
        return AddrSpec{sh->addr, true, sh->bin, sh->slide};
    }
    return std::nullopt;
}

[[nodiscard]] addr_t resolve_runtime_multi(const AddrSpec& spec) {
    if (!spec.was_symbol) return spec.addr;
    return spec.addr + spec.slide;
}

// Walk the union of (primary, aux) and pick the one whose `containing_function`
// reports a hit for the given static PC interpretation. Returns the
// (bin, slide) that owns this PC, or nullopt.
[[nodiscard]] std::string sym_at_runtime(addr_t pc, const ReplState& rs) {
    if (auto h = find_bin_for_pc(rs, pc); h) {
        return sym_at_in_bin(pc, h->bin, h->slide);
    }
    // Last-resort: try primary's symbol table even if PC isn't in its
    // declared range (handles PIE binaries with sparse section data).
    return sym_at_in_bin(pc, rs.bin, rs.slide);
}

// One row of /proc/<pid>/maps. `path` is the file path for file-backed
// mappings, empty for anon, and bracketed (e.g. "[vdso]") for kernel
// regions.
struct MappedRegion { addr_t base; addr_t size; std::string path; };

std::vector<MappedRegion> read_mappings(debug::ProcessId pid) {
    std::vector<MappedRegion> out;
    char path[64];
    std::snprintf(path, sizeof path, "/proc/%u/maps", pid);
    FILE* f = std::fopen(path, "r");
    if (!f) return out;

    auto parse_hex = [](std::string_view s) -> addr_t {
        addr_t v = 0;
        for (char c : s) {
            const int d = (c >= '0' && c <= '9') ? c - '0'
                        : (c >= 'a' && c <= 'f') ? c - 'a' + 10
                        : (c >= 'A' && c <= 'F') ? c - 'A' + 10
                        : -1;
            if (d < 0) break;
            v = (v << 4) | static_cast<addr_t>(d);
        }
        return v;
    };

    char line[4096];
    while (std::fgets(line, sizeof line, f)) {
        std::string_view sv(line);
        while (!sv.empty() && (sv.back() == '\n' || sv.back() == '\r')) {
            sv.remove_suffix(1);
        }
        // Format: <start>-<end> <perms> <offset> <dev> <inode> [<path>]
        // Skip past 5 whitespace-separated fields, anything after is path.
        std::size_t pos = 0;
        std::size_t field_starts[5] = {};
        for (int k = 0; k < 5; ++k) {
            while (pos < sv.size() && sv[pos] == ' ') ++pos;
            field_starts[k] = pos;
            while (pos < sv.size() && sv[pos] != ' ') ++pos;
            if (pos == field_starts[k]) break;  // ran out of fields
        }
        if (pos == field_starts[4]) continue;  // malformed

        const auto addr_field = sv.substr(field_starts[0], field_starts[1] - field_starts[0] - 1);
        const auto dash = addr_field.find('-');
        if (dash == std::string_view::npos) continue;
        const addr_t start = parse_hex(addr_field.substr(0, dash));
        const addr_t end   = parse_hex(addr_field.substr(dash + 1));
        if (end <= start) continue;

        while (pos < sv.size() && sv[pos] == ' ') ++pos;
        std::string_view path_sv = sv.substr(pos);
        while (!path_sv.empty() && (path_sv.back() == ' ' || path_sv.back() == '\t')) {
            path_sv.remove_suffix(1);
        }
        out.push_back({start, end - start, std::string(path_sv)});
    }
    std::fclose(f);
    return out;
}

// Magic-bytes check: read the first 4 bytes of the candidate region
// and verify they match the binary's format. Catches the 4KB-Mach-O
// false-positive case where a libc anon-rwx page happens to match
// the size but has nothing to do with our binary.
[[nodiscard]] bool magic_matches_at(
    debug::Target& tgt, addr_t base, const Binary& bin) {
    std::byte hdr[4] = {};
    auto rv = tgt.read_mem(base, hdr);
    if (!rv || *rv != 4) return false;
    u32 magic = 0;
    std::memcpy(&magic, hdr, 4);
    switch (bin.format()) {
        case Format::Elf:
            return magic == 0x464C457Fu;            // 0x7F 'E' 'L' 'F'
        case Format::MachO:
            return magic == 0xfeedfacfu || magic == 0xfeedfaceu ||
                   magic == 0xcffaedfeu || magic == 0xcefaedfeu;
        case Format::Pe:
            return (magic & 0xFFFFu) == 0x5A4Du;    // 'MZ'
        default:
            return true;                            // unknown; accept
    }
}

// Slide for an aux binary. Manual @hex wins; otherwise:
//   1. File-backed match: same path or basename in /proc/pid/maps →
//      runtime base = lowest mapping for that file. Covers stock
//      shared libraries (libc, libstdc++, ...) loaded normally.
//   2. Anon-rwx match: size + format-magic check at the candidate
//      region's first 4 bytes. Covers Mach-O blobs / scrubbed
//      shared objects that an in-process userspace loader mmap'd.
std::optional<addr_t>
compute_aux_slide(debug::Target& tgt, const AuxBin& aux) {
    if (!aux.bin) return std::nullopt;
    const addr_t pref = aux.bin->preferred_load_base();
    if (aux.manual_base) return *aux.manual_base - pref;

    const auto regions = read_mappings(tgt.pid());

    namespace fs = std::filesystem;
    std::error_code ec;
    std::string aux_canon = aux.path;
    if (auto p = fs::canonical(aux.path, ec); !ec) aux_canon = p.string();
    const std::string aux_base = fs::path(aux.path).filename().string();

    addr_t file_base = 0;
    bool   file_hit  = false;
    for (const auto& r : regions) {
        if (r.path.empty() || r.path.front() == '[') continue;
        const bool path_eq = (r.path == aux.path || r.path == aux_canon);
        const bool base_eq = !aux_base.empty() &&
                             fs::path(r.path).filename().string() == aux_base;
        if (!path_eq && !base_eq) continue;
        if (!file_hit || r.base < file_base) {
            file_base = r.base;
            file_hit  = true;
        }
    }
    if (file_hit) return file_base - pref;

    const addr_t want_size = aux.bin->mapped_size();
    if (want_size == 0) return std::nullopt;
    constexpr addr_t kPage = 0x1000;
    const addr_t want = (want_size + kPage - 1) & ~(kPage - 1);

    addr_t anon_base = 0;
    int    matches   = 0;
    for (const auto& r : regions) {
        if (!r.path.empty() && r.path.front() != '[') continue;
        if (r.size != want) continue;
        if (!magic_matches_at(tgt, r.base, *aux.bin)) continue;
        anon_base = r.base;
        ++matches;
    }
    if (matches == 1) return anon_base - pref;
    return std::nullopt;
}

// Try to resolve every aux whose slide isn't yet known. Cheap on a
// stable address space (one /proc/maps read), so callable from the
// stop-event path without measurable overhead.
void refresh_unresolved_aux_slides(ReplState& rs) {
    if (!rs.live) return;
    for (auto& aux : rs.aux_bins) {
        if (aux.slide_resolved) continue;
        if (auto s = compute_aux_slide(*rs.tgt, aux); s) {
            aux.slide = *s;
            aux.slide_resolved = true;
            std::println("  aux: {} loaded at {} (auto, lazy)",
                         aux.path,
                         fmt_addr(aux.bin->preferred_load_base() + aux.slide));
        }
    }
}

void on_target_acquired(ReplState& rs) {
    g_active_target.store(rs.tgt.get(), std::memory_order_release);
    rs.live = true;
    if (auto threads = rs.tgt->threads(); !threads.empty()) {
        rs.current_tid = threads.front();
    }
    rs.slide = (rs.bin && !rs.bin_path.empty())
        ? compute_slide(*rs.tgt, *rs.bin, rs.bin_path) : 0;

    // Resolve aux-binary slides. Manual @hex always works; auto-
    // detection requires a unique size match in /proc/<pid>/maps and
    // can fail benignly (the binary just stays unmapped at attach
    // time, gets resolved later if the user re-runs `aux`).
    for (auto& aux : rs.aux_bins) {
        if (auto s = compute_aux_slide(*rs.tgt, aux); s) {
            aux.slide = *s;
            aux.slide_resolved = true;
        } else {
            aux.slide_resolved = false;
        }
    }

    std::println("Process {} attached, {} thread(s){}.",
                 rs.tgt->pid(), rs.tgt->threads().size(),
                 rs.slide ? std::format(" — slide {}", fmt_addr(rs.slide))
                          : std::string{});
    for (const auto& aux : rs.aux_bins) {
        if (aux.slide_resolved) {
            std::println("  aux: {} loaded at {}{}",
                         aux.path,
                         fmt_addr(aux.bin->preferred_load_base() + aux.slide),
                         aux.manual_base ? " (manual)" : " (auto)");
        } else {
            std::println(stderr,
                "  aux: {} — slide unresolved (no unique anon-rwx region of size {} bytes); "
                "specify '--aux-binary {}@<hex>' or use the `aux` REPL command",
                aux.path, aux.bin->mapped_size(), aux.path);
        }
    }
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
    for (auto& aux : rs.aux_bins) {
        aux.slide = 0;
        aux.slide_resolved = false;
    }
    // Persisted bp/wp specs are scoped to a target's lifetime —
    // re-arm-across-exec is for the same process that called execve,
    // not for a fresh `run` after the previous tracee exited.
    rs.bp_specs.clear();
    rs.wp_specs.clear();
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

    const addr_t va = best + sh->slide;
    auto id = rs.tgt->set_breakpoint(va);
    if (!id) { print_error(id.error()); return true; }
    std::println("Breakpoint #{} at {}  ({}:{} → static {})",
                 *id, fmt_addr(va), sym_tok, target_line, fmt_addr(best));
    return true;
}

// `<bin>:<sym>` — restrict the symbol lookup to the named binary.
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
// level — x86 has no read-only watchpoint mode. Emit a one-line note
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
        std::println("note: x86 has no read-only watch mode — armed as read+write "
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

// Re-arm bp/wp specs against the post-exec image. main() owns the
// initial Binary; after exec we own the replacement here so rs.bin
// stays valid for the rest of the session.
std::unique_ptr<Binary> g_post_exec_bin;

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
            if ((i & 1) == 1) std::print("\n");
        }
    }
    if (r.present & debug::Registers::PresentSse) {
        std::println("--- sse ---  mxcsr={:08x} mask={:08x}", r.mxcsr, r.mxcsr_mask);
        for (int i = 0; i < 16; ++i) {
            std::print("xmm{:<2}=", i);
            print_zmm(r.zmm[i], 16);
            std::print("\n");
        }
    }
    if (r.present & debug::Registers::PresentAvx) {
        std::println("--- avx (ymm high halves) ---");
        for (int i = 0; i < 16; ++i) {
            std::print("ymm{:<2}=", i);
            print_zmm(r.zmm[i], 32);
            std::print("\n");
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
            std::print("\n");
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

// Map a register name (lowercase, dollar-prefix optional) to a writable
// pointer inside Registers. Only the GPRs + RIP + RFLAGS + segment regs
// are exposed — those are the ones a debugger typically wants to nudge
// to skip past faults or redirect control flow. SIMD / x87 / DR are
// reachable via `regs all` for inspection; if someone needs to write
// them, that's a future extension.
[[nodiscard]] u64* gpr_field(debug::Registers& r, std::string_view name) {
    if (!name.empty() && name.front() == '$') name.remove_prefix(1);
    struct M { std::string_view n; u64 debug::Registers::* p; };
    static const M kMap[] = {
        {"rax", &debug::Registers::rax}, {"rbx", &debug::Registers::rbx},
        {"rcx", &debug::Registers::rcx}, {"rdx", &debug::Registers::rdx},
        {"rsi", &debug::Registers::rsi}, {"rdi", &debug::Registers::rdi},
        {"rbp", &debug::Registers::rbp}, {"rsp", &debug::Registers::rsp},
        {"r8",  &debug::Registers::r8},  {"r9",  &debug::Registers::r9},
        {"r10", &debug::Registers::r10}, {"r11", &debug::Registers::r11},
        {"r12", &debug::Registers::r12}, {"r13", &debug::Registers::r13},
        {"r14", &debug::Registers::r14}, {"r15", &debug::Registers::r15},
        {"rip", &debug::Registers::rip}, {"rflags", &debug::Registers::rflags},
        {"cs",  &debug::Registers::cs},  {"ds", &debug::Registers::ds},
        {"es",  &debug::Registers::es},  {"fs", &debug::Registers::fs},
        {"gs",  &debug::Registers::gs},  {"ss", &debug::Registers::ss},
        {"fs_base", &debug::Registers::fs_base},
        {"gs_base", &debug::Registers::gs_base},
    };
    for (const auto& m : kMap) if (m.n == name) return &(r.*m.p);
    return nullptr;
}

int cmd_set_reg(ReplState& rs, std::string_view reg_tok,
                std::string_view value_tok) {
    if (!rs.live) { std::println("Not attached."); return 0; }
    auto regs = rs.tgt->get_regs(rs.current_tid);
    if (!regs) { print_error(regs.error()); return 1; }
    u64* slot = gpr_field(*regs, reg_tok);
    if (!slot) {
        std::println(stderr,
            "ember-dbg: set: unknown register '{}' (try rax/rbx/.../rip/rflags/cs/...)",
            reg_tok);
        return 1;
    }
    // Accept hex (with or without `0x`), decimal, or address-spec
    // (sym, sym+ofs, bin:sym) — same syntax as `b` and `x` so a user
    // can `set rip <symbol>` to force a jump back into known code.
    std::optional<u64> value;
    if (auto h = parse_hex_addr(value_tok); h) {
        value = static_cast<u64>(*h);
    } else if (auto i = parse_int(value_tok); i && *i >= 0) {
        value = static_cast<u64>(*i);
    } else if (auto spec = parse_addr_spec_multi(value_tok, rs); spec) {
        value = static_cast<u64>(resolve_runtime_multi(*spec));
    }
    if (!value) {
        std::println(stderr, "ember-dbg: set: bad value '{}'", value_tok);
        return 1;
    }
    *slot = *value;
    auto wv = rs.tgt->set_regs(rs.current_tid, *regs);
    if (!wv) { print_error(wv.error()); return 1; }
    std::println("{} = {}", reg_tok, fmt_addr(*value));
    return 0;
}

// Parse a sequence of hex-byte tokens (e.g. `c3`, `90`, `0xff`) into a
// flat byte buffer. Used by `poke`. Returns nullopt on the first token
// that doesn't look like a 1- or 2-digit hex byte.
[[nodiscard]] std::optional<std::vector<std::byte>>
parse_hex_bytes(std::span<const std::string> toks) {
    std::vector<std::byte> out;
    out.reserve(toks.size());
    for (auto sv : toks) {
        std::string_view tok = sv;
        if (tok.starts_with("0x") || tok.starts_with("0X")) tok.remove_prefix(2);
        if (tok.empty() || tok.size() > 2) return std::nullopt;
        unsigned v = 0;
        for (char c : tok) {
            const int d = (c >= '0' && c <= '9') ? c - '0'
                        : (c >= 'a' && c <= 'f') ? c - 'a' + 10
                        : (c >= 'A' && c <= 'F') ? c - 'A' + 10
                        : -1;
            if (d < 0) return std::nullopt;
            v = (v << 4) | static_cast<unsigned>(d);
        }
        out.push_back(static_cast<std::byte>(v & 0xff));
    }
    return out;
}

int cmd_poke(ReplState& rs, std::string_view addr_tok,
             std::span<const std::string> byte_toks) {
    if (!rs.live) { std::println("Not attached."); return 0; }
    if (byte_toks.empty()) {
        std::println(stderr,
            "ember-dbg: poke: usage `poke <addr> <hex-byte> [<hex-byte>...]`");
        return 1;
    }
    auto spec = parse_addr_spec_multi(addr_tok, rs);
    if (!spec) {
        std::println(stderr, "ember-dbg: poke: bad address '{}'", addr_tok);
        return 1;
    }
    auto bytes = parse_hex_bytes(byte_toks);
    if (!bytes) {
        std::println(stderr,
            "ember-dbg: poke: bad hex byte (expected pairs like c3 90 0xff)");
        return 1;
    }
    const addr_t va_runtime = resolve_runtime_multi(*spec);
    auto rv = rs.tgt->write_mem(va_runtime, *bytes);
    if (!rv) { print_error(rv.error()); return 1; }
    const std::size_t got = *rv;
    std::println("wrote {} byte(s) at {}", got, fmt_addr(va_runtime));
    if (got < bytes->size()) {
        std::println("(write short — {} of {} requested bytes)", got, bytes->size());
    }
    return 0;
}

int cmd_xmem(ReplState& rs, std::string_view addr_tok, std::string_view count_tok) {
    if (!rs.live) { std::println("Not attached."); return 0; }
    auto spec = parse_addr_spec_multi(addr_tok, rs);
    if (!spec) {
        std::println(stderr, "ember-dbg: x: bad address '{}'", addr_tok);
        return 1;
    }
    const addr_t va_runtime = resolve_runtime_multi(*spec);
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
        std::print("\n");
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

    // Scavenged frames: when the structured unwind dies after one or
    // two frames (Rust panic chains, CFF, hand-rolled asm without
    // .eh_frame), scan the stack for qwords whose predecessor byte
    // is a `call` instruction inside a known function. Order is not
    // guaranteed; the user gets the names anyway. Skip when the
    // structured unwind already reaches deep enough that scavenged
    // hits would just be noise.
    constexpr std::size_t kScavengeThreshold = 3;
    if (frames.size() < kScavengeThreshold) {
        std::vector<debug::BinarySlide> bins;
        bins.reserve(1 + rs.aux_bins.size());
        if (rs.bin) bins.push_back({rs.bin, rs.slide});
        for (const auto& aux : rs.aux_bins) {
            if (aux.slide_resolved) bins.push_back({aux.bin, aux.slide});
        }
        if (!bins.empty()) {
            if (auto sc = debug::unwind_scavenge(*rs.tgt, rs.current_tid,
                                                 std::span<const debug::BinarySlide>(bins));
                sc && !sc->empty()) {
                std::set<addr_t> already;
                for (const auto& f : frames) already.insert(f.pc);
                for (auto& f : *sc) {
                    if (already.contains(f.pc)) continue;
                    frames.push_back(f);
                    already.insert(f.pc);
                }
            }
        }
    }

    int idx = 0;
    for (const auto& f : frames) {
        std::println("#{:<2} {}{}{}", idx++, fmt_addr(f.pc),
                     sym_at_runtime(f.pc, rs),
                     f.scavenged ? "  *scavenged*" : "");
    }
    if (used_eh) std::println("  (via .eh_frame; *scavenged* frames are best-effort)");
    return 0;
}

int cmd_code(ReplState& rs) {
    if (!rs.live) { std::println("Not attached."); return 0; }
    if (!rs.bin && rs.aux_bins.empty()) {
        std::println(stderr, "ember-dbg: code: no binary loaded");
        return 1;
    }
    auto regs = rs.tgt->get_regs(rs.current_tid);
    if (!regs) { print_error(regs.error()); return 1; }

    const addr_t pc_runtime = regs->rip;

    // Pick the binary whose mapped range covers this PC. Falls back
    // to the primary if none claims it (typical for ld.so / vDSO
    // frames at attach time).
    auto hit = find_bin_for_pc(rs, pc_runtime);
    const Binary* code_bin = hit ? hit->bin   : rs.bin;
    const addr_t  slide    = hit ? hit->slide : rs.slide;
    if (!code_bin) {
        std::println("No binary covers {}.", fmt_addr(pc_runtime));
        return 0;
    }
    const addr_t pc_static = pc_runtime - slide;

    auto cf = ember::containing_function(*code_bin, pc_static);
    if (!cf) {
        std::println("No function covers {} (static {}).",
                     fmt_addr(pc_runtime), fmt_addr(pc_static));
        return 0;
    }
    auto win = ember::resolve_function_at(*code_bin, cf->entry);
    if (!win) {
        std::println(stderr, "ember-dbg: code: failed to resolve {}", cf->name);
        return 1;
    }

    LineMap line_map;
    EmitOptions opts;
    opts.line_map = &line_map;
    auto pseudo = ember::format_struct(*code_bin, *win, /*pseudo*/true,
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
            std::println(stderr, "ember-dbg: aux: bad hex base in '{}'", tok);
            return 1;
        }
        manual = v;
        path.resize(at);
    }
    auto loaded = ember::load_binary(path);
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
        std::println(stderr, "ember-dbg: ignore: bad hex '{}'", tok);
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
        std::println(stderr, "ember-dbg: unignore: bad hex '{}'", tok);
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
        std::println(stderr, "ember-dbg: ignore-file: usage: ignore-file <path>");
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
                            accepted but armed as rw — x86 has no read-only
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
                            the tracee — e.g. Mach-O blobs mmap'd by an
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
                "ember-dbg: --ignore-fault-at: bad hex '{}'", tok);
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
                        "ember-dbg: warning: short name '{}' collides between "
                        "primary and aux — `<bin>:<sym>` will pick the first match",
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
        std::println("ember-dbg: no binary path and no --attach-pid; use `run` or `attach`.");
    }

    std::string line;
    while (true) {
        std::print("(ember) ");
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

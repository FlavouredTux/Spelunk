// Symbol, module and auxiliary-binary resolution at runtime addresses.

#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <format>
#include <map>
#include <optional>
#include <print>
#include <set>
#include <signal.h>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <ember/binary/binary.hpp>
#include <ember/binary/format.hpp>
#include <ember/common/types.hpp>
#include <ember/debug/target.hpp>
#include <ember/debug/types.hpp>

#include "dbg_internal.hpp"

namespace ember::cli::dbg {

namespace {

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

}  // namespace

// Strip directories and the trailing extension from a path; the
// resulting "short name" is what the `<bin>:<sym>` syntax matches.
std::string short_name_for(const std::string& path) {
    std::filesystem::path p(path);
    auto stem = p.stem().string();
    return stem.empty() ? p.filename().string() : stem;
}

// Parse a hex string with optional 0x prefix, returning the addr or
// nullopt on bad input. Empty strings reject too.
std::optional<addr_t> parse_hex_addr(std::string_view s) {
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
        // Take just the leading token - comments after whitespace.
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

bool is_fault_signal(int signo) {
    return signo == SIGSEGV ||
#if !defined(_WIN32)
           signo == SIGBUS  ||
#endif
           signo == SIGFPE  || signo == SIGILL;
}

std::optional<BinHit>
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

std::optional<SymHit>
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
            "ember-dbg: warning: '{}' resolves in {} bins; using first match - qualify with <bin>:<sym> to pick (also: {})",
            name, also_in.size() + 1, tags);
    }
    return first;
}

// `<bin>:<sym>` lookup. Returns nullopt when the colon-prefix doesn't
// name a known bin so the caller can fall back to a plain global
// symbol search.
std::optional<SymHit>
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

addr_t resolve_runtime_multi(const AddrSpec& spec) {
    if (!spec.was_symbol) return spec.addr;
    return spec.addr + spec.slide;
}

// Walk the union of (primary, aux) and pick the one whose `containing_function`
// reports a hit for the given static PC interpretation. Returns the
// (bin, slide) that owns this PC, or nullopt.
std::string sym_at_runtime(addr_t pc, const ReplState& rs) {
    if (auto h = find_bin_for_pc(rs, pc); h) {
        return sym_at_in_bin(pc, h->bin, h->slide);
    }
    // Last-resort: try primary's symbol table even if PC isn't in its
    // declared range (handles PIE binaries with sparse section data).
    return sym_at_in_bin(pc, rs.bin, rs.slide);
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
                 rs.slide ? std::format(" - slide {}", fmt_addr(rs.slide))
                          : std::string{});
    for (const auto& aux : rs.aux_bins) {
        if (aux.slide_resolved) {
            std::println("  aux: {} loaded at {}{}",
                         aux.path,
                         fmt_addr(aux.bin->preferred_load_base() + aux.slide),
                         aux.manual_base ? " (manual)" : " (auto)");
        } else {
            std::println(stderr,
                "  aux: {} - slide unresolved (no unique anon-rwx region of size {} bytes); "
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
    // Persisted bp/wp specs are scoped to a target's lifetime -
    // re-arm-across-exec is for the same process that called execve,
    // not for a fresh `run` after the previous tracee exited.
    rs.bp_specs.clear();
    rs.wp_specs.clear();
}

}  // namespace ember::cli::dbg

#include "subcommands.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <format>
#include <fstream>
#include <iostream>
#include <map>
#include <optional>
#include <unistd.h>

#if defined(__linux__)
#include <sys/prctl.h>
#include <signal.h>
#endif
#include <atomic>
#include <print>
#include <set>
#include <string>
#include <string_view>
#include <chrono>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <system_error>
#include <vector>

#include <ember/analysis/cfg_builder.hpp>
#include <ember/analysis/eh_frame.hpp>
#include <ember/analysis/indirect_calls.hpp>
#include <ember/analysis/ir_cache.hpp>
#include <ember/analysis/objc.hpp>
#include <ember/analysis/pe_unwind.hpp>
#include <ember/analysis/pipeline.hpp>
#include <ember/analysis/rtti.hpp>
#include <ember/analysis/sig_inference.hpp>
#include <ember/analysis/sigs.hpp>
#include <ember/analysis/strings.hpp>
#include <ember/common/hash.hpp>
#include <ember/common/threads.hpp>
#include <ember/analysis/syscalls.hpp>
#include <ember/analysis/teef.hpp>
#include <ember/analysis/teef_behav.hpp>
#include <ember/analysis/teef_orbit.hpp>
#include <ember/analysis/teef_recognize.hpp>
#include <ember/common/progress.hpp>
#include <ember/binary/binary.hpp>
#include <ember/binary/pe.hpp>
#include <ember/common/annotations.hpp>
#include <ember/common/cache.hpp>
#include <ember/decompile/emitter.hpp>
#include <ember/disasm/decoder.hpp>
#include <ember/ir/ir.hpp>
#include <ember/ir/lifter.hpp>
#include <ember/ir/passes.hpp>
#include <ember/ir/ssa.hpp>
#include <ember/ir/types.hpp>
#include <ember/script/declarative.hpp>

#include "builders.hpp"
#include "cli_error.hpp"
#include "fingerprint.hpp"
#include "info.hpp"
#include "util.hpp"

namespace ember::cli {

// ---------------------------------------------------------------------------
// One-shot helpers
// ---------------------------------------------------------------------------

int run_dump_types() {
    TypeArena arena;
    std::println("type-lattice self-test");
    std::println("  arena size after seed: {}", arena.size());
    const auto i32a = arena.int_t(32);
    const auto i32b = arena.int_t(32);
    std::println("  i32 interned twice -> same id: {}",
                 i32a == i32b ? "yes" : "no");
    const auto i64t = arena.int_t(64);
    const auto pi32 = arena.ptr_t(i32a);
    const auto pi32b = arena.ptr_t(i32a);
    std::println("  ptr(i32) interned twice -> same id: {}",
                 pi32 == pi32b ? "yes" : "no");
    std::println("  meet(top, i32)            = {}",
                 arena.format(arena.meet(arena.top(), i32a)));
    std::println("  meet(i32, i32)            = {}",
                 arena.format(arena.meet(i32a, i32a)));
    std::println("  meet(i32, i64)            = {}",
                 arena.format(arena.meet(i32a, i64t)));
    const auto si32 = arena.int_t(32, true, true);
    std::println("  meet(i32, s32)            = {}",
                 arena.format(arena.meet(i32a, si32)));
    const auto ptop = arena.ptr_t(arena.top());
    std::println("  meet(ptr(i32), ptr(top))  = {}",
                 arena.format(arena.meet(pi32, ptop)));
    std::println("  meet(ptr(i32), i32)       = {}",
                 arena.format(arena.meet(pi32, i32a)));
    return EXIT_SUCCESS;
}

int run_export_annotations(const Args& args) {
    const std::filesystem::path exp_cache_dir =
        !args.cache_dir.empty() ? std::filesystem::path{args.cache_dir}
                                : cache::default_dir();
    const auto src = resolve_annotation_location(
        args.binary, args.annotations_path, exp_cache_dir);
    Annotations a;
    std::error_code ec;
    if (src.source != AnnotationSource::None &&
        std::filesystem::exists(src.path, ec) && !ec) {
        auto rv = Annotations::load(src.path);
        if (!rv) return report(rv.error());
        a = std::move(*rv);
    }
    auto sv = a.save(args.export_annotations);
    if (!sv) return report(sv.error());
    if (!args.quiet) {
        const std::size_t n = a.renames.size() + a.signatures.size()
                            + a.notes.size()   + a.named_constants.size();
        std::println(stderr,
            "ember: exported {} annotation(s) from {} to '{}'",
            n,
            src.source == AnnotationSource::None ? std::string{"<empty>"}
                                                 : src.path.string(),
            args.export_annotations);
    }
    return EXIT_SUCCESS;
}

int run_apply_ember(const Args& args, const Binary& b) {
    // Resolver for the destination file. Same precedence as emit:
    // explicit --annotations beats sidecar beats cache. The resolver
    // returns a cache path even when the file doesn't exist yet, so a
    // first-time apply still lands somewhere durable.
    const std::filesystem::path cache_dir =
        !args.cache_dir.empty() ? std::filesystem::path{args.cache_dir}
                                : cache::default_dir();
    auto loc = resolve_annotation_location(args.binary, args.annotations_path, cache_dir);
    if (args.no_cache && loc.source == AnnotationSource::Cache) loc = {};

    Annotations ann;
    if (loc.source != AnnotationSource::None) {
        std::error_code ec;
        if (std::filesystem::exists(loc.path, ec) && !ec) {
            auto rv = Annotations::load(loc.path);
            if (!rv) return report(rv.error());
            ann = std::move(*rv);
        }
    }

    auto rv = script::apply_file(args.apply_ember, b, ann);
    if (!rv) return report(rv.error());

    if (args.dry_run) {
        // Print the would-be file contents to stdout so the result is
        // diffable without touching disk. Stats + the proposed
        // destination still go to stderr for human review.
        const std::string text = ann.to_text();
        std::fwrite(text.data(), 1, text.size(), stdout);
    } else {
        if (loc.source == AnnotationSource::None || loc.path.empty()) {
            std::println(stderr, "ember: --apply: nowhere to write annotations "
                                 "(no --annotations / sidecar / cache)");
            return EXIT_FAILURE;
        }
        if (auto sv = ann.save(loc.path); !sv) return report(sv.error());
    }

    if (!args.quiet) {
        const char* tag = args.dry_run ? "--apply --dry-run" : "--apply";
        std::println(stderr,
            "ember: {}: +{} renames, +{} notes, +{} sigs, "
            "{} pattern-matches, {} from-strings, "
            "-{} renames / -{} notes / -{} sigs -> {} ({})",
            tag,
            rv->renames_added, rv->notes_added, rv->signatures_added,
            rv->pattern_renames_applied, rv->string_renames_applied,
            rv->renames_removed, rv->notes_removed, rv->signatures_removed,
            loc.path.empty() ? std::string{"<no destination>"} : loc.path.string(),
            annotation_source_name(loc.source));
        for (const auto& w : rv->warnings) {
            std::println(stderr, "ember: {}: warning: {}", tag, w);
        }
    }
    return EXIT_SUCCESS;
}

// ---------------------------------------------------------------------------
// Side-effect setup (no exit code)
// ---------------------------------------------------------------------------

void load_trace_edges(const Args& args, const Binary& b) {
    // Indirect-edge trace must seed the oracle BEFORE any analysis runs
    // — the CFG builder consults it lazily but the result gets cached
    // in IR caches downstream, so late-loading wouldn't take effect on
    // subsequent passes.
    std::ifstream tf(args.trace_path);
    if (!tf) {
        std::println(stderr, "ember: cannot open trace '{}'", args.trace_path);
        return;
    }
    std::string line;
    std::size_t loaded = 0, line_no = 0;
    while (std::getline(tf, line)) {
        ++line_no;
        if (line.empty() || line.front() == '#') continue;
        const auto tab = line.find('\t');
        if (tab == std::string::npos) {
            std::println(stderr,
                "ember: trace '{}' line {}: missing tab — expected `from\\tto`",
                args.trace_path, line_no);
            continue;
        }
        auto parse_hex = [](std::string_view s, addr_t& out) {
            if (s.starts_with("0x") || s.starts_with("0X")) s.remove_prefix(2);
            u64 v = 0;
            auto r = std::from_chars(s.data(), s.data() + s.size(), v, 16);
            if (r.ec != std::errc{} || r.ptr != s.data() + s.size()) return false;
            out = static_cast<addr_t>(v);
            return true;
        };
        addr_t from = 0, to = 0;
        if (!parse_hex(std::string_view(line).substr(0, tab), from) ||
            !parse_hex(std::string_view(line).substr(tab + 1),  to)) {
            std::println(stderr,
                "ember: trace '{}' line {}: bad hex addr",
                args.trace_path, line_no);
            continue;
        }
        b.record_indirect_edge(from, to);
        ++loaded;
    }
    std::println(stderr, "ember: loaded {} indirect edge(s) from '{}'",
                 loaded, args.trace_path);
}

// ---------------------------------------------------------------------------
// Cached output runners
// ---------------------------------------------------------------------------

int run_xrefs(const Args& args, const Binary& b) {
    return run_cached(args, "xrefs", [&] { return build_xrefs_output(b); });
}

int run_data_xrefs(const Args& args, const Binary& b) {
    // TSV and JSON share the compute step but differ in output format,
    // so they cache under distinct tags — otherwise the first form
    // served would silently satisfy the second.
    const std::string_view tag = args.json ? "data-xrefs-json-v1" : "data-xrefs-v1";
    return run_cached(args, tag, [&] { return build_data_xrefs_output(b, args.json); });
}

int run_strings(const Args& args, const Binary& b) {
    // Cache tag bumped to v2 when the scanner started covering executable
    // sections (Mach-O __cstring lives in __TEXT). Old "strings" cache
    // entries from before that change are now orphaned.
    return run_cached(args, "strings-v2", [&] { return build_strings_output(b); });
}

namespace {

// Address-range scope filter, populated from --module NAME against a
// minidump (or any Binary that synthesizes module Symbols of kind=Section
// with addr=base / size=image-size — currently just MinidumpBinary). When
// inactive, contains() returns true for every address; the caller-side
// code paths run unchanged. When active, fn-walking subcommands skip
// every address outside [lo, hi) before fingerprinting/decompiling — the
// motivating case is a process minidump where ~95% of discovered fns
// belong to wine ntdll/kernelbase reimpl pages and would never match
// the real-Microsoft TEEF corpus.
struct ModuleScope {
    addr_t lo = 0;
    addr_t hi = 0;
    bool   active = false;
    std::string matched_name;       // for stderr diagnostics

    [[nodiscard]] bool contains(addr_t a) const noexcept {
        return !active || (a >= lo && a < hi);
    }
};

// Case-insensitive substring match on basenames. The minidump loader
// already trims paths to basenames before populating Symbol::name, so
// `loader.exe` finds `loader.exe` — but accept partials too (`loader`
// finds `loader.exe`, `kernel32` finds `kernel32.dll`). Ambiguous
// matches: use the first hit and warn — the user can disambiguate by
// passing the full basename.
[[nodiscard]] ModuleScope resolve_module_scope(const Binary& b,
                                               std::string_view name) {
    ModuleScope ms;
    if (name.empty()) return ms;

    auto lc = [](std::string_view s) {
        std::string out(s);
        for (auto& c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        return out;
    };
    const std::string needle = lc(name);

    std::vector<const Symbol*> candidates;
    for (const auto& s : b.symbols()) {
        if (s.kind != SymbolKind::Section) continue;   // module spans only
        if (s.size == 0) continue;
        if (lc(s.name).find(needle) != std::string::npos) {
            candidates.push_back(&s);
        }
    }

    if (candidates.empty()) {
        std::println(stderr, "ember: --module '{}' matched no loaded module", name);
        std::println(stderr, "ember: available modules:");
        for (const auto& s : b.symbols()) {
            if (s.kind != SymbolKind::Section) continue;
            if (s.size == 0) continue;
            std::println(stderr, "  {}\t{:#x}\t{:#x}", s.name, s.addr, s.size);
        }
        return ms;   // inactive — caller should bail
    }
    if (candidates.size() > 1) {
        std::println(stderr,
            "ember: --module '{}' is ambiguous ({} matches); using first ({})",
            name, candidates.size(), candidates.front()->name);
        for (const auto* c : candidates) {
            std::println(stderr, "  {}\t{:#x}\t{:#x}", c->name, c->addr, c->size);
        }
    }
    ms.lo = candidates.front()->addr;
    ms.hi = candidates.front()->addr + candidates.front()->size;
    ms.matched_name = candidates.front()->name;
    ms.active = true;
    std::println(stderr,
        "ember: --module '{}' resolved to {} [{:#x}, {:#x})",
        name, ms.matched_name, ms.lo, ms.hi);
    return ms;
}

// Parse hex string -> u64. Used by parse_teef_tsv below.
[[nodiscard]] u64 parse_u64_hex_local(std::string_view s) noexcept {
    u64 v = 0;
    for (char c : s) {
        u64 d = (c >= '0' && c <= '9') ? static_cast<u64>(c - '0')
              : (c >= 'a' && c <= 'f') ? static_cast<u64>(c - 'a' + 10)
              : (c >= 'A' && c <= 'F') ? static_cast<u64>(c - 'A' + 10)
              : 0u;
        v = (v << 4) | d;
    }
    return v;
}

// Parse a TEEF TSV (output of build_teef_tsv / `ember --teef`) back into
// a per-function structure suitable for the recognizer's query path.
// Lets `--recognize` reuse the disk cache that `--teef` writes — no need
// to re-fingerprint a binary that was already analyzed once.
[[nodiscard]] std::vector<std::pair<addr_t, TeefFunction>>
parse_teef_tsv(std::string_view tsv) {
    std::vector<std::pair<addr_t, TeefFunction>> out;
    std::unordered_map<addr_t, std::size_t> idx_by_addr;
    auto split_tabs = [](std::string_view line) {
        std::vector<std::string_view> f;
        std::size_t s = 0;
        for (std::size_t i = 0; i < line.size(); ++i) {
            if (line[i] == '\t') { f.emplace_back(line.substr(s, i - s)); s = i + 1; }
        }
        f.emplace_back(line.substr(s));
        return f;
    };
    std::size_t pos = 0;
    while (pos < tsv.size()) {
        std::size_t nl = tsv.find('\n', pos);
        if (nl == std::string_view::npos) nl = tsv.size();
        auto line = tsv.substr(pos, nl - pos);
        pos = nl + 1;
        if (line.empty()) continue;
        auto f = split_tabs(line);
        if (f.empty()) continue;
        if (f[0] == "F" && f.size() >= 24) {
            // F row: addr  L2_exact  L2_mh*8  name
            //         L4_exact  L4_mh*8  L4_done  L4_aborted  topo_hash
            const addr_t a = static_cast<addr_t>(parse_u64_hex_local(f[1]));
            TeefFunction tf;
            tf.whole.exact_hash = parse_u64_hex_local(f[2]);
            for (std::size_t k = 0; k < 8; ++k) {
                tf.whole.minhash[k] = parse_u64_hex_local(f[3 + k]);
            }
            tf.behav.exact_hash = parse_u64_hex_local(f[12]);
            for (std::size_t k = 0; k < 8; ++k) {
                tf.behav.minhash[k] = parse_u64_hex_local(f[13 + k]);
            }
            u32 done = 0;
            std::from_chars(f[21].data(),
                            f[21].data() + f[21].size(), done);
            tf.behav.traces_done = static_cast<u8>(std::min<u32>(done, 255));
            u32 aborted = 0;
            std::from_chars(f[22].data(),
                            f[22].data() + f[22].size(), aborted);
            tf.behav.traces_aborted = static_cast<u8>(std::min<u32>(aborted, 255));
            tf.topo_hash = parse_u64_hex_local(f[23]);
            idx_by_addr[a] = out.size();
            out.emplace_back(a, std::move(tf));
        } else if (f[0] == "S" && f.size() >= 3) {
            // S<TAB>addr<TAB>hash1,hash2,...
            const addr_t a = static_cast<addr_t>(parse_u64_hex_local(f[1]));
            auto it = idx_by_addr.find(a);
            if (it == idx_by_addr.end()) continue;
            std::string_view csv = f[2];
            std::size_t cp = 0;
            while (cp < csv.size()) {
                std::size_t comma = csv.find(',', cp);
                if (comma == std::string_view::npos) comma = csv.size();
                std::string_view tok = csv.substr(cp, comma - cp);
                if (!tok.empty()) {
                    out[it->second].second.string_hashes.push_back(parse_u64_hex_local(tok));
                }
                cp = comma + 1;
            }
        } else if (f[0] == "C" && f.size() >= 14) {
            const addr_t a = static_cast<addr_t>(parse_u64_hex_local(f[1]));
            auto it = idx_by_addr.find(a);
            if (it == idx_by_addr.end()) continue;
            TeefChunk ch;
            // kind + inst_count are emitted as decimal by build_teef_tsv.
            u32 v = 0; std::from_chars(f[2].data(), f[2].data() + f[2].size(), v);
            ch.kind = static_cast<u8>(v);
            v = 0; std::from_chars(f[3].data(), f[3].data() + f[3].size(), v);
            ch.inst_count = v;
            ch.sig.exact_hash = parse_u64_hex_local(f[4]);
            for (std::size_t k = 0; k < 8; ++k) {
                ch.sig.minhash[k] = parse_u64_hex_local(f[5 + k]);
            }
            out[it->second].second.chunks.push_back(ch);
        }
    }
    return out;
}

// Extracted from run_teef so --recognize can reuse it on cache miss.
// Returns the same TSV the user would see from `ember --teef <bin>`.
// `scope`, when active, filters every fn-walking step so we don't pay
// fingerprint cost on out-of-module noise.
// `corpus_mode` controls one optimization: when building a TSV intended
// to be loaded as a CORPUS (via TeefCorpus::load_tsv), unnamed fns
// (`sub_<addr>`) skip the K=64 behavioural traces and emit zeros for
// the L4 columns. The recognizer's load_tsv drops sub_* rows entirely
// after counting their L2 exact_hash for popularity tracking, so the
// L4 sketch on those rows is never read — computing it is pure waste.
//
// Recognize-time fingerprinting (build_teef_tsv called on a query
// binary that may itself be stripped, so all its fns are sub_*) needs
// L4 for every fn — leave corpus_mode at its default false.
//
// `min_fn_bytes` / `max_fn_bytes` filter fns by their byte-extent
// estimate BEFORE fingerprinting. Obfuscator-spawned binaries
// (Themida, Lua-VM, hellgate) emit hundreds of thousands of trivial
// sub-32-byte stubs alongside VM-dispatcher functions that span
// entire sections. The dispatchers' cfg.build alone can take tens of
// ms each and dominate the run on a 200K+-fn target — even when
// --l0-prefilter would otherwise skip their lift, the cfg pass
// already happened. The byte-size bracket lets the caller cull both
// extremes before any per-fn pipeline work. 0 means no bound on that
// side.
//
// `l4_topo_filter`, when non-null, is the corpus's set of L0 topology
// hashes — passed straight to compute_teef_max so target fns whose
// topology isn't in the corpus skip the K=64 trace pass. Recognize-
// time only; corpus build leaves it nullptr (no corpus to filter
// against).
[[nodiscard]] std::string
build_teef_tsv(const Binary& b,
               const ModuleScope& scope = {},
               bool corpus_mode = false,
               u64 min_fn_bytes = 0,
               u64 max_fn_bytes = 0,
               const std::unordered_set<u64>* l4_topo_filter = nullptr) {
    const bool show = progress_enabled();

        std::unordered_map<addr_t, std::string> name_by_addr;
        for (const auto& s : b.symbols()) {
            if (s.is_import) continue;
            if (s.kind != SymbolKind::Function) continue;
            if (s.addr == 0 || s.name.empty()) continue;
            if (!scope.contains(s.addr)) continue;
            name_by_addr.try_emplace(s.addr, s.name);
        }

        // Use enumerate_functions — same source as --functions — so we
        // pick up CFG-discovered sub_* on stripped / static-pie targets
        // (HellGates, Rust release builds, Go binaries). compute_call_graph
        // alone misses these because it filters on s.size != 0.
        std::vector<addr_t> fns;
        std::size_t filtered_small = 0;
        std::size_t filtered_large = 0;
        {
            std::set<addr_t> uniq;
            // Named fns always go in regardless of size — they may be
            // intentional small thunks (deregister_tm_clones, _init).
            for (const auto& [a, _] : name_by_addr) uniq.insert(a);
            // CFG-discovered fns may have size=0 when the discovery
            // pass doesn't know the extent (linear-sweep entry points,
            // hellgate stubs, the bulk of obfuscator-spawned tiny
            // helpers). For the size-bracket filter we need a usable
            // size estimate; derive it from the gap to the next
            // discovered fn after sorting. Upper bound — over-counts
            // when there's padding/jump tables in between, but that's
            // the safe direction for filtering both ends.
            auto disc = enumerate_functions(b, EnumerateMode::Auto,
                                            scope.lo, scope.hi);
            std::sort(disc.begin(), disc.end(),
                [](const auto& x, const auto& y) { return x.addr < y.addr; });
            for (std::size_t i = 0; i < disc.size(); ++i) {
                u64 sz = disc[i].size;
                if (sz == 0 && i + 1 < disc.size() &&
                    disc[i + 1].addr > disc[i].addr) {
                    sz = disc[i + 1].addr - disc[i].addr;
                }
                if (b.import_at_plt(disc[i].addr)) continue;
                if (min_fn_bytes > 0 && sz > 0 && sz < min_fn_bytes) {
                    ++filtered_small;
                    continue;
                }
                if (max_fn_bytes > 0 && sz > max_fn_bytes) {
                    ++filtered_large;
                    continue;
                }
                uniq.insert(disc[i].addr);
            }
            fns.assign(uniq.begin(), uniq.end());
        }
        if (show && filtered_small > 0) {
            std::println(stderr,
                "ember: TEEF: --min-fn-size dropped {} fns smaller than {} bytes",
                filtered_small, min_fn_bytes);
        }
        if (show && filtered_large > 0) {
            std::println(stderr,
                "ember: TEEF: --max-fn-size dropped {} fns larger than {} bytes",
                filtered_large, max_fn_bytes);
        }

        // ---- Per-fn reachable strings (TEEF schema v4) ----
        // For every string in the binary's strings table, record which
        // functions reach it via xref site. We bucket xref sites into
        // their containing fn by binary-searching `fns` for the largest
        // entry ≤ site, then storing the string text under that fn. The
        // alternative — scan_strings + per-fn linear filter — is N×M
        // and unbearable on big binaries.
        //
        // Strings act as a precision anchor at recognize time: two
        // functions with identical TEEF structure but disjoint string
        // sets are almost certainly not the same function (different
        // error message constants, different format strings, different
        // path constants), and the recognizer can use that to suppress
        // structural false positives.
        // Build (entry, size) pairs from enumerate_functions for fns
        // with KNOWN extent — size-0 shadow entries (linear-sweep
        // probes inside another fn's body) are skipped; their xref
        // sites get attributed to the containing real fn instead.
        std::vector<std::pair<addr_t, u64>> sized_fns;
        for (const auto& d : enumerate_functions(b, EnumerateMode::Auto, scope.lo, scope.hi)) {
            if (b.import_at_plt(d.addr)) continue;
            if (d.size == 0) continue;
            sized_fns.emplace_back(d.addr, d.size);
        }
        // Also include named symbols whose size we can derive.
        for (const auto& s : b.symbols()) {
            if (s.is_import) continue;
            if (s.kind != SymbolKind::Function) continue;
            if (s.addr == 0 || s.size == 0) continue;
            if (!scope.contains(s.addr)) continue;
            sized_fns.emplace_back(s.addr, s.size);
        }
        std::sort(sized_fns.begin(), sized_fns.end());
        sized_fns.erase(std::unique(sized_fns.begin(), sized_fns.end(),
            [](const auto& x, const auto& y) { return x.first == y.first; }),
            sized_fns.end());

        std::unordered_map<addr_t, std::vector<std::string>> strings_by_fn;
        if (show) {
            std::println(stderr, "ember: TEEF: scanning strings for per-fn anchors...");
            std::fflush(stderr);
        }
        for (const auto& s : scan_strings(b)) {
            // Filter pure-noise strings — too short to identify. The
            // scanner already enforces ≥4-char strings; we tighten here
            // to 4 (== scanner floor; everything below is library-name-
            // length-or-less and contributes more noise than signal).
            if (s.text.size() < 4) continue;
            for (addr_t site : s.xrefs) {
                // Find the sized fn whose [entry, entry+size) actually
                // contains the site. upper_bound + walk back, then
                // verify containment. Sites that fall in gaps (no fn
                // covers them) are skipped — they can't be reliably
                // attributed.
                auto it = std::upper_bound(sized_fns.begin(), sized_fns.end(),
                    std::pair<addr_t, u64>{site, ~u64{0}});
                if (it == sized_fns.begin()) continue;
                --it;
                if (site >= it->first + it->second) continue;
                strings_by_fn[it->first].push_back(s.text);
            }
        }
        // Dedup + cap to top-8 by length per fn. Length-biased because
        // long unique strings ("X509_CHECK_FLAG_NO_WILDCARDS") are far
        // more identifying than short common ones ("ok", "%s").
        for (auto& [_, list] : strings_by_fn) {
            std::sort(list.begin(), list.end());
            list.erase(std::unique(list.begin(), list.end()), list.end());
            if (list.size() > 8) {
                std::partial_sort(list.begin(), list.begin() + 8, list.end(),
                    [](const std::string& x, const std::string& y) {
                        return x.size() > y.size();
                    });
                list.resize(8);
            }
        }

        const std::size_t total = fns.size();
        const unsigned threads = thread_pool_size(16);
        if (show) {
            std::println(stderr,
                "ember: TEEF on {} functions across {} threads (full decompile per fn)...",
                total, threads);
            std::fflush(stderr);
        }

        // Per-function results in input order. Workers pull indices off
        // `next` atomically; ordering is preserved by writing into the
        // pre-sized result vector at the function's index.
        std::vector<std::string> rows(total);
        std::atomic<std::size_t> next{0};
        std::atomic<std::size_t> done{0};
        // Counters for the post-phase summary so the user can see how
        // much --l0-prefilter is actually helping vs. how many fns
        // still go through the full pipeline.
        std::atomic<std::size_t> early_exit_topo{0};
        std::atomic<std::size_t> empty_fingerprint{0};
        const auto t_fp_start = std::chrono::steady_clock::now();
        std::mutex fp_progress_mu;
        std::atomic<bool> fp_phase_done{false};

        // Time-driven progress ticker. Workers used to print every Nth
        // fn; on huge or VM-protected targets a single fn can take
        // hundreds of milliseconds, so the user sees no update for tens
        // of seconds at a time. The ticker runs independently and
        // refreshes every 500 ms with whatever `done` and the worker
        // pool have accomplished so far. TTY-only.
        std::thread fp_ticker;
        if (show) {
            fp_ticker = std::thread([&] {
                while (!fp_phase_done.load(std::memory_order_relaxed)) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(500));
                    const std::size_t d = done.load(std::memory_order_relaxed);
                    if (d == 0 || d == total) continue;
                    const std::size_t ee = early_exit_topo.load(std::memory_order_relaxed);
                    const auto now = std::chrono::steady_clock::now();
                    const double elapsed = std::chrono::duration<double>(
                        now - t_fp_start).count();
                    const double rate = elapsed > 0
                        ? static_cast<double>(d) / elapsed : 0.0;
                    const double eta = rate > 0
                        ? static_cast<double>(total - d) / rate : 0.0;
                    const double pct_ee = d > 0
                        ? 100.0 * static_cast<double>(ee) / static_cast<double>(d) : 0.0;
                    std::lock_guard<std::mutex> lock(fp_progress_mu);
                    std::fprintf(stderr,
                        "\r  fingerprint [%zu/%zu] %.0f fn/s · skip %.0f%% · elapsed %.1fs · eta %.1fs   ",
                        d, total, rate, pct_ee, elapsed, eta);
                    std::fflush(stderr);
                }
            });
        }

        auto worker = [&] {
            while (true) {
                const std::size_t i = next.fetch_add(1, std::memory_order_relaxed);
                if (i >= total) break;
                const addr_t a = fns[i];
                // Corpus-mode fast path: sub_* (unnamed) fns are dropped
                // by TeefCorpus::load_tsv after their L2 exact_hash is
                // counted into the popularity guard, so their L4 sketch
                // is never read — fall back to compute_teef_with_chunks
                // (L0 + L2 only, no K=64 traces). ~3 ms saved per sub_*.
                // Recognize-time fingerprinting leaves corpus_mode false
                // so query-side stripped binaries still get full L4.
                const bool is_named = name_by_addr.contains(a);
                const bool full_l4  = !corpus_mode || is_named;
                const auto tf = full_l4
                    ? compute_teef_max(b, a, /*min_chunk_insts=*/10,
                                       l4_topo_filter)
                    : compute_teef_with_chunks(b, a);
                const auto& bs = tf.behav;
                done.fetch_add(1, std::memory_order_relaxed);
                // Telemetry: distinguish "early-exited via topo filter"
                // from "made it through the full pipeline but came out
                // empty" (e.g., insn-cap hit). Lets the user see at a
                // glance whether --l0-prefilter is paying off.
                if (tf.whole.exact_hash == 0) {
                    if (l4_topo_filter && tf.topo_hash != 0 &&
                        !l4_topo_filter->contains(tf.topo_hash)) {
                        early_exit_topo.fetch_add(1, std::memory_order_relaxed);
                    } else {
                        empty_fingerprint.fetch_add(1, std::memory_order_relaxed);
                    }
                }
                if (tf.whole.exact_hash == 0) continue;
                std::string name;
                if (auto it = name_by_addr.find(a); it != name_by_addr.end()) {
                    name = it->second;
                } else {
                    name = std::format("sub_{:x}", a);
                }
                // F row: F addr L2_exact L2_mh*8 name L4_exact L4_mh*8
                //         L4_done L4_aborted topo_hash
                // (24 tab-separated fields). L4 columns trail the name
                // so the structural-only fields stay at fixed positions
                // 0..11 — handy for grep/awk inspection. topo_hash is
                // the L0 CFG-shape signal, used by the recognizer as a
                // pre-filter for L2 jaccard scans.
                std::string buf =
                    std::format("F\t{:x}\t{:016x}", a, tf.whole.exact_hash);
                for (u64 mh : tf.whole.minhash) buf += std::format("\t{:016x}", mh);
                buf += '\t';
                buf += name;
                buf += std::format("\t{:016x}", bs.exact_hash);
                for (u64 mh : bs.minhash) buf += std::format("\t{:016x}", mh);
                buf += std::format("\t{}\t{}",
                                    static_cast<u32>(bs.traces_done),
                                    static_cast<u32>(bs.traces_aborted));
                buf += std::format("\t{:016x}", tf.topo_hash);
                buf += '\n';

                // String-anchor row: S<TAB>addr<TAB>hash1,hash2,...
                // Up to 8 fnv1a64 hashes of the function's identifying
                // strings. Loader stores them on WholeEntry; recognizer
                // uses overlap as a precision filter against
                // structural false positives.
                if (auto sit = strings_by_fn.find(a); sit != strings_by_fn.end() && !sit->second.empty()) {
                    buf += std::format("S\t{:x}", a);
                    bool first = true;
                    for (const auto& str : sit->second) {
                        buf += first ? '\t' : ',';
                        first = false;
                        buf += std::format("{:016x}", fnv1a_64(str));
                    }
                    buf += '\n';
                }
                // Chunk rows: C<TAB>addr<TAB>kind<TAB>insts<TAB>exact<TAB>mh0..7<TAB>name
                for (const auto& ch : tf.chunks) {
                    if (ch.sig.exact_hash == 0) continue;
                    buf += std::format("C\t{:x}\t{}\t{}\t{:016x}",
                                       a, ch.kind, ch.inst_count, ch.sig.exact_hash);
                    for (u64 mh : ch.sig.minhash) buf += std::format("\t{:016x}", mh);
                    buf += '\t';
                    buf += name;
                    buf += '\n';
                }
                rows[i] = std::move(buf);
            }
        };

        std::vector<std::thread> pool;
        pool.reserve(threads);
        for (unsigned k = 0; k < threads; ++k) pool.emplace_back(worker);
        for (auto& t : pool) t.join();
        fp_phase_done.store(true, std::memory_order_relaxed);
        if (fp_ticker.joinable()) fp_ticker.join();
        if (show) {
            // Final progress line so the last `[total/total]` actually
            // appears (the ticker only emits intermediate states).
            const auto now = std::chrono::steady_clock::now();
            const double elapsed = std::chrono::duration<double>(
                now - t_fp_start).count();
            const double rate = elapsed > 0
                ? static_cast<double>(total) / elapsed : 0.0;
            std::fprintf(stderr,
                "\r  fingerprint [%zu/%zu] %.0f fn/s · elapsed %.1fs · done           \n",
                total, total, rate, elapsed);
            std::fflush(stderr);
            const std::size_t ee = early_exit_topo.load(std::memory_order_relaxed);
            const std::size_t eg = empty_fingerprint.load(std::memory_order_relaxed);
            const std::size_t full_pipe = (total > ee + eg) ? (total - ee - eg) : 0;
            std::println(stderr,
                "ember: TEEF: {} fns full-pipeline, {} early-exit (l0-prefilter), "
                "{} empty (insn-cap / lift bail)",
                full_pipe, ee, eg);
        }

    std::string out;
    std::size_t total_bytes = 0;
    for (const auto& r : rows) total_bytes += r.size();
    out.reserve(total_bytes);
    for (const auto& r : rows) out += r;
    return out;
}
}  // namespace

// Pulled out so the daemon (run_serve) can cache one TeefCorpus across
// recognize requests instead of re-parsing 50-150 MB of TSV per call.
[[nodiscard]] static std::unique_ptr<TeefCorpus>
load_corpus_from_args(const Args& args) {
    if (args.corpus_paths.empty()) return nullptr;
    auto corpus = std::make_unique<TeefCorpus>();
    std::size_t total_rows = 0;
    const auto t_start = std::chrono::steady_clock::now();
    for (const auto& p : args.corpus_paths) {
        // Per-file timings come from TeefCorpus::load_tsv itself —
        // it logs phase breakdown (mmap / parse / merge / total).
        const std::size_t n = corpus->load_tsv(p);
        total_rows += n;
    }
    const auto t_end = std::chrono::steady_clock::now();
    const double total_ms = std::chrono::duration<double, std::milli>(
        t_end - t_start).count();
    std::println(stderr,
        "ember: corpus loaded: {} fns / {} chunks across {} TSVs "
        "({} rows) in {:.0f} ms",
        corpus->function_count(), corpus->chunk_count(),
        args.corpus_paths.size(), total_rows, total_ms);
    return corpus;
}

// Heuristic: classify the query binary's runtime/ABI for the TEEF
// recognizer's cross-language plausibility filter. Only the obvious
// cases get a tag; "" means unknown / wildcard. Conservative — false
// positives here (saying a Rust binary is C) just disable filtering;
// false negatives (saying a C binary is Rust) would block legitimate
// libstdc++ matches on a C++ binary.
[[nodiscard]] static std::string_view detect_query_runtime(const Binary& b) {
    std::size_t rust_hits     = 0;
    std::size_t cxx_std_hits  = 0;
    std::size_t cxx_hits      = 0;
    std::size_t msvc_cxx_hits = 0;
    std::size_t msvcrt_hits   = 0;
    std::size_t winapi_hits   = 0;
    for (const auto& s : b.symbols()) {
        if (s.name.empty()) continue;
        // Rust: _R-mangled names or the runtime alloc/panic shims.
        if (s.name.starts_with("_R") || s.name.starts_with("__rust_")) {
            ++rust_hits;
            continue;
        }
        // MSVC C++ ABI: ?... mangled names. msvcrt.dll exports look like
        // ??0... (constructor), ??1... (destructor), ?... (mangled fn).
        if (s.name.starts_with("?") || s.name.starts_with("??")) {
            ++msvc_cxx_hits;
            continue;
        }
        // libstdc++ template instantiations are dominantly _ZSt / _ZNSt.
        if (s.name.starts_with("_ZSt") || s.name.starts_with("_ZNSt")) {
            ++cxx_std_hits;
            continue;
        }
        // Generic Itanium-mangled C++.
        if (s.name.starts_with("_Z")) {
            ++cxx_hits;
            continue;
        }
        // Windows imports — kernel32/ntdll/user32 etc export plain
        // names, so we recognize via known-API surface. is_import
        // filters to the bound IAT entries.
        if (s.is_import) {
            const std::string_view n = s.name;
            // Kernel/Win32 surface tells us this is a Windows binary
            if (n == "GetProcAddress" || n == "LoadLibraryA" || n == "LoadLibraryW" ||
                n == "VirtualAlloc" || n == "VirtualProtect" ||
                n == "CreateFileW"  || n == "CreateFileA" ||
                n == "ReadFile"     || n == "WriteFile" ||
                n == "GetModuleHandleA" || n == "GetModuleHandleW" ||
                n == "ExitProcess"  || n == "GetCommandLineW" ||
                n == "RtlAllocateHeap" || n == "RtlFreeHeap" ||
                n == "NtCreateFile" || n.starts_with("Nt")) {
                ++winapi_hits;
                continue;
            }
            // CRT entry points
            if (n == "_initterm" || n == "_set_app_type" || n == "exit" ||
                n.starts_with("_CRT_") || n.starts_with("__chkstk")) {
                ++msvcrt_hits;
            }
        }
    }
    if (rust_hits >= 4)        return teef_runtime::kRust;
    if (msvc_cxx_hits >= 4)    return teef_runtime::kCxxMsvc;
    if (cxx_std_hits >= 4)     return teef_runtime::kLibstdcxx;
    if (cxx_hits >= 8)         return teef_runtime::kCxx;
    if (winapi_hits >= 3)      return teef_runtime::kWinapi;
    if (msvcrt_hits >= 2)      return teef_runtime::kMsvcrt;
    return "";
}

int run_recognize(const Args& args, const Binary& b) {
    if (args.corpus_paths.empty()) {
        std::println(stderr,
            "ember: --recognize requires at least one --corpus PATH");
        return EXIT_FAILURE;
    }
    // Daemon-friendly corpus cache. Identical --corpus PATH lists
    // reuse the parsed in-memory indices across calls. One-shot CLI
    // runs hit this path exactly once per process, so the static is
    // a no-op for them; --serve sessions repeating recognize against
    // the same corpus get the load amortized away.
    static std::vector<std::string> cached_paths;
    static std::unique_ptr<TeefCorpus> cached_corpus;
    if (!cached_corpus || cached_paths != args.corpus_paths) {
        cached_corpus = load_corpus_from_args(args);
        cached_paths = args.corpus_paths;
    } else {
        std::println(stderr,
            "ember: reusing cached corpus ({} fns / {} chunks)",
            cached_corpus->function_count(), cached_corpus->chunk_count());
    }
    const TeefCorpus& corpus = *cached_corpus;

    // Resolve --module if any. Inactive scope = no-op everywhere below.
    // An unresolved scope (user passed a name but it didn't match any
    // module) bails — running unscoped would silently process the wrong
    // surface and waste work.
    const ModuleScope scope = resolve_module_scope(b, args.module_filter);
    if (!args.module_filter.empty() && !scope.active) {
        return EXIT_FAILURE;
    }

    // Walk every named-or-discovered function in the binary, fingerprint
    // it, ask the corpus for matches above threshold.
    std::unordered_map<addr_t, std::string> name_by_addr;
    for (const auto& s : b.symbols()) {
        if (s.is_import) continue;
        if (s.kind != SymbolKind::Function) continue;
        if (s.addr == 0 || s.name.empty()) continue;
        if (!scope.contains(s.addr)) continue;
        name_by_addr.try_emplace(s.addr, s.name);
    }
    // Stride-1 dedup. enumerate_functions() can emit multiple
    // overlapping addresses on stripped binaries when the prologue-
    // sweep heuristic fires at consecutive bytes inside one real fn's
    // body. Without this filter, --recognize re-fingerprints each of
    // those shadow entries, producing dozens of identical-name hits at
    // a stride of 1 (the user-reported "126x _ZSt7getlineIw..." case
    // in libloader.so). Fix: walk sorted, drop any addr that lands
    // inside a previously-seen fn's [entry, entry+size) window.
    std::map<addr_t, u64> windows;     // entry → known size
    for (const auto& [a, _] : name_by_addr) windows[a]; // size 0 by default
    for (const auto& d : enumerate_functions(b, EnumerateMode::Auto, scope.lo, scope.hi)) {
        if (b.import_at_plt(d.addr)) continue;
        auto& sz = windows[d.addr];
        if (d.size > sz) sz = d.size;  // prefer the larger known extent
    }
    std::set<addr_t> fns;
    addr_t shadow_until = 0;
    std::size_t shadow_dropped = 0;
    for (auto [a, sz] : windows) {
        if (a < shadow_until) { ++shadow_dropped; continue; }
        fns.insert(a);
        if (sz > 0) shadow_until = a + sz;
    }
    if (shadow_dropped > 0) {
        std::println(stderr, "ember: recognize: dropped {} shadow entries (stride-1 dedup)",
                     shadow_dropped);
    }

    const std::size_t total = fns.size();
    const unsigned hw = std::thread::hardware_concurrency();
    const unsigned threads = std::max(1u, std::min(hw ? hw : 4u, 16u));
    std::vector<addr_t> fns_vec(fns.begin(), fns.end());

    // Pass 1: get the target's TEEF TSV. This unifies cache-hit and
    // miss paths: hit reads the cached string, miss runs the same
    // build_teef_tsv that --teef would and writes it back so the next
    // run is fast. parse_teef_tsv then materializes the per-function
    // fingerprints we'll match against the corpus.
    //
    // When --module is active, the disk cache is bypassed in both
    // directions: a scoped run produces a strict subset of the
    // unscoped TSV, which would either be served (incorrectly) to a
    // future unscoped query or — worse — poison the cache slot that
    // the unscoped path expects to find a full table in.
    const bool cacheable = !args.no_cache && !scope.active;
    std::string target_tsv;
    bool cache_hit = false;
    if (cacheable) {
        const auto dir = args.cache_dir.empty()
            ? cache::default_dir()
            : std::filesystem::path(args.cache_dir);
        if (auto k = cache::key_for(args.binary); k) {
            const std::string tag = std::format("teef-{}", kTeefSchema);
            if (auto hit = cache::read(dir, *k, tag); hit) {
                target_tsv = std::move(*hit);
                cache_hit = true;
            }
        }
    }
    if (!cache_hit) {
        // Optional L0 pre-filter: when --l0-prefilter is set, target
        // fns whose L0 topology hash isn't in the corpus skip L4. Big
        // throughput win on obfuscator-heavy targets but lossy on
        // cross-opt-level matches (CFG topology shifts even for the
        // same source), so off by default.
        //
        // Popularity guard (kMaxTopoPopularity): exclude corpus
        // topologies shared by more than this many corpus entries.
        // These are generic shapes (return-stub, simple if-then) that
        // match thousands of unrelated fns AND a target's stubs;
        // letting them through makes the filter useless for the
        // target's high-volume boilerplate. Tuneable via
        // EMBER_TEEF_MAX_TOPO_POPULARITY (0 disables the guard).
        std::unordered_set<u64> corpus_topos;
        if (args.l0_prefilter) {
            static const std::size_t kMaxTopoPopularity = []() -> std::size_t {
                if (const char* s = std::getenv("EMBER_TEEF_MAX_TOPO_POPULARITY")) {
                    try { return static_cast<std::size_t>(std::stoull(s)); }
                    catch (...) {}
                }
                return 50;
            }();
            corpus_topos = corpus.topo_hashes(kMaxTopoPopularity);
            std::println(stderr,
                "ember: --l0-prefilter on; {} corpus topologies "
                "(after popularity guard ≤{})",
                corpus_topos.size(), kMaxTopoPopularity);
        }
        const auto t_fp_start = std::chrono::steady_clock::now();
        target_tsv = build_teef_tsv(b, scope, /*corpus_mode=*/false,
                                    args.min_fn_bytes, args.max_fn_bytes,
                                    args.l0_prefilter ? &corpus_topos : nullptr);
        const auto t_fp_end = std::chrono::steady_clock::now();
        const double fp_ms = std::chrono::duration<double, std::milli>(
            t_fp_end - t_fp_start).count();
        std::println(stderr,
            "ember: target fingerprint built in {:.0f} ms ({} bytes, {} fns)",
            fp_ms, target_tsv.size(), total);
        if (cacheable) {
            const auto dir = args.cache_dir.empty()
                ? cache::default_dir()
                : std::filesystem::path(args.cache_dir);
            if (auto k = cache::key_for(args.binary); k) {
                const std::string tag = std::format("teef-{}", kTeefSchema);
                (void)cache::write(dir, *k, tag, target_tsv);
            }
        }
    } else {
        std::println(stderr, "ember: reusing cached TEEF for target ({} bytes)",
                     target_tsv.size());
    }

    std::vector<TeefFunction> fps(total);
    {
        auto parsed = parse_teef_tsv(target_tsv);
        std::unordered_map<addr_t, std::size_t> idx;
        for (std::size_t i = 0; i < total; ++i) idx[fns_vec[i]] = i;
        for (auto& [addr, tf] : parsed) {
            auto it = idx.find(addr);
            if (it != idx.end()) fps[it->second] = std::move(tf);
        }
    }
    std::unordered_map<u64, std::size_t> query_popularity;
    std::unordered_map<u64, std::size_t> query_popularity_l4;
    for (const auto& tf : fps) {
        if (tf.whole.exact_hash != 0) ++query_popularity[tf.whole.exact_hash];
        if (tf.behav.exact_hash != 0) ++query_popularity_l4[tf.behav.exact_hash];
    }
    constexpr std::size_t kQueryPopularityCap   = 8;
    // L4 cap mirrors the L2 one. Trivial-behaviour fns (return-zero,
    // return-arg-byte, simple float predicates like __isinfl) hash to
    // the same L4 multiset across thousands of unrelated stubs in
    // obfuscator-heavy targets. Without this guard a single corpus
    // entry like __isinfl pulls 20+ false-positive behav-exact hits
    // because the target's stubs all share its trivial behaviour.
    constexpr std::size_t kQueryPopularityCapL4 = 8;

    // Detect the query binary's runtime once. The recognizer uses it
    // to skip cross-language matches (e.g. Rust binary against
    // libstdc++ template instantiations).
    const std::string_view query_runtime = detect_query_runtime(b);
    if (!query_runtime.empty()) {
        std::println(stderr, "ember: recognize: query runtime detected as '{}'", query_runtime);
    }

    std::atomic<std::size_t> next{0};
    std::atomic<std::size_t> hit_count{0};
    std::atomic<std::size_t> done_count{0};
    const float threshold = args.recognize_threshold;
    const bool show = progress_enabled();
    if (show) {
        std::println(stderr,
            "ember: recognize {} functions across {} threads (corpus has {} fns)...",
            total, threads, corpus.function_count());
        std::fflush(stderr);
    }
    // Stream output as each fn finishes — gives the user visible progress
    // on big-corpus runs that previously sat silent for minutes. Order is
    // completion-order (workers race), not address-sorted; pipe through
    // `sort -n` if you need sorted output. The mutex bounds the number of
    // print calls to one in flight; the actual `recognize()` work runs
    // unlocked.
    std::mutex out_mu;
    const auto t_scan_start = std::chrono::steady_clock::now();
    std::atomic<bool> scan_phase_done{false};
    // Same time-driven progress ticker as the fingerprint phase.
    // Refresh independent of work cadence so a single slow recognize
    // call doesn't leave the user staring at a stale line.
    std::thread scan_ticker;
    if (show) {
        scan_ticker = std::thread([&] {
            while (!scan_phase_done.load(std::memory_order_relaxed)) {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                const std::size_t d = done_count.load(std::memory_order_relaxed);
                if (d == 0 || d == total) continue;
                const auto now = std::chrono::steady_clock::now();
                const double elapsed = std::chrono::duration<double>(
                    now - t_scan_start).count();
                const double rate = elapsed > 0
                    ? static_cast<double>(d) / elapsed : 0.0;
                const double eta = rate > 0
                    ? static_cast<double>(total - d) / rate : 0.0;
                std::lock_guard<std::mutex> lock(out_mu);
                std::fprintf(stderr,
                    "\r  recognize [%zu/%zu] %.0f fn/s · elapsed %.1fs · eta %.1fs   ",
                    d, total, rate, elapsed, eta);
                std::fflush(stderr);
            }
        });
    }
    auto worker = [&] {
        while (true) {
            const std::size_t i = next.fetch_add(1, std::memory_order_relaxed);
            if (i >= total) break;
            const addr_t a = fns_vec[i];
            const auto& tf = fps[i];
            done_count.fetch_add(1, std::memory_order_relaxed);
            if (tf.whole.exact_hash == 0) continue;
            // Skip query functions whose whole-fn TEEF appears too
            // many times in this binary — they're trivial-shape stubs
            // (xgetbv, return-zero) that would ALL collapse onto a
            // single arbitrary corpus name without this gate.
            if (query_popularity[tf.whole.exact_hash] > kQueryPopularityCap) continue;
            // L4-side trivial-behaviour guard. See kQueryPopularityCapL4
            // comment above.
            if (tf.behav.exact_hash != 0 &&
                query_popularity_l4[tf.behav.exact_hash] > kQueryPopularityCapL4) continue;
            auto matches = corpus.recognize(tf, /*top_k=*/3, query_runtime);
            if (matches.empty()) continue;
            if (matches[0].confidence < threshold) continue;
            ++hit_count;
            std::string current;
            if (auto it = name_by_addr.find(a); it != name_by_addr.end()) {
                current = it->second;
            } else {
                current = std::format("sub_{:x}", a);
            }
            std::string row = std::format("{:x}\t{}\t{}\t{:.3f}\t{}",
                                          a, current,
                                          matches[0].name,
                                          matches[0].confidence,
                                          matches[0].via);
            // Append top-2/top-3 alternates if present, for transparency.
            for (std::size_t k = 1; k < matches.size(); ++k) {
                row += std::format("\t{}={:.3f}", matches[k].name, matches[k].confidence);
            }
            row += '\n';
            {
                std::lock_guard<std::mutex> lock(out_mu);
                std::fputs(row.c_str(), stdout);
                std::fflush(stdout);
            }
        }
    };
    std::vector<std::thread> pool;
    pool.reserve(threads);
    for (unsigned k = 0; k < threads; ++k) pool.emplace_back(worker);
    for (auto& t : pool) t.join();
    scan_phase_done.store(true, std::memory_order_relaxed);
    if (scan_ticker.joinable()) scan_ticker.join();

    const auto t_scan_end = std::chrono::steady_clock::now();
    const double scan_s = std::chrono::duration<double>(
        t_scan_end - t_scan_start).count();
    if (show) {
        const double rate = scan_s > 0
            ? static_cast<double>(total) / scan_s : 0.0;
        std::fprintf(stderr,
            "\r  recognize [%zu/%zu] %.0f fn/s · elapsed %.1fs · done           \n",
            total, total, rate, scan_s);
        std::fflush(stderr);
    }
    const double per_fn_us = total > 0
        ? (scan_s * 1e6) / static_cast<double>(total) : 0.0;
    std::println(stderr,
        "ember: recognize: {} suggestions at threshold {:.2f} "
        "(scan {:.2f}s, {:.0f} µs/fn)",
        hit_count.load(), threshold, scan_s, per_fn_us);
    return EXIT_SUCCESS;
}


int run_teef(const Args& args, const Binary& b) {
    return run_cached(args, std::format("teef-{}", kTeefSchema),
                      [&] { return build_teef_tsv(b, {}, /*corpus_mode=*/true,
                                                  args.min_fn_bytes,
                                                  args.max_fn_bytes); });
}

// --orbit-dump: diagnostic that emits a TSV row per fn with all three
// per-fn signatures (L2 cleanup-canonical, L3 orbit-class, L4
// behavioural) side-by-side. Used by the cross-compile recall script;
// not part of the corpus surface. Schema:
//
//   addr name
//     L2_exact L2_mh*8
//     L3_exact L3_mh*16 L3_nodes L3_iters L3_budget
//     L4_exact L4_mh*8  L4_traces_done L4_traces_aborted
//
// Names default to `sub_<addr>` for CFG-discovered fns. Module scope
// (--module NAME) is honoured. Bypasses the disk cache so the dump
// always reflects live computation.
int run_orbit_dump(const Args& args, const Binary& b) {
    const ModuleScope scope = resolve_module_scope(b, args.module_filter);

    std::unordered_map<addr_t, std::string> name_by_addr;
    for (const auto& s : b.symbols()) {
        if (s.is_import) continue;
        if (s.kind != SymbolKind::Function) continue;
        if (s.addr == 0 || s.name.empty()) continue;
        if (!scope.contains(s.addr)) continue;
        name_by_addr.try_emplace(s.addr, s.name);
    }

    std::set<addr_t> uniq;
    for (const auto& [a, _] : name_by_addr) uniq.insert(a);
    for (const auto& d : enumerate_functions(b, EnumerateMode::Auto, scope.lo, scope.hi)) {
        if (!b.import_at_plt(d.addr)) uniq.insert(d.addr);
    }
    std::vector<addr_t> fns(uniq.begin(), uniq.end());

    std::string out;
    out.reserve(fns.size() * 384);
    out += "# orbit-dump  cols: addr name L2_exact L2_mh*8 "
           "L3_exact L3_mh*16 L3_nodes L3_iters L3_budget "
           "L4_exact L4_mh*8 L4_done L4_aborted\n";
    for (addr_t a : fns) {
        const auto tf = compute_teef_with_chunks(b, a);
        const auto os = compute_orbit_sig(b, a);
        const auto bs = compute_behav_sig(b, a);

        std::string name;
        if (auto it = name_by_addr.find(a); it != name_by_addr.end()) {
            name = it->second;
        } else {
            name = std::format("sub_{:x}", a);
        }

        out += std::format("0x{:x}\t{}\t{:016x}", a, name, tf.whole.exact_hash);
        for (u64 m : tf.whole.minhash) out += std::format("\t{:016x}", m);
        out += std::format("\t{:016x}", os.exact_hash);
        for (u64 m : os.minhash)       out += std::format("\t{:016x}", m);
        out += std::format("\t{}\t{}\t{}",
                            os.egraph_nodes,
                            static_cast<u32>(os.total_iters),
                            os.budget_hit ? 1 : 0);
        out += std::format("\t{:016x}", bs.exact_hash);
        for (u64 m : bs.minhash)       out += std::format("\t{:016x}", m);
        out += std::format("\t{}\t{}",
                            static_cast<u32>(bs.traces_done),
                            static_cast<u32>(bs.traces_aborted));
        out += '\n';
    }
    std::cout << out;
    std::cout.flush();
    return EXIT_SUCCESS;
}

int run_fingerprints(const Args& args, const Binary& b) {
    const int rc = run_cached(args, fingerprints_cache_tag(),
                              [&] { return build_fingerprints_output(b); });
    // Mirror the output to --fingerprint-out PATH so the fingerprints can
    // travel between machines / repo checkouts where the disk cache
    // doesn't apply.
    if (rc == EXIT_SUCCESS && !args.fp_out.empty()) {
        const auto dir = args.cache_dir.empty()
            ? cache::default_dir()
            : std::filesystem::path(args.cache_dir);
        auto k = cache::key_for(args.binary);
        if (k) {
            if (auto hit = cache::read(dir, *k, fingerprints_cache_tag()); hit) {
                std::ofstream f(args.fp_out, std::ios::binary | std::ios::trunc);
                if (f) f.write(hit->data(), static_cast<std::streamsize>(hit->size()));
            }
        }
    }
    return rc;
}

int run_objc_names(const Args& args, const Binary& b) {
    return run_cached(args, "objc-names", [&] { return build_objc_names_output(b); });
}

int run_objc_protos(const Args& args, const Binary& b) {
    return run_cached(args, "objc-protocols",
                      [&] { return build_objc_protocols_output(b); });
}

int run_rtti(const Args& args, const Binary& b) {
    return run_cached(args, "rtti", [&] { return build_rtti_output(b); });
}

int run_vm_detect(const Args& args, const Binary& b) {
    return run_cached(args, "vm-detect", [&] { return build_vm_detect_output(b); });
}

int run_arities(const Args& args, const Binary& b) {
    return run_cached(args, "arities", [&] { return build_arities_output(b); });
}

int run_functions(const Args& args, const Binary& b) {
    // Full TSV is cacheable independent of the pattern — build once,
    // filter at print time so the cache works across grep sessions.
    std::string tsv;
    const auto dir = args.cache_dir.empty()
        ? cache::default_dir()
        : std::filesystem::path(args.cache_dir);
    std::string key;
    bool cacheable = !args.no_cache;
    if (cacheable) {
        auto k = cache::key_for(args.binary);
        if (k) key = std::move(*k);
        else {
            std::println(stderr, "ember: warning: {}: {} (caching disabled)",
                         k.error().kind_name(), k.error().message);
            cacheable = false;
        }
    }
    // Different cache tag per mode: --full-analysis returns a strict
    // superset (and on packed binaries, a polluted one). Sharing one tag
    // would let a fast --functions run poison the cache for a later
    // --full-analysis user.
    const std::string_view fns_tag = args.full_analysis ? "functions_full" : "functions";
    if (cacheable) {
        if (auto hit = cache::read(dir, key, fns_tag); hit) {
            tsv.assign(hit->data(), hit->size());
        }
    }
    if (tsv.empty()) {
        tsv = build_functions_output(b, args.full_analysis);
        if (cacheable) {
            if (auto rv = cache::write(dir, key, fns_tag, tsv); !rv) {
                std::println(stderr, "ember: warning: {}: {}",
                             rv.error().kind_name(), rv.error().message);
            }
        }
    }
    // Resolve --module if set. Filtering is applied at output time so
    // the cache stays a single full-binary blob — different scope
    // requests reuse the same cached payload.
    const ModuleScope scope = resolve_module_scope(b, args.module_filter);
    if (!args.module_filter.empty() && !scope.active) return EXIT_FAILURE;

    if (args.functions_pattern.empty() && !scope.active) {
        std::fwrite(tsv.data(), 1, tsv.size(), stdout);
        return EXIT_SUCCESS;
    }
    std::string needle = args.functions_pattern;
    for (auto& c : needle) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    auto parse_addr = [](std::string_view s) -> std::optional<addr_t> {
        if (s.starts_with("0x") || s.starts_with("0X")) s.remove_prefix(2);
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
    };

    std::size_t pos = 0;
    while (pos < tsv.size()) {
        const auto nl = tsv.find('\n', pos);
        const std::size_t end = (nl == std::string::npos) ? tsv.size() : nl;
        std::string_view line(tsv.data() + pos, end - pos);
        // Columns: addr\tsize\tkind\tname.
        std::size_t tabs = 0, name_start = 0, addr_end = 0;
        for (std::size_t i = 0; i < line.size() && tabs < 3; ++i) {
            if (line[i] == '\t') {
                if (tabs == 0) addr_end = i;
                if (++tabs == 3) name_start = i + 1;
            }
        }
        if (scope.active) {
            auto a = parse_addr(line.substr(0, addr_end));
            if (!a || !scope.contains(*a)) {
                pos = (nl == std::string::npos) ? tsv.size() : nl + 1;
                continue;
            }
        }
        if (!needle.empty()) {
            std::string name_lc(line.substr(name_start));
            for (auto& c : name_lc) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            if (name_lc.find(needle) == std::string::npos) {
                pos = (nl == std::string::npos) ? tsv.size() : nl + 1;
                continue;
            }
        }
        std::fwrite(line.data(), 1, line.size(), stdout);
        std::fputc('\n', stdout);
        pos = (nl == std::string::npos) ? tsv.size() : nl + 1;
    }
    return EXIT_SUCCESS;
}

// ---------------------------------------------------------------------------
// Direct-output runners
// ---------------------------------------------------------------------------

int run_refs_to(const Args& args, const Binary& b) {
    auto va = parse_cli_addr(args.refs_to);
    if (!va) {
        std::println(stderr, "ember: --refs-to: bad address '{}'", args.refs_to);
        return EXIT_FAILURE;
    }
    std::string xrefs_tsv;
    const auto dir = args.cache_dir.empty()
        ? cache::default_dir()
        : std::filesystem::path(args.cache_dir);
    std::string key;
    if (!args.no_cache) {
        auto k = cache::key_for(args.binary);
        if (k) key = std::move(*k);
    }
    if (!key.empty()) {
        if (auto hit = cache::read(dir, key, "xrefs"); hit) {
            xrefs_tsv = std::move(*hit);
        }
    }
    if (xrefs_tsv.empty()) {
        // Populate the cache now. First run is expensive (one full
        // call-graph walk); every subsequent --refs-to hit is instant.
        std::println(stderr, "ember: --refs-to: building xrefs cache (one-time)...");
        std::fflush(stderr);
        xrefs_tsv = build_xrefs_output(b);
        if (!key.empty()) {
            (void)cache::write(dir, key, "xrefs", xrefs_tsv);
        }
    }
    const std::string needle = std::format("-> {:#x}\n", *va);
    std::size_t pos = 0;
    std::string out;
    while ((pos = xrefs_tsv.find(needle, pos)) != std::string::npos) {
        // Walk back to the start of the line to pull the caller addr.
        std::size_t ls = pos;
        while (ls > 0 && xrefs_tsv[ls - 1] != '\n') --ls;
        out.append(xrefs_tsv, ls, (pos + needle.size()) - ls);
        pos += needle.size();
    }
    std::fwrite(out.data(), 1, out.size(), stdout);
    return EXIT_SUCCESS;
}

int run_containing_fn(const Args& args, const Binary& b) {
    auto va = parse_cli_addr(args.containing_fn);
    if (!va) {
        std::println(stderr, "ember: --containing-fn: bad address '{}'", args.containing_fn);
        return EXIT_FAILURE;
    }
    auto cf = containing_function(b, *va);
    if (!cf) {
        std::println(stderr, "ember: --containing-fn: no function covers {:#x}", *va);
        return EXIT_FAILURE;
    }
    if (args.json) {
        std::println(
            "{{\"entry\":\"{:#x}\",\"size\":{},\"name\":\"{}\",\"offset\":{}}}",
            cf->entry, cf->size, cf->name, cf->offset_within);
    } else {
        std::println("{:#x}\t{:#x}\t{}\t{:#x}",
                     cf->entry, cf->size, cf->name, cf->offset_within);
    }
    return EXIT_SUCCESS;
}

int run_validate_name(const Args& args, const Binary& b) {
    // Read the cached --fingerprints TSV (or build it once if cold). On
    // a 102MB / 500K-fn binary this takes the per-call cost from ~3
    // minutes (full lift+SSA per fn) to milliseconds when the cache is
    // warm.
    const auto fp_tsv = fingerprints_tsv_for(args, b);
    const auto rows   = fingerprint_rows_from_tsv(fp_tsv);
    const auto v = validate_name(b, args.validate_name, rows);
    const std::string_view verdict = verdict_name(v.verdict);
    if (args.json) {
        std::string out = std::format(
            "{{\"name\":\"{}\",\"verdict\":\"{}\",\"bound\":[",
            json_escape(args.validate_name), verdict);
        for (std::size_t i = 0; i < v.bound.size(); ++i) {
            if (i) out += ',';
            const auto& fp = v.fps[i];
            out += std::format(
                "{{\"addr\":\"{:#x}\",\"hash\":\"{:#x}\","
                "\"blocks\":{},\"insts\":{},\"calls\":{},\"offset\":{}}}",
                v.bound[i], fp.hash, fp.blocks, fp.insts, fp.calls, v.offsets[i]);
        }
        out += "],\"near_matches\":[";
        for (std::size_t i = 0; i < v.near_matches.size(); ++i) {
            if (i) out += ',';
            const auto& nm = v.near_matches[i];
            out += std::format(
                "{{\"addr\":\"{:#x}\",\"hash\":\"{:#x}\","
                "\"blocks\":{},\"insts\":{},\"calls\":{},\"name\":\"{}\"}}",
                nm.addr, nm.fp.hash, nm.fp.blocks, nm.fp.insts, nm.fp.calls,
                json_escape(nm.name));
        }
        out += "]}\n";
        std::fwrite(out.data(), 1, out.size(), stdout);
    } else {
        std::string out = std::format("verdict\t{}\n", verdict);
        for (std::size_t i = 0; i < v.bound.size(); ++i) {
            const auto& fp = v.fps[i];
            out += std::format(
                "bound\t{:#x}\thash={:#x}\tblocks={}\tinsts={}\tcalls={}"
                "\tname={}\toffset_in_fn={:#x}\n",
                v.bound[i], fp.hash, fp.blocks, fp.insts, fp.calls,
                args.validate_name, v.offsets[i]);
        }
        // Cap near-match output at 8 lines: a name with hundreds of shape
        // twins is uninformative, and the verdict label is what the
        // caller actually checks.
        constexpr std::size_t kNearCap = 8;
        const std::size_t shown = std::min(v.near_matches.size(), kNearCap);
        for (std::size_t i = 0; i < shown; ++i) {
            const auto& nm = v.near_matches[i];
            out += std::format(
                "near\t{:#x}\thash={:#x}\tblocks={}\tinsts={}\tcalls={}"
                "\tname={}\n",
                nm.addr, nm.fp.hash, nm.fp.blocks, nm.fp.insts, nm.fp.calls,
                nm.name);
        }
        if (v.near_matches.size() > shown) {
            out += std::format("near_truncated\t{}\n", v.near_matches.size() - shown);
        }
        std::fwrite(out.data(), 1, out.size(), stdout);
    }
    // Exit code conveys verdict to shell pipelines: 0 STRONG, 1 anything
    // ambiguous/weak/unknown — matches the grep-style "did you find what
    // you wanted" contract callers already use for --refs-to et al.
    return v.verdict == NameValidation::Verdict::Strong ? EXIT_SUCCESS : EXIT_FAILURE;
}

int run_collisions(const Args& args, const Binary& b) {
    const auto fp_tsv = fingerprints_tsv_for(args, b);
    const auto rows   = fingerprint_rows_from_tsv(fp_tsv);
    const auto c = collect_collisions(b, rows);
    if (args.json) {
        std::string out = "{\"by_name\":[";
        for (std::size_t i = 0; i < c.by_name.size(); ++i) {
            if (i) out += ',';
            const auto& g = c.by_name[i];
            out += std::format("{{\"name\":\"{}\",\"addrs\":[", json_escape(g.name));
            for (std::size_t j = 0; j < g.addrs.size(); ++j) {
                if (j) out += ',';
                out += std::format("\"{:#x}\"", g.addrs[j]);
            }
            out += "]}";
        }
        out += "],\"by_fingerprint\":[";
        for (std::size_t i = 0; i < c.by_fingerprint.size(); ++i) {
            if (i) out += ',';
            const auto& g = c.by_fingerprint[i];
            out += std::format("{{\"hash\":\"{:#x}\",\"addrs\":[", g.hash);
            for (std::size_t j = 0; j < g.addrs.size(); ++j) {
                if (j) out += ',';
                out += std::format("\"{:#x}\"", g.addrs[j]);
            }
            out += "]}";
        }
        out += "]}\n";
        std::fwrite(out.data(), 1, out.size(), stdout);
    } else {
        std::string out;
        for (const auto& g : c.by_name) {
            out += std::format("name\t{}\t", g.name);
            for (std::size_t j = 0; j < g.addrs.size(); ++j) {
                if (j) out += ',';
                out += std::format("{:#x}", g.addrs[j]);
            }
            out += std::format("\t{}\n", g.addrs.size());
        }
        for (const auto& g : c.by_fingerprint) {
            out += std::format("fingerprint\t{:#x}\t", g.hash);
            for (std::size_t j = 0; j < g.addrs.size(); ++j) {
                if (j) out += ',';
                out += std::format("{:#x}", g.addrs[j]);
            }
            out += std::format("\t{}\n", g.addrs.size());
        }
        std::fwrite(out.data(), 1, out.size(), stdout);
    }
    return EXIT_SUCCESS;
}

int run_callees(const Args& args, const Binary& b) {
    auto win = resolve_function(b, args.callees);
    if (!win) {
        std::println(stderr, "ember: --callees: could not resolve '{}'", args.callees);
        return EXIT_FAILURE;
    }
    const auto va = win->start;
    const auto cs = compute_classified_callees(b, va);
    if (args.json) {
        std::string out = std::format("{{\"va\":\"{:#x}\",\"callees\":[", va);
        for (std::size_t i = 0; i < cs.size(); ++i) {
            if (i) out += ',';
            out += std::format("{{\"va\":\"{:#x}\",\"kind\":\"{}\"}}",
                               cs[i].target, callee_kind_name(cs[i].kind));
        }
        out += "]}\n";
        std::fwrite(out.data(), 1, out.size(), stdout);
    } else {
        std::string out;
        for (const auto& c : cs) {
            out += std::format("{:#x}\n", c.target);
        }
        std::fwrite(out.data(), 1, out.size(), stdout);
    }
    return EXIT_SUCCESS;
}

int run_callees_class(const Args& args, const Binary& b) {
    const auto classes = parse_itanium_rtti(b);
    const RttiClass* match = nullptr;
    for (const auto& c : classes) {
        if (c.mangled_name == args.callees_class ||
            c.demangled_name == args.callees_class) {
            match = &c;
            break;
        }
    }
    if (!match) {
        std::println(stderr,
                     "ember: --callees-class: no RTTI class matching '{}'",
                     args.callees_class);
        return EXIT_FAILURE;
    }
    std::string out = std::format(
        "{{\"class\":\"{}\",\"mangled\":\"{}\",\"vtable\":\"{:#x}\",\"slots\":{{",
        json_escape(match->demangled_name),
        json_escape(match->mangled_name),
        match->vtable);
    for (std::size_t i = 0; i < match->methods.size(); ++i) {
        if (i) out += ',';
        out += std::format("\"{}\":{{\"va\":", i);
        const auto imp = match->methods[i];
        if (imp == 0) {
            out += "null,\"callees\":[]}";
            continue;
        }
        out += std::format("\"{:#x}\",\"callees\":[", imp);
        const auto cs = compute_classified_callees(b, imp);
        for (std::size_t j = 0; j < cs.size(); ++j) {
            if (j) out += ',';
            out += std::format("{{\"va\":\"{:#x}\",\"kind\":\"{}\"}}",
                               cs[j].target, callee_kind_name(cs[j].kind));
        }
        out += "]}";
    }
    out += "}}\n";
    std::fwrite(out.data(), 1, out.size(), stdout);
    return EXIT_SUCCESS;
}

int run_disasm_at(const Args& args, const Binary& b) {
    auto va = parse_cli_addr(args.disasm_at);
    if (!va) {
        std::println(stderr, "ember: --disasm-at: bad address '{}'", args.disasm_at);
        return EXIT_FAILURE;
    }
    std::size_t count = 32;
    if (!args.disasm_count.empty()) {
        u64 n = 0;
        auto r = std::from_chars(args.disasm_count.data(),
                                 args.disasm_count.data() + args.disasm_count.size(),
                                 n, 10);
        if (r.ec == std::errc{}) count = static_cast<std::size_t>(n);
    }
    // 8 bytes/insn is the typical x86-64 average; ~15 bytes is the max.
    const addr_t end = static_cast<addr_t>(*va) +
                       static_cast<addr_t>(count * 15);
    auto rv = format_disasm_range(b, static_cast<addr_t>(*va), end);
    if (!rv) return report(rv.error());
    // Trim to N lines of disassembly (skip the header/comments).
    std::size_t emitted = 0;
    std::string out;
    std::size_t line_start = 0;
    for (std::size_t i = 0; i <= rv->size(); ++i) {
        if (i == rv->size() || (*rv)[i] == '\n') {
            const std::string_view line(rv->data() + line_start, i - line_start);
            out.append(line);
            out += '\n';
            // Count only disasm lines (start with address or whitespace
            // on continuation). Comments start with ';'.
            if (!line.empty() && line.front() != ';') ++emitted;
            if (emitted >= count) break;
            line_start = i + 1;
        }
    }
    std::print("{}", out);
    return EXIT_SUCCESS;
}

int run_list_syscalls(const Args& args, const Binary& b) {
    // Resolve target — accept symbol-by-name (`-s NAME`-style strings),
    // hex VA, or `sub_<hex>`. The address is the function entry the
    // syscall walker starts decoding from; mid-function VAs get
    // rebound to the containing function's start, same as `-p`.
    auto win = resolve_function(b, args.list_syscalls);
    if (!win) return EXIT_FAILURE;  // resolve_function already printed

    auto sites = analyze_syscalls(b, win->start);
    // Format: TSV `<file_offset>\t<va>\t<nr>\t<name>` per site, with
    // `?` for unresolved nr / name. file_offset is what you `dd
    // skip=…` to the binary to land on the syscall byte; va is the
    // runtime address; nr is the resolved syscall number; name is
    // the Linux x86-64 syscall name when nr matched the table.
    for (const auto& s : sites) {
        std::print("{:#x}\t{:#x}\t",
                   static_cast<unsigned long long>(s.file_offset),
                   static_cast<unsigned long long>(s.va));
        if (s.syscall_nr) {
            std::print("{}\t", *s.syscall_nr);
        } else {
            std::print("?\t");
        }
        std::print("{}\n", s.name.empty() ? std::string{"?"} : s.name);
    }
    return EXIT_SUCCESS;
}

// ---------------------------------------------------------------------------
// Per-view runners (asm / cfg / ir / pseudo / struct / cfg-pseudo)
// ---------------------------------------------------------------------------

int run_disasm(const Binary& b, std::string_view symbol) {
    auto win = resolve_function(b, symbol);
    if (!win) return EXIT_FAILURE;  // resolve_function already printed
    auto out = format_disasm(b, *win);
    if (!out) return report(out.error());
    std::print("{}", *out);
    return EXIT_SUCCESS;
}

int run_cfg(const Binary& b, std::string_view symbol) {
    auto win = resolve_function(b, symbol);
    if (!win) return EXIT_FAILURE;
    auto out = format_cfg(b, *win);
    if (!out) return report(out.error());
    std::print("{}", *out);
    return EXIT_SUCCESS;
}

int run_cfg_pseudo(const Binary& b, std::string_view symbol,
                   const Annotations* ann, EmitOptions opts) {
    auto win = resolve_function(b, symbol);
    if (!win) return EXIT_FAILURE;
    auto out = format_cfg_pseudo(b, *win, ann, opts);
    if (!out) return report(out.error());
    std::print("{}", *out);
    return EXIT_SUCCESS;
}

int run_ir(const Binary& b, std::string_view symbol,
           bool run_ssa, bool run_opt) {
    auto win = resolve_function(b, symbol);
    if (!win) return EXIT_FAILURE;

    auto dec_r = make_decoder(b);
    if (!dec_r) return report(dec_r.error());
    const CfgBuilder builder(b, **dec_r);
    auto fn_r = builder.build(win->start, win->label);
    if (!fn_r) return report(fn_r.error());

    auto lifter_r = make_lifter(b);
    if (!lifter_r) return report(lifter_r.error());
    auto ir_r = (*lifter_r)->lift(*fn_r);
    if (!ir_r) return report(ir_r.error());

    if (run_ssa) {
        const SsaBuilder ssa;
        if (auto rv = ssa.convert(*ir_r); !rv) return report(rv.error());
    }

    if (run_opt) {
        auto stats = run_cleanup(*ir_r);
        if (!stats) return report(stats.error());
        std::println("; cleanup: {} iter, removed {} insts / {} phis, folded {}, propagated {}",
                     stats->iterations, stats->insts_removed, stats->phis_removed,
                     stats->constants_folded, stats->copies_propagated);
        std::println("");
    }

    std::print("{}", format_ir_function(*ir_r));
    return EXIT_SUCCESS;
}

int run_struct(const Binary& b, std::string_view symbol, bool pseudo,
               const Annotations* annotations, EmitOptions opts) {
    auto win = resolve_function(b, symbol);
    if (!win) return EXIT_FAILURE;
    // Vtable back-trace: resolve indirect call sites in this function
    // once, up-front. Per-function so we only pay the RTTI parse + CFG
    // build for the one function the user is viewing.
    std::map<addr_t, addr_t> call_res;
    if (pseudo && !opts.call_resolutions) {
        call_res = compute_call_resolutions(b, win->start);
        if (!call_res.empty()) opts.call_resolutions = &call_res;
    }
    auto out = format_struct(b, *win, pseudo, annotations, opts);
    if (!out) return report(out.error());
    std::print("{}", *out);
    return EXIT_SUCCESS;
}

// ---------------------------------------------------------------------------
// Combined emit pipeline (default action)
// ---------------------------------------------------------------------------

namespace {

// Resolve + load the annotation source. Sets `loaded` true when a file
// was successfully read; returns the populated Annotations either way.
[[nodiscard]] Annotations load_annotations_for(const Args& args, bool& loaded) {
    const std::filesystem::path cache_dir =
        !args.cache_dir.empty() ? std::filesystem::path{args.cache_dir}
                                : cache::default_dir();
    auto loc = resolve_annotation_location(args.binary, args.annotations_path, cache_dir);
    // --no-cache bypasses the annotation *cache* path but still honors
    // sidecar / explicit --annotations.
    if (args.no_cache && loc.source == AnnotationSource::Cache) loc = {};

    Annotations annotations;
    loaded = false;
    if (loc.source == AnnotationSource::None) return annotations;
    std::error_code ec;
    if (!std::filesystem::exists(loc.path, ec) || ec) return annotations;
    auto rv = Annotations::load(loc.path);
    if (!rv) {
        std::println(stderr,
            "ember: warning: {}: {}; continuing without user annotations",
            rv.error().kind_name(), rv.error().message);
        return annotations;
    }
    annotations = std::move(*rv);
    loaded = true;
    if (!args.quiet) {
        const std::size_t n = annotations.renames.size()
                            + annotations.signatures.size()
                            + annotations.notes.size()
                            + annotations.named_constants.size();
        std::println(stderr, "ember: annotations: {} ({}, {} entries)",
                     loc.path.string(), annotation_source_name(loc.source), n);
    }
    return annotations;
}

// PDB-derived signature injection. PE binaries get a per-VA
// FunctionSig map populated by attach_pdb_from_path() — pull those
// records into the user-facing Annotations under a "user explicit
// wins" precedence so PDB types feed the emitter (and the UI's
// signature renderer) without ever overwriting hand-edits.
[[nodiscard]] std::size_t merge_pdb_signatures(const Binary& b,
                                                Annotations& annotations) {
    const auto* pe = dynamic_cast<const PeBinary*>(&b);
    if (pe == nullptr) return 0;
    const auto& sigs = pe->pdb_signatures();
    if (sigs.empty()) return 0;
    std::size_t added = 0;
    for (const auto& [va, sig] : sigs) {
        // try_emplace returns (it, true) only on insertion — perfect
        // semantics here: user explicit signature already there ⇒ skip.
        if (annotations.signatures.try_emplace(va, sig).second) ++added;
    }
    return added;
}

// FLIRT-style sig matching. Loads each --pat file, runs apply_signatures
// against the candidate function set, and merges resolved names into the
// annotations map. User renames win on conflict — sig matches never
// override operator intent.
[[nodiscard]] int apply_pat_files(const Args& args, const Binary& b,
                                  Annotations& annotations, bool& ann_loaded) {
    std::vector<std::filesystem::path> paths;
    paths.reserve(args.pat_paths.size());
    for (const auto& p : args.pat_paths) paths.emplace_back(p);
    auto db = sigs::load_pats(paths);
    if (!db) {
        std::println(stderr, "ember: --pat: {}: {}",
                     db.error().kind_name(), db.error().message);
        return EXIT_FAILURE;
    }
    const auto fns = enumerate_functions(b);
    std::vector<addr_t> existing;
    existing.reserve(annotations.renames.size());
    for (const auto& [a, _] : annotations.renames) existing.push_back(a);
    const auto matches = sigs::apply_signatures(b, *db, fns, existing);
    for (const auto& m : matches) {
        annotations.renames.try_emplace(m.addr, m.name);
    }
    if (matches.empty()) ann_loaded |= !annotations.renames.empty();
    else                 ann_loaded = true;
    if (!args.quiet) {
        std::println(stderr,
            "ember: sigs: loaded {} sig(s) from {} file(s), {} match(es)",
            db->size(), args.pat_paths.size(), matches.size());
    }
    return EXIT_SUCCESS;
}

}  // namespace

int run_emit(const Args& args, const Binary& b) {
    bool ann_loaded = false;
    Annotations annotations = load_annotations_for(args, ann_loaded);

    if (!args.pat_paths.empty()) {
        if (int rc = apply_pat_files(args, b, annotations, ann_loaded);
            rc != EXIT_SUCCESS) {
            return rc;
        }
    }

    // Merge PDB-derived signatures (only on PE binaries that had one
    // attached at load time). User-explicit sigs in the loaded
    // annotations win on collision.
    if (const std::size_t pdb_added = merge_pdb_signatures(b, annotations);
        pdb_added > 0) {
        ann_loaded = true;
        if (!args.quiet) {
            std::println(stderr,
                "ember: pdb: {} function signature{} from TPI",
                pdb_added, pdb_added == 1 ? "" : "s");
        }
    }

    const Annotations* ann_ptr = ann_loaded ? &annotations : nullptr;

    EmitOptions emit_opts;
    emit_opts.show_bb_labels = args.labels;

    // IPA: one-shot fixed-point over the call graph before emission so
    // char*-arg propagation can cross function boundaries. Expensive on
    // large binaries — opt-in via --ipa.
    // One IrCache shared across IPA + the indirect-call resolver. Each
    // function pays its lift+SSA+cleanup cost once — the resolver, which
    // walks roughly the same set of functions IPA does, becomes nearly
    // free on top of the IPA pass.
    IrCache shared_ir_cache;
    InferenceResult ipa;
    if (args.ipa && (args.pseudo || args.strct)) {
        std::println(stderr, "ember: running IPA (this pass lifts every function once)...");
        std::fflush(stderr);
        ipa = infer_signatures(b, &shared_ir_cache);
        std::println(stderr, "ember: IPA done: {} functions analyzed", ipa.sigs.size());
        emit_opts.signatures = &ipa.sigs;
        emit_opts.type_arena = &ipa.arena;
    }
    std::map<addr_t, addr_t> resolutions;
    if (args.resolve_calls && (args.pseudo || args.strct)) {
        std::println(stderr, "ember: resolving indirect calls (vtable + import back-trace)...");
        std::fflush(stderr);
        resolutions = resolve_indirect_calls(b, &shared_ir_cache);
        std::println(stderr, "ember: indirect-call resolver: {} sites resolved",
                     resolutions.size());
        emit_opts.call_resolutions = &resolutions;
    }
    LpMap lp_map;
    if (args.eh && (args.pseudo || args.strct)) {
        lp_map = parse_landing_pads(b);
        std::println(stderr, "ember: EH data: {} landing-pad ranges parsed",
                     lp_map.size());
        emit_opts.landing_pads = &lp_map;
    }
    // PE x64 prologue/epilogue suppression: parse UNWIND_INFO
    // unconditionally and feed the byte ranges to the emitter. Win64
    // frames are unreadable without this — every function leads with
    // `push rbx; sub rsp, K; mov [rsp+K], xmm6; ...` cruft that the
    // unwinder already describes.
    std::map<addr_t, addr_t> prologue_ranges;
    if ((args.pseudo || args.strct) && b.format() == Format::Pe) {
        prologue_ranges = build_prologue_ranges(b);
        if (!prologue_ranges.empty()) emit_opts.prologue_ranges = &prologue_ranges;
    }
    // __objc_selrefs is cheap to walk — do it unconditionally on Mach-O
    // so `objc_msgSend(*(u64*)(0x10...))` renders as `@selector(foo:)`
    // without requiring a separate flag.
    std::map<addr_t, std::string> selrefs;
    if ((args.pseudo || args.strct) && b.format() == Format::MachO) {
        selrefs = parse_objc_selrefs(b);
        if (!selrefs.empty()) emit_opts.objc_selrefs = &selrefs;
    }
    if (args.pseudo) {
        return run_struct(b, args.symbol, /*pseudo=*/true, ann_ptr, emit_opts);
    }
    if (args.strct) {
        return run_struct(b, args.symbol, /*pseudo=*/false, ann_ptr, emit_opts);
    }
    if (args.ir) {
        return run_ir(b, args.symbol, args.ssa, args.opt);
    }
    if (args.cfg_pseudo) {
        return run_cfg_pseudo(b, args.symbol, ann_ptr, emit_opts);
    }
    if (args.cfg) {
        return run_cfg(b, args.symbol);
    }
    if (args.disasm) {
        return run_disasm(b, args.symbol);
    }
    print_info(b, args.binary);
    return EXIT_SUCCESS;
}

// ---------------------------------------------------------------- serve

namespace {

// Capture stdout produced by `fn()` and return it as a string. Uses
// dup2(tmpfile()) so any printf/println/std::cout/fwrite path is
// caught — the existing subcommands write to the C stdout FILE*
// directly. tmpfile() handles overflow past pipe-buffer size; the
// fn is allowed to emit megabytes (whole-binary --functions runs do).
[[nodiscard]] std::string capture_stdout(auto&& fn) {
    std::fflush(stdout);
    int saved = ::dup(::fileno(stdout));
    std::FILE* tmp = std::tmpfile();
    if (!tmp || saved < 0) {
        // Fallback: just run fn without capture. Worst case the
        // request "succeeds" but the body lands on the parent's stdout
        // — agent client treats that as a malformed frame.
        fn();
        return {};
    }
    ::dup2(::fileno(tmp), ::fileno(stdout));
    fn();
    std::fflush(stdout);
    ::dup2(saved, ::fileno(stdout));
    ::close(saved);
    std::rewind(tmp);
    std::string out;
    char buf[8192];
    std::size_t n;
    while ((n = std::fread(buf, 1, sizeof buf, tmp)) > 0) {
        out.append(buf, n);
    }
    std::fclose(tmp);
    return out;
}

// Parse one request line of the form
//   <method>\t<key>=<val>\t<key>=<val>...
// into method + a small kv map.
struct Request {
    std::string method;
    std::unordered_map<std::string, std::string> params;
};

[[nodiscard]] std::optional<Request> parse_request(std::string_view line) {
    Request r;
    std::size_t i = 0;
    while (i < line.size() && line[i] != '\t' && line[i] != '\n') ++i;
    r.method.assign(line, 0, i);
    if (r.method.empty()) return std::nullopt;
    while (i < line.size()) {
        if (line[i] == '\t') ++i;
        std::size_t s = i;
        while (i < line.size() && line[i] != '=' && line[i] != '\t' && line[i] != '\n') ++i;
        if (i >= line.size() || line[i] != '=') break;
        std::string key(line.substr(s, i - s));
        ++i;
        std::size_t v = i;
        while (i < line.size() && line[i] != '\t' && line[i] != '\n') ++i;
        std::string val(line.substr(v, i - v));
        r.params.emplace(std::move(key), std::move(val));
    }
    return r;
}

void write_ok(std::string_view body) {
    // Frame: "ok <bytes>\n<body>\n". Trailing \n is for client convenience —
    // not counted in <bytes>.
    std::printf("ok %zu\n", body.size());
    std::fwrite(body.data(), 1, body.size(), stdout);
    std::fputc('\n', stdout);
    std::fflush(stdout);
}

void write_err(std::string_view msg) {
    std::printf("err %.*s\n", static_cast<int>(msg.size()), msg.data());
    std::fflush(stdout);
}

// Build a per-request Args copy seeded from the daemon's startup args
// (preserves --corpus, --cache-dir, --annotations, etc) plus the
// requested method/params populated.
Args derive_args(const Args& base) {
    Args a;
    // Carry only the read-side flags that affect tool answers.
    a.binary           = base.binary;
    a.cache_dir        = base.cache_dir;
    a.annotations_path = base.annotations_path;
    a.corpus_paths     = base.corpus_paths;
    a.recognize_threshold = base.recognize_threshold;
    a.module_filter    = base.module_filter;
    a.no_cache  = base.no_cache;
    a.no_pdb    = base.no_pdb;
    a.full_analysis = base.full_analysis;
    a.ipa       = base.ipa;
    a.eh        = base.eh;
    a.resolve_calls = base.resolve_calls;
    a.quiet     = true;       // suppress per-request stderr noise
    return a;
}

}  // namespace

int run_serve(const Args& base, const Binary& b) {
    // Bind our lifetime to the parent. If the parent (cascade,
    // worker, etc.) dies — even SIGKILL — the kernel sends us
    // SIGTERM, we exit cleanly. Without this the daemon survives
    // as an orphan and the next cascade attempt either races for
    // the disk cache with us or — worse — finds itself sharing
    // mmap/cache state with a defunct sibling. Linux-only; the
    // BSD/Mach equivalents are kqueue-based and noisier to wire.
#if defined(__linux__)
    ::prctl(PR_SET_PDEATHSIG, SIGTERM);
    // Race: if the parent died between our fork and the prctl,
    // SIGTERM was missed. Re-check getppid; if it's already 1
    // (or the subreaper), bail.
    if (::getppid() == 1) return EXIT_SUCCESS;
#endif

    // Tell the client we're alive. Helps agents detect a stale handle
    // (a previous --serve exited and a new one was spawned).
    std::printf("ready ember-serve v1\n");
    std::fflush(stdout);

    // Per-daemon caches. The daemon's lifetime spans one worker, and
    // annotations are loaded fresh each `decompile` request from the
    // resolver chain — so caching the rendered output is only safe
    // when annotations didn't move under us. They don't (worker can't
    // promote mid-run; promote is a between-rounds orchestrator op),
    // so simple-keyed-by-symbol works.
    std::unordered_map<std::string, std::string> decompile_cache;
    decompile_cache.reserve(64);

    // Strings cache: full --strings output is built once and cached;
    // strings_in_range filters the cached body in-place per request.
    // The strings table on a 50MB binary can be ~10MB of text — building
    // it per request was hot in profiling.
    std::optional<std::string> strings_cache;

    // Call-graph cache: the compute_call_graph pass walks every fn's
    // CFG, then we group into a per-caller TSV. Once-per-daemon.
    std::optional<std::string> callees_all_cache;

    std::string line;
    while (std::getline(std::cin, line)) {
        if (line.empty()) continue;
        auto req = parse_request(line);
        if (!req) { write_err("malformed request"); continue; }

        try {
            if (req->method == "ping") {
                write_ok("pong");
                continue;
            }
            if (req->method == "decompile") {
                const std::string& sym = req->params["fn"];
                if (auto it = decompile_cache.find(sym); it != decompile_cache.end()) {
                    write_ok(it->second);
                    continue;
                }
                Args a = derive_args(base);
                a.symbol = sym;
                a.pseudo = true;
                std::string body = capture_stdout([&]{ run_emit(a, b); });
                // Soft cap to avoid runaway memory on huge cascades. 1024
                // entries × typical 2KB pseudo-C ≈ 2MB; outliers (5000-line
                // fns) push that up but the worker dies before it matters.
                if (decompile_cache.size() > 1024) decompile_cache.clear();
                decompile_cache.emplace(sym, body);
                write_ok(body);
                continue;
            }
            if (req->method == "callees") {
                Args a = derive_args(base);
                a.callees = req->params["fn"];
                std::string body = capture_stdout([&]{ run_callees(a, b); });
                write_ok(body);
                continue;
            }
            if (req->method == "refs_to") {
                Args a = derive_args(base);
                a.refs_to = req->params["addr"];
                std::string body = capture_stdout([&]{ run_refs_to(a, b); });
                write_ok(body);
                continue;
            }
            if (req->method == "containing_fn") {
                Args a = derive_args(base);
                a.containing_fn = req->params["addr"];
                std::string body = capture_stdout([&]{ run_containing_fn(a, b); });
                write_ok(body);
                continue;
            }
            if (req->method == "functions") {
                Args a = derive_args(base);
                a.functions = true;
                std::string body = capture_stdout([&]{ run_functions(a, b); });
                write_ok(body);
                continue;
            }
            if (req->method == "strings") {
                if (!strings_cache) {
                    Args a = derive_args(base);
                    a.strings = true;
                    strings_cache = capture_stdout([&]{ run_strings(a, b); });
                }
                write_ok(*strings_cache);
                continue;
            }
            if (req->method == "strings_in_range") {
                // Server-side filter for `addr|text|xrefs` rows whose
                // any-xref-site lands in [start, end). Saves the agent
                // shipping the full strings table over the pipe each
                // call. Cached once like `strings`.
                if (!strings_cache) {
                    Args a = derive_args(base);
                    a.strings = true;
                    strings_cache = capture_stdout([&]{ run_strings(a, b); });
                }
                auto parse_hex = [](std::string_view s) -> std::optional<addr_t> {
                    if (s.starts_with("0x") || s.starts_with("0X")) s.remove_prefix(2);
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
                };
                auto sopt = parse_hex(req->params["start"]);
                auto eopt = parse_hex(req->params["end"]);
                if (!sopt || !eopt) { write_err("strings_in_range: bad start/end"); continue; }
                const addr_t lo = *sopt, hi = *eopt;
                std::string out;
                out.reserve(strings_cache->size() / 16);
                std::size_t pos = 0;
                while (pos < strings_cache->size()) {
                    std::size_t nl = strings_cache->find('\n', pos);
                    if (nl == std::string::npos) nl = strings_cache->size();
                    std::string_view ln(strings_cache->data() + pos, nl - pos);
                    pos = nl + 1;
                    // Format: <addr>|<text>|<xref1>,<xref2>,...
                    auto bar1 = ln.find('|');
                    if (bar1 == std::string_view::npos) continue;
                    auto bar2 = ln.find('|', bar1 + 1);
                    if (bar2 == std::string_view::npos) continue;
                    std::string_view xrefs = ln.substr(bar2 + 1);
                    bool match = false;
                    std::size_t xp = 0;
                    while (xp < xrefs.size()) {
                        std::size_t comma = xrefs.find(',', xp);
                        std::string_view tok = xrefs.substr(xp, (comma == std::string_view::npos ? xrefs.size() : comma) - xp);
                        if (auto va = parse_hex(tok); va && *va >= lo && *va < hi) {
                            match = true; break;
                        }
                        if (comma == std::string_view::npos) break;
                        xp = comma + 1;
                    }
                    if (match) { out.append(ln); out.push_back('\n'); }
                }
                write_ok(out);
                continue;
            }
            if (req->method == "annotations") {
                // Emit TSV `<addr-hex>\t<name>\n` per loaded rename.
                // Cascade reads this at startup to seed namedFromAnnotations
                // — TEEF anchors and prior-promoted cascade names land in
                // the annotation file but ember --functions still reports
                // those addresses as `kind=sub`, so the eligibility pass
                // wouldn't otherwise count them as known neighbors.
                Args a = derive_args(base);
                bool ann_loaded = false;
                Annotations ann = load_annotations_for(a, ann_loaded);
                std::string out;
                out.reserve(ann.renames.size() * 32);
                for (auto& [addr, name] : ann.renames) {
                    std::format_to(std::back_inserter(out), "{:#x}\t{}\n", addr, name);
                }
                write_ok(out);
                continue;
            }
            if (req->method == "callees_all") {
                // One-shot: emit the full call graph as
                // `<caller-hex>\t<callee-hex>,<callee-hex>,...\n`.
                // Caches the grouping after the first compute_call_graph
                // walk; subsequent calls return instantly. Replaces N
                // round-trips for cascade's eligibility pass.
                if (!callees_all_cache) {
                    const ModuleScope scope = resolve_module_scope(b, base.module_filter);
                    if (!base.module_filter.empty() && !scope.active) {
                        write_err("--module not resolved");
                        continue;
                    }
                    auto edges = compute_call_graph(b);
                    std::map<addr_t, std::vector<addr_t>> by_caller;
                    for (auto& e : edges) {
                        if (!scope.contains(e.caller)) continue;
                        by_caller[e.caller].push_back(e.callee);
                    }
                    std::string out;
                    out.reserve(edges.size() * 24);
                    for (auto& [caller, callees] : by_caller) {
                        std::format_to(std::back_inserter(out), "{:#x}\t", caller);
                        bool first = true;
                        for (auto c : callees) {
                            if (!first) out.push_back(',');
                            std::format_to(std::back_inserter(out), "{:#x}", c);
                            first = false;
                        }
                        out.push_back('\n');
                    }
                    callees_all_cache = std::move(out);
                }
                write_ok(*callees_all_cache);
                continue;
            }
            if (req->method == "recognize") {
                Args a = derive_args(base);
                a.recognize = true;
                std::string body = capture_stdout([&]{ run_recognize(a, b); });
                write_ok(body);
                continue;
            }
            write_err(std::format("unknown method: {}", req->method));
        } catch (const std::exception& e) {
            write_err(std::format("exception: {}", e.what()));
        } catch (...) {
            write_err("unknown exception");
        }
    }
    return EXIT_SUCCESS;
}

}  // namespace ember::cli

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
#include <limits>
#include <optional>
#if defined(_WIN32)
#include <io.h>
#define ember_dup     _dup
#define ember_dup2    _dup2
#define ember_close   _close
#define ember_fileno  _fileno
#else
#include <unistd.h>
#define ember_dup     ::dup
#define ember_dup2    ::dup2
#define ember_close   ::close
#define ember_fileno  ::fileno
#endif

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
#include <ember/analysis/data_xrefs.hpp>
#include <ember/binary/elf.hpp>
#include <ember/common/bytes.hpp>
#include <ember/analysis/eh_frame.hpp>
#include <ember/analysis/forge_spec.hpp>
#include <ember/analysis/indirect_calls.hpp>
#include <ember/analysis/ir_cache.hpp>
#include <ember/analysis/objc.hpp>
#include <ember/analysis/pe_unwind.hpp>
#include <ember/analysis/pipeline.hpp>
#include <ember/analysis/rtti.hpp>
#include <ember/analysis/sig_inference.hpp>
#include <ember/analysis/sigs.hpp>
#include <ember/analysis/strings.hpp>
#include <ember/analysis/symtable.hpp>
#include <ember/analysis/symresolve.hpp>
#include <ember/analysis/symuses.hpp>
#include <ember/common/hash.hpp>
#include <ember/common/threads.hpp>
#include <ember/analysis/syscalls.hpp>
#include <ember/analysis/teef.hpp>
#include <ember/analysis/teef_behav.hpp>
#include <ember/analysis/teef_orbit.hpp>
#include <ember/analysis/teef_recognize.hpp>
#include <ember/analysis/identify.hpp>
#include <ember/common/progress.hpp>
#include <ember/binary/binary.hpp>
#include <ember/binary/pe.hpp>
#include <ember/common/annotations.hpp>
#include <ember/common/cache.hpp>
#include <ember/common/timing.hpp>
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
#include "progress_panel.hpp"
#include "util.hpp"

namespace ember::cli {

namespace {

constexpr std::string_view kXrefsCacheTag = "xrefs-v2";
constexpr std::string_view kAritiesCacheTag = "arities-v2";
constexpr std::string_view kFunctionsCacheTag = "functions-v4";
constexpr std::string_view kFunctionsFullCacheTag = "functions_full-v4";

// Quiet sibling of load_annotations_for(): resolves and reads the
// annotations file using the same precedence chain (explicit > sidecar
// > cache, with --no-cache suppressing the cache leg) but never prints
// the "ember: annotations: …" status line. Used by the per-command
// resolvers that just need to thread renames into resolve_function;
// the noisy variant lives further down and runs once per emit pass.
[[nodiscard]] Annotations load_annotations_quiet(const Args& args) {
    Annotations ann;
    const std::filesystem::path cache_dir =
        !args.cache_dir.empty() ? std::filesystem::path{args.cache_dir}
                                : cache::default_dir();
    auto loc = resolve_annotation_location(args.binary, args.annotations_path, cache_dir);
    if (args.no_cache && loc.source == AnnotationSource::Cache) return ann;
    if (loc.source == AnnotationSource::None || loc.path.empty()) return ann;
    std::error_code ec;
    if (!std::filesystem::exists(loc.path, ec) || ec) return ann;
    if (auto rv = Annotations::load(loc.path); rv) ann = std::move(*rv);
    return ann;
}

[[nodiscard]] bool parse_disasm_count(std::string_view raw,
                                      std::size_t& out,
                                      std::string_view command) {
    if (raw.empty()) return true;
    u64 n = 0;
    const auto* first = raw.data();
    const auto* last = raw.data() + raw.size();
    const auto r = std::from_chars(first, last, n, 10);
    constexpr u64 kMaxCount =
        static_cast<u64>(std::numeric_limits<addr_t>::max() / 15);
    if (r.ec != std::errc{} || r.ptr != last || n == 0 || n > kMaxCount) {
        std::println(stderr, "ember: {}: bad --count '{}'", command, raw);
        return false;
    }
    out = static_cast<std::size_t>(n);
    return true;
}

}  // namespace

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

    // Sniff the input format. The persisted on-disk format (what
    // `Annotations::save` writes — what the cache stores) is line-per-
    // record without section headers; the .ember declarative format is
    // section-keyed (`[rename]` etc.). Feeding the persisted form to
    // the script parser used to fail with "directive outside any
    // section". Detect it and merge via `Annotations::load` instead so
    // a cache file from one binary copies cleanly onto another.
    bool is_persisted_form = false;
    {
        std::ifstream sniff(args.apply_ember);
        std::string line;
        while (std::getline(sniff, line)) {
            std::string_view sv = line;
            while (!sv.empty() && (sv.front() == ' ' || sv.front() == '\t' ||
                                   sv.front() == '\r')) {
                sv.remove_prefix(1);
            }
            if (sv.empty() || sv.front() == '#') continue;
            if (sv.front() == '[') break;  // declarative — section header
            if (sv.starts_with("rename ") || sv.starts_with("note ") ||
                sv.starts_with("sig ")    || sv.starts_with("const ") ||
                sv.starts_with("field ")  || sv.starts_with("meta ")) {
                is_persisted_form = true;
            }
            break;
        }
    }

    script::ApplyStats import_stats;
    if (is_persisted_form) {
        auto loaded = Annotations::load(args.apply_ember);
        if (!loaded) return report(loaded.error());
        // Merge into the destination, preserving existing values on
        // conflict — same precedence the declarative apply uses.
        for (const auto& [a, name] : loaded->renames) {
            if (ann.renames.try_emplace(a, name).second) ++import_stats.renames_added;
        }
        for (const auto& [a, sig] : loaded->signatures) {
            if (ann.signatures.try_emplace(a, sig).second) ++import_stats.signatures_added;
        }
        for (const auto& [a, text] : loaded->notes) {
            if (ann.notes.try_emplace(a, text).second) ++import_stats.notes_added;
        }
        for (const auto& [k, name] : loaded->field_names) {
            if (ann.field_names.try_emplace(k, name).second) ++import_stats.fields_added;
        }
        for (const auto& [k, v] : loaded->named_constants) {
            ann.named_constants.try_emplace(k, v);
        }
        // Carry provenance for any record we just imported (try_emplace
        // semantics: source-side entry wins only when the destination
        // had no prior record, so the meta we copy here is paired
        // correctly with the value we just adopted).
        for (const auto& [a, m] : loaded->rename_meta) {
            if (ann.renames.contains(a)) ann.rename_meta.try_emplace(a, m);
        }
        for (const auto& [a, m] : loaded->note_meta) {
            if (ann.notes.contains(a)) ann.note_meta.try_emplace(a, m);
        }
        for (const auto& [a, m] : loaded->signature_meta) {
            if (ann.signatures.contains(a)) ann.signature_meta.try_emplace(a, m);
        }
    }

    auto rv = is_persisted_form
        ? Result<script::ApplyStats>{std::move(import_stats)}
        : script::apply_file(args.apply_ember, b, ann);
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
            "ember: {}: +{} renames, +{} notes, +{} sigs, +{} fields, "
            "{} pattern-matches, {} from-strings, "
            "-{} renames / -{} notes / -{} sigs / -{} fields -> {} ({})",
            tag,
            rv->renames_added, rv->notes_added, rv->signatures_added,
            rv->fields_added,
            rv->pattern_renames_applied, rv->string_renames_applied,
            rv->renames_removed, rv->notes_removed, rv->signatures_removed,
            rv->fields_removed,
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
    return run_cached(args, kXrefsCacheTag, [&] { return build_xrefs_output(b); });
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

// Compiler-partition variant detector. gcc's -fpartition-functions /
// LTO splitting / IPA passes emit suffixed clones of real functions:
//   foo.cold       — unlikely-path partition (panic/throw/error glue)
//   foo.isra.0     — interprocedural scalar-replacement-of-aggregates clone
//   foo.constprop.0 — constant-propagation clone
//   foo.part.0     — partial-inline clone
//   foo.lto_priv.0 — LTO private clone
//
// The cold halves in particular are tiny string-load + call + abort
// stubs that all share the same shape — a chunk-vote will FP-match
// them to any generic-shape libstdc++ fn (std::getline being a
// canonical victim). Drop them from both corpus emit (so they don't
// pollute the search space) and from recognize input (so we don't
// emit confident garbage labels for cold-path fragments). The base
// function — without the suffix — is fingerprinted normally and
// retains the real identity.
//
// LLVM's `.llvm.<hash>` clone marker is NOT in this list — those are
// genuine instantiation clones whose parent symbol carries the real
// identity. Treating them as fragments would lose recall on real
// matches.
[[nodiscard]] inline bool is_compiler_partition_variant(std::string_view nm) noexcept {
    if (nm.find(".cold")      != std::string_view::npos) return true;
    if (nm.find(".isra")      != std::string_view::npos) return true;
    if (nm.find(".constprop") != std::string_view::npos) return true;
    if (nm.find(".part")      != std::string_view::npos) return true;
    if (nm.find(".lto_priv")  != std::string_view::npos) return true;
    return false;
}

// Hand-rolled hex appenders. The TSV worker emits ~22 fixed-width and
// 1-2 variable-width hex tokens per F row plus 9 per chunk row; on a
// 200K-fn binary that's millions of std::format calls, each of which
// goes through the format-spec parser, allocates a temporary string,
// and concatenates. These appenders write directly into the row
// buffer with a 16-byte char[] on the stack — measured 3-5× faster
// than std::format("{:016x}", v) for the hot path on gcc 15.
inline void append_hex16(std::string& s, u64 v) noexcept {
    static constexpr char kHex[] = "0123456789abcdef";
    char buf[16];
    for (int i = 15; i >= 0; --i) {
        buf[i] = kHex[v & 0xF];
        v >>= 4;
    }
    s.append(buf, 16);
}

inline void append_hex(std::string& s, u64 v) noexcept {
    // Variable-length lowercase hex matching std::format("{:x}", v).
    static constexpr char kHex[] = "0123456789abcdef";
    if (v == 0) { s += '0'; return; }
    char buf[16];
    int i = 16;
    while (v) {
        buf[--i] = kHex[v & 0xF];
        v >>= 4;
    }
    s.append(buf + i, static_cast<std::size_t>(16 - i));
}

std::string teef_cache_tag(const Args& args) {
    std::string tag = std::format("teef-{}", kTeefSchema);
    if (args.teef_no_l4) tag += "-nol4";
    if (args.min_fn_bytes) tag += std::format("-min{}", args.min_fn_bytes);
    if (args.max_fn_bytes) tag += std::format("-max{}", args.max_fn_bytes);
    if (args.max_cfg_blocks) tag += std::format("-cb{}", args.max_cfg_blocks);
    if (args.max_cfg_edges) tag += std::format("-ce{}", args.max_cfg_edges);
    if (args.max_cfg_insts) tag += std::format("-ci{}", args.max_cfg_insts);
    if (args.max_ir_insts) tag += std::format("-ii{}", args.max_ir_insts);
    return tag;
}

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
            // 24-field rows are pre-max.4; 25-field rows carry prefix_hash
            // in the trailing column.
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
            tf.prefix_hash = (f.size() >= 25) ? parse_u64_hex_local(f[24]) : 0u;
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
               const TeefComputeOptions& compute_opts = {},
               std::ostream* stream = nullptr) {
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
        // Run enumerate_functions once and reuse for both the fn-address
        // gather AND the sized_fns table built below. The pass walks the
        // call graph and CFG-discovery sweep — on a 200K-fn binary it's
        // tens of seconds; doing it twice was outright duplicated work.
        auto disc = enumerate_functions(b, EnumerateMode::Auto,
                                        scope.lo, scope.hi);
        std::sort(disc.begin(), disc.end(),
            [](const auto& x, const auto& y) { return x.addr < y.addr; });
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
        sized_fns.reserve(disc.size());
        for (const auto& d : disc) {
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
        std::vector<std::string> rows;
        if (!stream) rows.resize(total);
        std::mutex stream_mu;
        std::atomic<std::size_t> next{0};
        std::atomic<std::size_t> done{0};
        // Counters for the post-phase summary so the user can see how
        // much --l0-prefilter is actually helping vs. how many fns
        // still go through the full pipeline.
        std::atomic<std::size_t> early_exit_topo{0};
        std::atomic<std::size_t> empty_fingerprint{0};
        std::atomic<bool> fp_phase_done{false};

        // Time-driven progress panel. Workers used to print every Nth
        // fn; on huge or VM-protected targets a single fn can take
        // hundreds of milliseconds, so the user saw no update for tens
        // of seconds at a time. The ticker runs independently, refreshes
        // every 500 ms with whatever `done` and the worker pool have
        // accomplished, and renders a 3-line ANSI panel (header / bar /
        // stats) that's atomically repainted in place — no scrollback
        // noise. Falls back to a one-shot info line when stderr isn't
        // a TTY (`progress_enabled()` returns false).
        ProgressPanel panel;
        if (show) {
            panel.start("TEEF fingerprint", total, threads);
        }
        std::thread fp_ticker;
        if (show) {
            fp_ticker = std::thread([&] {
                while (!fp_phase_done.load(std::memory_order_relaxed)) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(500));
                    const std::size_t d  = done.load(std::memory_order_relaxed);
                    const std::size_t ee = early_exit_topo.load(std::memory_order_relaxed);
                    panel.tick(d, ee);
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
                // Single name-by-addr lookup reused below for the row's
                // emitted name field. compute_opts is passed by const&
                // through compute_teef_max/with_chunks — no need to
                // copy it per fn.
                const auto name_it = name_by_addr.find(a);
                const bool is_named = (name_it != name_by_addr.end());
                // Skip gcc partition variants (.cold/.isra/.constprop/
                // .part/.lto_priv) — fragments of real fns, not
                // standalone targets. Cold halves in particular all
                // share a "load string + call printf + abort" shape
                // that chunk-vote-collides against generic libstdc++
                // fns and emits confidently-wrong labels at recognize
                // time. The base function (without the suffix) still
                // gets fingerprinted; we just don't pollute the
                // corpus with its partition fragments.
                if (is_named && is_compiler_partition_variant(name_it->second)) {
                    done.fetch_add(1, std::memory_order_relaxed);
                    continue;
                }
                const bool full_l4  = !corpus_mode || is_named;
                const auto tf = full_l4
                    ? compute_teef_max(b, a, compute_opts)
                    : compute_teef_with_chunks(b, a, compute_opts);
                const auto& bs = tf.behav;
                done.fetch_add(1, std::memory_order_relaxed);
                // Telemetry: distinguish "early-exited via topo filter"
                // from "made it through the full pipeline but came out
                // empty" (e.g., insn-cap hit). Lets the user see at a
                // glance whether --l0-prefilter is paying off.
                if (tf.whole.exact_hash == 0) {
                    if (compute_opts.l4_topo_filter && tf.topo_hash != 0 &&
                        !compute_opts.l4_topo_filter->contains(tf.topo_hash)) {
                        early_exit_topo.fetch_add(1, std::memory_order_relaxed);
                    } else {
                        empty_fingerprint.fetch_add(1, std::memory_order_relaxed);
                    }
                }
                if (tf.whole.exact_hash == 0) continue;
                std::string name;
                if (is_named) {
                    name = name_it->second;
                } else {
                    name = std::format("sub_{:x}", a);
                }
                // F row: F addr L2_exact L2_mh*8 name L4_exact L4_mh*8
                //         L4_done L4_aborted topo_hash prefix_hash
                // (25 tab-separated fields). L4 columns trail the name
                // so the structural-only fields stay at fixed positions
                // 0..11 — handy for grep/awk inspection. topo_hash is
                // the L0 CFG-shape signal, used by the recognizer as a
                // pre-filter for L2 jaccard scans. prefix_hash is the
                // L1 byte-prefix hash; non-zero only on tiny fns
                // (≤16 insns / ≤64 bytes), used as a FLIRT-style fast
                // path for stubs L2/L4 can't disambiguate.
                std::string buf;
                buf.reserve(512);
                buf += "F\t";
                append_hex(buf, a);
                buf += '\t';
                append_hex16(buf, tf.whole.exact_hash);
                for (u64 mh : tf.whole.minhash) {
                    buf += '\t';
                    append_hex16(buf, mh);
                }
                buf += '\t';
                buf += name;
                buf += '\t';
                append_hex16(buf, bs.exact_hash);
                for (u64 mh : bs.minhash) {
                    buf += '\t';
                    append_hex16(buf, mh);
                }
                buf += '\t';
                buf += std::to_string(static_cast<u32>(bs.traces_done));
                buf += '\t';
                buf += std::to_string(static_cast<u32>(bs.traces_aborted));
                buf += '\t';
                append_hex16(buf, tf.topo_hash);
                buf += '\t';
                append_hex16(buf, tf.prefix_hash);
                buf += '\n';

                // String-anchor row: S<TAB>addr<TAB>hash1,hash2,...
                // Up to 8 fnv1a64 hashes of the function's identifying
                // strings. Loader stores them on WholeEntry; recognizer
                // uses overlap as a precision filter against
                // structural false positives.
                if (auto sit = strings_by_fn.find(a); sit != strings_by_fn.end() && !sit->second.empty()) {
                    buf += "S\t";
                    append_hex(buf, a);
                    bool first = true;
                    for (const auto& str : sit->second) {
                        buf += first ? '\t' : ',';
                        first = false;
                        append_hex16(buf, fnv1a_64(str));
                    }
                    buf += '\n';
                }
                // Chunk rows: C<TAB>addr<TAB>kind<TAB>insts<TAB>exact<TAB>mh0..7<TAB>name
                for (const auto& ch : tf.chunks) {
                    if (ch.sig.exact_hash == 0) continue;
                    buf += "C\t";
                    append_hex(buf, a);
                    buf += '\t';
                    buf += std::to_string(static_cast<unsigned>(ch.kind));
                    buf += '\t';
                    buf += std::to_string(ch.inst_count);
                    buf += '\t';
                    append_hex16(buf, ch.sig.exact_hash);
                    for (u64 mh : ch.sig.minhash) {
                        buf += '\t';
                        append_hex16(buf, mh);
                    }
                    buf += '\t';
                    buf += name;
                    buf += '\n';
                }
                if (stream) {
                    std::lock_guard lock(stream_mu);
                    (*stream) << buf;
                } else {
                    rows[i] = std::move(buf);
                }
            }
        };

        std::vector<std::thread> pool;
        pool.reserve(threads);
        for (unsigned k = 0; k < threads; ++k) pool.emplace_back(worker);
        for (auto& t : pool) t.join();
        fp_phase_done.store(true, std::memory_order_relaxed);
        if (fp_ticker.joinable()) fp_ticker.join();
        if (show) {
            const std::size_t ee = early_exit_topo.load(std::memory_order_relaxed);
            const std::size_t eg = empty_fingerprint.load(std::memory_order_relaxed);
            // Pin the final frame in scrollback so the user can see
            // the completed run after the next phase prints over it.
            panel.finish(total, ee);
            const std::size_t full_pipe = (total > ee + eg) ? (total - ee - eg) : 0;
            std::println(stderr,
                "ember: TEEF: {} fns full-pipeline, {} early-exit (l0-prefilter), "
                "{} empty (insn-cap / lift bail)",
                full_pipe, ee, eg);
        }

    if (stream) {
        stream->flush();
        return {};
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
    // Anti-corpus: same TSV format but only hashes are kept. Recognize
    // short-circuits any query whose L2/L4/prefix hash matches.
    if (!args.anti_corpus_paths.empty()) {
        std::size_t anti_rows = 0;
        const auto t_anti_start = std::chrono::steady_clock::now();
        for (const auto& p : args.anti_corpus_paths) {
            anti_rows += corpus->load_anti_tsv(p);
        }
        const auto t_anti_end = std::chrono::steady_clock::now();
        const double anti_ms = std::chrono::duration<double, std::milli>(
            t_anti_end - t_anti_start).count();
        std::println(stderr,
            "ember: anti-corpus loaded: {} blocked hashes from {} rows "
            "across {} TSVs in {:.0f} ms",
            corpus->blocked_count(), anti_rows,
            args.anti_corpus_paths.size(), anti_ms);
    }
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
    static std::vector<std::string> cached_anti_paths;
    static std::unique_ptr<TeefCorpus> cached_corpus;
    if (!cached_corpus ||
        cached_paths != args.corpus_paths ||
        cached_anti_paths != args.anti_corpus_paths) {
        cached_corpus = load_corpus_from_args(args);
        cached_paths = args.corpus_paths;
        cached_anti_paths = args.anti_corpus_paths;
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
        if (auto k = cache::key_for(args.binary, cache_scope_tag(args)); k) {
            const std::string tag = teef_cache_tag(args);
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
        TeefComputeOptions target_opts;
        target_opts.min_chunk_insts = 10;
        target_opts.l4_topo_filter = args.l0_prefilter ? &corpus_topos : nullptr;
        target_opts.skip_l4 = args.teef_no_l4;
        target_opts.max_cfg_blocks = args.max_cfg_blocks;
        target_opts.max_cfg_edges = args.max_cfg_edges;
        target_opts.max_cfg_insts = args.max_cfg_insts;
        target_opts.max_ir_insts = args.max_ir_insts;

        const auto t_fp_start = std::chrono::steady_clock::now();
        target_tsv = build_teef_tsv(b, scope, /*corpus_mode=*/false,
                                    args.min_fn_bytes, args.max_fn_bytes,
                                    target_opts);
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
            if (auto k = cache::key_for(args.binary, cache_scope_tag(args)); k) {
                const std::string tag = teef_cache_tag(args);
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
            // Skip gcc partition variants in the query — they're
            // fragments of real fns whose generic shape (load string +
            // call + abort, for the .cold case) chunk-vote-matches
            // arbitrary library functions and emits garbage labels.
            // The base function (without the suffix) goes through
            // recognize normally and surfaces the real identity.
            if (auto qit = name_by_addr.find(a);
                qit != name_by_addr.end() &&
                is_compiler_partition_variant(qit->second)) continue;
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


int run_identify(const Args& args, const Binary& b) {
    auto hits = identify_functions(b, args.identify_threshold);
    const auto tsv = format_identify_tsv(hits);
    std::fwrite(tsv.data(), 1, tsv.size(), stdout);
    return EXIT_SUCCESS;
}

int run_teef(const Args& args, const Binary& b) {
    TeefComputeOptions opts;
    opts.min_chunk_insts = 10;
    opts.skip_l4 = args.teef_no_l4;
    opts.max_cfg_blocks = args.max_cfg_blocks;
    opts.max_cfg_edges = args.max_cfg_edges;
    opts.max_cfg_insts = args.max_cfg_insts;
    opts.max_ir_insts = args.max_ir_insts;

    if (args.no_cache) {
        (void)build_teef_tsv(b, {}, /*corpus_mode=*/true,
                             args.min_fn_bytes, args.max_fn_bytes,
                             opts, &std::cout);
        return EXIT_SUCCESS;
    }

    return run_cached(args, teef_cache_tag(args),
                      [&] { return build_teef_tsv(b, {}, /*corpus_mode=*/true,
                                                  args.min_fn_bytes,
                                                  args.max_fn_bytes,
                                                  opts); });
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
        auto k = cache::key_for(args.binary, cache_scope_tag(args));
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

int run_int3_resolve(const Args& args, const Binary& b) {
    return run_cached(args, "int3-resolve", [&] { return build_int3_resolve_output(b); });
}

int run_arities(const Args& args, const Binary& b) {
    return run_cached(args, kAritiesCacheTag, [&] { return build_arities_output(b); });
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
        auto k = cache::key_for(args.binary, cache_scope_tag(args));
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
    const std::string_view fns_tag = args.full_analysis
        ? kFunctionsFullCacheTag
        : kFunctionsCacheTag;
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

    // Always consult resolved annotations. Renames substitute into the
    // emitted `name` column at print time so a `--functions=cap_check`
    // pattern matches the annotated name, and JSON rows pick up
    // `confidence` / `source` / `evidence` when present. The cached
    // TSV stays unannotated so changes to the annotations file don't
    // invalidate the cache slot.
    const Annotations ann_for_print = load_annotations_quiet(args);
    auto rename_for = [&](addr_t a) -> const std::string* {
        auto it = ann_for_print.renames.find(a);
        return it == ann_for_print.renames.end() ? nullptr : &it->second;
    };
    const bool any_rename = !ann_for_print.renames.empty();

    if (!args.json && args.functions_pattern.empty() && !scope.active && !any_rename) {
        std::fwrite(tsv.data(), 1, tsv.size(), stdout);
        return EXIT_SUCCESS;
    }

    std::string needle = args.functions_pattern;
    for (auto& c : needle) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    if (args.json) std::fputs("[", stdout);
    bool first = true;

    std::size_t pos = 0;
    while (pos < tsv.size()) {
        const auto nl = tsv.find('\n', pos);
        const std::size_t end = (nl == std::string::npos) ? tsv.size() : nl;
        std::string_view line(tsv.data() + pos, end - pos);
        // Columns: addr\tsize\tkind\tname.
        std::size_t tabs = 0, name_start = 0, addr_end = 0,
                    size_end = 0, kind_end = 0;
        for (std::size_t i = 0; i < line.size() && tabs < 3; ++i) {
            if (line[i] == '\t') {
                if (tabs == 0)      addr_end = i;
                else if (tabs == 1) size_end = i;
                else if (tabs == 2) kind_end = i;
                if (++tabs == 3)    name_start = i + 1;
            }
        }
        const std::string_view addr_s = line.substr(0, addr_end);
        const auto row_addr = parse_addr(addr_s);
        if (scope.active) {
            if (!row_addr || !scope.contains(*row_addr)) {
                pos = (nl == std::string::npos) ? tsv.size() : nl + 1;
                continue;
            }
        }
        // Substitute the annotation rename (if any) into the rendered
        // name. The original discovered name is dropped from the output;
        // it's reachable via `--no-cache` against an empty annotations
        // file when needed.
        const std::string_view discovered_name = line.substr(name_start);
        const std::string* rn = row_addr ? rename_for(*row_addr) : nullptr;
        const std::string_view effective_name =
            rn ? std::string_view{*rn} : discovered_name;
        if (!needle.empty()) {
            std::string name_lc(effective_name);
            for (auto& c : name_lc) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            if (name_lc.find(needle) == std::string::npos) {
                pos = (nl == std::string::npos) ? tsv.size() : nl + 1;
                continue;
            }
        }
        if (args.json) {
            if (!first) std::fputs(",", stdout);
            first = false;
            const std::string_view size_s = line.substr(addr_end + 1, size_end - addr_end - 1);
            const std::string_view kind_s = line.substr(size_end + 1, kind_end - size_end - 1);
            std::string row = std::format(
                "{{\"addr\":\"{}\",\"size\":\"{}\",\"kind\":\"{}\",\"name\":\"{}\"",
                addr_s, size_s, kind_s, json_escape(effective_name));
            if (row_addr) {
                if (const auto* m = ann_for_print.meta_for_rename(*row_addr); m) {
                    if (m->confidence > 0.0f) {
                        row += std::format(",\"confidence\":{:.3g}", m->confidence);
                    }
                    if (!m->source.empty()) {
                        row += std::format(",\"source\":\"{}\"", json_escape(m->source));
                    }
                    if (!m->evidence.empty()) {
                        row += std::format(",\"evidence\":\"{}\"", json_escape(m->evidence));
                    }
                }
            }
            row += "}";
            std::fwrite(row.data(), 1, row.size(), stdout);
        } else if (rn) {
            // Reconstruct the line with the annotation name in place.
            std::fwrite(line.data(), 1, name_start, stdout);
            std::fwrite(effective_name.data(), 1, effective_name.size(), stdout);
            std::fputc('\n', stdout);
        } else {
            std::fwrite(line.data(), 1, line.size(), stdout);
            std::fputc('\n', stdout);
        }
        pos = (nl == std::string::npos) ? tsv.size() : nl + 1;
    }
    if (args.json) std::fputs("]\n", stdout);
    return EXIT_SUCCESS;
}

// ---------------------------------------------------------------------------
// Direct-output runners
// ---------------------------------------------------------------------------

// One row of refs-to output. Both TSV and JSON formatters consume this
// shape; the agent-facing JSON mode picks up `slot` / `fn_name` /
// `fn_offset` as proper fields instead of having to grep them out of
// `(kind via 0xSLOT)  ; fn+0xN`.
struct RefRow {
    addr_t                   from_pc   = 0;
    addr_t                   target    = 0;
    std::string              kind;       // "direct" / "code-ptr" / "lea" / "imm64-stored" / "relocated"
    std::optional<addr_t>    slot;       // populated for imm64-stored / relocated
    std::optional<std::string> fn_name;
    std::optional<u64>       fn_offset;
};

[[nodiscard]] std::string_view section_name_containing(const Binary& b,
                                                       addr_t va) noexcept {
    for (const auto& s : b.sections()) {
        if (va < s.vaddr) continue;
        const auto off = va - s.vaddr;
        if (off < s.size) return s.name;
    }
    return {};
}

[[nodiscard]] bool addr_in_executable_section_cli(const Binary& b,
                                                  addr_t va) noexcept {
    for (const auto& s : b.sections()) {
        if (!s.flags.executable) continue;
        if (va < s.vaddr) continue;
        if (va - s.vaddr < s.size) return true;
    }
    return false;
}

[[nodiscard]] std::string first_disasm_line_at(const Binary& b, addr_t va) {
    auto r = format_disasm_range(b, va, va + 16);
    if (!r) return {};
    std::string_view s(*r);
    if (const auto nl = s.find('\n'); nl != std::string_view::npos) {
        s = s.substr(0, nl);
    }
    return std::string(s);
}

[[nodiscard]] std::string
format_ref_rows_tsv(std::span<const RefRow> rows,
                    const Binary* b = nullptr,
                    bool verbose = false) {
    std::string out;
    for (const auto& r : rows) {
        std::string ctx;
        if (r.fn_name) {
            ctx = std::format("  ; {}+{:#x}", *r.fn_name, r.fn_offset.value_or(0));
        }
        std::string detail;
        if (verbose && b != nullptr) {
            if (r.slot) {
                const auto sec = section_name_containing(*b, *r.slot);
                if (!sec.empty()) {
                    detail += std::format("  ; slot-section {}", sec);
                }
            }
            if (r.kind == "direct") {
                detail += "  ; site not cached (showing caller entry)";
            }
            if (const auto insn = first_disasm_line_at(*b, r.from_pc);
                !insn.empty()) {
                detail += std::format("  ; site {}", insn);
            }
        }
        if (r.slot) {
            out += std::format("{:#x} -> {:#x}  ({} via {:#x}){}{}\n",
                               r.from_pc, r.target, r.kind, *r.slot, ctx, detail);
        } else {
            out += std::format("{:#x} -> {:#x}  ({}){}{}\n",
                               r.from_pc, r.target, r.kind, ctx, detail);
        }
    }
    return out;
}

[[nodiscard]] std::string format_ref_rows_json(std::span<const RefRow> rows) {
    std::string out = "[";
    bool first = true;
    for (const auto& r : rows) {
        if (!first) out += ',';
        first = false;
        out += std::format(
            "{{\"from\":\"{:#x}\",\"target\":\"{:#x}\",\"kind\":\"{}\"",
            r.from_pc, r.target, r.kind);
        if (r.slot) {
            out += std::format(",\"slot\":\"{:#x}\"", *r.slot);
        }
        if (r.fn_name) {
            out += std::format(",\"fn\":\"{}\",\"fn_offset\":\"{:#x}\"",
                               json_escape(*r.fn_name),
                               r.fn_offset.value_or(0));
        }
        out += "}";
    }
    out += "]\n";
    return out;
}

// Internal helper: gather the standard --refs-to rows (direct callers
// from the cached call-graph plus CodePtr/Lea events from
// compute_data_xrefs) for a single target VA. Both run_refs_to and
// run_refs_to_loose use this; loose mode appends extra `imm64-stored`
// / `relocated` rows on top.
[[nodiscard]] std::vector<RefRow>
gather_refs_to_rows(const Args& args, const Binary& b, addr_t va) {
    std::vector<RefRow> out;
    std::string xrefs_tsv;
    const auto dir = args.cache_dir.empty()
        ? cache::default_dir()
        : std::filesystem::path(args.cache_dir);
    std::string key;
    if (!args.no_cache) {
        auto k = cache::key_for(args.binary, cache_scope_tag(args));
        if (k) key = std::move(*k);
    }
    if (!key.empty()) {
        if (auto hit = cache::read(dir, key, kXrefsCacheTag); hit) {
            xrefs_tsv = std::move(*hit);
        }
    }
    if (xrefs_tsv.empty()) {
        std::println(stderr, "ember: --refs-to: building xrefs cache (one-time)...");
        std::fflush(stderr);
        xrefs_tsv = build_xrefs_output(b);
        if (!key.empty()) {
            (void)cache::write(dir, key, kXrefsCacheTag, xrefs_tsv);
        }
    }
    const std::string needle = std::format("-> {:#x}\n", va);
    std::size_t pos = 0;
    while ((pos = xrefs_tsv.find(needle, pos)) != std::string::npos) {
        std::size_t ls = pos;
        while (ls > 0 && xrefs_tsv[ls - 1] != '\n') --ls;
        // Cached TSV rows are `<from> -> <to>\n`; pull from for the
        // structured form. The original line had no extra context.
        std::string_view fs(xrefs_tsv.data() + ls, pos - ls);
        if (fs.starts_with("0x") || fs.starts_with("0X")) fs.remove_prefix(2);
        u64 from = 0;
        auto rc = std::from_chars(fs.data(), fs.data() + fs.size(), from, 16);
        if (rc.ec == std::errc{}) {
            RefRow row;
            row.from_pc = static_cast<addr_t>(from);
            row.target  = va;
            row.kind    = "direct";
            if (auto cf = containing_function(b, row.from_pc); cf) {
                row.fn_name   = cf->name;
                row.fn_offset = cf->offset_within;
            }
            out.push_back(std::move(row));
        }
        pos += needle.size();
    }
    const auto dx = compute_data_xrefs(b);
    if (auto it = dx.find(va); it != dx.end()) {
        for (const auto& r : it->second) {
            if (r.kind != DataXrefKind::CodePtr &&
                r.kind != DataXrefKind::Lea) continue;
            RefRow row;
            row.from_pc = r.from_pc;
            row.target  = va;
            row.kind    = (r.kind == DataXrefKind::CodePtr) ? "code-ptr" : "lea";
            if (auto cf = containing_function(b, r.from_pc); cf) {
                row.fn_name   = cf->name;
                row.fn_offset = cf->offset_within;
            }
            out.push_back(std::move(row));
        }
    }
    return out;
}

int run_symtable(const Args& args, const Binary& b) {
    auto va = parse_cli_addr(args.symtable);
    if (!va) {
        std::println(stderr, "ember: --symtable: bad address '{}'", args.symtable);
        return EXIT_FAILURE;
    }
    auto walk = analysis::walk_symtable(b, *va);
    if (!walk) {
        std::println(stderr, "ember: --symtable: {}", walk.error().message);
        return EXIT_FAILURE;
    }

    // Per-entry TSV: VA \t offset \t length \t string. Display column
    // truncates at 256 chars + "…"; the length column always reports
    // the true byte length.
    constexpr std::size_t kDisplayCap = 256;
    for (const auto& e : walk->entries) {
        if (e.length > kDisplayCap) {
            std::print("{:#x}\t{:#x}\t{}\t",
                       e.va, e.offset, e.length);
            std::fwrite(e.text.data(), 1, kDisplayCap, stdout);
            std::print("…\n");
        } else {
            std::println("{:#x}\t{:#x}\t{}\t{}",
                         e.va, e.offset, e.length, e.text);
        }
    }
    std::println("# total: {} strings, table_size {:#x} bytes, ends @ {:#x} ({})",
                 walk->entries.size(), walk->table_size, walk->end_va,
                 analysis::symtable_termination_name(walk->terminated_by));

    // Bonus: keyword-bucketed view. Skipped when nothing matches —
    // keeps the output clean for tables that aren't dlsym targets.
    const auto cats = analysis::categorize_symtable(*walk);
    if (!cats.empty()) {
        std::println("# categories:");
        std::size_t pad = 0;
        for (const auto& c : cats) pad = std::max(pad, c.name.size());
        for (const auto& c : cats) {
            std::print("#   {:<{}}  ", c.name, pad);
            for (std::size_t i = 0; i < c.hits.size(); ++i) {
                if (i) std::print(", ");
                std::print("{}", c.hits[i]);
            }
            std::print("\n");
        }
    }
    return EXIT_SUCCESS;
}

namespace {

// Parse a comma-separated list of category names. Returns the input
// unchanged when empty. Whitespace is trimmed; empty tokens dropped.
[[nodiscard]] std::vector<std::string>
split_filter_arg(std::string_view raw) {
    std::vector<std::string> out;
    std::size_t i = 0;
    while (i < raw.size()) {
        std::size_t j = raw.find(',', i);
        if (j == std::string_view::npos) j = raw.size();
        std::size_t a = i, b = j;
        while (a < b && std::isspace(static_cast<unsigned char>(raw[a]))) ++a;
        while (b > a && std::isspace(static_cast<unsigned char>(raw[b - 1]))) --b;
        if (b > a) out.emplace_back(raw.substr(a, b - a));
        i = j + 1;
    }
    return out;
}

// Render a callsite VA as `<containing_fn>+0xN`, falling back to the
// raw VA when nothing covers it. Looking up `containing_function` per
// site re-enumerates fns each time, but the volume here is bounded by
// the per-row callsite cap so it's not the hot path.
[[nodiscard]] std::string
render_callsite(const Binary& b, addr_t va) {
    if (auto cf = containing_function(b, va); cf) {
        return std::format("{}+{:#x}", cf->name, cf->offset_within);
    }
    return std::format("{:#x}", va);
}

}  // namespace

int run_symresolve(const Args& args, const Binary& b) {
    auto va = parse_cli_addr(args.symresolve);
    if (!va) {
        std::println(stderr, "ember: --symresolve: bad address '{}'", args.symresolve);
        return EXIT_FAILURE;
    }
    auto res = analysis::resolve_symtable(b, *va);
    if (!res) {
        std::println(stderr, "ember: --symresolve: {}", res.error().message);
        return EXIT_FAILURE;
    }

    // Build the filter set (category buckets → membership-by-name) once.
    // The filter rejects unknown category names early so a typo doesn't
    // silently degrade to "show everything".
    std::vector<std::string> wanted_cats = split_filter_arg(args.category_filter);
    std::unordered_set<std::string_view> wanted_names;
    bool have_filter = !wanted_cats.empty();
    if (have_filter) {
        const auto cats = analysis::categorize_symtable(res->walk);
        for (const auto& want : wanted_cats) {
            for (const auto& c : cats) {
                if (c.name == want) {
                    for (auto h : c.hits) wanted_names.insert(h);
                }
            }
        }
    }

    if (!res->resolvers.empty()) {
        std::string list;
        for (std::size_t i = 0; i < res->resolvers.size(); ++i) {
            const auto& r = res->resolvers[i];
            if (i) list += ", ";
            list += std::format("{} ({} slots @ {:#x})",
                                r.fn_name.empty() ? "<unnamed>" : r.fn_name,
                                r.slots, r.base_va);
        }
        std::println(stderr, "ember: --symresolve: resolver(s) = {}", list);
    } else {
        std::println(stderr,
            "ember: --symresolve: no resolver function found for table at "
            "{:#x} — falling back to string table only", *va);
    }
    {
        const std::size_t total    = res->non_empty_count;
        const std::size_t resolved = res->resolved_count;
        const double pct = total == 0 ? 0.0
                                       : (100.0 * static_cast<double>(resolved)
                                                  / static_cast<double>(total));
        std::println(stderr,
            "ember: --symresolve: coverage: {}/{} slots resolved ({:.1f}%)",
            resolved, total, pct);
        if (total != 0 && pct < 50.0) {
            std::println(stderr,
                "ember: --symresolve: tip: try --symuses {:#x} for the "
                "lazy/per-function dispatch pattern", *va);
        }
    }

    std::println("idx\tstr_va\tsymbol\tfnptr_va\tn_callsites\ttop_callsites");
    const std::size_t cap = static_cast<std::size_t>(args.symresolve_max_callsites);
    for (const auto& r : res->rows) {
        if (have_filter && !wanted_names.contains(r.name)) continue;

        const std::string fnptr_col = r.fnptr_va
            ? std::format("{:#x}", *r.fnptr_va)
            : std::string{"-"};

        std::string sites_col;
        if (r.callsites.empty()) {
            sites_col = "-";
        } else {
            const std::size_t shown = (cap == 0)
                ? r.callsites.size()
                : std::min(cap, r.callsites.size());
            for (std::size_t i = 0; i < shown; ++i) {
                if (i) sites_col += ", ";
                sites_col += render_callsite(b, r.callsites[i]);
            }
            if (shown < r.callsites.size()) sites_col += ", ...";
        }

        std::println("{}\t{:#x}\t{}\t{}\t{}\t{}",
                     r.index, r.string_va, r.name,
                     fnptr_col, r.callsites.size(), sites_col);
    }
    return EXIT_SUCCESS;
}

int run_symuses(const Args& args, const Binary& b) {
    auto va = parse_cli_addr(args.symuses);
    if (!va) {
        std::println(stderr, "ember: --symuses: bad address '{}'", args.symuses);
        return EXIT_FAILURE;
    }
    analysis::SymUseOptions opts;
    opts.no_taint = args.symuses_no_taint;
    auto uses = analysis::collect_symbol_uses(b, *va, opts);
    if (!uses) {
        std::println(stderr, "ember: --symuses: {}", uses.error().message);
        return EXIT_FAILURE;
    }

    // Filter set: when --filter is given, only sites whose symbol
    // falls in any requested category bucket count toward n_uses or
    // appear in the symbols column. Empty filter = unrestricted.
    std::unordered_set<std::string_view> wanted_names;
    const bool have_filter = !args.category_filter.empty();
    if (have_filter) {
        const auto cats = analysis::categorize_symtable(uses->walk);
        for (const auto& want : split_filter_arg(args.category_filter)) {
            for (const auto& c : cats) {
                if (c.name == want) {
                    for (auto h : c.hits) wanted_names.insert(h);
                }
            }
        }
    }

    // Scope summary: which paths admitted candidate functions. Always
    // surfaced — operators reading the TSV need to know whether the
    // analysis even had a non-empty scope to scan, since "0 rows"
    // could mean "no consumers exist" or "the scope detector found
    // nothing to feed the per-fn pass".
    std::println(stderr,
        "ember: --symuses: scope: {} candidate function{} "
        "({} imm64-stored slot{}, {} relocated slot{})",
        uses->scope_fn_count, uses->scope_fn_count == 1 ? "" : "s",
        uses->scope_imm64_slots, uses->scope_imm64_slots == 1 ? "" : "s",
        uses->scope_relocated_slots, uses->scope_relocated_slots == 1 ? "" : "s");

    if (args.verbose) {
        // Per-fn diag: surfaces base-load count, raw IMM matches, and
        // unique-entry count. The sub-counts let an operator catch
        // the case where some scope candidate is producing no hits
        // because its body uses a different indirection than the
        // weak-filter exact-offset match.
        for (const auto& row : uses->rows) {
            if (row.base_load_sites.empty()) continue;
            std::unordered_set<std::string_view> uniq;
            for (const auto& s : row.sites) uniq.insert(s.name);
            std::println(stderr,
                "ember: --symuses:   {}: {} base-load{}, "
                "{} IMM match{} -> {} unique entr{}",
                row.fn_name.empty()
                    ? std::format("{:#x}", row.fn_addr)
                    : row.fn_name,
                row.base_load_sites.size(),
                row.base_load_sites.size() == 1 ? "" : "s",
                row.sites.size(),
                row.sites.size() == 1 ? "" : "es",
                uniq.size(),
                uniq.size() == 1 ? "y" : "ies");
        }
    }

    auto site_passes = [&](const analysis::SymUseSite& s) noexcept {
        if (s.name.empty()) return false;   // leading-empty entry: handled separately
        if (have_filter && !wanted_names.contains(s.name)) return false;
        return true;
    };

    if (args.verbose) {
        std::println("fn_va\tcallsite\tsymbol");
        for (const auto& row : uses->rows) {
            // Verbose mode emits every site individually. Table-walker
            // rows still surface their per-site refs to the leading
            // empty entry — render those as "<table_base>" so an
            // operator can see the walk-shape without confusing it
            // with a real symbol.
            for (const auto& s : row.sites) {
                if (s.name.empty()) {
                    if (have_filter) continue;
                    std::println("{:#x}\t{}+{:#x}\t<table_base>",
                                 row.fn_addr, row.fn_name,
                                 s.callsite - row.fn_addr);
                    continue;
                }
                if (!site_passes(s)) continue;
                std::println("{:#x}\t{}+{:#x}\t{}",
                             row.fn_addr, row.fn_name,
                             s.callsite - row.fn_addr, s.name);
            }
        }
        return EXIT_SUCCESS;
    }

    std::println("fn_va\tn_uses\tsymbols");
    for (const auto& row : uses->rows) {
        // Dedupe symbol names in walk-order — preserves the order in
        // which the function first touched each symbol, which is the
        // shape an operator wants when scanning a long row.
        std::vector<std::string_view> names_in_order;
        std::unordered_set<std::string_view> seen;
        std::size_t passing_uses = 0;
        for (const auto& s : row.sites) {
            if (!site_passes(s)) continue;
            ++passing_uses;
            if (seen.insert(s.name).second) names_in_order.push_back(s.name);
        }

        // No specific symbol hits but the function loaded the table
        // base — that's the table-walker shape (looping the table by
        // index rather than by constant offset). Emit a single
        // placeholder row, gated by --min-uses on the lea-to-base
        // count. Filtering is suppressed since there's no per-symbol
        // signal to match against.
        if (passing_uses == 0 && row.walks_full_table && !have_filter) {
            const std::size_t n = row.sites.empty() ? 1 : row.sites.size();
            if (n < args.symuses_min_uses) continue;
            std::println("{:#x}\t{}\t<full_table_walker>", row.fn_addr, n);
            continue;
        }

        if (passing_uses < args.symuses_min_uses) continue;
        if (passing_uses == 0 && !args.symuses_show_empty) continue;

        std::string symbols_col;
        for (std::size_t i = 0; i < names_in_order.size(); ++i) {
            if (i) symbols_col += ", ";
            symbols_col += names_in_order[i];
        }
        if (symbols_col.empty()) symbols_col = "-";

        std::println("{:#x}\t{}\t{}", row.fn_addr, passing_uses, symbols_col);
    }
    return EXIT_SUCCESS;
}

int run_refs_to(const Args& args, const Binary& b) {
    auto va = parse_cli_addr(args.refs_to);
    if (!va) {
        std::println(stderr, "ember: --refs-to: bad address '{}'", args.refs_to);
        return EXIT_FAILURE;
    }
    const auto rows = gather_refs_to_rows(args, b, *va);
    const std::string out = args.json
        ? format_ref_rows_json(rows)
        : format_ref_rows_tsv(rows, &b, args.verbose);
    std::fwrite(out.data(), 1, out.size(), stdout);
    return EXIT_SUCCESS;
}

int run_refs_to_loose(const Args& args, const Binary& b) {
    // Heavier sibling of --refs-to. Beyond the cached call-graph
    // xrefs and CodePtr/Lea events surfaced by compose_refs_to_output,
    // this also walks every readable section for the literal target
    // VA stored as an 8-byte (or 4-byte on 32-bit) value, then folds
    // in the per-function references to those slots — recovering the
    // fn-pointer-only case where the target is reached as
    // `lea rax, [rip+disp_to_table]; mov rbx, [rax+N]; call rbx`
    // and there is no static call edge to the target itself.
    //
    // Confidence tagging in the row body lets a downstream agent
    // weight follow-ups: `code-ptr` / `lea` rows are static-evidence
    // strong; `imm64-stored` rows are circumstantial — the function
    // reads from a slot whose value matches the target, but the read
    // hasn't been chased to a call.
    auto va = parse_cli_addr(args.refs_to_loose);
    if (!va) {
        std::println(stderr, "ember: --refs-to-loose: bad address '{}'",
                     args.refs_to_loose);
        return EXIT_FAILURE;
    }

    std::vector<RefRow> rows = gather_refs_to_rows(args, b, *va);

    // Constant-pool scan: every readable section. Function-pointer
    // tables live in .rodata / .data / .data.rel.ro, sometimes inside
    // an .init_array ctor's frame. Bounded by total readable bytes —
    // a 100MB binary's data sections are the budget on agent flows.
    std::vector<addr_t> slot_addrs;
    const u64 target = static_cast<u64>(*va);
    const bool is_64 = arch_pointer_bits(b.arch()) == 64;
    const std::size_t needle_size = is_64 ? 8u : 4u;
    // Only scan at pointer-aligned slot VAs (8-byte for 64-bit pointers,
    // 4-byte for 32-bit). Without this guard, a single legitimate
    // function-pointer slot whose value contains the target's bytes
    // produces a cluster of byte-shifted false positives at the same
    // location — every bit-shift coincidentally matching the lower
    // 8 bytes of the next slot. Function-pointer tables are
    // pointer-aligned by linker convention; the rare unaligned case
    // is not worth the noise.
    for (const auto& s : b.sections()) {
        if (!s.flags.readable) continue;
        if (s.data.empty()) continue;
        const std::byte* p = s.data.data();
        const std::size_t n = s.data.size();
        if (n < needle_size) continue;
        const auto sec_base = static_cast<addr_t>(s.vaddr);
        // Step the cursor up to the first aligned slot VA inside this
        // section, then advance by `needle_size` from there.
        const std::size_t first_aligned =
            (needle_size - (sec_base % needle_size)) % needle_size;
        for (std::size_t i = first_aligned; i + needle_size <= n;
             i += needle_size) {
            const u64 v = is_64
                ? read_le_at<u64>(p + i)
                : static_cast<u64>(read_le_at<u32>(p + i));
            if (v == target) {
                slot_addrs.push_back(sec_base + static_cast<addr_t>(i));
            }
        }
    }

    const auto dx = compute_data_xrefs(b);

    // De-dupe against direct rows so `--refs-to-loose` stays a strict
    // superset without re-listing the same from_pc twice.
    std::set<addr_t> already_emitted;
    for (const auto& r : rows) already_emitted.insert(r.from_pc);

    auto emit_slot_readers = [&](addr_t slot, std::string_view tag) {
        if (auto it = dx.find(slot); it != dx.end()) {
            for (const auto& xr : it->second) {
                if (xr.kind != DataXrefKind::Read &&
                    xr.kind != DataXrefKind::Lea) continue;
                if (!already_emitted.insert(xr.from_pc).second) continue;
                RefRow row;
                row.from_pc = xr.from_pc;
                row.target  = *va;
                row.kind    = std::string(tag);
                row.slot    = slot;
                if (auto cf = containing_function(b, xr.from_pc); cf) {
                    row.fn_name   = cf->name;
                    row.fn_offset = cf->offset_within;
                }
                rows.push_back(std::move(row));
            }
        }
    };
    for (addr_t slot : slot_addrs) emit_slot_readers(slot, "imm64-stored");

    // Relocation-driven slots: a `.data.rel.ro` qword whose static
    // on-disk value is zero but whose dynamic-linker addend is the
    // target VA. The static qword scan above misses these because
    // it only matches against the file bytes; the relocation table
    // knows the *post-load* value. ELF-only path; non-ELF binaries
    // get an empty map.
    std::size_t reloc_slot_count = 0;
    if (const auto* elf = dynamic_cast<const ElfBinary*>(&b)) {
        const auto reloc_map = elf->relocated_qwords();
        for (const auto& [slot, addend] : reloc_map) {
            if (addend != static_cast<addr_t>(*va)) continue;
            ++reloc_slot_count;
            emit_slot_readers(slot, "relocated");
        }
    }

    const std::string out = args.json
        ? format_ref_rows_json(rows)
        : format_ref_rows_tsv(rows, &b, args.verbose);
    std::fwrite(out.data(), 1, out.size(), stdout);
    if (rows.empty()) {
        std::println(stderr, "ember: --refs-to-loose: 0 references found "
                             "({} static slot{}, {} relocated slot{}, 0 readers)",
                     slot_addrs.size(),
                     slot_addrs.size() == 1 ? "" : "s",
                     reloc_slot_count,
                     reloc_slot_count == 1 ? "" : "s");
    }
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

    // Pull annotations once for provenance lookup. Bound rows that
    // carry a meta record get an extra `confidence=` / `source=`
    // hint so a verifier knows whether the binding was cheap (a
    // symbol) or earned (a high-conf agent claim).
    Annotations validate_ann;
    bool validate_ann_ready = false;
    {
        const auto adir = !args.cache_dir.empty()
            ? std::filesystem::path{args.cache_dir}
            : cache::default_dir();
        auto loc = resolve_annotation_location(args.binary, args.annotations_path, adir);
        if (args.no_cache && loc.source == AnnotationSource::Cache) loc = {};
        if (loc.source != AnnotationSource::None && !loc.path.empty()) {
            std::error_code ec;
            if (std::filesystem::exists(loc.path, ec) && !ec) {
                if (auto rv = Annotations::load(loc.path); rv) {
                    validate_ann = std::move(*rv);
                    validate_ann_ready = true;
                }
            }
        }
    }
    auto bound_meta = [&](addr_t a) -> const AnnotationMeta* {
        return validate_ann_ready ? validate_ann.meta_for_rename(a) : nullptr;
    };

    if (args.json) {
        std::string out = std::format(
            "{{\"name\":\"{}\",\"verdict\":\"{}\",\"bound\":[",
            json_escape(args.validate_name), verdict);
        for (std::size_t i = 0; i < v.bound.size(); ++i) {
            if (i) out += ',';
            const auto& fp = v.fps[i];
            out += std::format(
                "{{\"addr\":\"{:#x}\",\"hash\":\"{:#x}\","
                "\"blocks\":{},\"insts\":{},\"calls\":{},\"offset\":{}",
                v.bound[i], fp.hash, fp.blocks, fp.insts, fp.calls, v.offsets[i]);
            if (const auto* m = bound_meta(v.bound[i]); m) {
                if (m->confidence > 0.0f) {
                    out += std::format(",\"confidence\":{:.3g}", m->confidence);
                }
                if (!m->source.empty()) {
                    out += std::format(",\"source\":\"{}\"",
                                       json_escape(m->source));
                }
            }
            out += "}";
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
            std::string row = std::format(
                "bound\t{:#x}\thash={:#x}\tblocks={}\tinsts={}\tcalls={}"
                "\tname={}\toffset_in_fn={:#x}",
                v.bound[i], fp.hash, fp.blocks, fp.insts, fp.calls,
                args.validate_name, v.offsets[i]);
            if (const auto* m = bound_meta(v.bound[i]); m) {
                if (m->confidence > 0.0f) {
                    row += std::format("\tconfidence={:.3g}", m->confidence);
                }
                if (!m->source.empty()) {
                    row += std::format("\tsource={}", m->source);
                }
            }
            out += row + "\n";
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
    const Annotations callees_ann = load_annotations_quiet(args);
    auto win = resolve_function(b, args.callees, &callees_ann);
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
    if (!parse_disasm_count(args.disasm_count, count, "--disasm-at")) {
        return EXIT_FAILURE;
    }
    // 8 bytes/insn is the typical x86-64 average; ~15 bytes is the max.
    const addr_t end = static_cast<addr_t>(*va) +
                       static_cast<addr_t>(count * 15);
    auto rv = format_disasm_range(b, static_cast<addr_t>(*va), end);
    if (!rv) return report(rv.error());
    // Trim to N lines of disassembly (skip the header/comments).
    std::size_t emitted = 0;
    std::string out;
    if (!addr_in_executable_section_cli(b, static_cast<addr_t>(*va))) {
        const auto sec = section_name_containing(b, static_cast<addr_t>(*va));
        if (!sec.empty()) {
            out += std::format(
                "; warning: {:#x} is in non-executable section {}; bytes may be data\n",
                static_cast<addr_t>(*va), sec);
        } else {
            out += std::format(
                "; warning: {:#x} is not in an executable section; bytes may be data\n",
                static_cast<addr_t>(*va));
        }
    }
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

int run_disasm_window(const Args& args, const Binary& b) {
    // Batch sibling of --disasm-at. Accepts a comma-separated VA list
    // (`0x...,sub_...,...`) or `@PATH` to read VAs one-per-line from a
    // file, runs the same per-VA window each --disasm-at does, and
    // separates blocks with a `# <hex-va>` line so a downstream
    // splitter can pull them apart. Saves an agent the per-invocation
    // ember startup cost when sweeping thousands of refs-to / scan
    // hits.
    std::vector<addr_t> vas;
    auto push_va = [&](std::string_view tok) -> bool {
        // Trim whitespace.
        while (!tok.empty() && (tok.front() == ' ' || tok.front() == '\t' ||
                                tok.front() == '\r')) tok.remove_prefix(1);
        while (!tok.empty() && (tok.back() == ' ' || tok.back() == '\t' ||
                                tok.back() == '\r')) tok.remove_suffix(1);
        if (tok.empty()) return true;
        auto a = parse_cli_addr(tok);
        if (!a) {
            std::println(stderr,
                "ember: --disasm-window: bad address '{}'", tok);
            return false;
        }
        vas.push_back(*a);
        return true;
    };

    const std::string_view raw = args.disasm_window;
    if (!raw.empty() && raw.front() == '@') {
        // File source: one VA per line, blank lines and `#`-prefixed
        // comment lines skipped.
        const std::string path{raw.substr(1)};
        std::ifstream f(path);
        if (!f) {
            std::println(stderr, "ember: --disasm-window: cannot open '{}'", path);
            return EXIT_FAILURE;
        }
        std::string line;
        while (std::getline(f, line)) {
            std::string_view sv = line;
            while (!sv.empty() && (sv.front() == ' ' || sv.front() == '\t')) sv.remove_prefix(1);
            if (sv.empty() || sv.front() == '#') continue;
            if (!push_va(sv)) return EXIT_FAILURE;
        }
    } else {
        std::size_t start = 0;
        for (std::size_t i = 0; i <= raw.size(); ++i) {
            if (i == raw.size() || raw[i] == ',') {
                if (!push_va(raw.substr(start, i - start))) return EXIT_FAILURE;
                start = i + 1;
            }
        }
    }

    if (vas.empty()) {
        std::println(stderr, "ember: --disasm-window: empty VA list");
        return EXIT_FAILURE;
    }

    std::size_t count = 32;
    if (!parse_disasm_count(args.disasm_count, count, "--disasm-window")) {
        return EXIT_FAILURE;
    }

    auto window_for_va = [&](addr_t va) -> std::string {
        // Mirror run_disasm_at: 15 bytes/insn upper bound, then trim to
        // `count` non-comment lines after the formatter returns.
        const addr_t end = va + static_cast<addr_t>(count * 15);
        auto rv = format_disasm_range(b, va, end);
        if (!rv) {
            return std::format("# error: {}\n", rv.error().message);
        }
        std::string out;
        if (!addr_in_executable_section_cli(b, va)) {
            const auto sec = section_name_containing(b, va);
            if (!sec.empty()) {
                out += std::format(
                    "; warning: {:#x} is in non-executable section {}; bytes may be data\n",
                    va, sec);
            } else {
                out += std::format(
                    "; warning: {:#x} is not in an executable section; bytes may be data\n",
                    va);
            }
        }
        std::size_t emitted = 0;
        std::size_t line_start = 0;
        for (std::size_t i = 0; i <= rv->size(); ++i) {
            if (i == rv->size() || (*rv)[i] == '\n') {
                const std::string_view line(rv->data() + line_start, i - line_start);
                out.append(line);
                out += '\n';
                if (!line.empty() && line.front() != ';') ++emitted;
                if (emitted >= count) break;
                line_start = i + 1;
            }
        }
        return out;
    };

    if (args.json) {
        std::string out = "[";
        bool first = true;
        for (addr_t va : vas) {
            if (!first) out += ',';
            first = false;
            const std::string body = window_for_va(va);
            out += std::format("{{\"addr\":\"{:#x}\",\"disasm\":\"{}\"}}",
                               va, json_escape(body));
        }
        out += "]\n";
        std::fwrite(out.data(), 1, out.size(), stdout);
    } else {
        std::string out;
        for (addr_t va : vas) {
            out += std::format("# {:#x}\n", va);
            out += window_for_va(va);
        }
        std::fwrite(out.data(), 1, out.size(), stdout);
    }
    return EXIT_SUCCESS;
}

int run_list_syscalls(const Args& args, const Binary& b) {
    // Resolve target — accept symbol-by-name (`-s NAME`-style strings),
    // hex VA, or `sub_<hex>`. The address is the function entry the
    // syscall walker starts decoding from; mid-function VAs get
    // rebound to the containing function's start, same as `-p`.
    const Annotations syscalls_ann = load_annotations_quiet(args);
    auto win = resolve_function(b, args.list_syscalls, &syscalls_ann);
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

int run_forge_spec(const Args& args, const Binary& b) {
    // --forge-spec accepts ENTRY:VA. ENTRY = symbol name | hex VA | sub_<hex>;
    // VA = hex | sub_<hex>. Both halves are required; bail with a useful
    // error otherwise (mirroring how --apply-patches refuses malformed
    // input rather than silently doing nothing).
    const std::string_view raw = args.forge_spec;
    const auto colon = raw.find(':');
    if (colon == std::string_view::npos) {
        std::println(stderr,
            "ember: --forge-spec: expected ENTRY:VA, got '{}'", raw);
        return EXIT_FAILURE;
    }
    const std::string_view entry_tok = raw.substr(0, colon);
    const std::string_view target_tok = raw.substr(colon + 1);

    const Annotations forge_ann = load_annotations_quiet(args);
    auto entry_win = resolve_function(b, entry_tok, &forge_ann);
    if (!entry_win) return EXIT_FAILURE;  // resolve_function already printed

    auto target_va = parse_cli_addr(target_tok);
    if (!target_va) {
        std::println(stderr,
            "ember: --forge-spec: bad target VA '{}'", target_tok);
        return EXIT_FAILURE;
    }

    auto spec = infer_forge_spec(b, entry_win->start, *target_va);
    if (!spec) return report(spec.error());

    if (args.json) {
        std::print("{}\n", format_forge_spec_json(*spec));
    } else {
        std::print("{}", format_forge_spec(*spec));
    }
    return EXIT_SUCCESS;
}

int run_annotate(const Args& args, const Binary& /*b*/) {
    // One-shot annotation write. Resolves the destination file with the
    // same chain `--apply` uses (explicit > sidecar > cache), loads the
    // existing contents, sets whichever record(s) the user asked for,
    // attaches provenance (--confidence / --evidence / --source), and
    // writes back atomically. --dry-run prints the would-be file to
    // stdout instead of touching disk.
    auto va = parse_cli_addr(args.annotate_addr);
    if (!va) {
        std::println(stderr,
            "ember: --annotate: bad address '{}'", args.annotate_addr);
        return EXIT_FAILURE;
    }

    if (args.annotate_name.empty() && args.annotate_note.empty() &&
        args.annotate_signature.empty()) {
        std::println(stderr,
            "ember: --annotate: nothing to set "
            "(pass --set-name, --set-note, or --set-signature)");
        return EXIT_FAILURE;
    }

    AnnotationMeta meta;
    if (!args.annotate_conf.empty()) {
        // Reuse charconv on a local view; clamp to [0,1] to match the
        // annotations parser's clamp on load.
        float v = 0.0f;
        const auto* first = args.annotate_conf.data();
        const auto* last  = first + args.annotate_conf.size();
        auto rc = std::from_chars(first, last, v);
        if (rc.ec != std::errc{} || rc.ptr != last) {
            std::println(stderr,
                "ember: --confidence: expected a float in [0,1], got '{}'",
                args.annotate_conf);
            return EXIT_FAILURE;
        }
        if (v < 0.0f) v = 0.0f;
        if (v > 1.0f) v = 1.0f;
        meta.confidence = v;
    }
    meta.evidence = args.annotate_evidence;
    meta.source   = args.annotate_source.empty()
        ? std::string{"cli"}
        : args.annotate_source;
    // A user passing --evidence / --source without --confidence still
    // wants the metadata persisted; promote to a tiny non-zero
    // confidence if explicitly empty would suppress it. The serializer
    // omits empty-meta records entirely (confidence==0 + empty
    // evidence + empty source), so we have to keep at least one field
    // populated. `source` is always populated above, so this is fine.

    const std::filesystem::path cache_dir =
        !args.cache_dir.empty() ? std::filesystem::path{args.cache_dir}
                                : cache::default_dir();
    auto loc = resolve_annotation_location(args.binary, args.annotations_path, cache_dir);
    if (args.no_cache && loc.source == AnnotationSource::Cache) loc = {};
    if (loc.source == AnnotationSource::None || loc.path.empty()) {
        std::println(stderr,
            "ember: --annotate: nowhere to write annotations "
            "(no --annotations / sidecar / cache)");
        return EXIT_FAILURE;
    }

    Annotations ann;
    {
        std::error_code ec;
        if (std::filesystem::exists(loc.path, ec) && !ec) {
            auto rv = Annotations::load(loc.path);
            if (!rv) return report(rv.error());
            ann = std::move(*rv);
        }
    }

    // Apply each requested mutation. Provenance attaches to every kind
    // the user set in this invocation — most agent flows set one
    // (typically --set-name) per call, but a human dropping in a known
    // signature might want both --set-name and --set-signature, in
    // which case both meta records get the same evidence.
    if (!args.annotate_name.empty()) {
        ann.renames[*va]      = args.annotate_name;
        ann.rename_meta[*va]  = meta;
    }
    if (!args.annotate_note.empty()) {
        ann.notes[*va]        = args.annotate_note;
        ann.note_meta[*va]    = meta;
    }
    if (!args.annotate_signature.empty()) {
        auto sig = ::ember::script::parse_signature(args.annotate_signature);
        if (!sig) {
            std::println(stderr,
                "ember: --set-signature: cannot parse '{}'",
                args.annotate_signature);
            return EXIT_FAILURE;
        }
        ann.signatures[*va]       = std::move(*sig);
        ann.signature_meta[*va]   = meta;
    }

    if (args.dry_run) {
        const std::string text = ann.to_text();
        std::fwrite(text.data(), 1, text.size(), stdout);
    } else {
        if (auto sv = ann.save(loc.path); !sv) return report(sv.error());
    }

    if (!args.quiet) {
        const char* tag = args.dry_run ? "--annotate --dry-run" : "--annotate";
        std::println(stderr,
            "ember: {}: {:#x} -> {} ({})",
            tag, static_cast<u64>(*va),
            loc.path.empty() ? std::string{"<no destination>"} : loc.path.string(),
            annotation_source_name(loc.source));
    }
    return EXIT_SUCCESS;
}

int run_list_annotations(const Args& args, const Binary& /*b*/) {
    // Walk the resolved annotations file and emit every record. Sibling
    // of `--functions --json` for the cases where what the user wrote is
    // a `--set-note` (no rename), which `--functions` can't surface
    // because its TSV row keys off the discovered name. TSV output
    // groups one record per line:
    //
    //   <hex-addr> <kind> <value> [conf=<f> [src=<tag> [ev=<text>]]]
    //
    // where <kind> is `rename` / `note` / `signature`. JSON form
    // returns one object per address with `rename` / `note` /
    // `signature` keys (only those actually set) plus the matching
    // `*_meta` blocks. Both forms emit nothing if the destination file
    // is missing — silence is correct for "no annotations yet".
    const std::filesystem::path cache_dir =
        !args.cache_dir.empty() ? std::filesystem::path{args.cache_dir}
                                : cache::default_dir();
    auto loc = resolve_annotation_location(args.binary, args.annotations_path, cache_dir);
    if (args.no_cache && loc.source == AnnotationSource::Cache) loc = {};

    Annotations ann;
    if (loc.source != AnnotationSource::None && !loc.path.empty()) {
        std::error_code ec;
        if (std::filesystem::exists(loc.path, ec) && !ec) {
            auto rv = Annotations::load(loc.path);
            if (!rv) return report(rv.error());
            ann = std::move(*rv);
        }
    }

    auto sig_to_string = [](const FunctionSig& s) {
        std::string out = s.return_type.empty() ? std::string{"void"} : s.return_type;
        out += '(';
        for (std::size_t i = 0; i < s.params.size(); ++i) {
            if (i) out += ", ";
            out += s.params[i].type;
            if (!s.params[i].name.empty()) {
                out += ' ';
                out += s.params[i].name;
            }
        }
        if (s.params.empty()) out += "void";
        out += ')';
        return out;
    };

    auto append_meta_tsv = [](std::string& row, const AnnotationMeta* m) {
        if (!m) return;
        if (m->confidence > 0.0f) {
            row += std::format("\tconf={:.3g}", m->confidence);
        }
        if (!m->source.empty()) {
            row += std::format("\tsrc={}", m->source);
        }
        if (!m->evidence.empty()) {
            row += std::format("\tev={}", escape_for_line(m->evidence));
        }
    };

    if (args.json) {
        // Build the union of all addresses appearing in any record kind
        // so each address gets one combined object, regardless of which
        // map it shows up in.
        std::set<addr_t> addrs;
        for (const auto& [a, _] : ann.renames)    addrs.insert(a);
        for (const auto& [a, _] : ann.notes)      addrs.insert(a);
        for (const auto& [a, _] : ann.signatures) addrs.insert(a);

        std::string out = "[";
        bool first = true;
        for (addr_t a : addrs) {
            if (!first) out += ',';
            first = false;
            out += std::format("{{\"addr\":\"{:#x}\"", a);
            if (auto it = ann.renames.find(a); it != ann.renames.end()) {
                out += std::format(",\"rename\":\"{}\"", json_escape(it->second));
                if (const auto* m = ann.meta_for_rename(a); m) {
                    if (m->confidence > 0.0f)
                        out += std::format(",\"rename_confidence\":{:.3g}", m->confidence);
                    if (!m->source.empty())
                        out += std::format(",\"rename_source\":\"{}\"", json_escape(m->source));
                    if (!m->evidence.empty())
                        out += std::format(",\"rename_evidence\":\"{}\"", json_escape(m->evidence));
                }
            }
            if (auto it = ann.notes.find(a); it != ann.notes.end()) {
                out += std::format(",\"note\":\"{}\"", json_escape(it->second));
                if (const auto* m = ann.meta_for_note(a); m) {
                    if (m->confidence > 0.0f)
                        out += std::format(",\"note_confidence\":{:.3g}", m->confidence);
                    if (!m->source.empty())
                        out += std::format(",\"note_source\":\"{}\"", json_escape(m->source));
                    if (!m->evidence.empty())
                        out += std::format(",\"note_evidence\":\"{}\"", json_escape(m->evidence));
                }
            }
            if (auto it = ann.signatures.find(a); it != ann.signatures.end()) {
                out += std::format(",\"signature\":\"{}\"",
                                   json_escape(sig_to_string(it->second)));
                if (const auto* m = ann.meta_for_signature(a); m) {
                    if (m->confidence > 0.0f)
                        out += std::format(",\"signature_confidence\":{:.3g}", m->confidence);
                    if (!m->source.empty())
                        out += std::format(",\"signature_source\":\"{}\"", json_escape(m->source));
                    if (!m->evidence.empty())
                        out += std::format(",\"signature_evidence\":\"{}\"", json_escape(m->evidence));
                }
            }
            out += '}';
        }
        out += "]\n";
        std::fwrite(out.data(), 1, out.size(), stdout);
        return EXIT_SUCCESS;
    }

    // TSV: one record per line. Iteration order is by address, then by
    // kind (rename, note, signature) — stable across runs so diffs read
    // cleanly.
    std::set<addr_t> addrs;
    for (const auto& [a, _] : ann.renames)    addrs.insert(a);
    for (const auto& [a, _] : ann.notes)      addrs.insert(a);
    for (const auto& [a, _] : ann.signatures) addrs.insert(a);
    std::string out;
    for (addr_t a : addrs) {
        if (auto it = ann.renames.find(a); it != ann.renames.end()) {
            std::string row = std::format("{:#x}\trename\t{}", a,
                                          escape_for_line(it->second));
            append_meta_tsv(row, ann.meta_for_rename(a));
            out += row + "\n";
        }
        if (auto it = ann.notes.find(a); it != ann.notes.end()) {
            std::string row = std::format("{:#x}\tnote\t{}", a,
                                          escape_for_line(it->second));
            append_meta_tsv(row, ann.meta_for_note(a));
            out += row + "\n";
        }
        if (auto it = ann.signatures.find(a); it != ann.signatures.end()) {
            std::string row = std::format("{:#x}\tsignature\t{}", a,
                                          escape_for_line(sig_to_string(it->second)));
            append_meta_tsv(row, ann.meta_for_signature(a));
            out += row + "\n";
        }
    }
    std::fwrite(out.data(), 1, out.size(), stdout);
    return EXIT_SUCCESS;
}

// ---------------------------------------------------------------------------
// Per-view runners (asm / cfg / ir / pseudo / struct / cfg-pseudo)
// ---------------------------------------------------------------------------

int run_disasm(const Binary& b, std::string_view symbol,
               const Annotations* ann) {
    auto win = resolve_function(b, symbol, ann);
    if (!win) return EXIT_FAILURE;  // resolve_function already printed
    auto out = format_disasm(b, *win);
    if (!out) return report(out.error());
    std::print("{}", *out);
    return EXIT_SUCCESS;
}

int run_cfg(const Binary& b, std::string_view symbol,
            const Annotations* ann) {
    auto win = resolve_function(b, symbol, ann);
    if (!win) return EXIT_FAILURE;
    auto out = format_cfg(b, *win);
    if (!out) return report(out.error());
    std::print("{}", *out);
    return EXIT_SUCCESS;
}

int run_cfg_pseudo(const Binary& b, std::string_view symbol,
                   const Annotations* ann, EmitOptions opts) {
    auto win = resolve_function(b, symbol, ann);
    if (!win) return EXIT_FAILURE;
    auto out = format_cfg_pseudo(b, *win, ann, opts);
    if (!out) return report(out.error());
    std::print("{}", *out);
    return EXIT_SUCCESS;
}

int run_ir(const Binary& b, std::string_view symbol,
           bool run_ssa, bool run_opt, const Annotations* ann) {
    auto win = resolve_function(b, symbol, ann);
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
    auto win = resolve_function(b, symbol, annotations);
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
    emit_opts.show_bb_labels  = args.labels;
    emit_opts.show_provenance = args.show_provenance;

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
        ScopedTimer t("ipa");
        std::println(stderr, "ember: running IPA (this pass lifts every function once)...");
        std::fflush(stderr);
        ipa = infer_signatures(b, &shared_ir_cache);
        std::println(stderr, "ember: IPA done: {} functions analyzed", ipa.sigs.size());
        emit_opts.signatures = &ipa.sigs;
        emit_opts.type_arena = &ipa.arena;
    }
    std::map<addr_t, addr_t> resolutions;
    if (args.resolve_calls && (args.pseudo || args.strct)) {
        ScopedTimer t("resolve_calls");
        // Scope to the requested function — emit only renders one fn at a
        // time, so the rest of the binary's indirect calls would never be
        // observed. When the symbol can't be resolved the format step is
        // about to bail with "no symbol named X", so don't bother
        // resolving anything either.
        if (auto win = resolve_function(b, args.symbol)) {
            const addr_t fn = win->start;
            const std::span<const addr_t> scope{&fn, 1};
            std::println(stderr, "ember: resolving indirect calls (vtable + import back-trace)...");
            std::fflush(stderr);
            resolutions = resolve_indirect_calls(b, &shared_ir_cache, scope);
            std::println(stderr, "ember: indirect-call resolver: {} sites resolved",
                         resolutions.size());
            emit_opts.call_resolutions = &resolutions;
        }
    }
    LpMap lp_map;
    if (args.eh && (args.pseudo || args.strct)) {
        ScopedTimer t("eh_landing_pads");
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
        ScopedTimer t("pe_unwind_prologues");
        prologue_ranges = build_prologue_ranges(b);
        if (!prologue_ranges.empty()) emit_opts.prologue_ranges = &prologue_ranges;
    }
    // __objc_selrefs is cheap to walk — do it unconditionally on Mach-O
    // so `objc_msgSend(*(u64*)(0x10...))` renders as `@selector(foo:)`
    // without requiring a separate flag.
    std::map<addr_t, std::string> selrefs;
    if ((args.pseudo || args.strct) && b.format() == Format::MachO) {
        ScopedTimer t("objc_selrefs");
        selrefs = parse_objc_selrefs(b);
        if (!selrefs.empty()) emit_opts.objc_selrefs = &selrefs;
    }
    if (args.pseudo) {
        ScopedTimer t("emit_pseudo");
        return run_struct(b, args.symbol, /*pseudo=*/true, ann_ptr, emit_opts);
    }
    if (args.strct) {
        ScopedTimer t("emit_struct");
        return run_struct(b, args.symbol, /*pseudo=*/false, ann_ptr, emit_opts);
    }
    if (args.ir) {
        return run_ir(b, args.symbol, args.ssa, args.opt, ann_ptr);
    }
    if (args.cfg_pseudo) {
        return run_cfg_pseudo(b, args.symbol, ann_ptr, emit_opts);
    }
    if (args.cfg) {
        return run_cfg(b, args.symbol, ann_ptr);
    }
    if (args.disasm) {
        return run_disasm(b, args.symbol, ann_ptr);
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
    int saved = ember_dup(ember_fileno(stdout));
    std::FILE* tmp = std::tmpfile();
    if (!tmp || saved < 0) {
        // Fallback: just run fn without capture. Worst case the
        // request "succeeds" but the body lands on the parent's stdout
        // — agent client treats that as a malformed frame.
        fn();
        return {};
    }
    ember_dup2(ember_fileno(tmp), ember_fileno(stdout));
    fn();
    std::fflush(stdout);
    ember_dup2(saved, ember_fileno(stdout));
    ember_close(saved);
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
            if (req->method == "identify") {
                Args a = derive_args(base);
                a.identify = true;
                std::string body = capture_stdout([&]{ run_identify(a, b); });
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

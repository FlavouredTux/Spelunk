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
#include <map>
#include <print>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <ember/analysis/cfg_builder.hpp>
#include <ember/analysis/eh_frame.hpp>
#include <ember/analysis/indirect_calls.hpp>
#include <ember/analysis/objc.hpp>
#include <ember/analysis/pe_unwind.hpp>
#include <ember/analysis/pipeline.hpp>
#include <ember/analysis/rtti.hpp>
#include <ember/analysis/sig_inference.hpp>
#include <ember/analysis/sigs.hpp>
#include <ember/binary/binary.hpp>
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
    if (args.functions_pattern.empty()) {
        std::fwrite(tsv.data(), 1, tsv.size(), stdout);
        return EXIT_SUCCESS;
    }
    std::string needle = args.functions_pattern;
    for (auto& c : needle) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    std::size_t pos = 0;
    while (pos < tsv.size()) {
        const auto nl = tsv.find('\n', pos);
        const std::size_t end = (nl == std::string::npos) ? tsv.size() : nl;
        std::string_view line(tsv.data() + pos, end - pos);
        // Columns: addr\tsize\tkind\tname — skip to the fourth.
        std::size_t tabs = 0, name_start = 0;
        for (std::size_t i = 0; i < line.size() && tabs < 3; ++i) {
            if (line[i] == '\t' && ++tabs == 3) name_start = i + 1;
        }
        std::string name_lc(line.substr(name_start));
        for (auto& c : name_lc) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (name_lc.find(needle) != std::string::npos) {
            std::fwrite(line.data(), 1, line.size(), stdout);
            std::fputc('\n', stdout);
        }
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

    const Annotations* ann_ptr = ann_loaded ? &annotations : nullptr;

    EmitOptions emit_opts;
    emit_opts.show_bb_labels = args.labels;

    // IPA: one-shot fixed-point over the call graph before emission so
    // char*-arg propagation can cross function boundaries. Expensive on
    // large binaries — opt-in via --ipa.
    InferenceResult ipa;
    if (args.ipa && (args.pseudo || args.strct)) {
        std::println(stderr, "ember: running IPA (this pass lifts every function once)...");
        std::fflush(stderr);
        ipa = infer_signatures(b);
        std::println(stderr, "ember: IPA done: {} functions analyzed", ipa.sigs.size());
        emit_opts.signatures = &ipa.sigs;
        emit_opts.type_arena = &ipa.arena;
    }
    std::map<addr_t, addr_t> resolutions;
    if (args.resolve_calls && (args.pseudo || args.strct)) {
        std::println(stderr, "ember: resolving indirect calls (vtable + import back-trace)...");
        std::fflush(stderr);
        resolutions = resolve_indirect_calls(b);
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

}  // namespace ember::cli

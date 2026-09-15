// Function inventory: --functions, arities, PPC coverage.

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <format>
#include <optional>
#include <print>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include <spelunk/analysis/arity.hpp>
#include <spelunk/analysis/function.hpp>
#include <spelunk/analysis/identify.hpp>
#include <spelunk/analysis/pipeline.hpp>
#include <spelunk/analysis/sigs.hpp>
#include <spelunk/binary/arch.hpp>
#include <spelunk/binary/binary.hpp>
#include <spelunk/common/annotations.hpp>
#include <spelunk/common/bytes.hpp>
#include <spelunk/common/cache.hpp>
#include <spelunk/common/timing.hpp>
#include <spelunk/common/types.hpp>
#include <spelunk/disasm/decoder.hpp>
#include <spelunk/disasm/instruction.hpp>
#include <spelunk/disasm/ppc_decoder.hpp>
#include <spelunk/ir/ir.hpp>
#include <spelunk/ir/lifter.hpp>
#include <spelunk/script/declarative.hpp>

#include "../args.hpp"
#include "../builders.hpp"
#include "../cli_error.hpp"
#include "../subcommands.hpp"
#include "../util.hpp"
#include "common.hpp"

namespace spelunk::cli {

namespace {

constexpr std::string_view kAritiesCacheTag = "arities-v3";

constexpr std::string_view kFunctionsCacheTag = "functions-v7";

constexpr std::string_view kFunctionsFullCacheTag = "functions_full-v7";

constexpr std::string_view kFunctionsInferredCacheTag = "functions_inferred-v6";

constexpr std::string_view kFunctionsFullInferredCacheTag = "functions_full_inferred-v6";

struct ViewFlagSpec {
    std::string_view name;
    bool (*present)(const Args&);
};

// One row per exclusive output selector, in main()'s dispatch order:
// when several are present the first match wins and the rest are
// ignored (main() prints the mutual-exclusion warning). Keep this in
// sync with the if-chain at the bottom of main() - a new view flag
// needs a row here and a dispatch line there, nothing else; pairwise
// checks would be O(n^2) and drift.
constexpr auto kViewFlags = std::to_array<ViewFlagSpec>({
    {"--xrefs",            [](const Args& a) { return a.xrefs; }},
    {"--data-xrefs",       [](const Args& a) { return a.data_xrefs; }},
    {"--symtable",         [](const Args& a) { return !a.symtable.empty(); }},
    {"--symresolve",       [](const Args& a) { return !a.symresolve.empty(); }},
    {"--symuses",          [](const Args& a) { return !a.symuses.empty(); }},
    {"--refs-to",          [](const Args& a) { return !a.refs_to.empty(); }},
    {"--refs-to-loose",    [](const Args& a) { return !a.refs_to_loose.empty(); }},
    {"--state-map",        [](const Args& a) { return !a.state_map.empty(); }},
    {"--branch-on",        [](const Args& a) { return !a.branch_on.empty(); }},
    {"--guard-map",        [](const Args& a) { return !a.guard_map.empty(); }},
    {"--state-lifetime",   [](const Args& a) { return !a.state_lifetime.empty(); }},
    {"--side-effects",     [](const Args& a) { return !a.side_effects.empty(); }},
    {"--object-roles",     [](const Args& a) { return !a.object_roles.empty(); }},
    {"--explain-address",  [](const Args& a) { return !a.explain_address.empty(); }},
    {"--explain-vcall",    [](const Args& a) { return !a.explain_vcall.empty(); }},
    {"--recover-imports",  [](const Args& a) { return a.recover_imports; }},
    {"--vtable-at",        [](const Args& a) { return !a.vtable_at.empty(); }},
    {"--dump-object",      [](const Args& a) { return !a.dump_object.empty(); }},
    {"--containing-fn",    [](const Args& a) { return !a.containing_fn.empty(); }},
    {"--validate",         [](const Args& a) { return !a.validate_name.empty(); }},
    {"--collisions",       [](const Args& a) { return a.collisions; }},
    {"--callees",          [](const Args& a) { return !a.callees.empty(); }},
    {"--callees-class",    [](const Args& a) { return !a.callees_class.empty(); }},
    {"--patch-plan",       [](const Args& a) { return !a.patch_plan.empty(); }},
    {"--disasm-at",        [](const Args& a) { return !a.disasm_at.empty(); }},
    {"--disasm-window",    [](const Args& a) { return !a.disasm_window.empty(); }},
    {"--list-syscalls",    [](const Args& a) { return !a.list_syscalls.empty(); }},
    {"--forge-spec",       [](const Args& a) { return !a.forge_spec.empty(); }},
    {"--annotate",         [](const Args& a) { return !a.annotate_addr.empty(); }},
    {"--list-annotations", [](const Args& a) { return a.list_annotations; }},
    {"--decompile-data",   [](const Args& a) { return !a.decompile_data.empty(); }},
    {"--evt-script",       [](const Args& a) { return !a.evt_script.empty(); }},
    {"--strings",          [](const Args& a) { return a.strings; }},
    {"--surfaces",         [](const Args& a) { return a.surfaces; }},
    {"--graphics",         [](const Args& a) { return a.graphics; }},
    {"--log-categories",   [](const Args& a) { return a.log_categories; }},
    {"--fingerprints",     [](const Args& a) { return a.fingerprints; }},
    {"--identify",         [](const Args& a) { return a.identify; }},
    {"--objc-names",       [](const Args& a) { return a.objc_names; }},
    {"--objc-protocols",   [](const Args& a) { return a.objc_protos; }},
    {"--objc-surfaces",    [](const Args& a) { return a.objc_surfaces; }},
    {"--rtti",             [](const Args& a) { return a.rtti; }},
    {"--vtables",          [](const Args& a) { return a.vtables; }},
    {"--int3-resolve",     [](const Args& a) { return a.int3_resolve; }},
    {"--ppc-coverage",     [](const Args& a) { return a.ppc_coverage; }},
    {"--arities",          [](const Args& a) { return a.arities; }},
    {"--functions",        [](const Args& a) { return a.functions; }},
}

);

}  // namespace

std::string_view functions_cache_tag(const Args& args) {
    return args.full_analysis
               ? (args.infer_string_names ? kFunctionsFullInferredCacheTag : kFunctionsFullCacheTag)
               : (args.infer_string_names ? kFunctionsInferredCacheTag : kFunctionsCacheTag);
}

std::vector<std::string_view> requested_view_flags(const Args& args) {
    std::vector<std::string_view> names;
    for (const auto& flag : kViewFlags) {
        if (flag.present(args)) names.push_back(flag.name);
    }
    return names;
}

std::optional<int> run_functions_cache_only(const Args& args) {
    if (!args.functions || args.no_cache || args.json || !args.module_filter.empty()) {
        return std::nullopt;
    }
    // When conflicting view flags are present the dispatch chain picks a
    // winner that may not be --functions; serving the cached listing
    // from here would let a warm cache outrank that winner (and fire
    // before main's warning could change the outcome). Step aside and
    // let the chain decide.
    const auto requested = requested_view_flags(args);
    if (requested.size() > 1 && requested.front() != "--functions") {
        return std::nullopt;
    }

    const auto dir =
        args.cache_dir.empty() ? cache::default_dir() : std::filesystem::path(args.cache_dir);
    auto key = cache::key_for(args.binary, cache_scope_tag(args));
    if (!key)
        return std::nullopt;
    auto hit = cache::read(dir, *key, functions_cache_tag(args));
    if (!hit)
        return std::nullopt;

    const Annotations ann = load_annotations_quiet(args);
    if (ann.renames.empty() && args.functions_pattern.empty() &&
        (!args.row_limit_set || args.row_limit == 0)) {
        std::fwrite(hit->data(), 1, hit->size(), stdout);
        return EXIT_SUCCESS;
    }

    auto parse_addr = [](std::string_view s) -> std::optional<addr_t> {
        if (s.starts_with("0x") || s.starts_with("0X"))
            s.remove_prefix(2);
        addr_t v = 0;
        for (char c : s) {
            const int d = (c >= '0' && c <= '9')   ? c - '0'
                          : (c >= 'a' && c <= 'f') ? c - 'a' + 10
                          : (c >= 'A' && c <= 'F') ? c - 'A' + 10
                                                   : -1;
            if (d < 0)
                return std::nullopt;
            v = (v << 4) | static_cast<addr_t>(d);
        }
        return v;
    };

    std::string needle = args.functions_pattern;
    for (auto& c : needle)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    std::size_t pos = 0;
    std::size_t emitted = 0;
    while (pos < hit->size()) {
        const auto nl = hit->find('\n', pos);
        const std::size_t line_end = (nl == std::string::npos) ? hit->size() : nl;
        std::string_view line(hit->data() + pos, line_end - pos);
        std::size_t tabs = 0, name_start = 0, addr_end = 0;
        for (std::size_t i = 0; i < line.size() && tabs < 3; ++i) {
            if (line[i] == '\t') {
                if (tabs == 0)
                    addr_end = i;
                if (++tabs == 3)
                    name_start = i + 1;
            }
        }
        const auto row_addr = parse_addr(line.substr(0, addr_end));
        const std::string* rn = row_addr ? [&]() -> const std::string* {
            auto it = ann.renames.find(*row_addr);
            return it == ann.renames.end() ? nullptr : &it->second;
        }()
            : nullptr;
        const std::string_view discovered_name = line.substr(name_start);
        const std::string_view effective_name = rn ? std::string_view{*rn} : discovered_name;
        if (!needle.empty()) {
            std::string name_lc(effective_name);
            for (auto& c : name_lc)
                c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            if (name_lc.find(needle) == std::string::npos) {
                pos = (nl == std::string::npos) ? hit->size() : nl + 1;
                continue;
            }
        }
        if (rn) {
            std::fwrite(line.data(), 1, name_start, stdout);
            std::fwrite(effective_name.data(), 1, effective_name.size(), stdout);
            std::fputc('\n', stdout);
        } else {
            std::fwrite(line.data(), 1, line.size(), stdout);
            std::fputc('\n', stdout);
        }
        ++emitted;
        if (args.row_limit_set && args.row_limit != 0 && emitted >= args.row_limit)
            break;
        pos = (nl == std::string::npos) ? hit->size() : nl + 1;
    }
    return EXIT_SUCCESS;
}

int run_ppc_coverage(const Args& args, const Binary& b) {
    if (b.arch() != Arch::Ppc32 && b.arch() != Arch::Ppc64) {
        std::println(stderr, "spelunk: --ppc-coverage: binary arch is {}, expected ppc32/ppc64",
                     arch_name(b.arch()));
        return EXIT_FAILURE;
    }

    struct Hit {
        u32 word = 0;
        std::size_t count = 0;
        std::vector<addr_t> samples;
        std::string error;
    };

    struct OpaqueHit {
        std::string name;
        std::string mnemonic;
        std::size_t count = 0;
        std::vector<addr_t> samples;
    };

    auto word_at = [&](const std::byte* p) noexcept -> u32 {
        return b.endian() == Endian::Big ? read_be_at<u32>(p) : read_le_at<u32>(p);
    };

    auto shape_for = [](u32 word) {
        const u32 op = word >> 26;
        const u32 xo = (word >> 1) & 0x3ffu;
        const u32 fp_xo = (word >> 1) & 0x1fu;
        if (op == 19 || op == 31) return std::format("op={} xo={}", op, xo);
        if (op == 59 || op == 63) return std::format("op={} xo={} fp_xo={}", op, xo, fp_xo);
        if (op == 58 || op == 62) return std::format("op={} ds_xo={}", op, word & 0x3u);
        return std::format("op={}", op);
    };

    PpcDecoder dec(b.endian());
    auto lifter_r = make_lifter(b);
    if (!lifter_r) return report(lifter_r.error());
    std::unordered_map<u32, Hit> unsupported;
    std::unordered_map<std::string, OpaqueHit> opaque;
    std::size_t executable_sections = 0;
    std::size_t total_words = 0;
    std::size_t padding_words = 0;
    std::size_t decoded_words = 0;
    std::size_t unsupported_words = 0;
    std::size_t opaque_lift_words = 0;

    for (const auto& sec : b.sections()) {
        if (!sec.flags.executable || sec.data.size() < 4) continue;
        ++executable_sections;
        const auto data = sec.data;
        const std::size_t n = data.size() & ~std::size_t{3};
        for (std::size_t off = 0; off < n; off += 4) {
            const addr_t va = sec.vaddr + static_cast<addr_t>(off);
            auto rv = dec.decode(data.subspan(off, 4), va);
            ++total_words;
            if (rv) {
                ++decoded_words;

                // Decoder coverage alone can hide the more useful frontier:
                // decoded instructions whose semantics still collapse to an
                // opaque ppc.* intrinsic. Lift each word in a one-instruction
                // return block and rank those fallbacks alongside hard decode
                // failures. This intentionally scans executable-section data
                // too, matching the conservative decoder metric above.
                Function fn;
                fn.start = va;
                fn.end = va + 4;
                BasicBlock bb;
                bb.start = fn.start;
                bb.end = fn.end;
                bb.kind = BlockKind::Return;
                bb.instructions.push_back(*rv);
                fn.blocks.push_back(std::move(bb));
                auto ir = (*lifter_r)->lift(fn);
                if (!ir) return report(ir.error());

                bool word_is_opaque = false;
                for (const auto& ir_bb : ir->blocks) {
                    for (const auto& inst : ir_bb.insts) {
                        if (inst.op != IrOp::Intrinsic ||
                            !std::string_view(inst.name).starts_with("ppc.")) {
                            continue;
                        }
                        word_is_opaque = true;
                        auto& h = opaque[inst.name];
                        h.name = inst.name;
                        h.mnemonic = mnemonic_name(rv->mnemonic);
                        ++h.count;
                        if (h.samples.size() < 4) h.samples.push_back(va);
                    }
                }
                if (word_is_opaque) ++opaque_lift_words;
                continue;
            }
            ++unsupported_words;
            const u32 word = word_at(data.data() + off);
            if (word == 0) {
                ++padding_words;
                continue;
            }
            auto& h = unsupported[word];
            h.word = word;
            ++h.count;
            if (h.samples.size() < 4) h.samples.push_back(va);
            if (h.error.empty()) h.error = rv.error().message;
        }
    }

    std::vector<const Hit*> rows;
    rows.reserve(unsupported.size());
    for (const auto& [_, h] : unsupported) rows.push_back(&h);
    std::sort(rows.begin(), rows.end(), [](const Hit* lhs, const Hit* rhs) {
        if (lhs->count != rhs->count) return lhs->count > rhs->count;
        return lhs->word < rhs->word;
    });
    if (args.ppc_coverage_limit != 0 &&
        rows.size() > static_cast<std::size_t>(args.ppc_coverage_limit)) {
        rows.resize(static_cast<std::size_t>(args.ppc_coverage_limit));
    }

    std::vector<const OpaqueHit*> opaque_rows;
    opaque_rows.reserve(opaque.size());
    for (const auto& [_, h] : opaque) opaque_rows.push_back(&h);
    std::sort(opaque_rows.begin(), opaque_rows.end(),
              [](const OpaqueHit* lhs, const OpaqueHit* rhs) {
                  if (lhs->count != rhs->count) return lhs->count > rhs->count;
                  return lhs->name < rhs->name;
              });
    if (args.ppc_coverage_limit != 0 &&
        opaque_rows.size() > static_cast<std::size_t>(args.ppc_coverage_limit)) {
        opaque_rows.resize(static_cast<std::size_t>(args.ppc_coverage_limit));
    }

    const double coverage = total_words == 0
        ? 100.0
        : (100.0 * static_cast<double>(decoded_words) / static_cast<double>(total_words));

    if (args.json) {
        std::string out = std::format(
            "{{\"arch\":\"{}\",\"endian\":\"{}\",\"executable_sections\":{},"
            "\"total_words\":{},\"decoded_words\":{},\"unsupported_words\":{},"
            "\"padding_words\":{},\"coverage\":{:.3f},"
            "\"opaque_lift_words\":{},\"unsupported\":[",
            arch_name(b.arch()), endian_name(b.endian()), executable_sections,
            total_words, decoded_words, unsupported_words, padding_words, coverage,
            opaque_lift_words);
        bool first = true;
        for (const Hit* h : rows) {
            if (!first) out += ',';
            first = false;
            out += std::format("{{\"word\":\"0x{:08x}\",\"count\":{},\"shape\":\"{}\","
                               "\"error\":\"{}\",\"samples\":[",
                               h->word, h->count, json_escape(shape_for(h->word)),
                               json_escape(h->error));
            for (std::size_t i = 0; i < h->samples.size(); ++i) {
                if (i) out += ',';
                out += std::format("\"{:#x}\"", h->samples[i]);
            }
            out += "]}";
        }
        out += "],\"opaque_lifts\":[";
        first = true;
        for (const OpaqueHit* h : opaque_rows) {
            if (!first) out += ',';
            first = false;
            out += std::format("{{\"name\":\"{}\",\"mnemonic\":\"{}\",\"count\":{},"
                               "\"samples\":[",
                               json_escape(h->name), json_escape(h->mnemonic), h->count);
            for (std::size_t i = 0; i < h->samples.size(); ++i) {
                if (i) out += ',';
                out += std::format("\"{:#x}\"", h->samples[i]);
            }
            out += "]}";
        }
        out += "]}\n";
        std::fwrite(out.data(), 1, out.size(), stdout);
        return EXIT_SUCCESS;
    }

    std::println("; ppc coverage: decoded {}/{} words ({:.1f}%), unsupported {} (padding {}) across {} executable section(s)",
                 decoded_words, total_words, coverage, unsupported_words, padding_words, executable_sections);
    std::println("count\tword\tshape\tsamples\terror");
    for (const Hit* h : rows) {
        std::string samples;
        for (std::size_t i = 0; i < h->samples.size(); ++i) {
            if (i) samples += ",";
            samples += std::format("{:#x}", h->samples[i]);
        }
        std::println("{}\t0x{:08x}\t{}\t{}\t{}",
                     h->count, h->word, shape_for(h->word), samples, h->error);
    }
    std::println("; opaque lift fallbacks: {} decoded words", opaque_lift_words);
    std::println("count\tintrinsic\tmnemonic\tsamples");
    for (const OpaqueHit* h : opaque_rows) {
        std::string samples;
        for (std::size_t i = 0; i < h->samples.size(); ++i) {
            if (i) samples += ",";
            samples += std::format("{:#x}", h->samples[i]);
        }
        std::println("{}\t{}\t{}\t{}", h->count, h->name, h->mnemonic, samples);
    }
    return EXIT_SUCCESS;
}

int run_arities(const Args& args, const Binary& b) {
    if (args.row_limit_set) {
        std::string out;
        std::size_t emitted = 0;
        for (const auto& fn : enumerate_functions(b, EnumerateMode::Auto)) {
            if (b.import_at_plt(fn.addr)) continue;
            if (args.row_limit != 0 && emitted >= args.row_limit) break;
            out += std::format("{:#x} {}\n", fn.addr, infer_arity(b, fn.addr));
            ++emitted;
        }
        std::print("{}", out);
        return EXIT_SUCCESS;
    }
    return run_cached(args, kAritiesCacheTag, [&] { return build_arities_output(b); });
}

int run_functions(const Args& args, const Binary& b) {
    ScopedTimer total_timer("functions.total");
    // Full TSV is cacheable independent of the pattern - build once,
    // filter at print time so the cache works across grep sessions.
    std::string tsv;
    const auto dir =
        args.cache_dir.empty() ? cache::default_dir() : std::filesystem::path(args.cache_dir);
    std::string key;
    bool cacheable = !args.no_cache;
    if (cacheable) {
        auto k = cache::key_for(args.binary, cache_scope_tag(args));
        if (k)
            key = std::move(*k);
        else {
            std::println(stderr, "spelunk: warning: {}: {} (caching disabled)", k.error().kind_name(),
                         k.error().message);
            cacheable = false;
        }
    }
    // Different cache tag per mode: --full-analysis returns a strict
    // superset (and on packed binaries, a polluted one). Sharing one tag
    // would let a fast --functions run poison the cache for a later
    // --full-analysis user.
    const std::string_view fns_tag = functions_cache_tag(args);
    if (cacheable) {
        ScopedTimer phase("functions.cache_read");
        if (auto hit = cache::read(dir, key, fns_tag); hit) {
            tsv.assign(hit->data(), hit->size());
        }
    }
    if (tsv.empty()) {
        ScopedTimer phase("functions.cache_miss");
        tsv = build_functions_output(b, args.full_analysis);
        if (cacheable) {
            ScopedTimer write_phase("functions.cache_write");
            if (auto rv = cache::write(dir, key, fns_tag, tsv); !rv) {
                std::println(stderr, "spelunk: warning: {}: {}", rv.error().kind_name(),
                             rv.error().message);
            }
        }
    }
    // Resolve --module if set. Filtering is applied at output time so
    // the cache stays a single full-binary blob - different scope
    // requests reuse the same cached payload.
    const ModuleScope scope = resolve_module_scope(b, args.module_filter);
    if (!args.module_filter.empty() && !scope.active)
        return EXIT_FAILURE;

    auto parse_addr = [](std::string_view s) -> std::optional<addr_t> {
        if (s.starts_with("0x") || s.starts_with("0X"))
            s.remove_prefix(2);
        addr_t v = 0;
        for (char c : s) {
            const int d = (c >= '0' && c <= '9')   ? c - '0'
                          : (c >= 'a' && c <= 'f') ? c - 'a' + 10
                          : (c >= 'A' && c <= 'F') ? c - 'A' + 10
                                                   : -1;
            if (d < 0)
                return std::nullopt;
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

    if (!args.json && args.functions_pattern.empty() && !scope.active && !any_rename &&
        !args.row_limit_set) {
        ScopedTimer phase("functions.emit_raw");
        std::fwrite(tsv.data(), 1, tsv.size(), stdout);
        return EXIT_SUCCESS;
    }

    std::string needle = args.functions_pattern;
    for (auto& c : needle)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    if (args.json)
        std::fputs("[", stdout);
    bool first = true;
    std::size_t emitted = 0;

    ScopedTimer filter_phase("functions.filter_emit");
    std::size_t pos = 0;
    while (pos < tsv.size()) {
        const auto nl = tsv.find('\n', pos);
        const std::size_t end = (nl == std::string::npos) ? tsv.size() : nl;
        std::string_view line(tsv.data() + pos, end - pos);
        // Columns: addr\tsize\tkind\tname.
        std::size_t tabs = 0, name_start = 0, addr_end = 0, size_end = 0, kind_end = 0;
        for (std::size_t i = 0; i < line.size() && tabs < 3; ++i) {
            if (line[i] == '\t') {
                if (tabs == 0)
                    addr_end = i;
                else if (tabs == 1)
                    size_end = i;
                else if (tabs == 2)
                    kind_end = i;
                if (++tabs == 3)
                    name_start = i + 1;
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
        const std::string_view effective_name = rn ? std::string_view{*rn} : discovered_name;
        if (!needle.empty()) {
            std::string name_lc(effective_name);
            for (auto& c : name_lc)
                c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            if (name_lc.find(needle) == std::string::npos) {
                pos = (nl == std::string::npos) ? tsv.size() : nl + 1;
                continue;
            }
        }
        if (args.json) {
            if (!first)
                std::fputs(",", stdout);
            first = false;
            const std::string_view size_s = line.substr(addr_end + 1, size_end - addr_end - 1);
            const std::string_view kind_s = line.substr(size_end + 1, kind_end - size_end - 1);
            std::string row =
                std::format("{{\"addr\":\"{}\",\"size\":\"{}\",\"kind\":\"{}\",\"name\":\"{}\"",
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
        ++emitted;
        if (args.row_limit_set && args.row_limit != 0 && emitted >= args.row_limit)
            break;
        pos = (nl == std::string::npos) ? tsv.size() : nl + 1;
    }
    if (args.json)
        std::fputs("]\n", stdout);
    return EXIT_SUCCESS;
}

}  // namespace spelunk::cli

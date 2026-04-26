#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <cstdlib>
#include <format>
#include <filesystem>
#include <fstream>
#include <map>
#include <optional>
#include <print>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>

#include <ember/analysis/arity.hpp>
#include <ember/analysis/cfg_builder.hpp>
#include <ember/analysis/data_xrefs.hpp>
#include <ember/analysis/eh_frame.hpp>
#include <ember/analysis/fingerprint.hpp>
#include <ember/analysis/indirect_calls.hpp>
#include <ember/analysis/function.hpp>
#include <ember/analysis/objc.hpp>
#include <ember/analysis/pe_unwind.hpp>
#include <ember/analysis/pipeline.hpp>
#include <ember/analysis/rtti.hpp>
#include <ember/analysis/vm_detect.hpp>
#include <ember/analysis/sig_inference.hpp>
#include <ember/analysis/strings.hpp>
#include <ember/binary/binary.hpp>
#include <ember/binary/raw_regions.hpp>
#include <ember/common/annotations.hpp>
#include <ember/common/cache.hpp>
#include <ember/common/progress.hpp>
#include <ember/disasm/instruction.hpp>
#include <ember/disasm/decoder.hpp>
#include <ember/ir/ir.hpp>
#include <ember/ir/passes.hpp>
#include <ember/ir/ssa.hpp>
#include <ember/ir/lifter.hpp>
#include <ember/ir/types.hpp>
#include <ember/decompile/emitter.hpp>
#include <ember/script/runtime.hpp>
#include <ember/structure/region.hpp>
#include <ember/structure/structurer.hpp>

#include "args.hpp"
#include "cli_error.hpp"
#include "fingerprint.hpp"
#include "subcommands.hpp"

namespace {

using namespace ember::cli;

// Parse an address from the command line. Accepts `0x…`, `0X…`,
// `sub_…`, or plain hex (requires a-f/A-F letter to disambiguate from
// decimal-looking names). Nullopt on malformed input.
[[nodiscard]] std::optional<ember::addr_t>
parse_cli_addr(std::string_view s) {
    if (s.starts_with("sub_"))          s.remove_prefix(4);
    else if (s.starts_with("0x") || s.starts_with("0X")) s.remove_prefix(2);
    if (s.empty() || s.size() > 16) return std::nullopt;
    for (char c : s) {
        const bool ok = (c >= '0' && c <= '9') ||
                        (c >= 'a' && c <= 'f') ||
                        (c >= 'A' && c <= 'F');
        if (!ok) return std::nullopt;
    }
    ember::u64 v = 0;
    auto r = std::from_chars(s.data(), s.data() + s.size(), v, 16);
    if (r.ec != std::errc{}) return std::nullopt;
    return static_cast<ember::addr_t>(v);
}

struct BoolFlag {
    std::string_view short_;        // may be empty
    std::string_view long_;
    bool Args::* field;
};

struct ValueFlag {
    std::string_view short_;        // may be empty
    std::string_view long_;
    std::string Args::* field;
};

constexpr auto kBoolFlags = std::to_array<BoolFlag>({
    {"-h", "--help",      &Args::help},
    {"-d", "--disasm",    &Args::disasm},
    {"-c", "--cfg",       &Args::cfg},
    {"-i", "--ir",        &Args::ir},
    {"",   "--ssa",       &Args::ssa},
    {"-O", "--opt",       &Args::opt},
    {"",   "--struct",    &Args::strct},
    {"-p", "--pseudo",    &Args::pseudo},
    {"-X", "--xrefs",     &Args::xrefs},
    {"",   "--data-xrefs", &Args::data_xrefs},
    {"",   "--strings",   &Args::strings},
    {"",   "--arities",   &Args::arities},
    {"",   "--fingerprints", &Args::fingerprints},
    {"",   "--ipa",       &Args::ipa},
    {"",   "--resolve-calls", &Args::resolve_calls},
    {"",   "--eh",        &Args::eh},
    {"",   "--objc-names", &Args::objc_names},
    {"",   "--objc-protocols", &Args::objc_protos},
    {"",   "--rtti",     &Args::rtti},
    {"",   "--vm-detect", &Args::vm_detect},
    {"",   "--cfg-pseudo", &Args::cfg_pseudo},
    {"",   "--functions", &Args::functions},
    {"",   "--collisions", &Args::collisions},
    {"",   "--no-cache",  &Args::no_cache},
    {"",   "--full-analysis", &Args::full_analysis},
    {"",   "--dump-types", &Args::dump_types},
    {"",   "--labels",    &Args::labels},
    {"",   "--json",      &Args::json},
    {"-q", "--quiet",     &Args::quiet},
});

constexpr auto kValueFlags = std::to_array<ValueFlag>({
    {"-s", "--symbol",      &Args::symbol},
    {"",   "--annotations", &Args::annotations_path},
    {"",   "--export-annotations", &Args::export_annotations},
    {"",   "--trace",       &Args::trace_path},
    {"",   "--cache-dir",   &Args::cache_dir},
    {"",   "--project",     &Args::project_path},
    {"",   "--script",      &Args::script_path},
    {"",   "--diff",        &Args::diff_path},
    {"",   "--diff-format", &Args::diff_format},
    {"",   "--fingerprint-out", &Args::fp_out},
    {"",   "--fingerprint-old", &Args::fp_old_in},
    {"",   "--fingerprint-new", &Args::fp_new_in},
    {"",   "--refs-to",     &Args::refs_to},
    {"",   "--callees",      &Args::callees},
    {"",   "--containing-fn", &Args::containing_fn},
    {"",   "--validate",    &Args::validate_name},
    {"",   "--callees-class", &Args::callees_class},
    {"",   "--disasm-at",   &Args::disasm_at},
    {"",   "--count",       &Args::disasm_count},
    {"",   "--apply-patches", &Args::apply_patches},
    {"-o", "--output",      &Args::output_path},
    {"",   "--regions",     &Args::regions_manifest},
});

template <class F>
bool matches(std::string_view s, const F& f) {
    return (!f.short_.empty() && s == f.short_) || s == f.long_;
}

// Stage implications: picking a later stage requires all earlier ones.
void apply_stage_implications(Args& a) {
    if (a.pseudo) a.strct = true;
    if (a.strct)  a.opt   = true;
    if (a.opt)    a.ssa   = true;
    if (a.ssa)    a.ir    = true;
}

[[nodiscard]] ember::Result<Args> parse_args(int argc, char** argv) {
    Args a;
    for (int i = 1; i < argc; ++i) {
        const std::string_view s = argv[i];
        if (s == "--") {
            for (int j = i + 1; j < argc; ++j) a.script_argv.emplace_back(argv[j]);
            break;
        }

        // `--functions=PATTERN` — unambiguous way to specify the filter
        // without positional-order gotchas (main vs binary path).
        if (s.starts_with("--functions=")) {
            a.functions = true;
            a.functions_pattern = std::string(s.substr(12));
            continue;
        }

        bool hit = false;
        for (const auto& f : kBoolFlags) {
            if (matches(s, f)) { a.*f.field = true; hit = true; break; }
        }
        if (hit) continue;

        for (const auto& f : kValueFlags) {
            if (matches(s, f)) {
                if (++i >= argc) {
                    return std::unexpected(ember::Error::invalid_format(
                        std::format("{} requires an argument", s)));
                }
                a.*f.field = argv[i];
                hit = true;
                break;
            }
        }
        if (hit) continue;

        if (s.starts_with("-")) {
            return std::unexpected(ember::Error::invalid_format(
                std::format("unknown flag: {}", s)));
        } else if (a.binary.empty()) {
            a.binary = s;
        } else if (a.functions && a.functions_pattern.empty()) {
            a.functions_pattern = s;
        } else {
            return std::unexpected(ember::Error::invalid_format(
                std::format("unexpected positional argument: {}", s)));
        }
    }
    // Rescue the common `ember --functions PATTERN BINARY` mis-order:
    // positionals are taken left-to-right, so a user who types the
    // filter first has PATTERN interpreted as the binary path. If the
    // binary slot names a non-existent path but the pattern slot names
    // an existing file, swap them.
    if (a.functions && !a.binary.empty() && !a.functions_pattern.empty()) {
        namespace fs = std::filesystem;
        std::error_code ec;
        const bool bin_is_file = fs::is_regular_file(a.binary, ec);
        const bool pat_is_file = fs::is_regular_file(a.functions_pattern, ec);
        if (!bin_is_file && pat_is_file) {
            std::swap(a.binary, a.functions_pattern);
        }
    }

    // A positional binary is not required when the user is diffing two
    // already-computed fingerprint TSVs — no bytes to parse. Likewise
    // --dump-types is a self-test that doesn't read any binary, and
    // --regions points at a manifest instead of a binary positional.
    const bool diffs_from_tsvs = !a.fp_old_in.empty() && !a.fp_new_in.empty();
    if (!a.help && a.binary.empty() && !diffs_from_tsvs && !a.dump_types
        && a.regions_manifest.empty()) {
        return std::unexpected(ember::Error::invalid_format("no binary specified"));
    }
    apply_stage_implications(a);
    return a;
}

[[nodiscard]] constexpr std::string_view flag_str(ember::SectionFlags f) noexcept {
    constexpr std::string_view table[8] = {
        "---", "r--", "-w-", "rw-",
        "--x", "r-x", "-wx", "rwx",
    };
    const unsigned idx =
        (f.readable   ? 0b0001u : 0u) |
        (f.writable   ? 0b0010u : 0u) |
        (f.executable ? 0b0100u : 0u);
    return table[idx & 0x7];
}

void print_info(const ember::Binary& b, std::string_view path) {
    std::println("file    {}", path);
    std::println("format  {}", ember::format_name(b.format()));
    std::println("arch    {}", ember::arch_name(b.arch()));
    std::println("endian  {}", ember::endian_name(b.endian()));
    std::println("entry   {:#018x}", b.entry_point());

    const auto secs = b.sections();
    std::println("");
    std::println("sections ({})", secs.size());
    std::println("  {:>3}  {:<24} {:>18} {:>10}  {}", "idx", "name", "vaddr", "size", "flags");
    std::size_t i = 0;
    for (const auto& s : secs) {
        std::println("  {:>3}  {:<24} {:>#18x} {:>#10x}  {}",
                     i++, s.name, s.vaddr, s.size, flag_str(s.flags));
    }

    const auto syms = b.symbols();
    std::size_t n_defined = 0;
    std::size_t n_imports = 0;
    for (const auto& s : syms) (s.is_import ? n_imports : n_defined)++;

    std::println("");
    std::println("defined symbols ({})", n_defined);
    std::println("  {:>18} {:>8}  {:<8}  {}", "addr", "size", "kind", "name");
    for (const auto& s : syms) {
        if (s.is_import) continue;
        std::println("  {:>#18x} {:>#8x}  {:<8}  {}",
                     s.addr, s.size, ember::symbol_kind_name(s.kind), s.name);
    }

    std::println("");
    std::println("imports ({})", n_imports);
    std::println("  {:>10}  {:>12}  {:<8}  {}", "plt", "got", "kind", "name");
    for (const auto& s : syms) {
        if (!s.is_import) continue;
        std::println("  {:>#10x}  {:>#12x}  {:<8}  {}",
                     s.addr, s.got_addr, ember::symbol_kind_name(s.kind), s.name);
    }
}


// Minimal JSON string-escape — we emit a tight, machine-readable form.
[[nodiscard]] std::string json_escape(std::string_view s) {
    std::string out;
    out.reserve(s.size() + 2);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    out += std::format("\\u{:04x}", static_cast<unsigned>(c));
                } else {
                    out += c;
                }
        }
    }
    return out;
}

[[nodiscard]] std::string escape_for_line(const std::string& s) {
    // Escape non-printables and the separator char so the UI can tokenize safely.
    std::string out;
    out.reserve(s.size() + 2);
    for (char c : s) {
        const auto uc = static_cast<unsigned char>(c);
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            case '|':  out += "\\|";  break;
            default:
                if (uc < 0x20 || uc > 0x7e) {
                    out += std::format("\\x{:02x}", uc);
                } else {
                    out += c;
                }
        }
    }
    return out;
}

[[nodiscard]] std::string build_strings_output(const ember::Binary& b) {
    // Format: "addr|escaped-text|xref1,xref2,..."  (addrs in hex, no 0x prefix)
    std::string out;
    const auto entries = ember::scan_strings(b);
    for (const auto& e : entries) {
        std::string xrefs;
        for (std::size_t i = 0; i < e.xrefs.size(); ++i) {
            if (i > 0) xrefs += ",";
            xrefs += std::format("{:x}", e.xrefs[i]);
        }
        out += std::format("{:x}|{}|{}\n", e.addr, escape_for_line(e.text), xrefs);
    }
    return out;
}

// TSV: one row per detected VM dispatcher. Format:
//   <function-addr>\t<dispatch-addr>\t<table-addr>\t<handler-count>\t<comma-sep handler addrs>
[[nodiscard]] std::string build_vm_detect_output(const ember::Binary& b) {
    std::string out;
    for (const auto& d : ember::detect_vm_dispatchers(b)) {
        std::string handlers;
        for (std::size_t i = 0; i < d.handlers.size(); ++i) {
            if (i) handlers += ',';
            handlers += std::format("{:x}", d.handlers[i]);
        }
        out += std::format("{:x}\t{:x}\t{:x}\t{}\t{}\n",
                           d.function_addr, d.dispatch_addr,
                           d.table_addr, d.handlers.size(), handlers);
    }
    return out;
}

// TSV: one row per discovered function entry. Format:
//   <addr_hex>\t<size_hex>\t<kind>\t<name>
// `kind` is "symbol" for a defined function symbol or "sub" for an entry
// that only appeared as a call target during CFG walking. Size is 0 for
// `sub` rows — see `enumerate_functions` for why.
[[nodiscard]] std::string build_functions_output(const ember::Binary& b,
                                                  bool full_analysis) {
    std::string out;
    const auto mode = full_analysis ? ember::EnumerateMode::Full
                                    : ember::EnumerateMode::Auto;
    for (const auto& fn : ember::enumerate_functions(b, mode)) {
        out += std::format("{:#018x}\t{:#x}\t{}\t{}\n",
                           fn.addr, fn.size,
                           ember::discovered_kind_name(fn.kind),
                           fn.name);
    }
    return out;
}

[[nodiscard]] std::string build_arities_output(const ember::Binary& b) {
    std::string out;
    for (const auto& s : b.symbols()) {
        if (s.is_import) continue;
        if (s.kind != ember::SymbolKind::Function) continue;
        if (s.size == 0 || s.name.empty()) continue;
        const auto a = ember::infer_arity(b, s.addr);
        out += std::format("{:#x} {}\n", s.addr, a);
    }
    return out;
}

// TSV: one row per ObjC method recovered from __objc_classlist. Format:
//   <imp-hex>\t<[+-]>\t<class>\t<selector>\t<decoded-signature>
[[nodiscard]] std::string build_objc_names_output(const ember::Binary& b) {
    std::string out;
    for (const auto& m : ember::parse_objc_methods(b)) {
        out += std::format("{:x}\t{}\t{}\t{}\t{}\n",
                           m.imp,
                           m.is_class ? '+' : '-',
                           m.cls, m.selector,
                           ember::decode_objc_type(m.type_encoding));
    }
    return out;
}

// Dump Itanium C++ RTTI classes + vtables. One row per (class, vfn_idx,
// imp_addr). Separate meta row per class with vtable address + method
// count so a consumer can regroup if needed.
[[nodiscard]] std::string build_rtti_output(const ember::Binary& b) {
    std::string out;
    const auto classes = ember::parse_itanium_rtti(b);
    for (const auto& c : classes) {
        out += std::format("class\t{:x}\t{:x}\t{}\t{}\t{}\n",
                           c.typeinfo, c.vtable, c.methods.size(),
                           c.demangled_name, c.mangled_name);
        for (std::size_t i = 0; i < c.methods.size(); ++i) {
            out += std::format("vfn\t{:x}\t{}\t{}::vfn_{}\n",
                               c.methods[i], i, c.demangled_name, i);
        }
    }
    return out;
}

// Formal protocol signatures: one block per protocol, each line a method
// formatted as `protocol\t[+-][!?]\tselector\tsignature`. `!` marks
// required, `?` marks optional. Useful for lifting class-method names
// into typed signatures where a class conforms to a known protocol.
[[nodiscard]] std::string build_objc_protocols_output(const ember::Binary& b) {
    std::string out;
    auto emit = [&](const ember::ObjcProtocol& p, const std::vector<ember::ObjcMethod>& ml,
                    char tag, char req) {
        for (const auto& m : ml) {
            out += std::format("{}\t{}{}\t{}\t{}\n",
                               p.name, tag, req, m.selector,
                               ember::decode_objc_type(m.type_encoding));
        }
    };
    for (const auto& p : ember::parse_objc_protocols(b)) {
        emit(p, p.required_instance, '-', '!');
        emit(p, p.required_class,    '+', '!');
        emit(p, p.optional_instance, '-', '?');
        emit(p, p.optional_class,    '+', '?');
    }
    return out;
}

// Rip-relative + absolute memory-operand references to data sections.
// One TSV row per (target, site, kind) tuple, grouped by target:
//   <target-hex>\t<site-hex>\t<kind>
// kind ∈ {read, write, lea}. --json emits [{target, refs: [{site, kind}]}].
[[nodiscard]] std::string build_data_xrefs_output(const ember::Binary& b, bool json) {
    const auto xrefs = ember::compute_data_xrefs(b);
    std::string out;
    if (!json) {
        for (const auto& [target, refs] : xrefs) {
            for (const auto& r : refs) {
                out += std::format("{:x}\t{:x}\t{}\n",
                                   target, r.from_pc,
                                   ember::data_xref_kind_name(r.kind));
            }
        }
        return out;
    }
    out = "[";
    bool first_t = true;
    for (const auto& [target, refs] : xrefs) {
        if (!first_t) out += ',';
        first_t = false;
        out += std::format("{{\"target\":\"{:#x}\",\"refs\":[", target);
        bool first_r = true;
        for (const auto& r : refs) {
            if (!first_r) out += ',';
            first_r = false;
            out += std::format("{{\"site\":\"{:#x}\",\"kind\":\"{}\"}}",
                               r.from_pc, ember::data_xref_kind_name(r.kind));
        }
        out += "]}";
    }
    out += "]\n";
    return out;
}

[[nodiscard]] std::string build_xrefs_output(const ember::Binary& b) {
    // Order edges so leaves come first and the rough `main`-ward hierarchy
    // reads top-down. Topological sort (Kahn's algorithm) over the caller
    // graph; cycles fall through in arbitrary order at the tail.
    const auto edges = ember::compute_call_graph(b);
    std::unordered_map<ember::addr_t, std::vector<ember::addr_t>> succs;
    std::unordered_map<ember::addr_t, std::size_t> indeg;
    std::set<ember::addr_t> nodes;
    for (const auto& e : edges) {
        succs[e.caller].push_back(e.callee);
        indeg[e.callee] += 1;
        if (!indeg.contains(e.caller)) indeg[e.caller] += 0;
        nodes.insert(e.caller);
        nodes.insert(e.callee);
    }
    // Kahn: start with leaves (no outgoing edges → no callers above them yet).
    // We invert the intuition: emit callers before callees, so nodes with
    // zero in-degree (never called) go first. That matches reader habit —
    // main at top, helpers below.
    std::vector<ember::addr_t> order;
    std::vector<ember::addr_t> ready;
    for (ember::addr_t n : nodes) if (indeg[n] == 0) ready.push_back(n);
    std::ranges::sort(ready);  // deterministic output on ties
    while (!ready.empty()) {
        const auto v = ready.back();
        ready.pop_back();
        order.push_back(v);
        auto it = succs.find(v);
        if (it == succs.end()) continue;
        for (ember::addr_t w : it->second) {
            if (--indeg[w] == 0) ready.push_back(w);
        }
    }
    // Append any remaining nodes (those on cycles) in addr order.
    std::set<ember::addr_t> emitted(order.begin(), order.end());
    for (ember::addr_t n : nodes) if (!emitted.contains(n)) order.push_back(n);

    // Group edges by caller in topo order, sort each group by callee for
    // stability within a caller.
    std::unordered_map<ember::addr_t, std::vector<ember::addr_t>> by_caller;
    for (const auto& e : edges) by_caller[e.caller].push_back(e.callee);
    for (auto& [_, v] : by_caller) std::ranges::sort(v);

    std::string out;
    for (ember::addr_t caller : order) {
        auto it = by_caller.find(caller);
        if (it == by_caller.end()) continue;
        for (ember::addr_t callee : it->second) {
            out += std::format("{:#x} -> {:#x}\n", caller, callee);
        }
    }
    return out;
}


template <class Compute>
int run_cached(const Args& args, std::string_view tag, Compute compute) {
    const auto dir = args.cache_dir.empty()
        ? ember::cache::default_dir()
        : std::filesystem::path(args.cache_dir);
    std::string key;
    bool cacheable = !args.no_cache;
    if (cacheable) {
        auto k = ember::cache::key_for(args.binary);
        if (k) {
            key = std::move(*k);
        } else {
            std::println(stderr, "ember: warning: {}: {} (caching disabled)",
                         k.error().kind_name(), k.error().message);
            cacheable = false;
        }
    }
    if (cacheable) {
        if (auto hit = ember::cache::read(dir, key, tag); hit) {
            std::fwrite(hit->data(), 1, hit->size(), stdout);
            return EXIT_SUCCESS;
        }
    }
    const std::string out = compute();
    std::fwrite(out.data(), 1, out.size(), stdout);
    if (cacheable) {
        if (auto rv = ember::cache::write(dir, key, tag, out); !rv) {
            std::println(stderr, "ember: warning: {}: {}",
                         rv.error().kind_name(), rv.error().message);
        }
    }
    return EXIT_SUCCESS;
}



void print_help() {
    std::println("usage: ember [-d|-c|-i|--ssa|-O|--struct|-p] [-s SYMBOL] <binary>");
    std::println("");
    std::println("  -d, --disasm         linear disassembly of a function");
    std::println("  -c, --cfg            control-flow graph of a function (asm bodies)");
    std::println("      --cfg-pseudo     control-flow graph of a function (pseudo-C bodies)");
    std::println("  -i, --ir             lifted IR of a function");
    std::println("      --ssa            IR in SSA form (implies -i)");
    std::println("  -O, --opt            run cleanup passes (implies --ssa)");
    std::println("      --struct         structured regions (implies -O)");
    std::println("  -p, --pseudo         pseudo-C output (implies --struct)");
    std::println("  -X, --xrefs          emit full call graph (all fn -> call targets)");
    std::println("      --strings        dump printable strings (addr|text|xrefs)");
    std::println("      --arities        dump inferred arity per function (addr N)");
    std::println("      --functions [P]  list every discovered function (symbols ∪ sub_*) as TSV;");
    std::println("                       optional substring P filters by name (case-insensitive).");
    std::println("                       Prefer --functions=P to avoid positional-order ambiguity");
    std::println("                       with the binary path.");
    std::println("      --fingerprints   dump address-independent content hash per function");
    std::println("      --diff OLD       diff OLD binary vs the positional binary by fingerprint");
    std::println("      --diff-format    'tsv' (default) or 'json' for --diff output");
    std::println("      --fingerprint-out P  also write --fingerprints TSV to P (portable across machines)");
    std::println("      --fingerprint-old P  skip OLD-side fingerprint compute in --diff; read TSV from P");
    std::println("      --fingerprint-new P  skip NEW-side fingerprint compute in --diff; read TSV from P");
    std::println("      --refs-to VA     list callers of VA (one-shot reverse xref)");
    std::println("      --data-xrefs     TSV: <target>\\t<site>\\t<kind> for every rip-rel/abs");
    std::println("                       data-section reference (kind=read/write/lea)");
    std::println("      --callees VA     list direct/tail/indirect_const callees of the function at VA");
    std::println("      --containing-fn VA  entry/size/name/offset of the function covering VA (TSV/JSON)");
    std::println("      --validate NAME  list every addr bound to NAME + byte-similar lookalikes (TSV/JSON)");
    std::println("      --collisions     dump every name and fingerprint bound to >1 address (TSV/JSON)");
    std::println("      --callees-class NAME  JSON: {{slot_N: [callees]}} for every vfn of an RTTI class");
    std::println("      --json           machine-readable output for --callees / --callees-class");
    std::println("      --disasm-at VA   disasm a bounded window at VA (default 32 insns; --count N to override)");
    std::println("      --ipa            run interprocedural char*-arg propagation before -p/--struct");
    std::println("      --eh             parse __eh_frame + LSDA; annotate landing-pad blocks");
    std::println("      --objc-names     dump recovered Obj-C methods as TSV (imp, ±, class, selector, sig)");
    std::println("      --objc-protocols dump Obj-C protocol method signatures");
    std::println("      --rtti           dump Itanium C++ RTTI: classes + vtables + IMPs");
    std::println("      --vm-detect      scan for interpreter-style VM dispatchers (TSV)");
    std::println("  -s, --symbol NAME    target a specific symbol (default: main)");
    std::println("      --annotations P  explicit project file with renames/signatures (overrides");
    std::println("                       the sidecar/cache auto-load)");
    std::println("      --export-annotations P  copy the currently-resolved annotations file to P");
    std::println("      --trace PATH     load indirect-edge trace (TSV: from\\tto per line)");
    std::println("      --labels         keep // bb_XXXX comments in pseudo-C output");
    std::println("      --project PATH   project file scripts may read/write via project.*");
    std::println("      --script PATH    run a JavaScript file against the loaded binary");
    std::println("      -- ARG...        pass remaining args to the script as argv");
    std::println("      --cache-dir DIR  override ~/.cache/ember for disk cache");
    std::println("      --no-cache       bypass the disk cache (--xrefs/strings/arities)");
    std::println("      --apply-patches FILE  apply byte patches (vaddr_hex bytes_hex per line)");
    std::println("  -o, --output PATH    output path (required with --apply-patches)");
    std::println("  -q, --quiet          suppress stderr progress output");
    std::println("  -h, --help           show this help");
}

// Read a patches file: one patch per line, `<vaddr_hex> <bytes_hex>`.
// `vaddr_hex` is required to be 0x-prefixed for clarity; `bytes_hex` is
// a contiguous hex string (whitespace tolerated, but no 0x prefixes
// inside). Comments (`#`) and blank lines skipped.
struct Patch { ember::addr_t vaddr; std::vector<std::byte> bytes; };
[[nodiscard]] ember::Result<std::vector<Patch>>
parse_patches_file(const std::string& path) {
    std::ifstream f(path);
    if (!f) return std::unexpected(
        ember::Error::io(std::format("cannot open patches file '{}'", path)));
    std::vector<Patch> out;
    std::string line;
    std::size_t line_no = 0;
    while (std::getline(f, line)) {
        ++line_no;
        std::size_t p = 0;
        while (p < line.size() && std::isspace(static_cast<unsigned char>(line[p]))) ++p;
        if (p == line.size() || line[p] == '#') continue;

        // Address token.
        std::size_t addr_end = p;
        while (addr_end < line.size() &&
               !std::isspace(static_cast<unsigned char>(line[addr_end]))) ++addr_end;
        std::string_view addr_tok(line.data() + p, addr_end - p);
        if (!addr_tok.starts_with("0x") && !addr_tok.starts_with("0X")) {
            return std::unexpected(ember::Error::invalid_format(std::format(
                "patches '{}' line {}: vaddr must be 0x-prefixed", path, line_no)));
        }
        addr_tok.remove_prefix(2);
        ember::u64 va = 0;
        auto ar = std::from_chars(addr_tok.data(), addr_tok.data() + addr_tok.size(), va, 16);
        if (ar.ec != std::errc{} || ar.ptr != addr_tok.data() + addr_tok.size()) {
            return std::unexpected(ember::Error::invalid_format(std::format(
                "patches '{}' line {}: bad hex vaddr", path, line_no)));
        }

        // Bytes: pairs of hex digits, whitespace ignored.
        std::string hex;
        for (std::size_t i = addr_end; i < line.size(); ++i) {
            if (!std::isspace(static_cast<unsigned char>(line[i]))) hex.push_back(line[i]);
        }
        if (hex.empty()) {
            return std::unexpected(ember::Error::invalid_format(std::format(
                "patches '{}' line {}: missing bytes", path, line_no)));
        }
        if (hex.size() % 2 != 0) {
            return std::unexpected(ember::Error::invalid_format(std::format(
                "patches '{}' line {}: odd hex digit count", path, line_no)));
        }
        std::vector<std::byte> bytes;
        bytes.reserve(hex.size() / 2);
        for (std::size_t i = 0; i < hex.size(); i += 2) {
            unsigned b = 0;
            auto br = std::from_chars(hex.data() + i, hex.data() + i + 2, b, 16);
            if (br.ec != std::errc{} || br.ptr != hex.data() + i + 2) {
                return std::unexpected(ember::Error::invalid_format(std::format(
                    "patches '{}' line {}: bad hex byte", path, line_no)));
            }
            bytes.push_back(static_cast<std::byte>(b));
        }
        out.push_back({static_cast<ember::addr_t>(va), std::move(bytes)});
    }
    return out;
}

// Apply --apply-patches: load the binary's section table for vaddr→
// file-offset translation, slurp the original file bytes, mutate per
// patch, write to args.output_path. Returns process exit code.
int run_apply_patches(const Args& args) {
    if (args.output_path.empty()) {
        std::println(stderr, "ember: --apply-patches requires -o/--output PATH");
        return EXIT_FAILURE;
    }
    auto patches_r = parse_patches_file(args.apply_patches);
    if (!patches_r) {
        std::println(stderr, "ember: {}", patches_r.error().message);
        return EXIT_FAILURE;
    }
    auto bin = ember::load_binary(args.binary);
    if (!bin) return report(bin.error());
    const auto sections = (**bin).sections();

    // Slurp the original binary file.
    std::ifstream src(args.binary, std::ios::binary | std::ios::ate);
    if (!src) {
        std::println(stderr, "ember: cannot read '{}'", args.binary);
        return EXIT_FAILURE;
    }
    const auto sz = src.tellg();
    src.seekg(0, std::ios::beg);
    std::vector<char> buf(static_cast<std::size_t>(sz));
    src.read(buf.data(), sz);

    // Apply each patch.
    std::size_t applied = 0;
    for (const auto& p : *patches_r) {
        const ember::Section* host = nullptr;
        for (const auto& s : sections) {
            if (p.vaddr >= s.vaddr && p.vaddr < s.vaddr + s.size) {
                host = &s; break;
            }
        }
        if (!host) {
            std::println(stderr, "ember: patch @ 0x{:x}: no containing section",
                         p.vaddr);
            return EXIT_FAILURE;
        }
        const auto file_off = host->file_offset + (p.vaddr - host->vaddr);
        if (file_off + p.bytes.size() > buf.size()) {
            std::println(stderr, "ember: patch @ 0x{:x}: extends past EOF",
                         p.vaddr);
            return EXIT_FAILURE;
        }
        for (std::size_t i = 0; i < p.bytes.size(); ++i) {
            buf[file_off + i] = static_cast<char>(p.bytes[i]);
        }
        ++applied;
    }

    std::ofstream dst(args.output_path, std::ios::binary | std::ios::trunc);
    if (!dst) {
        std::println(stderr, "ember: cannot write '{}'", args.output_path);
        return EXIT_FAILURE;
    }
    dst.write(buf.data(), static_cast<std::streamsize>(buf.size()));
    if (!dst) {
        std::println(stderr, "ember: write failed for '{}'", args.output_path);
        return EXIT_FAILURE;
    }
    std::println(stderr, "ember: applied {} patch(es) -> {}",
                 applied, args.output_path);
    return EXIT_SUCCESS;
}

}  // namespace

int main(int argc, char** argv) {
    auto args_r = parse_args(argc, argv);
    if (!args_r) {
        std::println(stderr, "ember: {}", args_r.error().message);
        print_help();
        return EXIT_FAILURE;
    }
    const auto& args = *args_r;

    if (args.quiet) {
#ifdef _WIN32
        ::_putenv_s("EMBER_QUIET", "1");
#else
        ::setenv("EMBER_QUIET", "1", 1);
#endif
    }

    if (args.help) {
        print_help();
        return EXIT_SUCCESS;
    }

    if (args.dump_types) {
        ember::TypeArena arena;
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

    if (!args.diff_path.empty() ||
        !args.fp_old_in.empty() ||
        !args.fp_new_in.empty()) {
        return run_diff(args);
    }

    // --apply-patches is a one-shot file operation: it loads the
    // binary only to consult the section table for vaddr→file-offset
    // translation, then writes a patched copy. No analysis runs.
    if (!args.apply_patches.empty()) {
        return run_apply_patches(args);
    }

    // --regions: skip magic-byte dispatch; load via the manifest path.
    // The manifest's first region's vaddr becomes the natural entry for
    // analysis (the user can override with -s <addr>).
    ember::Result<std::unique_ptr<ember::Binary>> bin =
        std::unexpected(ember::Error::invalid_format("uninitialized"));
    if (!args.regions_manifest.empty()) {
        auto rr = ember::RawRegionsBinary::load_from_manifest(args.regions_manifest);
        if (!rr) bin = std::unexpected(std::move(rr).error());
        else     bin = std::unique_ptr<ember::Binary>(std::move(*rr));
    } else {
        bin = ember::load_binary(args.binary);
    }
    if (!bin) return report(bin.error());
    const ember::Binary& b = **bin;

    // Indirect-edge trace, if any, must seed the oracle BEFORE any
    // analysis runs — the CFG builder consults it lazily but the result
    // gets cached in IR caches downstream, so late-loading wouldn't
    // take effect on subsequent passes.
    if (!args.trace_path.empty()) {
        std::ifstream tf(args.trace_path);
        if (!tf) {
            std::println(stderr, "ember: cannot open trace '{}'", args.trace_path);
            return EXIT_FAILURE;
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
            auto parse_hex = [](std::string_view s, ember::addr_t& out) {
                if (s.starts_with("0x") || s.starts_with("0X")) s.remove_prefix(2);
                ember::u64 v = 0;
                auto r = std::from_chars(s.data(), s.data() + s.size(), v, 16);
                if (r.ec != std::errc{} || r.ptr != s.data() + s.size()) return false;
                out = static_cast<ember::addr_t>(v);
                return true;
            };
            ember::addr_t from = 0, to = 0;
            if (!parse_hex(std::string_view(line).substr(0, tab), from) ||
                !parse_hex(std::string_view(line).substr(tab + 1), to)) {
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

    // --export-annotations PATH: promote the resolved source (sidecar or
    // cache — or an explicit --annotations/--project path) to PATH and
    // exit. One-shot, so it runs before any analysis work.
    if (!args.export_annotations.empty()) {
        const std::filesystem::path exp_cache_dir =
            !args.cache_dir.empty() ? std::filesystem::path{args.cache_dir}
                                    : ember::cache::default_dir();
        std::filesystem::path exp_explicit;
        if (!args.annotations_path.empty())  exp_explicit = args.annotations_path;
        else if (!args.project_path.empty()) exp_explicit = args.project_path;
        const auto src = ember::resolve_annotation_location(
            args.binary, exp_explicit, exp_cache_dir);
        ember::Annotations a;
        std::error_code ec;
        if (src.source != ember::AnnotationSource::None &&
            std::filesystem::exists(src.path, ec) && !ec) {
            auto rv = ember::Annotations::load(src.path);
            if (!rv) return report(rv.error());
            a = std::move(*rv);
        }
        auto sv = a.save(args.export_annotations);
        if (!sv) return report(sv.error());
        if (!args.quiet) {
            const std::size_t n = a.renames.size() + a.signatures.size()
                                + a.notes.size() + a.named_constants.size();
            std::println(stderr,
                "ember: exported {} annotation(s) from {} to '{}'",
                n,
                src.source == ember::AnnotationSource::None ? std::string{"<empty>"}
                                                            : src.path.string(),
                args.export_annotations);
        }
        return EXIT_SUCCESS;
    }

    if (!args.script_path.empty()) {
        // Scripts inherit the same source-precedence ladder as emission:
        // --project/--annotations beat the sidecar which beats the cache.
        // Mutations are still gated (empty path → mutation API raises),
        // but the gate now opens automatically when a sidecar or cache
        // entry exists; otherwise a fresh `commit()` writes to the cache
        // path the resolver returned.
        const std::filesystem::path script_cache_dir =
            !args.cache_dir.empty() ? std::filesystem::path{args.cache_dir}
                                    : ember::cache::default_dir();
        auto loc = ember::resolve_annotation_location(
            args.binary,
            !args.project_path.empty() ? args.project_path : args.annotations_path,
            script_cache_dir);
        if (args.no_cache && loc.source == ember::AnnotationSource::Cache) {
            loc = {};
        }

        std::optional<ember::ProjectContext> project;
        if (loc.source != ember::AnnotationSource::None) {
            project.emplace();
            project->path = loc.path;
            // Missing-file is a clean-start; a malformed file is a real error.
            std::error_code ec;
            if (std::filesystem::exists(loc.path, ec) && !ec) {
                auto ld = ember::Annotations::load(loc.path);
                if (!ld) return report(ld.error());
                project->loaded = std::move(*ld);
                if (!args.quiet) {
                    const std::size_t n = project->loaded.renames.size()
                                        + project->loaded.signatures.size()
                                        + project->loaded.notes.size()
                                        + project->loaded.named_constants.size();
                    std::println(stderr,
                        "ember: annotations: {} ({}, {} entries)",
                        loc.path.string(),
                        ember::annotation_source_name(loc.source), n);
                }
            }
        }
        ember::ScriptRuntime rt(b, project ? &*project : nullptr);
        rt.set_argv(args.script_argv);
        auto rv = rt.run_file(args.script_path);
        if (!rv) return report(rv.error());
        return EXIT_SUCCESS;
    }
    if (args.xrefs) {
        return run_cached(args, "xrefs",   [&] { return build_xrefs_output(b);   });
    }
    if (args.data_xrefs) {
        // TSV and JSON share the compute step but differ in output format,
        // so they cache under distinct tags — otherwise the first form
        // served would silently satisfy the second.
        const char* tag = args.json ? "data-xrefs-json-v1" : "data-xrefs-v1";
        return run_cached(args, tag, [&] {
            return build_data_xrefs_output(b, args.json);
        });
    }
    // --refs-to VA: callers of a specific address. Reuses the xrefs cache
    // to avoid recomputing the full call graph on every invocation; if no
    // cache entry exists it's built once, then every subsequent query is
    // a grep of the cached TSV.
    if (!args.refs_to.empty()) {
        auto va = parse_cli_addr(args.refs_to);
        if (!va) {
            std::println(stderr, "ember: --refs-to: bad address '{}'", args.refs_to);
            return EXIT_FAILURE;
        }
        std::string xrefs_tsv;
        const auto dir = args.cache_dir.empty()
            ? ember::cache::default_dir()
            : std::filesystem::path(args.cache_dir);
        std::string key;
        if (!args.no_cache) {
            auto k = ember::cache::key_for(args.binary);
            if (k) key = std::move(*k);
        }
        if (!key.empty()) {
            if (auto hit = ember::cache::read(dir, key, "xrefs"); hit) {
                xrefs_tsv = std::move(*hit);
            }
        }
        if (xrefs_tsv.empty()) {
            // Populate the cache now. First run is expensive (one full
            // call-graph walk); every subsequent --refs-to hit is instant.
            std::println(stderr,
                "ember: --refs-to: building xrefs cache (one-time)...");
            std::fflush(stderr);
            xrefs_tsv = build_xrefs_output(b);
            if (!key.empty()) {
                (void)ember::cache::write(dir, key, "xrefs", xrefs_tsv);
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
    // --callees VA|NAME: direct (call <imm>), tail (jmp to known entry),
    // and indirect_const (call [rip+X] resolving to code) outgoing edges
    // of the function at VA. Accepts either a hex VA or a symbol name —
    // `resolve_function` handles both so batch scripts can pass either
    // --containing-fn VA: name + extent of the function whose body
    // covers VA. Tab-separated (entry, size, name, offset_within) or
    // JSON under --json. Replaces the bisect-into-fingerprints.tsv
    // idiom shell scripts hand-roll today.
    if (!args.containing_fn.empty()) {
        auto va = parse_cli_addr(args.containing_fn);
        if (!va) {
            std::println(stderr, "ember: --containing-fn: bad address '{}'",
                         args.containing_fn);
            return EXIT_FAILURE;
        }
        auto cf = ember::containing_function(b, *va);
        if (!cf) {
            std::println(stderr, "ember: --containing-fn: no function covers {:#x}",
                         *va);
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

    // --validate NAME: report every address that carries NAME and every
    // function whose shape (blocks/insts/calls) twins the bound entry's
    // fingerprint. Tonight's bug — `find_by_name("NetworkClient::ctor")`
    // pointing at an OpenTelemetry function — would have shown up here as
    // a WEAK verdict with a flagged near-match.
    if (!args.validate_name.empty()) {
        // Read the cached --fingerprints TSV (or build it once if cold).
        // On a 102MB / 500K-fn binary this takes the per-call cost from
        // ~3 minutes (full lift+SSA per fn) to milliseconds when the
        // cache is warm.
        const auto fp_tsv = fingerprints_tsv_for(args, b);
        const auto rows   = fingerprint_rows_from_tsv(fp_tsv);
        const auto v = ember::validate_name(b, args.validate_name, rows);
        const std::string_view verdict = ember::verdict_name(v.verdict);
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
                    v.bound[i], fp.hash, fp.blocks, fp.insts, fp.calls,
                    v.offsets[i]);
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
            // Cap near-match output at 8 lines: a name with hundreds of
            // shape twins is uninformative, and the verdict label is what
            // the caller actually checks.
            constexpr std::size_t kNearCap = 8;
            const std::size_t shown =
                std::min(v.near_matches.size(), kNearCap);
            for (std::size_t i = 0; i < shown; ++i) {
                const auto& nm = v.near_matches[i];
                out += std::format(
                    "near\t{:#x}\thash={:#x}\tblocks={}\tinsts={}\tcalls={}"
                    "\tname={}\n",
                    nm.addr, nm.fp.hash, nm.fp.blocks, nm.fp.insts, nm.fp.calls,
                    nm.name);
            }
            if (v.near_matches.size() > shown) {
                out += std::format("near_truncated\t{}\n",
                                   v.near_matches.size() - shown);
            }
            std::fwrite(out.data(), 1, out.size(), stdout);
        }
        // Exit code conveys verdict to shell pipelines: 0 STRONG, 1 anything
        // ambiguous/weak/unknown — matches the grep-style "did you find what
        // you wanted" contract callers already use for --refs-to et al.
        return v.verdict == ember::NameValidation::Verdict::Strong
            ? EXIT_SUCCESS : EXIT_FAILURE;
    }

    // --collisions: every name → multi-addr group and every fingerprint
    // → multi-addr group. Subsumes the per-import warning loop in
    // scripts/names.js so it runs without a --project.
    if (args.collisions) {
        const auto fp_tsv = fingerprints_tsv_for(args, b);
        const auto rows   = fingerprint_rows_from_tsv(fp_tsv);
        const auto c = ember::collect_collisions(b, rows);
        if (args.json) {
            std::string out = "{\"by_name\":[";
            for (std::size_t i = 0; i < c.by_name.size(); ++i) {
                if (i) out += ',';
                const auto& g = c.by_name[i];
                out += std::format("{{\"name\":\"{}\",\"addrs\":[",
                                   json_escape(g.name));
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

    // form without reflowing. Unlike --refs-to this does not need the
    // full call-graph cache; one function gets built and walked.
    if (!args.callees.empty()) {
        auto win = ember::resolve_function(b, args.callees);
        if (!win) {
            std::println(stderr, "ember: --callees: could not resolve '{}'",
                         args.callees);
            return EXIT_FAILURE;
        }
        const auto va = win->start;
        const auto cs = ember::compute_classified_callees(b, va);
        if (args.json) {
            std::string out = std::format("{{\"va\":\"{:#x}\",\"callees\":[", va);
            for (std::size_t i = 0; i < cs.size(); ++i) {
                if (i) out += ',';
                out += std::format("{{\"va\":\"{:#x}\",\"kind\":\"{}\"}}",
                                   cs[i].target, ember::callee_kind_name(cs[i].kind));
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
    // --callees-class NAME: batch mode for C++ class atlases. Looks up
    // the Itanium RTTI entry by mangled or demangled name, then calls
    // compute_classified_callees for each vfn slot. Always emits JSON
    // since the per-slot layout is structured.
    if (!args.callees_class.empty()) {
        const auto classes = ember::parse_itanium_rtti(b);
        const ember::RttiClass* match = nullptr;
        for (const auto& c : classes) {
            if (c.mangled_name == args.callees_class ||
                c.demangled_name == args.callees_class) {
                match = &c;
                break;
            }
        }
        if (!match) {
            std::println(stderr, "ember: --callees-class: no RTTI class matching '{}'",
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
            const auto cs = ember::compute_classified_callees(b, imp);
            for (std::size_t j = 0; j < cs.size(); ++j) {
                if (j) out += ',';
                out += std::format("{{\"va\":\"{:#x}\",\"kind\":\"{}\"}}",
                                   cs[j].target, ember::callee_kind_name(cs[j].kind));
            }
            out += "]}";
        }
        out += "}}\n";
        std::fwrite(out.data(), 1, out.size(), stdout);
        return EXIT_SUCCESS;
    }
    // --disasm-at VA [--count N]: bounded disasm window anywhere in the
    // binary, including mid-function. Count defaults to 32 instructions.
    if (!args.disasm_at.empty()) {
        auto va = parse_cli_addr(args.disasm_at);
        if (!va) {
            std::println(stderr, "ember: --disasm-at: bad address '{}'", args.disasm_at);
            return EXIT_FAILURE;
        }
        std::size_t count = 32;
        if (!args.disasm_count.empty()) {
            ember::u64 n = 0;
            auto r = std::from_chars(args.disasm_count.data(),
                                     args.disasm_count.data() + args.disasm_count.size(),
                                     n, 10);
            if (r.ec == std::errc{}) count = static_cast<std::size_t>(n);
        }
        // 8 bytes/insn is the typical x86-64 average; ~15 bytes is the max.
        const ember::addr_t end = static_cast<ember::addr_t>(*va) +
                                  static_cast<ember::addr_t>(count * 15);
        auto rv = ember::format_disasm_range(b, static_cast<ember::addr_t>(*va), end);
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
    if (args.strings) {
        // Cache tag bumped to v2 when the scanner started covering
        // executable-flagged sections (Mach-O __cstring lives in __TEXT).
        // Old "strings" cache entries from before that change are now
        // orphaned.
        return run_cached(args, "strings-v2", [&] { return build_strings_output(b); });
    }
    if (args.fingerprints) {
        const int rc = run_cached(args, fingerprints_cache_tag(),
                                  [&] { return build_fingerprints_output(b); });
        // Mirror the output to --fingerprint-out PATH so the fingerprints
        // can travel between machines / repo checkouts where the disk
        // cache doesn't apply.
        if (rc == EXIT_SUCCESS && !args.fp_out.empty()) {
            const auto dir = args.cache_dir.empty()
                ? ember::cache::default_dir()
                : std::filesystem::path(args.cache_dir);
            auto k = ember::cache::key_for(args.binary);
            if (k) {
                if (auto hit = ember::cache::read(dir, *k, fingerprints_cache_tag()); hit) {
                    std::ofstream f(args.fp_out, std::ios::binary | std::ios::trunc);
                    if (f) f.write(hit->data(), static_cast<std::streamsize>(hit->size()));
                }
            }
        }
        return rc;
    }
    if (args.objc_names) {
        return run_cached(args, "objc-names",
                          [&] { return build_objc_names_output(b); });
    }
    if (args.objc_protos) {
        return run_cached(args, "objc-protocols",
                          [&] { return build_objc_protocols_output(b); });
    }
    if (args.rtti) {
        return run_cached(args, "rtti",
                          [&] { return build_rtti_output(b); });
    }
    if (args.vm_detect) {
        return run_cached(args, "vm-detect",
                          [&] { return build_vm_detect_output(b); });
    }
    if (args.arities) {
        return run_cached(args, "arities", [&] { return build_arities_output(b); });
    }
    if (args.functions) {
        // Full TSV is cacheable independent of the pattern — build once,
        // filter at print time so the cache works across grep sessions.
        std::string tsv;
        const auto dir = args.cache_dir.empty()
            ? ember::cache::default_dir()
            : std::filesystem::path(args.cache_dir);
        std::string key;
        bool cacheable = !args.no_cache;
        if (cacheable) {
            auto k = ember::cache::key_for(args.binary);
            if (k) key = std::move(*k);
            else {
                std::println(stderr, "ember: warning: {}: {} (caching disabled)",
                             k.error().kind_name(), k.error().message);
                cacheable = false;
            }
        }
        // Different cache tag per mode: --full-analysis returns a strict
        // superset (and on packed binaries, a polluted one). Sharing one
        // tag would let a fast --functions run poison the cache for a
        // later --full-analysis user.
        const std::string_view fns_tag = args.full_analysis
            ? "functions_full" : "functions";
        if (cacheable) {
            if (auto hit = ember::cache::read(dir, key, fns_tag); hit) {
                tsv.assign(hit->data(), hit->size());
            }
        }
        if (tsv.empty()) {
            tsv = build_functions_output(b, args.full_analysis);
            if (cacheable) {
                if (auto rv = ember::cache::write(dir, key, fns_tag, tsv); !rv) {
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
    // Resolve the annotation source. Precedence is
    // --annotations/--project → sidecar → cache; the resolver returns a
    // cache path even when no file exists yet, so a fresh commit lands
    // in the cache automatically. Missing/empty is non-fatal — we just
    // fall back to the generated names.
    std::filesystem::path _explicit_ann;
    if (!args.annotations_path.empty())    _explicit_ann = args.annotations_path;
    else if (!args.project_path.empty())   _explicit_ann = args.project_path;
    const std::filesystem::path _cache_dir =
        !args.cache_dir.empty() ? std::filesystem::path{args.cache_dir}
                                : ember::cache::default_dir();
    auto ann_loc = ember::resolve_annotation_location(
        args.binary, _explicit_ann, _cache_dir);
    // --no-cache bypasses the annotation *cache* path but still honors
    // the sidecar and any explicit --annotations/--project. The user
    // asked not to touch the cache; we respect that symmetrically.
    if (args.no_cache && ann_loc.source == ember::AnnotationSource::Cache) {
        ann_loc = {};
    }

    ember::Annotations annotations;
    bool ann_loaded = false;
    if (ann_loc.source != ember::AnnotationSource::None) {
        std::error_code ec;
        if (std::filesystem::exists(ann_loc.path, ec) && !ec) {
            auto rv = ember::Annotations::load(ann_loc.path);
            if (rv) {
                annotations = std::move(*rv);
                ann_loaded = true;
                if (!args.quiet) {
                    const std::size_t n = annotations.renames.size()
                                        + annotations.signatures.size()
                                        + annotations.notes.size()
                                        + annotations.named_constants.size();
                    std::println(stderr,
                        "ember: annotations: {} ({}, {} entries)",
                        ann_loc.path.string(),
                        ember::annotation_source_name(ann_loc.source), n);
                }
            } else {
                std::println(stderr,
                    "ember: warning: {}: {}; continuing without user annotations",
                    rv.error().kind_name(), rv.error().message);
            }
        }
    }
    const ember::Annotations* ann_ptr = ann_loaded ? &annotations : nullptr;

    ember::EmitOptions emit_opts;
    emit_opts.show_bb_labels = args.labels;
    // IPA: one-shot fixed-point over the call graph before emission so
    // char*-arg propagation can cross function boundaries. Expensive on
    // large binaries — opt-in via --ipa.
    ember::InferenceResult ipa;
    if (args.ipa && (args.pseudo || args.strct)) {
        std::println(stderr, "ember: running IPA (this pass lifts every function once)...");
        std::fflush(stderr);
        ipa = ember::infer_signatures(b);
        std::println(stderr, "ember: IPA done: {} functions analyzed", ipa.sigs.size());
        emit_opts.signatures = &ipa.sigs;
        emit_opts.type_arena = &ipa.arena;
    }
    std::map<ember::addr_t, ember::addr_t> resolutions;
    if (args.resolve_calls && (args.pseudo || args.strct)) {
        std::println(stderr, "ember: resolving indirect calls (vtable + import back-trace)...");
        std::fflush(stderr);
        resolutions = ember::resolve_indirect_calls(b);
        std::println(stderr, "ember: indirect-call resolver: {} sites resolved",
                     resolutions.size());
        emit_opts.call_resolutions = &resolutions;
    }
    ember::LpMap lp_map;
    if (args.eh && (args.pseudo || args.strct)) {
        lp_map = ember::parse_landing_pads(b);
        std::println(stderr, "ember: EH data: {} landing-pad ranges parsed",
                     lp_map.size());
        emit_opts.landing_pads = &lp_map;
    }
    // PE x64 prologue/epilogue suppression: parse UNWIND_INFO unconditionally
    // and feed the byte ranges to the emitter. Win64 frames are unreadable
    // without this — every function leads with `push rbx; sub rsp, K;
    // mov [rsp+K], xmm6; ...` cruft that the unwinder already describes.
    std::map<ember::addr_t, ember::addr_t> prologue_ranges;
    if ((args.pseudo || args.strct) && b.format() == ember::Format::Pe) {
        prologue_ranges = ember::build_prologue_ranges(b);
        if (!prologue_ranges.empty()) emit_opts.prologue_ranges = &prologue_ranges;
    }
    // __objc_selrefs is cheap to walk — do it unconditionally on Mach-O
    // so `objc_msgSend(*(u64*)(0x10...))` renders as `@selector(foo:)`
    // without requiring a separate flag.
    std::map<ember::addr_t, std::string> selrefs;
    if ((args.pseudo || args.strct) && b.format() == ember::Format::MachO) {
        selrefs = ember::parse_objc_selrefs(b);
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

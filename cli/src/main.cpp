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
#include <ember/analysis/function.hpp>
#include <ember/analysis/objc.hpp>
#include <ember/analysis/pipeline.hpp>
#include <ember/analysis/rtti.hpp>
#include <ember/analysis/vm_detect.hpp>
#include <ember/analysis/sig_inference.hpp>
#include <ember/analysis/strings.hpp>
#include <ember/binary/binary.hpp>
#include <ember/common/annotations.hpp>
#include <ember/common/cache.hpp>
#include <ember/common/progress.hpp>
#include <ember/disasm/instruction.hpp>
#include <ember/disasm/decoder.hpp>
#include <ember/ir/ir.hpp>
#include <ember/ir/passes.hpp>
#include <ember/ir/ssa.hpp>
#include <ember/ir/lifter.hpp>
#include <ember/decompile/emitter.hpp>
#include <ember/script/runtime.hpp>
#include <ember/structure/region.hpp>
#include <ember/structure/structurer.hpp>

namespace {

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

struct Args {
    std::string binary;
    std::string symbol;
    std::string annotations_path;   // optional project-file for user edits (read-only load)
    std::string export_annotations; // --export-annotations PATH: promote resolved source to PATH and exit
    std::string trace_path;         // optional indirect-edge trace TSV (from\tto per line)
    std::string project_path;       // optional project-file authorising script mutations
    std::string script_path;        // optional JS script to run against the binary
    std::vector<std::string> script_argv; // args passed to the script after `--`
    std::string cache_dir;          // override for the disk cache location
    std::string diff_path;          // --diff OLD: compare this older binary against args.binary
    std::string diff_format;        // --diff-format: "tsv" (default) or "json"
    std::string fp_out;             // --fingerprint-out PATH: also write fingerprints TSV here
    std::string fp_old_in;          // --fingerprint-old PATH: read OLD side fingerprints from PATH
    std::string fp_new_in;          // --fingerprint-new PATH: read NEW side fingerprints from PATH
    std::string refs_to;            // --refs-to VA: print callers of VA
    std::string callees;            // --callees VA: print direct call targets of the function at VA
    std::string containing_fn;      // --containing-fn VA: name/extent of the function covering VA
    std::string validate_name;      // --validate NAME: report all addrs bound to NAME + byte-similar lookalikes
    std::string callees_class;      // --callees-class NAME: JSON callee map for every vfn slot of a class
    std::string disasm_at;          // --disasm-at VA: disasm window at VA
    std::string disasm_count;       // --count N: instructions for --disasm-at
    std::string apply_patches;      // --apply-patches FILE: vaddr_hex bytes_hex per line
    std::string output_path;        // -o / --output PATH: destination for --apply-patches
    bool no_cache = false;          // disable the disk cache entirely
    bool json = false;              // --json: machine-readable output where supported
    bool disasm = false;
    bool cfg    = false;
    bool ir     = false;
    bool ssa    = false;
    bool opt    = false;
    bool strct  = false;
    bool pseudo = false;
    bool xrefs  = false;
    bool strings = false;
    bool arities = false;
    bool fingerprints = false;      // dump address-independent content hash per function
    bool labels = false;            // keep // bb_XXXX comments in pseudo-C output
    bool ipa    = false;            // run interprocedural signature inference for -p
    bool eh     = false;            // parse __eh_frame + LSDA and annotate landing pads
    bool objc_names = false;        // dump ObjC runtime -[Class sel] => IMP as TSV
    bool objc_protos = false;       // dump ObjC protocol signatures
    bool rtti   = false;            // dump Itanium RTTI classes + vtables
    bool vm_detect = false;         // scan for interpreter-style VM dispatchers
    bool cfg_pseudo = false;        // CFG view with pseudo-C bodies per block
    bool functions = false;         // --functions [PATTERN]: list every discovered function (symbols ∪ sub_*)
    bool collisions = false;        // --collisions: dump every name/fingerprint group bound to >1 address
    std::string functions_pattern;  // optional substring filter for --functions (second positional)
    bool quiet  = false;            // suppress progress output regardless of TTY
    bool data_xrefs = false;        // --data-xrefs: dump every rip-rel/abs data reference
    bool help   = false;
};

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
    {"",   "--eh",        &Args::eh},
    {"",   "--objc-names", &Args::objc_names},
    {"",   "--objc-protocols", &Args::objc_protos},
    {"",   "--rtti",     &Args::rtti},
    {"",   "--vm-detect", &Args::vm_detect},
    {"",   "--cfg-pseudo", &Args::cfg_pseudo},
    {"",   "--functions", &Args::functions},
    {"",   "--collisions", &Args::collisions},
    {"",   "--no-cache",  &Args::no_cache},
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
    // already-computed fingerprint TSVs — no bytes to parse.
    const bool diffs_from_tsvs = !a.fp_old_in.empty() && !a.fp_new_in.empty();
    if (!a.help && a.binary.empty() && !diffs_from_tsvs) {
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

int run_disasm(const ember::Binary& b, std::string_view symbol) {
    auto win = ember::resolve_function(b, symbol);
    if (!win) {
        return EXIT_FAILURE;  // resolve_function already printed a diagnostic
    }
    auto out = ember::format_disasm(b, *win);
    if (!out) {
        std::println(stderr, "ember: {}: {}",
                     out.error().kind_name(), out.error().message);
        return EXIT_FAILURE;
    }
    std::print("{}", *out);
    return EXIT_SUCCESS;
}

int run_cfg(const ember::Binary& b, std::string_view symbol) {
    auto win = ember::resolve_function(b, symbol);
    if (!win) {
        return EXIT_FAILURE;  // resolve_function already printed a diagnostic
    }
    auto out = ember::format_cfg(b, *win);
    if (!out) {
        std::println(stderr, "ember: {}: {}",
                     out.error().kind_name(), out.error().message);
        return EXIT_FAILURE;
    }
    std::print("{}", *out);
    return EXIT_SUCCESS;
}

int run_cfg_pseudo(const ember::Binary& b, std::string_view symbol,
                   const ember::Annotations* ann,
                   ember::EmitOptions opts) {
    auto win = ember::resolve_function(b, symbol);
    if (!win) {
        return EXIT_FAILURE;
    }
    auto out = ember::format_cfg_pseudo(b, *win, ann, opts);
    if (!out) {
        std::println(stderr, "ember: {}: {}",
                     out.error().kind_name(), out.error().message);
        return EXIT_FAILURE;
    }
    std::print("{}", *out);
    return EXIT_SUCCESS;
}

int run_ir(const ember::Binary& b, std::string_view symbol,
           bool run_ssa, bool run_opt) {
    auto win = ember::resolve_function(b, symbol);
    if (!win) {
        return EXIT_FAILURE;  // resolve_function already printed a diagnostic
    }

    auto dec_r = ember::make_decoder(b);
    if (!dec_r) {
        std::println(stderr, "ember: {}: {}",
                     dec_r.error().kind_name(), dec_r.error().message);
        return EXIT_FAILURE;
    }
    const ember::CfgBuilder  builder(b, **dec_r);
    auto fn_r = builder.build(win->start, win->label);
    if (!fn_r) {
        std::println(stderr, "ember: {}: {}",
                     fn_r.error().kind_name(), fn_r.error().message);
        return EXIT_FAILURE;
    }

    auto lifter_r = ember::make_lifter(b);
    if (!lifter_r) {
        std::println(stderr, "ember: {}: {}",
                     lifter_r.error().kind_name(), lifter_r.error().message);
        return EXIT_FAILURE;
    }
    auto ir_r = (*lifter_r)->lift(*fn_r);
    if (!ir_r) {
        std::println(stderr, "ember: {}: {}",
                     ir_r.error().kind_name(), ir_r.error().message);
        return EXIT_FAILURE;
    }

    if (run_ssa) {
        const ember::SsaBuilder ssa;
        auto rv = ssa.convert(*ir_r);
        if (!rv) {
            std::println(stderr, "ember: {}: {}",
                         rv.error().kind_name(), rv.error().message);
            return EXIT_FAILURE;
        }
    }

    if (run_opt) {
        auto stats = ember::run_cleanup(*ir_r);
        if (!stats) {
            std::println(stderr, "ember: {}: {}",
                         stats.error().kind_name(), stats.error().message);
            return EXIT_FAILURE;
        }
        std::println("; cleanup: {} iter, removed {} insts / {} phis, folded {}, propagated {}",
                     stats->iterations, stats->insts_removed, stats->phis_removed,
                     stats->constants_folded, stats->copies_propagated);
        std::println("");
    }

    std::print("{}", format_ir_function(*ir_r));
    return EXIT_SUCCESS;
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
[[nodiscard]] std::string build_functions_output(const ember::Binary& b) {
    std::string out;
    for (const auto& fn : ember::enumerate_functions(b)) {
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

// Per-function content hash. One TSV row per entry:
//   <addr-hex>\t<fp-hex>\t<blocks>\t<insts>\t<calls>\t<collisions>\t<name>
// `collisions` is the number of functions sharing `fp` in this output
// (1 = unique; N > 1 = N-way collision, common for short stubs whose
// body carries too little entropy for a 64-bit content hash).
// Sorted by address. Address-independent — same algorithm across two PIE
// builds of the same code produces the same fingerprint column.
[[nodiscard]] std::string build_fingerprints_output(const ember::Binary& b) {
    const bool show = ember::progress_enabled();
    // Build a one-shot addr -> name map; previously this was an O(n²) linear
    // rescan per function which took minutes on large stripped binaries.
    if (show) {
        std::println(stderr, "ember: collecting named functions...");
        std::fflush(stderr);
    }
    std::unordered_map<ember::addr_t, std::string> name_by_addr;
    for (const auto& s : b.symbols()) {
        if (s.is_import) continue;
        if (s.kind != ember::SymbolKind::Function) continue;
        if (s.addr == 0 || s.name.empty()) continue;
        name_by_addr.try_emplace(s.addr, s.name);
    }

    if (show) {
        std::println(stderr, "ember: {} named functions; walking call graph "
                             "(this is the slow first step on big binaries)...",
                             name_by_addr.size());
        std::fflush(stderr);
    }
    const auto edges = ember::compute_call_graph(b);
    if (show) {
        std::println(stderr, "ember: {} call edges discovered", edges.size());
        std::fflush(stderr);
    }

    std::set<ember::addr_t> fns;
    for (const auto& [a, _] : name_by_addr) fns.insert(a);
    for (const auto& e : edges) {
        if (!b.import_at_plt(e.callee)) fns.insert(e.callee);
    }

    struct Row {
        ember::addr_t addr;
        ember::u64 hash;
        ember::u32 blocks;
        ember::u32 insts;
        ember::u32 calls;
        std::string name;
    };
    std::vector<Row> rows;
    rows.reserve(fns.size());

    const auto total = fns.size();
    std::size_t done = 0;
    const auto tick = std::max<std::size_t>(1, total / 40);
    if (show) {
        std::println(stderr, "ember: fingerprinting {} functions...", total);
        std::fflush(stderr);
    }

    for (ember::addr_t a : fns) {
        const auto fp = ember::compute_fingerprint(b, a);
        ++done;
        if (show && (done % tick == 0 || done == total)) {
            std::fprintf(stderr, "\r  [%zu/%zu]", done, total);
            std::fflush(stderr);
        }
        if (fp.hash == 0) continue;
        std::string name;
        if (auto it = name_by_addr.find(a); it != name_by_addr.end()) {
            name = it->second;
        } else {
            name = std::format("sub_{:x}", a);
        }
        rows.push_back(Row{a, fp.hash, fp.blocks, fp.insts, fp.calls,
                           std::move(name)});
    }
    if (show) std::fputc('\n', stderr);

    std::unordered_map<ember::u64, ember::u32> hash_count;
    hash_count.reserve(rows.size());
    for (const auto& r : rows) ++hash_count[r.hash];

    std::string out;
    for (const auto& r : rows) {
        out += std::format("{:x}\t{:016x}\t{}\t{}\t{}\t{}\t{}\n",
                           r.addr, r.hash, r.blocks, r.insts, r.calls,
                           hash_count[r.hash], r.name);
    }
    return out;
}

// Read the cached fingerprints TSV for `binary_path`, or compute + store it.
// Matches the cache-key logic of run_cached() but doesn't touch stdout — used
// by run_diff() to pull TSVs for both binaries into memory for comparison.
// Cache tag for fingerprint TSVs includes the fingerprint schema version
// so schema bumps orphan old entries without nuking unrelated caches.
// Tag = fingerprints-<hash_schema>-<output_format_version>. Bumping either
// invalidates stale TSVs on disk: hash_schema when the hash bytes change,
// the output token when the column layout changes.
[[nodiscard]] std::string fingerprints_cache_tag() {
    return std::format("fingerprints-{}-o2", ember::kFingerprintSchema);
}

[[nodiscard]] std::string
fingerprints_cached_or_compute(const std::filesystem::path& binary_path,
                               const std::filesystem::path& cache_dir,
                               bool no_cache) {
    const std::string tag = fingerprints_cache_tag();
    std::string key;
    if (!no_cache) {
        auto k = ember::cache::key_for(binary_path);
        if (k) key = std::move(*k);
    }
    if (!key.empty()) {
        if (auto hit = ember::cache::read(cache_dir, key, tag); hit) {
            return std::move(*hit);
        }
    }
    auto bin = ember::load_binary(binary_path);
    if (!bin) {
        std::println(stderr, "ember: {}: {}",
                     bin.error().kind_name(), bin.error().message);
        std::exit(EXIT_FAILURE);
    }
    std::string out = build_fingerprints_output(**bin);
    if (!key.empty()) {
        if (auto rv = ember::cache::write(cache_dir, key, tag, out); !rv) {
            std::println(stderr, "ember: warning: {}: {}",
                         rv.error().kind_name(), rv.error().message);
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

struct FpEntry {
    ember::addr_t addr = 0;
    std::string fp;
    std::string name;
    // Shape metadata retained for fuzzy-matching: two functions with the
    // same (blocks, insts, calls) triple are very likely the same function
    // edited by a few instructions across versions.
    ember::u32 blocks = 0;
    ember::u32 insts  = 0;
    ember::u32 calls  = 0;
};
struct ParsedFps {
    std::unordered_map<std::string, std::vector<FpEntry>> by_fp;
    std::size_t total = 0;
};

// Parse the TSV that build_fingerprints_output produces:
//   <addr>\t<fp>\t<blocks>\t<insts>\t<calls>\t<collisions>\t<name>
[[nodiscard]] ParsedFps parse_fingerprints_tsv(const std::string& tsv) {
    ParsedFps out;
    std::size_t pos = 0;
    while (pos < tsv.size()) {
        const auto nl = tsv.find('\n', pos);
        const std::size_t end = (nl == std::string::npos) ? tsv.size() : nl;
        const std::string_view line(tsv.data() + pos, end - pos);
        pos = (nl == std::string::npos) ? tsv.size() : nl + 1;
        if (line.empty() || line.front() == '#') continue;
        std::array<std::string_view, 7> f{};
        std::size_t s = 0, fi = 0;
        for (std::size_t i = 0; i <= line.size() && fi < f.size(); ++i) {
            if (i == line.size() || line[i] == '\t') {
                f[fi++] = line.substr(s, i - s);
                s = i + 1;
            }
        }
        if (fi < 7) continue;
        ember::addr_t addr = 0;
        const auto r = std::from_chars(f[0].data(),
                                       f[0].data() + f[0].size(), addr, 16);
        if (r.ec != std::errc{}) continue;
        auto parse_u32 = [](std::string_view sv) -> ember::u32 {
            ember::u32 v = 0;
            std::from_chars(sv.data(), sv.data() + sv.size(), v, 10);
            return v;
        };
        out.by_fp[std::string{f[1]}].push_back(FpEntry{
            addr,
            std::string{f[1]},
            std::string{f[6]},
            parse_u32(f[2]),
            parse_u32(f[3]),
            parse_u32(f[4]),
        });
        ++out.total;
    }
    return out;
}

// Reuse the existing fingerprints disk cache for an already-loaded
// binary. Mirrors fingerprints_cached_or_compute() (which re-loads the
// binary from disk for run_diff()) but takes the Binary by reference so
// callers that already paid the load cost don't pay it twice. Cache hits
// turn --validate / --collisions on a 100MB+ binary from "minutes" into
// "milliseconds" — every fingerprint comes from the cached TSV instead
// of running the lift+SSA pipeline per fn.
[[nodiscard]] std::string
fingerprints_tsv_for(const Args& args, const ember::Binary& b) {
    const auto dir = args.cache_dir.empty()
        ? ember::cache::default_dir()
        : std::filesystem::path(args.cache_dir);
    const std::string tag = fingerprints_cache_tag();
    if (!args.no_cache) {
        if (auto k = ember::cache::key_for(args.binary); k) {
            if (auto hit = ember::cache::read(dir, *k, tag); hit) {
                return std::move(*hit);
            }
        }
    }
    std::string out = build_fingerprints_output(b);
    if (!args.no_cache) {
        if (auto k = ember::cache::key_for(args.binary); k) {
            if (auto rv = ember::cache::write(dir, *k, tag, out); !rv) {
                std::println(stderr, "ember: warning: {}: {}",
                             rv.error().kind_name(), rv.error().message);
            }
        }
    }
    return out;
}

// Parse the build_fingerprints_output TSV into the flat row form
// pipeline.cpp's validate_name / collect_collisions consume. The TSV
// columns are: addr, hash, blocks, insts, calls, dup-count, name.
// We drop dup-count — the pipeline functions recompute it locally
// from the row set when reporting collisions.
[[nodiscard]] std::vector<ember::FingerprintRow>
fingerprint_rows_from_tsv(std::string_view tsv) {
    std::vector<ember::FingerprintRow> out;
    std::size_t pos = 0;
    while (pos < tsv.size()) {
        const auto nl = tsv.find('\n', pos);
        const std::size_t end = (nl == std::string_view::npos) ? tsv.size() : nl;
        const std::string_view line = tsv.substr(pos, end - pos);
        pos = (nl == std::string_view::npos) ? tsv.size() : nl + 1;
        if (line.empty() || line.front() == '#') continue;

        std::array<std::string_view, 7> f{};
        std::size_t s = 0, fi = 0;
        for (std::size_t i = 0; i <= line.size() && fi < f.size(); ++i) {
            if (i == line.size() || line[i] == '\t') {
                f[fi++] = line.substr(s, i - s);
                s = i + 1;
            }
        }
        if (fi < 7) continue;
        ember::addr_t addr = 0;
        if (auto r = std::from_chars(f[0].data(),
                                     f[0].data() + f[0].size(), addr, 16);
            r.ec != std::errc{}) continue;
        ember::u64 hash = 0;
        if (auto r = std::from_chars(f[1].data(),
                                     f[1].data() + f[1].size(), hash, 16);
            r.ec != std::errc{}) continue;
        auto parse_u32 = [](std::string_view sv) -> ember::u32 {
            ember::u32 v = 0;
            std::from_chars(sv.data(), sv.data() + sv.size(), v, 10);
            return v;
        };
        ember::FingerprintRow row;
        row.addr      = addr;
        row.fp.hash   = hash;
        row.fp.blocks = parse_u32(f[2]);
        row.fp.insts  = parse_u32(f[3]);
        row.fp.calls  = parse_u32(f[4]);
        row.name      = std::string{f[6]};
        out.push_back(std::move(row));
    }
    return out;
}

// Fuzzy-pair unmatched "removed" and "added" entries. Two heuristics,
// applied in order:
//   1. Exact-name match across versions — obvious case of "same named
//      function, body differs by a few instructions". Tagged `edited`.
//   2. Shape proximity — equal (blocks, insts, calls) tuple plus (sub_*
//      in both OR close hash-prefix). Tagged `fuzzy`.
// Works on the raw vectors; caller passes in the leftover entries after
// the exact-fp pass.
struct FuzzyPair {
    FpEntry old_e;
    FpEntry new_e;
    const char* tag;  // "edited" or "fuzzy"
};
[[nodiscard]] std::vector<FuzzyPair>
fuzzy_pair(std::vector<FpEntry>& removed, std::vector<FpEntry>& added) {
    std::vector<FuzzyPair> out;
    // Pass 1: name equality.
    auto is_sub = [](std::string_view n) {
        return n.starts_with("sub_");
    };
    std::vector<bool> rm_taken(removed.size(), false);
    std::vector<bool> ad_taken(added.size(),   false);
    for (std::size_t i = 0; i < removed.size(); ++i) {
        if (is_sub(removed[i].name)) continue;
        for (std::size_t j = 0; j < added.size(); ++j) {
            if (ad_taken[j]) continue;
            if (added[j].name != removed[i].name) continue;
            out.push_back({removed[i], added[j], "edited"});
            rm_taken[i] = true;
            ad_taken[j] = true;
            break;
        }
    }
    // Pass 2: shape proximity on sub_* pairs. Both sides must be sub_*
    // (named collisions were handled in pass 1), same shape tuple, and a
    // shared 4-hex-char fingerprint prefix — that's a generous-but-sane
    // signal that they started as the same function.
    for (std::size_t i = 0; i < removed.size(); ++i) {
        if (rm_taken[i]) continue;
        if (!is_sub(removed[i].name)) continue;
        std::size_t best = std::size_t(-1);
        for (std::size_t j = 0; j < added.size(); ++j) {
            if (ad_taken[j]) continue;
            if (!is_sub(added[j].name)) continue;
            if (added[j].blocks != removed[i].blocks) continue;
            if (added[j].insts  != removed[i].insts)  continue;
            if (added[j].calls  != removed[i].calls)  continue;
            if (removed[i].fp.size() < 4 || added[j].fp.size() < 4) continue;
            if (removed[i].fp.substr(0, 4) != added[j].fp.substr(0, 4)) continue;
            best = j;
            break;
        }
        if (best != std::size_t(-1)) {
            out.push_back({removed[i], added[best], "fuzzy"});
            rm_taken[i] = true;
            ad_taken[best] = true;
        }
    }
    // Compact the "still unmatched" entries back into the caller's vectors.
    std::vector<FpEntry> rm_left, ad_left;
    rm_left.reserve(removed.size());
    ad_left.reserve(added.size());
    for (std::size_t i = 0; i < removed.size(); ++i)
        if (!rm_taken[i]) rm_left.push_back(std::move(removed[i]));
    for (std::size_t j = 0; j < added.size(); ++j)
        if (!ad_taken[j]) ad_left.push_back(std::move(added[j]));
    removed = std::move(rm_left);
    added   = std::move(ad_left);
    return out;
}

// Diff two fingerprint maps. Output is one TSV row per function pairing:
//   kept     <fp> <old_addr> <new_addr> <old_name> <new_name>
//   moved    <fp> <old_addr> <new_addr> <old_name> <new_name>
//   added    <fp> -          <new_addr> -          <new_name>
//   removed  <fp> <old_addr> -          <old_name> -
//   edited   <fp_old>>< fp_new> <old>   <new>     <name>    <name>
//   fuzzy    <fp_old>>< fp_new> <old>   <new>     <name>    <name>
// `kept`  = same fp, same addr, same name.
// `moved` = same fp, different addr or name.
// `edited`/`fuzzy` = fuzzy-paired leftovers (see fuzzy_pair).
// Summary line prefixed with '#' so awk filters stay simple.

// Gather paired entries + unmatched leftovers from an exact-fp diff.
// The caller then runs fuzzy_pair() over the leftovers and renders.
struct DiffBuckets {
    std::vector<std::pair<FpEntry, FpEntry>> kept;   // same addr + name
    std::vector<std::pair<FpEntry, FpEntry>> moved;  // same fp, different addr/name
    std::vector<FpEntry>                     added_left;
    std::vector<FpEntry>                     removed_left;
};

[[nodiscard]] DiffBuckets
bucket_exact(const ParsedFps& old_p, const ParsedFps& new_p) {
    DiffBuckets b;
    for (const auto& [fp, nvec] : new_p.by_fp) {
        const auto it = old_p.by_fp.find(fp);
        if (it == old_p.by_fp.end()) {
            for (const auto& ne : nvec) b.added_left.push_back(ne);
            continue;
        }
        const auto& ovec = it->second;
        const auto pairs = std::min(ovec.size(), nvec.size());
        for (std::size_t i = 0; i < pairs; ++i) {
            const auto& oe = ovec[i];
            const auto& ne = nvec[i];
            if (oe.addr == ne.addr && oe.name == ne.name) b.kept.emplace_back(oe, ne);
            else                                           b.moved.emplace_back(oe, ne);
        }
        for (std::size_t i = pairs; i < nvec.size(); ++i) b.added_left.push_back(nvec[i]);
        for (std::size_t i = pairs; i < ovec.size(); ++i) b.removed_left.push_back(ovec[i]);
    }
    for (const auto& [fp, ovec] : old_p.by_fp) {
        if (new_p.by_fp.contains(fp)) continue;
        for (const auto& oe : ovec) b.removed_left.push_back(oe);
    }
    return b;
}

[[nodiscard]] std::string
format_diff(const ParsedFps& old_p, const ParsedFps& new_p,
            const std::string& old_label, const std::string& new_label) {
    auto b = bucket_exact(old_p, new_p);
    auto fuzzy = fuzzy_pair(b.removed_left, b.added_left);

    std::string body;
    auto emit = [&](std::string_view tag,
                    const FpEntry* oe, const FpEntry* ne,
                    std::string_view fp) {
        body += std::format("{}\t{}\t{}\t{}\t{}\t{}\n",
            tag, fp,
            oe ? std::format("{:x}", oe->addr) : std::string{"-"},
            ne ? std::format("{:x}", ne->addr) : std::string{"-"},
            oe ? oe->name                      : std::string{"-"},
            ne ? ne->name                      : std::string{"-"});
    };
    for (const auto& [oe, ne] : b.kept)   emit("kept",  &oe, &ne, oe.fp);
    for (const auto& [oe, ne] : b.moved)  emit("moved", &oe, &ne, oe.fp);
    for (const auto& p : fuzzy)           emit(p.tag, &p.old_e, &p.new_e,
                                               std::format("{}>{}", p.old_e.fp.substr(0, 4),
                                                           p.new_e.fp.substr(0, 4)));
    for (const auto& ne : b.added_left)   emit("added",   nullptr, &ne, ne.fp);
    for (const auto& oe : b.removed_left) emit("removed", &oe, nullptr, oe.fp);

    std::size_t edited = 0, fuz = 0;
    for (const auto& p : fuzzy) {
        if (std::string_view(p.tag) == "edited") ++edited; else ++fuz;
    }

    std::string out;
    out += std::format("# ember diff\n");
    out += std::format("# old: {} ({} functions)\n", old_label, old_p.total);
    out += std::format("# new: {} ({} functions)\n", new_label, new_p.total);
    out += std::format(
        "# summary: kept={} moved={} edited={} fuzzy={} added={} removed={}\n",
        b.kept.size(), b.moved.size(), edited, fuz,
        b.added_left.size(), b.removed_left.size());
    out += "# columns: tag\tfp\told_addr\tnew_addr\told_name\tnew_name\n";
    out += body;
    return out;
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

[[nodiscard]] std::string
format_diff_json(const ParsedFps& old_p, const ParsedFps& new_p,
                 const std::string& old_label, const std::string& new_label) {
    auto b = bucket_exact(old_p, new_p);
    auto fuzzy = fuzzy_pair(b.removed_left, b.added_left);

    std::string body;
    auto emit = [&](std::string_view tag, std::string_view fp,
                    std::optional<ember::addr_t> old_addr,
                    std::optional<ember::addr_t> new_addr,
                    std::string_view old_name, std::string_view new_name) {
        if (!body.empty()) body += ",\n";
        body += std::format(
            "  {{\"tag\":\"{}\",\"fp\":\"{}\","
            "\"old_addr\":{},\"new_addr\":{},"
            "\"old_name\":\"{}\",\"new_name\":\"{}\"}}",
            tag, fp,
            old_addr ? std::format("\"{:#x}\"", *old_addr) : std::string{"null"},
            new_addr ? std::format("\"{:#x}\"", *new_addr) : std::string{"null"},
            json_escape(old_name), json_escape(new_name));
    };
    for (const auto& [oe, ne] : b.kept)
        emit("kept",  oe.fp, oe.addr, ne.addr, oe.name, ne.name);
    for (const auto& [oe, ne] : b.moved)
        emit("moved", oe.fp, oe.addr, ne.addr, oe.name, ne.name);
    for (const auto& p : fuzzy) {
        const std::string fp_tag = std::format("{}>{}",
            p.old_e.fp.substr(0, 4), p.new_e.fp.substr(0, 4));
        emit(p.tag, fp_tag, p.old_e.addr, p.new_e.addr, p.old_e.name, p.new_e.name);
    }
    for (const auto& ne : b.added_left)
        emit("added",   ne.fp, std::nullopt, ne.addr, "",      ne.name);
    for (const auto& oe : b.removed_left)
        emit("removed", oe.fp, oe.addr, std::nullopt, oe.name, "");

    std::size_t edited = 0, fuz = 0;
    for (const auto& p : fuzzy) {
        if (std::string_view(p.tag) == "edited") ++edited; else ++fuz;
    }

    std::string out;
    out += "{\n";
    out += std::format("  \"old\": {{\"path\":\"{}\",\"functions\":{}}},\n",
                       json_escape(old_label), old_p.total);
    out += std::format("  \"new\": {{\"path\":\"{}\",\"functions\":{}}},\n",
                       json_escape(new_label), new_p.total);
    out += std::format(
        "  \"summary\": {{\"kept\":{},\"moved\":{},\"edited\":{},\"fuzzy\":{},\"added\":{},\"removed\":{}}},\n",
        b.kept.size(), b.moved.size(), edited, fuz,
        b.added_left.size(), b.removed_left.size());
    out += "  \"entries\": [\n";
    out += body;
    out += "\n  ]\n}\n";
    return out;
}

[[nodiscard]] std::string slurp_file(const std::filesystem::path& path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) return {};
    const auto n = f.tellg();
    if (n < 0) return {};
    f.seekg(0, std::ios::beg);
    std::string s;
    s.resize(static_cast<std::size_t>(n));
    if (!s.empty()) f.read(s.data(), static_cast<std::streamsize>(s.size()));
    if (!f && !f.eof()) return {};
    return s;
}

int run_diff(const Args& args) {
    const auto cache_dir = args.cache_dir.empty()
        ? ember::cache::default_dir()
        : std::filesystem::path(args.cache_dir);

    // Pre-computed fingerprint TSVs via --fingerprint-old / --fingerprint-new
    // skip the lift-SSA-cleanup pipeline entirely. Useful for iterative
    // version diffs: export v717 once, then diff v717→v718 / v718→v719 /
    // … against that stored TSV without recomputing v717.
    std::string old_tsv, new_tsv;
    std::string old_label = args.diff_path;
    std::string new_label = args.binary;

    if (!args.fp_old_in.empty()) {
        old_tsv = slurp_file(args.fp_old_in);
        if (old_tsv.empty()) {
            std::println(stderr, "ember: --fingerprint-old: cannot read '{}'",
                         args.fp_old_in);
            return EXIT_FAILURE;
        }
        old_label = args.fp_old_in;
    }
    if (!args.fp_new_in.empty()) {
        new_tsv = slurp_file(args.fp_new_in);
        if (new_tsv.empty()) {
            std::println(stderr, "ember: --fingerprint-new: cannot read '{}'",
                         args.fp_new_in);
            return EXIT_FAILURE;
        }
        new_label = args.fp_new_in;
    }

    if (old_tsv.empty()) {
        if (args.diff_path.empty()) {
            std::println(stderr, "ember: --diff needs --fingerprint-old PATH or --diff OLD_BINARY");
            return EXIT_FAILURE;
        }
        std::println(stderr, "ember: diff OLD={}", args.diff_path);
        old_tsv = fingerprints_cached_or_compute(args.diff_path, cache_dir, args.no_cache);
    }
    if (new_tsv.empty()) {
        if (args.binary.empty()) {
            std::println(stderr, "ember: --diff needs --fingerprint-new PATH or a positional binary");
            return EXIT_FAILURE;
        }
        std::println(stderr, "ember: diff NEW={}", args.binary);
        new_tsv = fingerprints_cached_or_compute(args.binary, cache_dir, args.no_cache);
    }
    const auto old_p = parse_fingerprints_tsv(old_tsv);
    const auto new_p = parse_fingerprints_tsv(new_tsv);
    const std::string out = (args.diff_format == "json")
        ? format_diff_json(old_p, new_p, old_label, new_label)
        : format_diff     (old_p, new_p, old_label, new_label);
    std::fwrite(out.data(), 1, out.size(), stdout);
    return EXIT_SUCCESS;
}

int run_struct(const ember::Binary& b, std::string_view symbol, bool pseudo,
               const ember::Annotations* annotations, ember::EmitOptions opts) {
    auto win = ember::resolve_function(b, symbol);
    if (!win) {
        return EXIT_FAILURE;  // resolve_function already printed a diagnostic
    }
    // Vtable back-trace: resolve indirect call sites in this function
    // once, up-front. The map is per-function so we only pay the RTTI
    // parse + CFG build for the one function the user is viewing.
    std::map<ember::addr_t, ember::addr_t> call_res;
    if (pseudo && !opts.call_resolutions) {
        call_res = ember::compute_call_resolutions(b, win->start);
        if (!call_res.empty()) opts.call_resolutions = &call_res;
    }
    auto out = ember::format_struct(b, *win, pseudo, annotations, opts);
    if (!out) {
        std::println(stderr, "ember: {}: {}",
                     out.error().kind_name(), out.error().message);
        return EXIT_FAILURE;
    }
    std::print("{}", *out);
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
    if (!bin) {
        std::println(stderr, "ember: {}: {}",
                     bin.error().kind_name(), bin.error().message);
        return EXIT_FAILURE;
    }
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

    auto bin = ember::load_binary(args.binary);
    if (!bin) {
        std::println(stderr, "ember: {}: {}",
                     bin.error().kind_name(), bin.error().message);
        return EXIT_FAILURE;
    }
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
            if (!rv) {
                std::println(stderr, "ember: {}: {}",
                             rv.error().kind_name(), rv.error().message);
                return EXIT_FAILURE;
            }
            a = std::move(*rv);
        }
        auto sv = a.save(args.export_annotations);
        if (!sv) {
            std::println(stderr, "ember: {}: {}",
                         sv.error().kind_name(), sv.error().message);
            return EXIT_FAILURE;
        }
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
                if (!ld) {
                    std::println(stderr, "ember: {}: {}",
                                 ld.error().kind_name(), ld.error().message);
                    return EXIT_FAILURE;
                }
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
        if (!rv) {
            std::println(stderr, "ember: {}: {}",
                         rv.error().kind_name(), rv.error().message);
            return EXIT_FAILURE;
        }
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
        if (!rv) {
            std::println(stderr, "ember: {}: {}",
                         rv.error().kind_name(), rv.error().message);
            return EXIT_FAILURE;
        }
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
        if (cacheable) {
            if (auto hit = ember::cache::read(dir, key, "functions"); hit) {
                tsv.assign(hit->data(), hit->size());
            }
        }
        if (tsv.empty()) {
            tsv = build_functions_output(b);
            if (cacheable) {
                if (auto rv = ember::cache::write(dir, key, "functions", tsv); !rv) {
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
    std::map<ember::addr_t, ember::InferredSig> sigs;
    if (args.ipa && (args.pseudo || args.strct)) {
        std::println(stderr, "ember: running IPA (this pass lifts every function once)...");
        std::fflush(stderr);
        sigs = ember::infer_signatures(b);
        std::println(stderr, "ember: IPA done: {} functions analyzed", sigs.size());
        emit_opts.signatures = &sigs;
    }
    ember::LpMap lp_map;
    if (args.eh && (args.pseudo || args.strct)) {
        lp_map = ember::parse_landing_pads(b);
        std::println(stderr, "ember: EH data: {} landing-pad ranges parsed",
                     lp_map.size());
        emit_opts.landing_pads = &lp_map;
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

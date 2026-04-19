#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdlib>
#include <format>
#include <optional>
#include <print>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>

#include <ember/analysis/arity.hpp>
#include <ember/analysis/cfg_builder.hpp>
#include <ember/analysis/fingerprint.hpp>
#include <ember/analysis/function.hpp>
#include <ember/analysis/pipeline.hpp>
#include <ember/analysis/strings.hpp>
#include <ember/binary/binary.hpp>
#include <ember/common/annotations.hpp>
#include <ember/common/cache.hpp>
#include <ember/disasm/instruction.hpp>
#include <ember/disasm/x64_decoder.hpp>
#include <ember/ir/ir.hpp>
#include <ember/ir/passes.hpp>
#include <ember/ir/ssa.hpp>
#include <ember/ir/x64_lifter.hpp>
#include <ember/decompile/emitter.hpp>
#include <ember/script/runtime.hpp>
#include <ember/structure/region.hpp>
#include <ember/structure/structurer.hpp>

namespace {

struct Args {
    std::string binary;
    std::string symbol;
    std::string annotations_path;   // optional project-file for user edits (read-only load)
    std::string project_path;       // optional project-file authorising script mutations
    std::string script_path;        // optional JS script to run against the binary
    std::vector<std::string> script_argv; // args passed to the script after `--`
    std::string cache_dir;          // override for the disk cache location
    bool no_cache = false;          // disable the disk cache entirely
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
    {"",   "--strings",   &Args::strings},
    {"",   "--arities",   &Args::arities},
    {"",   "--fingerprints", &Args::fingerprints},
    {"",   "--no-cache",  &Args::no_cache},
    {"",   "--labels",    &Args::labels},
});

constexpr auto kValueFlags = std::to_array<ValueFlag>({
    {"-s", "--symbol",      &Args::symbol},
    {"",   "--annotations", &Args::annotations_path},
    {"",   "--cache-dir",   &Args::cache_dir},
    {"",   "--project",     &Args::project_path},
    {"",   "--script",      &Args::script_path},
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
        } else {
            return std::unexpected(ember::Error::invalid_format(
                std::format("unexpected positional argument: {}", s)));
        }
    }
    if (!a.help && a.binary.empty()) {
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
        std::println(stderr, "ember: symbol '{}' not found", symbol);
        return EXIT_FAILURE;
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
        std::println(stderr, "ember: symbol '{}' not found", symbol);
        return EXIT_FAILURE;
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

int run_ir(const ember::Binary& b, std::string_view symbol,
           bool run_ssa, bool run_opt) {
    auto win = ember::resolve_function(b, symbol);
    if (!win) {
        std::println(stderr, "ember: symbol '{}' not found", symbol);
        return EXIT_FAILURE;
    }

    const ember::X64Decoder  dec;
    const ember::CfgBuilder  builder(b, dec);
    auto fn_r = builder.build(win->start, win->label);
    if (!fn_r) {
        std::println(stderr, "ember: {}: {}",
                     fn_r.error().kind_name(), fn_r.error().message);
        return EXIT_FAILURE;
    }

    const ember::X64Lifter lifter;
    auto ir_r = lifter.lift(*fn_r);
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

[[nodiscard]] std::string build_arities_output(const ember::Binary& b) {
    std::string out;
    for (const auto& s : b.symbols()) {
        if (s.is_import) continue;
        if (s.kind != ember::SymbolKind::Function) continue;
        if (s.size == 0 || s.name.empty()) continue;
        const auto a = ember::infer_sysv_arity(b, s.addr);
        out += std::format("{:#x} {}\n", s.addr, a);
    }
    return out;
}

[[nodiscard]] std::string build_xrefs_output(const ember::Binary& b) {
    std::string out;
    for (const auto& e : ember::compute_call_graph(b)) {
        out += std::format("{:#x} -> {:#x}\n", e.caller, e.callee);
    }
    return out;
}

// Per-function content hash. One TSV row per entry:
//   <addr-hex>\t<fingerprint-hex>\t<blocks>\t<insts>\t<calls>\t<symbol-or-sub>
// Sorted by address. Address-independent — same algorithm across two PIE
// builds of the same code produces the same fingerprint column.
[[nodiscard]] std::string build_fingerprints_output(const ember::Binary& b) {
    // Build a one-shot addr -> name map; previously this was an O(n²) linear
    // rescan per function which took minutes on large stripped binaries.
    std::println(stderr, "ember: collecting named functions...");
    std::fflush(stderr);
    std::unordered_map<ember::addr_t, std::string> name_by_addr;
    for (const auto& s : b.symbols()) {
        if (s.is_import) continue;
        if (s.kind != ember::SymbolKind::Function) continue;
        if (s.addr == 0 || s.name.empty()) continue;
        name_by_addr.try_emplace(s.addr, s.name);
    }

    std::println(stderr, "ember: {} named functions; walking call graph "
                         "(this is the slow first step on big binaries)...",
                         name_by_addr.size());
    std::fflush(stderr);
    const auto edges = ember::compute_call_graph(b);
    std::println(stderr, "ember: {} call edges discovered", edges.size());
    std::fflush(stderr);

    std::set<ember::addr_t> fns;
    for (const auto& [a, _] : name_by_addr) fns.insert(a);
    for (const auto& e : edges) {
        if (!b.import_at_plt(e.callee)) fns.insert(e.callee);
    }

    std::string out;
    const auto total = fns.size();
    std::size_t done = 0;
    const auto tick = std::max<std::size_t>(1, total / 40);
    std::println(stderr, "ember: fingerprinting {} functions...", total);
    std::fflush(stderr);

    for (ember::addr_t a : fns) {
        const auto fp = ember::compute_fingerprint(b, a);
        ++done;
        if (done % tick == 0 || done == total) {
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
        out += std::format("{:x}\t{:016x}\t{}\t{}\t{}\t{}\n",
                           a, fp.hash, fp.blocks, fp.insts, fp.calls, name);
    }
    std::fputc('\n', stderr);
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

int run_struct(const ember::Binary& b, std::string_view symbol, bool pseudo,
               const ember::Annotations* annotations, ember::EmitOptions opts) {
    auto win = ember::resolve_function(b, symbol);
    if (!win) {
        std::println(stderr, "ember: symbol '{}' not found", symbol);
        return EXIT_FAILURE;
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
    std::println("  -c, --cfg            control-flow graph of a function");
    std::println("  -i, --ir             lifted IR of a function");
    std::println("      --ssa            IR in SSA form (implies -i)");
    std::println("  -O, --opt            run cleanup passes (implies --ssa)");
    std::println("      --struct         structured regions (implies -O)");
    std::println("  -p, --pseudo         pseudo-C output (implies --struct)");
    std::println("  -X, --xrefs          emit full call graph (all fn -> call targets)");
    std::println("      --strings        dump printable strings (addr|text|xrefs)");
    std::println("      --arities        dump inferred SysV arity per function (addr N)");
    std::println("      --fingerprints   dump address-independent content hash per function");
    std::println("  -s, --symbol NAME    target a specific symbol (default: main)");
    std::println("      --annotations P  path to a project file with renames/signatures");
    std::println("      --labels         keep // bb_XXXX comments in pseudo-C output");
    std::println("      --project PATH   project file scripts may read/write via project.*");
    std::println("      --script PATH    run a JavaScript file against the loaded binary");
    std::println("      -- ARG...        pass remaining args to the script as argv");
    std::println("      --cache-dir DIR  override ~/.cache/ember for disk cache");
    std::println("      --no-cache       bypass the disk cache (--xrefs/strings/arities)");
    std::println("  -h, --help           show this help");
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

    if (args.help) {
        print_help();
        return EXIT_SUCCESS;
    }

    auto bin = ember::load_binary(args.binary);
    if (!bin) {
        std::println(stderr, "ember: {}: {}",
                     bin.error().kind_name(), bin.error().message);
        return EXIT_FAILURE;
    }
    const ember::Binary& b = **bin;

    if (!args.script_path.empty()) {
        std::optional<ember::ProjectContext> project;
        if (!args.project_path.empty()) {
            project.emplace();
            project->path = args.project_path;
            // Missing-file is a clean-start; a malformed file is a real error.
            if (std::filesystem::exists(args.project_path)) {
                auto ld = ember::Annotations::load(args.project_path);
                if (!ld) {
                    std::println(stderr, "ember: {}: {}",
                                 ld.error().kind_name(), ld.error().message);
                    return EXIT_FAILURE;
                }
                project->loaded = std::move(*ld);
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
    if (args.strings) {
        return run_cached(args, "strings", [&] { return build_strings_output(b); });
    }
    if (args.fingerprints) {
        return run_cached(args, "fingerprints", [&] { return build_fingerprints_output(b); });
    }
    if (args.arities) {
        return run_cached(args, "arities", [&] { return build_arities_output(b); });
    }
    // Load user edits (renames, declared signatures) if the UI passed us a
    // project file. Missing/empty is non-fatal — we just fall back to the
    // generated names.
    ember::Annotations annotations;
    if (!args.annotations_path.empty()) {
        auto rv = ember::Annotations::load(args.annotations_path);
        if (rv) {
            annotations = std::move(*rv);
        } else {
            std::println(stderr,
                "ember: warning: {}: {}; continuing without user annotations",
                rv.error().kind_name(), rv.error().message);
        }
    }
    const ember::Annotations* ann_ptr =
        (!args.annotations_path.empty()) ? &annotations : nullptr;

    ember::EmitOptions emit_opts;
    emit_opts.show_bb_labels = args.labels;
    if (args.pseudo) {
        return run_struct(b, args.symbol, /*pseudo=*/true, ann_ptr, emit_opts);
    }
    if (args.strct) {
        return run_struct(b, args.symbol, /*pseudo=*/false, ann_ptr, emit_opts);
    }
    if (args.ir) {
        return run_ir(b, args.symbol, args.ssa, args.opt);
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

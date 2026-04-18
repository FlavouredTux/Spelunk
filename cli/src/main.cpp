#include <algorithm>
#include <cstddef>
#include <cstdlib>
#include <format>
#include <optional>
#include <print>
#include <span>
#include <string>
#include <string_view>

#include <ember/analysis/arity.hpp>
#include <ember/analysis/cfg_builder.hpp>
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
    bool help   = false;
};

[[nodiscard]] ember::Result<Args> parse_args(int argc, char** argv) {
    Args a;
    for (int i = 1; i < argc; ++i) {
        const std::string_view s = argv[i];
        if (s == "--") {
            // Everything after `--` is passed verbatim to the script as argv.
            for (int j = i + 1; j < argc; ++j) a.script_argv.emplace_back(argv[j]);
            break;
        }
        if (s == "-h" || s == "--help") {
            a.help = true;
        } else if (s == "-d" || s == "--disasm") {
            a.disasm = true;
        } else if (s == "-c" || s == "--cfg") {
            a.cfg = true;
        } else if (s == "-i" || s == "--ir") {
            a.ir = true;
        } else if (s == "--ssa") {
            a.ssa = true;
            a.ir = true;
        } else if (s == "-O" || s == "--opt") {
            a.opt = true;
            a.ssa = true;
            a.ir  = true;
        } else if (s == "--struct") {
            a.strct = true;
            a.opt   = true;
            a.ssa   = true;
        } else if (s == "-p" || s == "--pseudo") {
            a.pseudo = true;
            a.strct  = true;
            a.opt    = true;
            a.ssa    = true;
        } else if (s == "-X" || s == "--xrefs") {
            a.xrefs = true;
        } else if (s == "--strings") {
            a.strings = true;
        } else if (s == "--arities") {
            a.arities = true;
        } else if (s == "-s" || s == "--symbol") {
            if (++i >= argc) {
                return std::unexpected(ember::Error::invalid_format(
                    "-s requires an argument"));
            }
            a.symbol = argv[i];
        } else if (s == "--annotations") {
            if (++i >= argc) {
                return std::unexpected(ember::Error::invalid_format(
                    "--annotations requires a path"));
            }
            a.annotations_path = argv[i];
        } else if (s == "--cache-dir") {
            if (++i >= argc) {
                return std::unexpected(ember::Error::invalid_format(
                    "--cache-dir requires a path"));
            }
            a.cache_dir = argv[i];
        } else if (s == "--no-cache") {
            a.no_cache = true;
        } else if (s == "--project") {
            if (++i >= argc) {
                return std::unexpected(ember::Error::invalid_format(
                    "--project requires a path"));
            }
            a.project_path = argv[i];
        } else if (s == "--script") {
            if (++i >= argc) {
                return std::unexpected(ember::Error::invalid_format(
                    "--script requires a path"));
            }
            a.script_path = argv[i];
        } else if (s.starts_with("-")) {
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

template <class Compute>
int run_cached(const Args& args, std::string_view tag, Compute compute) {
    const auto dir = args.cache_dir.empty()
        ? ember::cache::default_dir()
        : std::filesystem::path(args.cache_dir);
    const std::string key = args.no_cache ? std::string{}
                                          : ember::cache::key_for(args.binary);
    if (!args.no_cache) {
        if (auto hit = ember::cache::read(dir, key, tag); hit) {
            std::fwrite(hit->data(), 1, hit->size(), stdout);
            return EXIT_SUCCESS;
        }
    }
    const std::string out = compute();
    std::fwrite(out.data(), 1, out.size(), stdout);
    if (!args.no_cache) {
        if (auto rv = ember::cache::write(dir, key, tag, out); !rv) {
            std::println(stderr, "ember: warning: {}: {}",
                         rv.error().kind_name(), rv.error().message);
        }
    }
    return EXIT_SUCCESS;
}

int run_struct(const ember::Binary& b, std::string_view symbol, bool pseudo,
               const ember::Annotations* annotations) {
    auto win = ember::resolve_function(b, symbol);
    if (!win) {
        std::println(stderr, "ember: symbol '{}' not found", symbol);
        return EXIT_FAILURE;
    }
    auto out = ember::format_struct(b, *win, pseudo, annotations);
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
    std::println("  -s, --symbol NAME    target a specific symbol (default: main)");
    std::println("      --annotations P  path to a project file with renames/signatures");
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

    if (args.pseudo) {
        return run_struct(b, args.symbol, /*pseudo=*/true, ann_ptr);
    }
    if (args.strct) {
        return run_struct(b, args.symbol, /*pseudo=*/false, ann_ptr);
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

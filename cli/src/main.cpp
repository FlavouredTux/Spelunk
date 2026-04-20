#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdlib>
#include <format>
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
#include <ember/analysis/eh_frame.hpp>
#include <ember/analysis/fingerprint.hpp>
#include <ember/analysis/function.hpp>
#include <ember/analysis/objc.hpp>
#include <ember/analysis/pipeline.hpp>
#include <ember/analysis/sig_inference.hpp>
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
    std::string diff_path;          // --diff OLD: compare this older binary against args.binary
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
    bool ipa    = false;            // run interprocedural signature inference for -p
    bool eh     = false;            // parse __eh_frame + LSDA and annotate landing pads
    bool objc_names = false;        // dump ObjC runtime -[Class sel] => IMP as TSV
    bool objc_protos = false;       // dump ObjC protocol signatures
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
    {"",   "--ipa",       &Args::ipa},
    {"",   "--eh",        &Args::eh},
    {"",   "--objc-names", &Args::objc_names},
    {"",   "--objc-protocols", &Args::objc_protos},
    {"",   "--no-cache",  &Args::no_cache},
    {"",   "--labels",    &Args::labels},
});

constexpr auto kValueFlags = std::to_array<ValueFlag>({
    {"-s", "--symbol",      &Args::symbol},
    {"",   "--annotations", &Args::annotations_path},
    {"",   "--cache-dir",   &Args::cache_dir},
    {"",   "--project",     &Args::project_path},
    {"",   "--script",      &Args::script_path},
    {"",   "--diff",        &Args::diff_path},
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

// Read the cached fingerprints TSV for `binary_path`, or compute + store it.
// Matches the cache-key logic of run_cached() but doesn't touch stdout — used
// by run_diff() to pull TSVs for both binaries into memory for comparison.
// Cache tag for fingerprint TSVs includes the fingerprint schema version
// so schema bumps orphan old entries without nuking unrelated caches.
[[nodiscard]] std::string fingerprints_cache_tag() {
    return std::format("fingerprints-{}", ember::kFingerprintSchema);
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
};
struct ParsedFps {
    std::unordered_map<std::string, std::vector<FpEntry>> by_fp;
    std::size_t total = 0;
};

// Parse the TSV that build_fingerprints_output produces:
//   <addr>\t<fp>\t<blocks>\t<insts>\t<calls>\t<name>
[[nodiscard]] ParsedFps parse_fingerprints_tsv(const std::string& tsv) {
    ParsedFps out;
    std::size_t pos = 0;
    while (pos < tsv.size()) {
        const auto nl = tsv.find('\n', pos);
        const std::size_t end = (nl == std::string::npos) ? tsv.size() : nl;
        const std::string_view line(tsv.data() + pos, end - pos);
        pos = (nl == std::string::npos) ? tsv.size() : nl + 1;
        if (line.empty() || line.front() == '#') continue;
        std::array<std::string_view, 6> f{};
        std::size_t s = 0, fi = 0;
        for (std::size_t i = 0; i <= line.size() && fi < f.size(); ++i) {
            if (i == line.size() || line[i] == '\t') {
                f[fi++] = line.substr(s, i - s);
                s = i + 1;
            }
        }
        if (fi < 6) continue;
        ember::addr_t addr = 0;
        const auto r = std::from_chars(f[0].data(),
                                       f[0].data() + f[0].size(), addr, 16);
        if (r.ec != std::errc{}) continue;
        out.by_fp[std::string{f[1]}].push_back(
            FpEntry{addr, std::string{f[1]}, std::string{f[5]}});
        ++out.total;
    }
    return out;
}

// Diff two fingerprint maps. Output is one TSV row per function pairing:
//   kept     <fp> <old_addr> <new_addr> <old_name> <new_name>
//   moved    <fp> <old_addr> <new_addr> <old_name> <new_name>
//   added    <fp> -          <new_addr> -          <new_name>
//   removed  <fp> <old_addr> -          <old_name> -
// `kept` = same fp, same addr, same name. `moved` = same fp, anything else.
// Summary line prefixed with '#' so awk filters stay simple.
[[nodiscard]] std::string
format_diff(const ParsedFps& old_p, const ParsedFps& new_p,
            const std::string& old_label, const std::string& new_label) {
    std::size_t kept = 0, moved = 0, added = 0, removed = 0;
    std::string body;

    for (const auto& [fp, nvec] : new_p.by_fp) {
        const auto it = old_p.by_fp.find(fp);
        if (it == old_p.by_fp.end()) {
            for (const auto& ne : nvec) {
                body += std::format("added\t{}\t-\t{:x}\t-\t{}\n",
                                    fp, ne.addr, ne.name);
                ++added;
            }
            continue;
        }
        const auto& ovec = it->second;
        const auto pairs = std::min(ovec.size(), nvec.size());
        for (std::size_t i = 0; i < pairs; ++i) {
            const auto& oe = ovec[i];
            const auto& ne = nvec[i];
            const bool identical = oe.addr == ne.addr && oe.name == ne.name;
            body += std::format("{}\t{}\t{:x}\t{:x}\t{}\t{}\n",
                                identical ? "kept" : "moved",
                                fp, oe.addr, ne.addr, oe.name, ne.name);
            if (identical) ++kept; else ++moved;
        }
        // Leftover instances on either side (collision-count mismatches) show
        // up as added/removed for the uncovered entries.
        for (std::size_t i = pairs; i < nvec.size(); ++i) {
            body += std::format("added\t{}\t-\t{:x}\t-\t{}\n",
                                fp, nvec[i].addr, nvec[i].name);
            ++added;
        }
        for (std::size_t i = pairs; i < ovec.size(); ++i) {
            body += std::format("removed\t{}\t{:x}\t-\t{}\t-\n",
                                fp, ovec[i].addr, ovec[i].name);
            ++removed;
        }
    }
    for (const auto& [fp, ovec] : old_p.by_fp) {
        if (new_p.by_fp.contains(fp)) continue;
        for (const auto& oe : ovec) {
            body += std::format("removed\t{}\t{:x}\t-\t{}\t-\n",
                                fp, oe.addr, oe.name);
            ++removed;
        }
    }

    std::string out;
    out += std::format("# ember diff\n");
    out += std::format("# old: {} ({} functions)\n", old_label, old_p.total);
    out += std::format("# new: {} ({} functions)\n", new_label, new_p.total);
    out += std::format("# summary: kept={} moved={} added={} removed={}\n",
                       kept, moved, added, removed);
    out += "# columns: tag\tfp\told_addr\tnew_addr\told_name\tnew_name\n";
    out += body;
    return out;
}

int run_diff(const Args& args) {
    if (args.binary.empty()) {
        std::println(stderr, "ember: --diff requires the new binary as the final arg");
        return EXIT_FAILURE;
    }
    const auto cache_dir = args.cache_dir.empty()
        ? ember::cache::default_dir()
        : std::filesystem::path(args.cache_dir);

    std::println(stderr, "ember: diff OLD={}", args.diff_path);
    std::println(stderr, "ember: diff NEW={}", args.binary);
    const std::string old_tsv =
        fingerprints_cached_or_compute(args.diff_path, cache_dir, args.no_cache);
    const std::string new_tsv =
        fingerprints_cached_or_compute(args.binary,   cache_dir, args.no_cache);
    const auto old_p = parse_fingerprints_tsv(old_tsv);
    const auto new_p = parse_fingerprints_tsv(new_tsv);
    const std::string out =
        format_diff(old_p, new_p, args.diff_path, args.binary);
    std::fwrite(out.data(), 1, out.size(), stdout);
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
    std::println("      --diff OLD       diff OLD binary vs the positional binary by fingerprint");
    std::println("      --ipa            run interprocedural char*-arg propagation before -p/--struct");
    std::println("      --eh             parse __eh_frame + LSDA; annotate landing-pad blocks");
    std::println("      --objc-names     dump recovered Obj-C methods as TSV (imp, ±, class, selector, sig)");
    std::println("      --objc-protocols dump Obj-C protocol method signatures");
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

    if (!args.diff_path.empty()) {
        return run_diff(args);
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
        return run_cached(args, fingerprints_cache_tag(),
                          [&] { return build_fingerprints_output(b); });
    }
    if (args.objc_names) {
        return run_cached(args, "objc-names",
                          [&] { return build_objc_names_output(b); });
    }
    if (args.objc_protos) {
        return run_cached(args, "objc-protocols",
                          [&] { return build_objc_protocols_output(b); });
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
    if (args.cfg) {
        return run_cfg(b, args.symbol);
    }
    if (args.disasm) {
        return run_disasm(b, args.symbol);
    }

    print_info(b, args.binary);
    return EXIT_SUCCESS;
}

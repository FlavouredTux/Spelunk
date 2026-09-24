#include <spelunk/common/diagnostic.hpp>
// Per-view runners (asm/cfg/ir/struct/pseudo) and the emit pipeline.

#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <expected>
#include <filesystem>
#include <format>
#include <fstream>
#include <map>
#include <optional>
#include <print>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

#include <spelunk/analysis/cfg_builder.hpp>
#include <spelunk/analysis/eh_frame.hpp>
#include <spelunk/analysis/identify.hpp>
#include <spelunk/analysis/indirect_calls.hpp>
#include <spelunk/analysis/ir_cache.hpp>
#include <spelunk/analysis/objc.hpp>
#include <spelunk/analysis/pe_unwind.hpp>
#include <spelunk/analysis/pipeline.hpp>
#include <spelunk/analysis/sig_inference.hpp>
#include <spelunk/analysis/sigs.hpp>
#include <spelunk/binary/arch.hpp>
#include <spelunk/binary/binary.hpp>
#include <spelunk/binary/format.hpp>
#include <spelunk/binary/pe.hpp>
#include <spelunk/common/annotations.hpp>
#include <spelunk/common/error.hpp>
#include <spelunk/common/timing.hpp>
#include <spelunk/common/types.hpp>
#include <spelunk/decompile/emit_options.hpp>
#include <spelunk/disasm/decoder.hpp>
#include <spelunk/ir/ir.hpp>
#include <spelunk/ir/lifter.hpp>
#include <spelunk/ir/passes.hpp>
#include <spelunk/ir/ssa.hpp>

#include "../cli_error.hpp"
#include "../build_stamp.hpp"
#include "../header_import.hpp"
#include "../info.hpp"
#include "../subcommands.hpp"
#include "common.hpp"

namespace spelunk::cli {

namespace {

[[nodiscard]] Result<std::vector<std::string>> load_view_symbols(const Args& args) {
    if (args.symbols_path.empty())
        return std::vector<std::string>{args.symbol};
    if (!args.symbol.empty()) {
        return std::unexpected(
            Error::invalid_format("--symbols cannot be combined with -s/--symbol"));
    }
    std::ifstream in(args.symbols_path);
    if (!in) {
        return std::unexpected(Error::io("could not open symbol manifest: " + args.symbols_path));
    }
    std::vector<std::string> symbols;
    std::set<std::string> seen;
    std::string line;
    std::size_t line_number = 0;
    while (std::getline(in, line)) {
        ++line_number;
        if (const auto hash = line.find('#'); hash != std::string::npos) {
            line.resize(hash);
        }
        const auto first = line.find_first_not_of(" \t\r\n");
        if (first == std::string::npos)
            continue;
        const auto last = line.find_last_not_of(" \t\r\n");
        std::string symbol = line.substr(first, last - first + 1);
        if (symbol.find_first_of(" \t") != std::string::npos) {
            return std::unexpected(Error::invalid_format(std::format(
                "{}:{}: symbol must not contain whitespace", args.symbols_path, line_number)));
        }
        if (!seen.insert(symbol).second) {
            return std::unexpected(Error::invalid_format(std::format(
                "{}:{}: duplicate symbol '{}'", args.symbols_path, line_number, symbol)));
        }
        symbols.push_back(std::move(symbol));
    }
    if (symbols.empty()) {
        return std::unexpected(
            Error::invalid_format(args.symbols_path + ": symbol manifest is empty"));
    }
    return symbols;
}

Result<std::string> render_struct_window(const Binary& b, const FuncWindow& win, bool pseudo,
                                         const Annotations* annotations, EmitOptions opts) {
    // Vtable back-trace: resolve indirect call sites in this function
    // once, up-front. Per-function so we only pay the RTTI parse + CFG
    // build for the one function the user is viewing.
    std::map<addr_t, addr_t> call_res;
    if (pseudo && !opts.call_resolutions) {
        call_res = compute_call_resolutions(b, win.start, opts.known_function_entries);
        if (!call_res.empty()) opts.call_resolutions = &call_res;
    }
    return format_struct(b, win, pseudo, annotations, opts);
}

Result<std::string> render_ir_window(const Binary& b, const FuncWindow& win,
                                     bool run_ssa, bool run_opt) {
    auto dec_r = make_decoder(b);
    if (!dec_r) return std::unexpected(dec_r.error());
    const CfgBuilder builder(b, **dec_r);
    auto fn_r = builder.build(win.start, win.label);
    if (!fn_r) return std::unexpected(fn_r.error());
    auto lifter_r = make_lifter(b);
    if (!lifter_r) return std::unexpected(lifter_r.error());
    auto ir_r = (*lifter_r)->lift(*fn_r);
    if (!ir_r) return std::unexpected(ir_r.error());
    if (run_ssa) {
        const SsaBuilder ssa;
        if (auto rv = ssa.convert(*ir_r); !rv) return std::unexpected(rv.error());
    }
    std::string output;
    if (run_opt) {
        auto stats = run_cleanup(*ir_r);
        if (!stats) return std::unexpected(stats.error());
        output = std::format("; cleanup: {} iter, removed {} insts / {} phis, folded {}, propagated {}\n\n",
            stats->iterations, stats->insts_removed, stats->phis_removed,
            stats->constants_folded, stats->copies_propagated);
    }
    output += format_ir_function(*ir_r);
    return output;
}

// PDB-derived signature injection. PE binaries get a per-VA
// FunctionSig map populated by attach_pdb_from_path() - pull those
// records into the user-facing Annotations under a "user explicit
// wins" precedence so PDB types feed the emitter (and the UI's
// signature renderer) without ever overwriting hand-edits.
[[nodiscard]] std::size_t merge_debug_signatures(const Binary& b,
                                                  Annotations& annotations) {
    std::size_t added = 0;
    for (const auto& [va, sig] : b.debug_signatures()) {
        if (annotations.signatures.try_emplace(va, sig).second) ++added;
    }
    if (const auto* pe = dynamic_cast<const PeBinary*>(&b); pe != nullptr) {
        for (const auto& [va, sig] : pe->pdb_signatures()) {
            if (annotations.signatures.try_emplace(va, sig).second) ++added;
        }
    }
    return added;
}

// FLIRT-style sig matching. Loads each --pat file, runs apply_signatures
// against the candidate function set, and merges resolved names into the
// annotations map. User renames win on conflict - sig matches never
// override operator intent.
[[nodiscard]] int apply_pat_files(const Args& args, const Binary& b,
                                  Annotations& annotations, bool& ann_loaded) {
    std::vector<std::filesystem::path> paths;
    paths.reserve(args.pat_paths.size());
    for (const auto& p : args.pat_paths) paths.emplace_back(p);
    auto db = sigs::load_pats(paths);
    if (!db) {
        spelunk::diagnostic::print("spelunk: --pat: {}: {}",
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
        spelunk::diagnostic::print("spelunk: sigs: loaded {} sig(s) from {} file(s), {} match(es)",
            db->size(), args.pat_paths.size(), matches.size());
    }
    return EXIT_SUCCESS;
}

}  // namespace

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

    auto out = render_ir_window(b, *win, run_ssa, run_opt);
    if (!out) return report(out.error());
    std::print("{}", *out);
    return EXIT_SUCCESS;
}

int run_struct(const Binary& b, std::string_view symbol, bool pseudo,
               const Annotations* annotations, EmitOptions opts) {
    auto win = resolve_function(b, symbol, annotations);
    if (!win) return EXIT_FAILURE;
    auto out = render_struct_window(b, *win, pseudo, annotations, opts);
    if (!out) return report(out.error());
    std::print("{}", *out);
    return EXIT_SUCCESS;
}

int run_emit(const Args& args, const Binary& b) {
    auto view_symbols_r = load_view_symbols(args);
    if (!view_symbols_r)
        return report(view_symbols_r.error());
    const std::vector<std::string>& view_symbols = *view_symbols_r;
    const bool batch = !args.symbols_path.empty();
    const bool function_view = args.pseudo || args.strct || args.ir ||
        args.cfg_pseudo || args.cfg || args.disasm;
    if (batch && !function_view)
        return report(Error::invalid_format("--symbols requires a function view such as -p or -d"));
    bool ann_loaded = false;
    Annotations annotations = load_annotations_for(args, ann_loaded);

    if (int rc = apply_header_annotations(args, b, annotations, ann_loaded);
        rc != EXIT_SUCCESS) return rc;

    if (!args.pat_paths.empty()) {
        if (int rc = apply_pat_files(args, b, annotations, ann_loaded);
            rc != EXIT_SUCCESS) {
            return rc;
        }
    }

    // Merge PDB-derived signatures (only on PE binaries that had one
    // attached at load time). User-explicit sigs in the loaded
    // annotations win on collision.
    if (const std::size_t debug_added = merge_debug_signatures(b, annotations);
        debug_added > 0) {
        ann_loaded = true;
        if (!args.quiet) {
            spelunk::diagnostic::print("spelunk: debug info: {} function signature{}",
                debug_added, debug_added == 1 ? "" : "s");
        }
    }

    const Annotations* ann_ptr = ann_loaded ? &annotations : nullptr;

    EmitOptions emit_opts;
    emit_opts.show_bb_labels  = args.labels;
    emit_opts.c_source = args.emit_c;
    emit_opts.show_provenance = args.show_provenance;
    std::unordered_set<addr_t> known_function_entries;
    if (batch && (args.pseudo || args.strct || args.cfg_pseudo)) {
        const auto functions = enumerate_functions(b);
        known_function_entries.reserve(functions.size());
        for (const auto& function : functions) {
            known_function_entries.insert(function.addr);
        }
        emit_opts.known_function_entries = &known_function_entries;
    }
    std::vector<addr_t> view_scope;
    std::vector<std::optional<FuncWindow>> windows;
    windows.reserve(view_symbols.size());
    view_scope.reserve(view_symbols.size());
    for (const auto& symbol : view_symbols) {
        auto win = resolve_function(b, symbol, ann_ptr);
        if (win) {
            view_scope.push_back(win->start);
        }
        windows.push_back(std::move(win));
    }

    // IPA: one-shot fixed-point over the call graph before emission so
    // char*-arg propagation can cross function boundaries. Expensive on
    // large binaries - opt-in via --ipa.
    // One IrCache shared across IPA + the indirect-call resolver. Each
    // function pays its lift+SSA+cleanup cost once - the resolver, which
    // walks roughly the same set of functions IPA does, becomes nearly
    // free on top of the IPA pass.
    IrCache shared_ir_cache;
    emit_opts.ir_cache = &shared_ir_cache;
    if (!known_function_entries.empty()) {
        shared_ir_cache.known_entries = known_function_entries;
    }
    InferenceResult ipa;
    const bool project_ipa = !args.header_paths.empty() &&
        (b.arch() == Arch::Ppc32 || b.arch() == Arch::Ppc64) &&
        (args.pseudo || args.strct) && !view_scope.empty();
    if ((args.ipa || project_ipa) && (args.pseudo || args.strct)) {
        ScopedTimer t("ipa");
        if (!args.quiet) {
            spelunk::diagnostic::print("spelunk: running {} IPA...",
                         args.ipa ? "whole-binary" : "project-scoped");
            std::fflush(stderr);
        }
        ipa = infer_signatures(
            b, &shared_ir_cache,
            args.ipa ? std::span<const addr_t>{}
                     : std::span<const addr_t>(view_scope));
        if (!args.quiet) {
            spelunk::diagnostic::print("spelunk: IPA done: {} functions analyzed", ipa.sigs.size());
        }
        emit_opts.signatures = &ipa.sigs;
        emit_opts.type_arena = &ipa.arena;
    }
    std::map<addr_t, addr_t> resolutions;
    if (args.resolve_calls && (args.pseudo || args.strct)) {
        ScopedTimer t("resolve_calls");
        // Scope to the requested function - emit only renders one fn at a
        // time, so the rest of the binary's indirect calls would never be
        // observed. When the symbol can't be resolved the format step is
        // about to bail with "no symbol named X", so don't bother
        // resolving anything either.
        if (!view_scope.empty()) {
            spelunk::diagnostic::print("spelunk: resolving indirect calls (vtable + "
                                 "import back-trace)...");
            std::fflush(stderr);
            resolutions = resolve_indirect_calls(b, &shared_ir_cache, view_scope);
            spelunk::diagnostic::print("spelunk: indirect-call resolver: {} sites resolved",
                         resolutions.size());
            emit_opts.call_resolutions = &resolutions;
        }
    }
    LpMap lp_map;
    if (args.eh && (args.pseudo || args.strct)) {
        ScopedTimer t("eh_landing_pads");
        lp_map = parse_landing_pads(b);
        spelunk::diagnostic::print("spelunk: EH data: {} landing-pad ranges parsed",
                     lp_map.size());
        emit_opts.landing_pads = &lp_map;
    }
    // PE x64 prologue/epilogue suppression: parse UNWIND_INFO
    // unconditionally and feed the byte ranges to the emitter. Win64
    // frames are unreadable without this - every function leads with
    // `push rbx; sub rsp, K; mov [rsp+K], xmm6; ...` cruft that the
    // unwinder already describes.
    std::map<addr_t, addr_t> prologue_ranges;
    if ((args.pseudo || args.strct) && b.format() == Format::Pe) {
        ScopedTimer t("pe_unwind_prologues");
        prologue_ranges = build_prologue_ranges(b);
        if (!prologue_ranges.empty()) emit_opts.prologue_ranges = &prologue_ranges;
    }
    // __objc_selrefs is cheap to walk - do it unconditionally on Mach-O
    // so `objc_msgSend(*(u64*)(0x10...))` renders as `@selector(foo:)`
    // without requiring a separate flag.
    std::map<addr_t, std::string> selrefs;
    if ((args.pseudo || args.strct) && b.format() == Format::MachO) {
        ScopedTimer t("objc_selrefs");
        selrefs = parse_objc_selrefs(b);
        if (!selrefs.empty()) emit_opts.objc_selrefs = &selrefs;
    }
    const std::string_view view = args.pseudo ? (args.emit_c ? "emit-c" : "pseudo") :
        args.strct ? "struct" : args.ir ? (args.opt ? "opt" : args.ssa ? "ssa" : "ir") :
        args.cfg_pseudo ? "cfg-pseudo" : args.cfg ? "cfg" : "disasm";
    const auto render_one = [&](const FuncWindow& win) -> Result<std::string> {
        if (args.pseudo || args.strct)
            return render_struct_window(b, win, args.pseudo, ann_ptr, emit_opts);
        if (args.ir) return render_ir_window(b, win, args.ssa, args.opt);
        if (args.cfg_pseudo) return format_cfg_pseudo(b, win, ann_ptr, emit_opts);
        if (args.cfg) return format_cfg(b, win);
        return format_disasm(b, win);
    };
    auto run_each = [&] {
        int status = EXIT_SUCCESS;
        std::size_t emitted = 0;
        for (std::size_t i = 0; i < view_symbols.size(); ++i) {
            const auto& win = windows[i];
            Result<std::string> output = win ? render_one(*win) :
                Result<std::string>{std::unexpected(Error::invalid_format(
                    std::format("could not resolve function '{}'", view_symbols[i])))};
            // A batch may visit thousands of distinct callees. Release old
            // lifted IR between completed functions while retaining the
            // discovered-entry set for later CFG builds.
            constexpr std::size_t kMaxCachedCallees = 1024;
            if (shared_ir_cache.by_addr.size() + shared_ir_cache.failed.size() >
                kMaxCachedCallees) {
                shared_ir_cache.by_addr.clear();
                shared_ir_cache.failed.clear();
            }
            if (!output) status = EXIT_FAILURE;
            if (args.json) {
                const auto quote = [](std::string_view text) {
                    return "\"" + diagnostic::escape(text) + "\"";
                };
                const auto kind = win ? (output ? std::string_view{} : output.error().kind_name()) : "resolve-failed";
                const std::string error = output ? "null" : std::format(
                    "{{\"kind\":{},\"message\":{}}}", quote(kind), quote(output.error().message));
                std::println("{{\"schema_version\":1,{},\"type\":\"function\",\"symbol\":{},\"address\":{},\"name\":{},\"view\":{},\"status\":\"{}\",\"output\":{},\"error\":{}}}",
                    build_json_member(), quote(view_symbols[i]), win ? quote(std::format("{:#x}", win->start)) : "null",
                    win ? quote(win->label) : "null", quote(view), output ? "ok" : "error",
                    output ? quote(*output) : "null", error);
                // Preserve completed results if a later function times out.
                std::fflush(stdout);
                if (!output) diagnostic::write(output.error().message, kind, true);
                continue;
            }
            if (!win) continue; // resolver already reported the failure
            if (batch) {
                if (emitted != 0)
                    std::println("");
                std::println("// spelunk-symbol: {}", view_symbols[i]);
            }
            if (output) {
                const auto prefix = (args.pseudo || args.strct) ? "//" : ";";
                std::print("{}{}", build_comment(prefix), *output);
            }
            else (void)report(output.error());
            ++emitted;
        }
        return status;
    };
    if (args.pseudo) {
        ScopedTimer t("emit_pseudo");
        return run_each();
    }
    if (args.strct) {
        ScopedTimer t("emit_struct");
        return run_each();
    }
    if (args.ir) {
        return run_each();
    }
    if (args.cfg_pseudo) {
        return run_each();
    }
    if (args.cfg) {
        return run_each();
    }
    if (args.disasm) {
        return run_each();
    }
    constexpr std::size_t kDefaultInfoRowLimit = 2000;
    const std::size_t info_limit = args.row_limit_set
        ? static_cast<std::size_t>(args.row_limit)
        : kDefaultInfoRowLimit;
    print_info(b, args.binary, info_limit, args.verbose);
    return EXIT_SUCCESS;
}

}  // namespace spelunk::cli

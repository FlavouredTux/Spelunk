#include "subcommands.hpp"

#include <cstdlib>
#include <map>
#include <print>
#include <string_view>

#include <ember/analysis/cfg_builder.hpp>
#include <ember/analysis/pipeline.hpp>
#include <ember/binary/binary.hpp>
#include <ember/common/annotations.hpp>
#include <ember/decompile/emitter.hpp>
#include <ember/disasm/decoder.hpp>
#include <ember/ir/ir.hpp>
#include <ember/ir/lifter.hpp>
#include <ember/ir/passes.hpp>
#include <ember/ir/ssa.hpp>

#include "cli_error.hpp"

namespace ember::cli {

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

}  // namespace ember::cli

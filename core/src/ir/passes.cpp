// Shared masking helpers, pass ordering and the run_cleanup entry point.

#include <spelunk/ir/passes.hpp>

#include <algorithm>
#include <cstddef>
#include <utility>
#include <vector>

#include <spelunk/common/error.hpp>
#include <spelunk/common/types.hpp>
#include <spelunk/ir/ir.hpp>

#include "passes_internal.hpp"

namespace spelunk::ir_passes {

// ============================================================================
// Mask i64 result to an IrType width (sign-extending from low bits)
// ============================================================================
// Helper bound: i64 representation. Widths > 64 (I128) can't fit and don't
// occur on the constant-fold path - SIMD never folds through these helpers.
// Guarded with a passthrough so a future code path that DOES hit them won't
// silently corrupt; the i64 payload is returned unchanged.
i64 mask_signed(i64 v, IrType t) noexcept {
    const unsigned bits = type_bits(t);
    if (bits == 0 || bits >= 64) return v;
    const unsigned sign_bit = bits - 1;
    const u64 mask = (u64(1) << bits) - 1;
    u64 u = static_cast<u64>(v) & mask;
    if (u & (u64(1) << sign_bit)) u |= ~mask;
    return static_cast<i64>(u);
}

u64 mask_unsigned(i64 v, IrType t) noexcept {
    const unsigned bits = type_bits(t);
    if (bits >= 64) return static_cast<u64>(v);
    const u64 mask = (u64(1) << bits) - 1;
    return static_cast<u64>(v) & mask;
}

// PassManager - fixpoint driver with per-block dirty tracking
// ============================================================================
//
// Iteration 0 sweeps all blocks. After each iteration, the union of blocks
// that any pass actually mutated becomes the input dirty set for the next
// iteration; per-block passes restrict their work to that set, while
// whole-function passes (copy_prop, trivial_phi, dce) still run but skip
// quickly if no Assigns / Phis / dead insts changed shape.
//
// DCE is the only pass that mutates instruction *locations* (it deletes
// Nops and dead insts), so it's the only pass that invalidates the cached
// def map.
CleanupStats run_pipeline(IrFunction& fn) {
    CleanupStats stats;
    AnalysisManager am;
    stats.copies_propagated += pass_msvc_security_cookie_return(fn, am);
    constexpr std::size_t kMaxIter = 16;

    std::vector<u32> dirty;
    dirty.reserve(fn.blocks.size());
    for (u32 i = 0; i < static_cast<u32>(fn.blocks.size()); ++i) dirty.push_back(i);

    for (std::size_t it = 0; it < kMaxIter; ++it) {
        ++stats.iterations;
        std::vector<u32> next_dirty;

        const auto folded  = pass_constant_fold (fn, am, dirty, next_dirty);
        const auto casted  = pass_cast_simplify (fn, am, dirty, next_dirty);
        const auto idiomed = pass_idiom_recognize(fn, am, dirty, next_dirty);
        // GVN must run before memory_forward so both stores and loads see
        // the same canonical SSA id for their address expression.
        const auto gvned   = pass_local_gvn     (fn, am, dirty, next_dirty);
        const auto memfwd  = pass_memory_forward(fn, am, dirty, next_dirty);
        const auto dse     = pass_dead_store_elim(fn, am, dirty, next_dirty);
        const auto copied  = pass_copy_prop     (fn, am, dirty, next_dirty);
        const auto phied   = pass_trivial_phi   (fn, am, dirty, next_dirty);
        const auto deleted = pass_dce           (fn, am, dirty, next_dirty);
        if (deleted) am.invalidate_defs();

        stats.constants_folded  += folded + casted;
        stats.copies_propagated += copied + memfwd + gvned + idiomed;
        stats.phis_removed      += phied;
        stats.insts_removed     += deleted + dse;

        if (!folded && !casted && !idiomed && !gvned && !memfwd &&
            !dse && !copied && !phied && !deleted) break;

        std::sort(next_dirty.begin(), next_dirty.end());
        next_dirty.erase(std::unique(next_dirty.begin(), next_dirty.end()),
                         next_dirty.end());
        dirty = std::move(next_dirty);
        if (dirty.empty()) break;
    }

    return stats;
}

}  // namespace spelunk::ir_passes

namespace spelunk {

using namespace ir_passes;

Result<CleanupStats> run_cleanup(IrFunction& fn) {
    return run_pipeline(fn);
}

}  // namespace spelunk

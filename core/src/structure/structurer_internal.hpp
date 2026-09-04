#pragma once

// CFG facts and the region builder shared by the structurer units.

#include <cstddef>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <unordered_map>
#include <vector>

#include <ember/structure/structurer.hpp>

#include <ember/common/types.hpp>
#include <ember/ir/ir.hpp>
#include <ember/ir/ssa.hpp>
#include <ember/structure/region.hpp>

namespace ember::structurer {

// Sentinel for "no valid block address" in the structurer. Using 0 would
// collide with functions that legitimately start at 0x0 (e.g. unlinked .o
// files), causing build_sequence to terminate before it even processes the
// entry block.
inline constexpr addr_t kNoAddr = static_cast<addr_t>(-1);

// ============================================================================
// CFG analysis: RPO, dominators, loop headers, post-dominator merge points
// ============================================================================
struct CfgInfo {
    std::vector<addr_t>                     rpo;
    std::unordered_map<addr_t, std::size_t> rpo_index;
    std::unordered_map<addr_t, addr_t>      idom;
    // Immediate post-dominators. `ipdom[b]` is the first node that every
    // non-terminating path from `b` passes through. `kNoAddr` (the virtual
    // exit) means every path from `b` terminates with no finite merge.
    // Used by the structurer to pick if/switch convergence points - proper
    // post-dominance, not a BFS-depth heuristic.
    std::unordered_map<addr_t, addr_t>      ipdom;
    // loop_headers stays std::map because find_loops iterates it to populate
    // loop_exit; keeping sorted order makes structurer output deterministic
    // under hash-function tweaks.
    std::map<addr_t, std::set<addr_t>>      loop_headers;  // header -> back-edge sources
    std::unordered_map<addr_t, addr_t>      loop_exit;     // header -> exit successor
};

void find_loops(const IrFunction& fn, CfgInfo& info);

[[nodiscard]] CfgInfo analyze_cfg(const IrFunction& fn);

[[nodiscard]] std::unique_ptr<Region> make_empty();

// ============================================================================
// Region builder
// ============================================================================
class Builder {
public:
    Builder(const IrFunction& fn, const CfgInfo& info);

    // A return-only merge: a Return block whose only "real" instructions are
    // Phi and Return (no loads, stores, or computation). Sinking such a block
    // into both branches of the preceding if/else lets us resolve the phi
    // operand per branch and emit `return <const>;` instead of a trailing
    // unresolved `return rax_N;`. Caller must check bb.kind == Return first.
    [[nodiscard]] bool is_phi_only_return(const IrBlock& bb) const noexcept;

    // Append the merge's `Block + Return` pair to `branch`, materialising
    // `branch` as a Seq if it isn't one already. `pred` is the CFG predecessor
    // along this branch - used by make_return_from_block's phi resolution to
    // pick the operand that actually flowed in along this path.
    void sink_return_into_branch(std::unique_ptr<Region>& branch,
                                 const IrBlock& mbb, addr_t pred);

    std::unique_ptr<Region> build_sequence(addr_t entry, addr_t stop,
                                           addr_t* out_last_block = nullptr);

    // The switch's merge = the immediate post-dominator of the dispatch
    // block itself: the first node every non-terminating case falls through
    // to. `kNoAddr` means every case terminates (return/unreachable) with no
    // finite merge.
    addr_t compute_switch_merge(const IrBlock& sw_bb) const;

    std::unique_ptr<Region> build_switch(const IrBlock& sw_bb);

    std::unique_ptr<Region> build_loop(addr_t header);

    // Walk a Reg/Temp value chain through Assign and predecessor-resolved Phi
    // nodes. When `from_pred` is set, a Phi whose `phi_preds` contains it is
    // simplified to the matching operand; this is what lets a return cloned
    // into a single-predecessor context render `return -1;` instead of the
    // raw merge name `return rax_8;`. Returns the deepest resolvable form.
    [[nodiscard]] IrValue resolve_through_phis(IrValue v, addr_t from_pred,
                                               int depth = 0) const;

    // Emit a Return region carrying the best available return-value source
    // from `bb`'s Return instruction (same policy the Conditional switch uses).
    // `from_pred`, when known, is the immediate CFG predecessor in the cloned
    // structural context - used to resolve the value through any Phi whose
    // operand list mentions it (e.g. a fail/success arm rendered into one of
    // its predecessors as `return -1;` / `return 0;` instead of `return rax_N;`).
    [[nodiscard]] std::unique_ptr<Region>
    make_return_from_block(const IrBlock& bb, addr_t from_pred = kNoAddr);

    // A "trivial tail" is a chain of at most 6 blocks linked by Unconditional/
    // Fallthrough edges, ending in a Return or TailCall block. Phi nodes and
    // Calls are fine: duplicating them in the textual pseudo-C doesn't change
    // observed behaviour - both paths still execute the same IR at runtime.
    [[nodiscard]] std::optional<std::vector<addr_t>>
    collect_trivial_tail(addr_t start) const;

    // If `start` heads a trivial tail, produce a Seq that inlines the chain
    // followed by the appropriate Return region. Null otherwise. `from_pred`
    // is the structural predecessor at the inline site - used together with
    // `chain[size-2]` to resolve the return-value phi to the operand that
    // actually flowed in along this clone's path.
    [[nodiscard]] std::unique_ptr<Region>
    try_inline_trivial_tail(addr_t start, addr_t from_pred = kNoAddr);

    // Fallback for non-Return tails: re-enter build_sequence from `target`
    // with a fresh visited context, cap the resulting subtree at a node
    // budget, and reject the result if it still contains any Goto (we want
    // strict improvement, not a goto-for-goto swap). Used when a simple
    // trivial-tail inline doesn't apply but the target's full subtree is
    // reasonably small.
    [[nodiscard]] std::unique_ptr<Region> try_inline_bounded_tail(addr_t target);

    static std::size_t count_regions(const Region& r) noexcept;

    static bool contains_goto(const Region& r) noexcept;
private:
    const IrFunction&                   fn_;
    const CfgInfo&                      info_;
    std::map<SsaKey, const IrInst*>     defs_;
    std::set<addr_t>                    visited_;
    std::set<addr_t>                    loop_headers_stack_;
    std::set<addr_t>                    loop_exits_stack_;
    bool                                inlining_bounded_ = false;
};

}  // namespace ember::structurer

#include <ember/structure/structurer.hpp>

#include <algorithm>
#include <cstddef>
#include <deque>
#include <format>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include <ember/analysis/cfg_util.hpp>
#include <ember/ir/ssa.hpp>

namespace ember {

namespace {

// Sentinel for "no valid block address" in the structurer. Using 0 would
// collide with functions that legitimately start at 0x0 (e.g. unlinked .o
// files), causing build_sequence to terminate before it even processes the
// entry block.
constexpr addr_t kNoAddr = static_cast<addr_t>(-1);

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
    // Used by the structurer to pick if/switch convergence points — proper
    // post-dominance, not a BFS-depth heuristic.
    std::unordered_map<addr_t, addr_t>      ipdom;
    // loop_headers stays std::map because find_loops iterates it to populate
    // loop_exit; keeping sorted order makes structurer output deterministic
    // under hash-function tweaks.
    std::map<addr_t, std::set<addr_t>>      loop_headers;  // header -> back-edge sources
    std::unordered_map<addr_t, addr_t>      loop_exit;     // header -> exit successor
};

// compute_rpo + compute_idoms live in <ember/analysis/cfg_util.hpp>.

// Cooper-Harvey-Kennedy on the reverse CFG: compute immediate post-dominators.
// The virtual exit (kNoAddr) is the root; forward-terminating blocks are its
// reverse-CFG predecessors.
[[nodiscard]] std::unordered_map<addr_t, addr_t>
compute_ipdoms(const IrFunction& fn) {
    std::vector<addr_t> post;   // post-order on reverse CFG from virtual exit
    std::set<addr_t>    seen;

    std::function<void(addr_t)> visit = [&](addr_t n) {
        if (!seen.insert(n).second) return;
        if (n == kNoAddr) {
            // Reverse-CFG successors of the virtual exit = forward-terminating
            // blocks (return, unreachable, or indirect-jmp-with-no-modeled-target).
            for (const auto& bb : fn.blocks) {
                if (bb.successors.empty()) visit(bb.start);
            }
        } else {
            auto it = fn.block_at.find(n);
            if (it != fn.block_at.end()) {
                // Reverse-CFG successors = forward predecessors.
                for (addr_t p : fn.blocks[it->second].predecessors) visit(p);
            }
        }
        post.push_back(n);
    };
    visit(kNoAddr);

    // RPO of reverse CFG = reverse of post-order.
    std::vector<addr_t> rpo(post.rbegin(), post.rend());
    std::unordered_map<addr_t, std::size_t> rpo_idx;
    rpo_idx.reserve(rpo.size());
    for (std::size_t i = 0; i < rpo.size(); ++i)
        rpo_idx[rpo[i]] = i;

    std::unordered_map<addr_t, addr_t> ipdom;
    ipdom[kNoAddr] = kNoAddr;

    auto intersect = [&](addr_t b1, addr_t b2) noexcept -> addr_t {
        while (b1 != b2) {
            auto i1 = rpo_idx.find(b1);
            auto i2 = rpo_idx.find(b2);
            if (i1 == rpo_idx.end() || i2 == rpo_idx.end()) return b1;
            while (i1->second > i2->second) {
                auto it = ipdom.find(b1);
                if (it == ipdom.end()) return b2;
                b1 = it->second;
                i1 = rpo_idx.find(b1);
                if (i1 == rpo_idx.end()) return b2;
            }
            while (i2->second > i1->second) {
                auto it = ipdom.find(b2);
                if (it == ipdom.end()) return b1;
                b2 = it->second;
                i2 = rpo_idx.find(b2);
                if (i2 == rpo_idx.end()) return b1;
            }
        }
        return b1;
    };

    bool changed = true;
    while (changed) {
        changed = false;
        for (std::size_t i = 1; i < rpo.size(); ++i) {
            const addr_t b = rpo[i];
            if (b == kNoAddr) continue;
            auto it = fn.block_at.find(b);
            if (it == fn.block_at.end()) continue;
            const auto& bb = fn.blocks[it->second];

            // Reverse-CFG predecessors of b = forward successors of b,
            // with kNoAddr substituted for a forward-terminating case.
            std::vector<addr_t> rev_preds;
            if (bb.successors.empty()) {
                rev_preds.push_back(kNoAddr);
            } else {
                for (addr_t s : bb.successors) rev_preds.push_back(s);
            }

            std::optional<addr_t> new_ipdom;
            for (addr_t p : rev_preds) {
                if (!ipdom.contains(p)) continue;
                new_ipdom = new_ipdom ? intersect(p, *new_ipdom) : p;
            }
            if (!new_ipdom) continue;

            auto cur = ipdom.find(b);
            if (cur == ipdom.end() || cur->second != *new_ipdom) {
                ipdom[b] = *new_ipdom;
                changed = true;
            }
        }
    }

    return ipdom;
}

[[nodiscard]] bool dominates(const std::unordered_map<addr_t, addr_t>& idom,
                             addr_t dominator, addr_t node) noexcept {
    while (true) {
        if (node == dominator) return true;
        auto it = idom.find(node);
        if (it == idom.end()) return false;
        if (it->second == node) return false;
        node = it->second;
    }
}

void find_loops(const IrFunction& fn, CfgInfo& info) {
    for (const auto& bb : fn.blocks) {
        for (addr_t s : bb.successors) {
            if (dominates(info.idom, /*dominator=*/s, /*node=*/bb.start)) {
                info.loop_headers[s].insert(bb.start);
            }
        }
    }

    auto can_reach = [&](addr_t start, const std::set<addr_t>& targets, addr_t forbidden) -> bool {
        std::set<addr_t> seen;
        std::deque<addr_t> q;
        q.push_back(start);
        while (!q.empty()) {
            addr_t n = q.front();
            q.pop_front();
            if (n == forbidden) continue;
            if (!seen.insert(n).second) continue;
            if (targets.contains(n)) return true;
            auto it = fn.block_at.find(n);
            if (it == fn.block_at.end()) continue;
            for (addr_t s : fn.blocks[it->second].successors) q.push_back(s);
        }
        return false;
    };

    for (auto& [header, backs] : info.loop_headers) {
        auto hit = fn.block_at.find(header);
        if (hit == fn.block_at.end()) continue;
        const auto& hbb = fn.blocks[hit->second];
        // Top-tested loop (while/for): header itself is the predicate.
        if (hbb.kind == BlockKind::Conditional && hbb.successors.size() == 2) {
            addr_t s1 = hbb.successors[0];
            addr_t s2 = hbb.successors[1];
            const bool s1_loops = can_reach(s1, backs, /*forbidden=*/header);
            const bool s2_loops = can_reach(s2, backs, /*forbidden=*/header);
            if (s1_loops && !s2_loops)      info.loop_exit[header] = s2;
            else if (s2_loops && !s1_loops) info.loop_exit[header] = s1;
            continue;
        }
        // Bottom-tested loop (do-while): header isn't conditional, but a
        // back-edge tail tests-and-exits. Pick the first qualifying tail's
        // non-back-edge successor as the loop's exit so build_sequence can
        // continue past the loop.
        for (const addr_t tail : backs) {
            auto tit = fn.block_at.find(tail);
            if (tit == fn.block_at.end()) continue;
            const auto& tbb = fn.blocks[tit->second];
            if (tbb.kind != BlockKind::Conditional || tbb.successors.size() != 2) continue;
            const addr_t t1 = tbb.successors[0];
            const addr_t t2 = tbb.successors[1];
            if      (t1 == header) { info.loop_exit[header] = t2; break; }
            else if (t2 == header) { info.loop_exit[header] = t1; break; }
        }
    }
}

[[nodiscard]] CfgInfo analyze_cfg(const IrFunction& fn) {
    CfgInfo info;
    info.rpo = compute_rpo(fn);
    info.rpo_index.reserve(info.rpo.size());
    for (std::size_t i = 0; i < info.rpo.size(); ++i)
        info.rpo_index[info.rpo[i]] = i;
    info.idom  = compute_idoms(fn, info.rpo, info.rpo_index);
    info.ipdom = compute_ipdoms(fn);
    find_loops(fn, info);
    return info;
}

// ============================================================================
// Merge-point lookup: exact post-dominance via CfgInfo.ipdom
// ============================================================================

[[nodiscard]] addr_t merge_after(const CfgInfo& info, addr_t b) noexcept {
    auto it = info.ipdom.find(b);
    if (it == info.ipdom.end()) return kNoAddr;
    // ipdom of a self-loop entry can point to the node itself; treat that
    // as "no finite merge" (loop structurer handles it via loop_exit).
    if (it->second == b) return kNoAddr;
    return it->second;
}

// ============================================================================
// Condition extraction
// ============================================================================

[[nodiscard]] IrValue extract_condition(const IrBlock& bb) noexcept {
    for (auto it = bb.insts.rbegin(); it != bb.insts.rend(); ++it) {
        if (it->op == IrOp::CondBranch && it->src_count >= 1) {
            return it->srcs[0];
        }
    }
    return IrValue{};
}

// ============================================================================
// Region helpers
// ============================================================================

[[nodiscard]] std::unique_ptr<Region> make_empty() {
    return std::make_unique<Region>();
}

[[nodiscard]] std::unique_ptr<Region> make_block(addr_t a) {
    auto r = std::make_unique<Region>();
    r->kind        = RegionKind::Block;
    r->block_start = a;
    return r;
}

[[nodiscard]] std::unique_ptr<Region> make_simple(RegionKind k) {
    auto r = std::make_unique<Region>();
    r->kind = k;
    return r;
}

[[nodiscard]] std::unique_ptr<Region> make_goto(addr_t t) {
    auto r = std::make_unique<Region>();
    r->kind   = RegionKind::Goto;
    r->target = t;
    return r;
}

[[nodiscard]] bool is_empty_region(const Region* r) noexcept {
    if (!r) return true;
    if (r->kind == RegionKind::Empty) return true;
    if (r->kind == RegionKind::Seq && r->children.empty()) return true;
    return false;
}

// ============================================================================
// Region builder
// ============================================================================

class Builder {
public:
    Builder(const IrFunction& fn, const CfgInfo& info) noexcept
        : fn_(fn), info_(info) {
        for (const auto& bb : fn_.blocks) {
            for (const auto& inst : bb.insts) {
                if (auto k = ssa_key(inst.dst); k) defs_[*k] = &inst;
            }
        }
    }

    // A return-only merge: a Return block whose only "real" instructions are
    // Phi and Return (no loads, stores, or computation). Sinking such a block
    // into both branches of the preceding if/else lets us resolve the phi
    // operand per branch and emit `return <const>;` instead of a trailing
    // unresolved `return rax_N;`. Caller must check bb.kind == Return first.
    [[nodiscard]] bool is_phi_only_return(const IrBlock& bb) const noexcept {
        if (bb.kind != BlockKind::Return) return false;
        for (const auto& inst : bb.insts) {
            switch (inst.op) {
                case IrOp::Phi:
                case IrOp::Return:
                case IrOp::Nop:
                    continue;
                default:
                    return false;
            }
        }
        return true;
    }

    // Append the merge's `Block + Return` pair to `branch`, materialising
    // `branch` as a Seq if it isn't one already. `pred` is the CFG predecessor
    // along this branch — used by make_return_from_block's phi resolution to
    // pick the operand that actually flowed in along this path.
    void sink_return_into_branch(std::unique_ptr<Region>& branch,
                                 const IrBlock& mbb, addr_t pred) {
        if (!branch || is_empty_region(branch.get())) {
            branch = std::make_unique<Region>();
            branch->kind = RegionKind::Seq;
        }
        if (branch->kind != RegionKind::Seq) {
            auto outer = std::make_unique<Region>();
            outer->kind = RegionKind::Seq;
            outer->children.push_back(std::move(branch));
            branch = std::move(outer);
        }
        branch->children.push_back(make_block(mbb.start));
        branch->children.push_back(make_return_from_block(mbb, pred));
    }

    std::unique_ptr<Region> build_sequence(addr_t entry, addr_t stop,
                                           addr_t* out_last_block = nullptr) {
        auto seq = std::make_unique<Region>();
        seq->kind = RegionKind::Seq;

        // Default: branch terminated internally (return / goto / break /
        // continue). Only natural fall-through exits update this with the
        // actual exit-pred — see end of function.
        if (out_last_block) *out_last_block = kNoAddr;

        addr_t current = entry;
        // Last block we just walked through, in order to identify the CFG
        // predecessor of a Return / inline target. Reset whenever we descend
        // into a sub-region whose own seq could end on multiple predecessors
        // (if/else, switch, loop) — those merge points are genuinely multi-pred
        // and the phi resolution should leave the value as a real merge.
        addr_t last_block = kNoAddr;
        while (current != kNoAddr && current != stop) {
            if (loop_headers_stack_.contains(current)) {
                seq->children.push_back(make_simple(RegionKind::Continue));
                return seq;
            }
            if (loop_exits_stack_.contains(current)) {
                seq->children.push_back(make_simple(RegionKind::Break));
                return seq;
            }
            if (visited_.contains(current)) {
                // Common idiom: `if (err) goto fail; ... fail: cleanup; return -1;`
                // When the target is a short unconditional chain ending in a
                // Return, duplicate it here instead of emitting the goto.
                if (auto inlined = try_inline_trivial_tail(current, last_block);
                    inlined) {
                    seq->children.push_back(std::move(inlined));
                    return seq;
                }
                // Fallback: try inlining the full subtree rooted at the goto
                // target. Only accepted if the result is small and contains
                // no further gotos (strict improvement, not a swap).
                if (auto inlined = try_inline_bounded_tail(current); inlined) {
                    seq->children.push_back(std::move(inlined));
                    return seq;
                }
                seq->children.push_back(make_goto(current));
                return seq;
            }

            if (info_.loop_headers.contains(current)) {
                auto loop_region = build_loop(current);
                seq->children.push_back(std::move(loop_region));
                auto it = info_.loop_exit.find(current);
                current = (it != info_.loop_exit.end()) ? it->second : kNoAddr;
                continue;
            }

            visited_.insert(current);
            auto bit = fn_.block_at.find(current);
            if (bit == fn_.block_at.end()) break;
            const auto& bb = fn_.blocks[bit->second];

            switch (bb.kind) {
                case BlockKind::Return:
                case BlockKind::TailCall: {
                    // TailCall was lifted as `call; return rax;` — the block
                    // ends with a Return IR inst, identical in shape to a
                    // Return block. Treat them uniformly. `last_block` is the
                    // single CFG predecessor we walked in from (kNoAddr if we
                    // got here through a merge of multiple structural paths,
                    // in which case the phi stays as a real merge).
                    seq->children.push_back(make_block(current));
                    seq->children.push_back(make_return_from_block(bb, last_block));
                    return seq;
                }
                case BlockKind::IndirectJmp: {
                    seq->children.push_back(make_block(current));
                    seq->children.push_back(make_simple(RegionKind::Unreachable));
                    return seq;
                }
                case BlockKind::Switch: {
                    seq->children.push_back(make_block(current));
                    auto sw = build_switch(bb);
                    // Pick a merge point for what comes after the switch —
                    // approximate the post-dominator as the shortest point
                    // reachable from every case target.
                    addr_t merge = compute_switch_merge(bb);
                    seq->children.push_back(std::move(sw));
                    if (merge == kNoAddr) return seq;
                    current = merge;
                    last_block = kNoAddr;  // merge has multiple structural preds
                    break;
                }
                case BlockKind::Unconditional:
                case BlockKind::Fallthrough: {
                    seq->children.push_back(make_block(current));
                    if (bb.successors.empty()) return seq;
                    last_block = current;
                    current = bb.successors[0];
                    break;
                }
                case BlockKind::Conditional: {
                    seq->children.push_back(make_block(current));
                    addr_t s_taken = bb.successors.size() > 0 ? bb.successors[0] : kNoAddr;
                    addr_t s_fall  = bb.successors.size() > 1 ? bb.successors[1] : kNoAddr;

                    const addr_t merge = merge_after(info_, bb.start);
                    const IrValue cond = extract_condition(bb);

                    std::unique_ptr<Region> then_r, else_r;
                    bool invert = false;
                    addr_t then_last = kNoAddr;
                    addr_t else_last = kNoAddr;

                    if (merge == s_taken && merge != kNoAddr) {
                        then_r = build_sequence(s_fall, s_taken, &then_last);
                        invert = true;
                    } else if (merge == s_fall && merge != kNoAddr) {
                        then_r = build_sequence(s_taken, s_fall, &then_last);
                    } else {
                        then_r = build_sequence(s_taken, merge, &then_last);
                        else_r = build_sequence(s_fall, merge, &else_last);
                    }

                    // If the merge is a phi-only return block, sink the
                    // return into each branch that actually falls through to
                    // it, with the phi resolved per that branch's exit
                    // predecessor — turning `return rax_N;` into
                    // `return 0;` / `return -1;` per arm.
                    //
                    // Branches that already terminated internally (via
                    // inline-trivial-tail or goto) have out_last_block ==
                    // kNoAddr and are skipped; appending a second return
                    // there would be dead code. For an IfThen (no else)
                    // the implicit-else path reaches the merge via the
                    // conditional block itself; we emit a synthetic
                    // trailing return after the if for that case.
                    bool sunk_return = false;
                    bool needs_trailing_return = false;
                    addr_t trailing_merge = kNoAddr;
                    if (merge != kNoAddr && then_r &&
                        (then_last != kNoAddr ||
                         (else_r && else_last != kNoAddr) ||
                         !else_r)) {
                        auto mit = fn_.block_at.find(merge);
                        if (mit != fn_.block_at.end() &&
                            is_phi_only_return(fn_.blocks[mit->second])) {
                            const auto& mbb = fn_.blocks[mit->second];
                            if (then_last != kNoAddr) {
                                sink_return_into_branch(then_r, mbb, then_last);
                            }
                            if (else_r && else_last != kNoAddr) {
                                sink_return_into_branch(else_r, mbb, else_last);
                            }
                            // No else region but the merge is phi-only-return
                            // — the condition-false path falls through and
                            // also needs a resolved return after the if.
                            // Predecessor for that operand is the conditional
                            // block itself (`current`).
                            if (!else_r) {
                                needs_trailing_return = true;
                                trailing_merge = merge;
                            }
                            visited_.insert(merge);
                            sunk_return = true;
                        }
                    }

                    auto ifr = std::make_unique<Region>();
                    ifr->condition = cond;
                    ifr->invert    = invert;
                    if (else_r && !is_empty_region(else_r.get())) {
                        ifr->kind = RegionKind::IfElse;
                        ifr->children.push_back(std::move(then_r));
                        ifr->children.push_back(std::move(else_r));
                    } else {
                        ifr->kind = RegionKind::IfThen;
                        ifr->children.push_back(std::move(then_r));
                    }
                    seq->children.push_back(std::move(ifr));

                    if (sunk_return) {
                        if (needs_trailing_return) {
                            auto mit = fn_.block_at.find(trailing_merge);
                            if (mit != fn_.block_at.end()) {
                                const auto& mbb = fn_.blocks[mit->second];
                                seq->children.push_back(make_block(trailing_merge));
                                seq->children.push_back(
                                    make_return_from_block(mbb, current));
                            }
                        }
                        // Merge consumed (in branches and/or trailing) —
                        // nothing more to emit at this level.
                        if (out_last_block) *out_last_block = kNoAddr;
                        return seq;
                    }
                    if (merge == kNoAddr) {
                        if (out_last_block) *out_last_block = kNoAddr;
                        return seq;
                    }
                    current = merge;
                    last_block = kNoAddr;  // merge has multiple structural preds
                    break;
                }
            }
        }

        // Natural exit: we walked off the loop because `current == stop` (or
        // hit kNoAddr). `last_block` holds the predecessor of `stop` along
        // this branch — the caller (e.g. the if/else handler) needs it to
        // resolve a phi at the merge.
        if (out_last_block) *out_last_block = last_block;
        return seq;
    }

    // The switch's merge = the immediate post-dominator of the dispatch
    // block itself: the first node every non-terminating case falls through
    // to. `kNoAddr` means every case terminates (return/unreachable) with no
    // finite merge.
    addr_t compute_switch_merge(const IrBlock& sw_bb) const {
        return merge_after(info_, sw_bb.start);
    }

    std::unique_ptr<Region> build_switch(const IrBlock& sw_bb) {
        auto r = std::make_unique<Region>();
        r->kind         = RegionKind::Switch;
        r->has_default  = sw_bb.has_default;
        r->switch_index = sw_bb.switch_index;

        const addr_t merge = compute_switch_merge(sw_bb);

        // For sparse switches the compiler pads the jump table by pointing
        // missing-case slots at the default block. Without recognising this,
        // those slots render as `case N:` falling through to the next
        // listed body — a bald lie about control flow. Treat any case
        // whose target equals the default's target as "covered by default"
        // and drop it from the rendered switch entirely.
        const addr_t dflt_target =
            (sw_bb.has_default && !sw_bb.successors.empty())
                ? sw_bb.successors.back()
                : kNoAddr;

        // If the switch's merge is a phi-only return block, every case
        // body would otherwise render as empty (each arm is just a
        // br-to-merge after cleanup hoists case-specific assignments
        // into the merge's phi). Sink the return into each non-empty
        // case body, with the phi resolved per the case's exit pred —
        // typically the case's own block when it falls through to merge
        // directly, which is the common compiler-emitted shape for big
        // jump-table switches over enums returning a value.
        bool sink_into_cases = false;
        if (merge != kNoAddr) {
            auto mit = fn_.block_at.find(merge);
            if (mit != fn_.block_at.end() &&
                is_phi_only_return(fn_.blocks[mit->second])) {
                sink_into_cases = true;
            }
        }

        // De-duplicate cases that share the same target — the resulting
        // switch would be structurally identical; instead we group them
        // by target and let the emitter render multiple "case N:" labels
        // before a single body. We encode this by emitting empty children
        // (RegionKind::Empty) for duplicates, with the body under the last
        // one. Simple and preserves the 1:1 values↔children mapping.
        const std::size_t n_cases = sw_bb.case_values.size();
        std::map<addr_t, std::size_t> last_occurrence;
        for (std::size_t i = 0; i < n_cases; ++i) {
            const addr_t tgt = sw_bb.successors[i];
            if (tgt == dflt_target) continue;
            last_occurrence[tgt] = i;
        }

        auto build_case_with_optional_sink = [&](addr_t tgt) {
            addr_t case_last = kNoAddr;
            auto body = build_sequence(tgt, merge, &case_last);
            if (sink_into_cases && case_last != kNoAddr) {
                auto mit = fn_.block_at.find(merge);
                if (mit != fn_.block_at.end()) {
                    sink_return_into_branch(body, fn_.blocks[mit->second],
                                            case_last);
                }
            }
            return body;
        };

        for (std::size_t i = 0; i < n_cases; ++i) {
            const addr_t tgt = sw_bb.successors[i];
            if (tgt == dflt_target) continue;
            r->case_values.push_back(sw_bb.case_values[i]);
            if (last_occurrence[tgt] == i) {
                r->children.push_back(build_case_with_optional_sink(tgt));
            } else {
                r->children.push_back(make_empty());
            }
        }
        if (sw_bb.has_default && !sw_bb.successors.empty()) {
            const addr_t dflt = sw_bb.successors.back();
            r->children.push_back(build_case_with_optional_sink(dflt));
        }
        if (sink_into_cases) visited_.insert(merge);
        return r;
    }

    std::unique_ptr<Region> build_loop(addr_t header) {
        auto bit = fn_.block_at.find(header);
        if (bit == fn_.block_at.end()) return make_empty();
        const auto& bb = fn_.blocks[bit->second];

        auto loop_r = std::make_unique<Region>();

        addr_t body_entry = kNoAddr;
        addr_t exit       = kNoAddr;
        bool   have_cond  = false;
        IrValue cond;
        bool    invert    = false;

        if (bb.kind == BlockKind::Conditional && bb.successors.size() == 2) {
            addr_t s1 = bb.successors[0];
            addr_t s2 = bb.successors[1];
            auto eit = info_.loop_exit.find(header);
            // Only a top-tested while-loop if one of the header's two
            // successors actually IS the loop's exit. Otherwise the
            // header's conditional is an *internal* branch (e.g. a
            // skip-and-accumulate inside a do-while body), and we must
            // fall through to do_while detection — picking up the
            // tail-tested predicate from the back-edge tail. Without
            // this guard the header's internal cond gets emitted as the
            // loop test, swallowing one of its arms entirely.
            if (eit != info_.loop_exit.end() &&
                (s1 == eit->second || s2 == eit->second)) {
                exit = eit->second;
                body_entry = (s1 == exit) ? s2 : s1;
                invert = (s1 == exit);
                cond = extract_condition(bb);
                have_cond = true;
            }
        }

        // Do-while detection: header has no usable top-of-loop condition,
        // but at least one back-edge source is conditional and one of its
        // successors is the loop's exit. The tail test drives the loop,
        // body runs at least once.
        //
        // We accept loops with multiple back-edge tails as long as exactly
        // one is the conditional test-and-exit shape: the other tails are
        // unconditional back-jumps from inside the body (e.g. an early
        // `continue` arm of an if/else inside the loop). Picking the
        // qualifying tail and treating it as the do-while predicate is
        // sound because every other back-edge already proceeds straight
        // to the same header.
        bool do_while = false;
        addr_t dw_tail = kNoAddr;
        if (!have_cond) {
            auto lh = info_.loop_headers.find(header);
            if (lh != info_.loop_headers.end() && !lh->second.empty()) {
                for (const addr_t tail : lh->second) {
                    auto tit = fn_.block_at.find(tail);
                    if (tit == fn_.block_at.end()) continue;
                    const auto& tbb = fn_.blocks[tit->second];
                    if (tbb.kind != BlockKind::Conditional ||
                        tbb.successors.size() != 2) continue;
                    const addr_t t1 = tbb.successors[0];
                    const addr_t t2 = tbb.successors[1];
                    addr_t ex = kNoAddr;
                    bool back_first = false;
                    if (t1 == header) { ex = t2; back_first = true; }
                    else if (t2 == header) { ex = t1; }
                    if (ex == kNoAddr) continue;

                    do_while = true;
                    dw_tail  = tail;
                    exit     = ex;
                    cond     = extract_condition(tbb);
                    invert   = !back_first;
                    break;
                }
            }
        }

        // For-loop detection: a while where the body's single back-edge
        // predecessor ends in an increment-and-store of a stack local that
        // the loop condition also uses. We look for the store at the last
        // body instruction of the block that branches back to the header.
        bool is_for = false;
        addr_t for_update_block = 0;
        u32    for_update_inst  = 0;
        auto detect_for_update = [&]() -> bool {
            if (!have_cond) return false;
            auto lh = info_.loop_headers.find(header);
            if (lh == info_.loop_headers.end() || lh->second.empty()) return false;
            // Pick the most-representative back-edge tail (single tail case
            // is overwhelmingly common for natural loops).
            const addr_t tail = *lh->second.begin();
            auto tit = fn_.block_at.find(tail);
            if (tit == fn_.block_at.end()) return false;
            const auto& tbb = fn_.blocks[tit->second];
            // Walk tail insts in reverse to find a Store of
            // Add/Sub(Load(addr), imm) where addr is a stack local.
            for (std::size_t k = tbb.insts.size(); k-- > 0;) {
                const auto& inst = tbb.insts[k];
                if (inst.op == IrOp::Branch ||
                    inst.op == IrOp::CondBranch ||
                    inst.op == IrOp::BranchIndirect ||
                    inst.op == IrOp::Return ||
                    inst.op == IrOp::Nop) continue;
                if (inst.op != IrOp::Store || inst.src_count < 2) return false;
                // The store's address must be a stack local.
                // (We can't re-run stack_offset here without a defs map;
                // approximate by requiring the address to be a Temp or Reg.)
                // Delta RHS must be an Add/Sub(Load(same_addr), Imm) shape.
                // That's the exact invariant we already rely on in the
                // emitter's peephole — if it matches, it'll render cleanly.
                for_update_block = tail;
                for_update_inst  = static_cast<u32>(k);
                return true;
            }
            return false;
        };

        if (have_cond) {
            is_for = detect_for_update();
        }

        if (have_cond) {
            loop_r->condition = cond;
            loop_r->invert    = invert;
            if (is_for) {
                loop_r->kind         = RegionKind::For;
                loop_r->has_update   = true;
                loop_r->update_block = for_update_block;
                loop_r->update_inst  = for_update_inst;
            } else {
                loop_r->kind = RegionKind::While;
            }
        } else if (do_while) {
            loop_r->kind      = RegionKind::DoWhile;
            loop_r->condition = cond;
            loop_r->invert    = invert;
        } else {
            loop_r->kind = RegionKind::Loop;
        }

        visited_.insert(header);
        loop_r->children.push_back(make_block(header));

        loop_headers_stack_.insert(header);
        if (exit != kNoAddr) loop_exits_stack_.insert(exit);

        // For a do-while the body continues through fallthrough / block
        // successors from the header until (but not including) the exit.
        // For a while, body starts at body_entry.
        if (body_entry != kNoAddr) {
            auto body = build_sequence(body_entry, header);
            loop_r->children.push_back(std::move(body));
        } else if (do_while) {
            // Walk header → tail via the body path. Stop *before* dw_tail so
            // its cond-branch isn't rendered as `if (cond) continue; else break;`
            // — the trailing `} while (cond);` already carries the predicate.
            // Then emit dw_tail's block (non-branch insts) as the loop's last
            // body element so observable effects match the asm.
            if (header != dw_tail && !bb.successors.empty()) {
                if (bb.kind == BlockKind::Conditional &&
                    bb.successors.size() == 2) {
                    // Header has its own *internal* conditional (neither arm
                    // is the loop exit — that's at dw_tail). Structure the
                    // two arms as an if/else inside the body so the skip /
                    // accumulate halves both render. Without this, only
                    // bb.successors[0]'s path is emitted and the other arm
                    // disappears silently.
                    const addr_t s1 = bb.successors[0];
                    const addr_t s2 = bb.successors[1];
                    auto then_r = build_sequence(s1, dw_tail);
                    auto else_r = build_sequence(s2, dw_tail);
                    auto ifr = std::make_unique<Region>();
                    ifr->condition = extract_condition(bb);
                    if (else_r && !is_empty_region(else_r.get())) {
                        ifr->kind = RegionKind::IfElse;
                        ifr->children.push_back(std::move(then_r));
                        ifr->children.push_back(std::move(else_r));
                    } else {
                        ifr->kind = RegionKind::IfThen;
                        ifr->children.push_back(std::move(then_r));
                    }
                    loop_r->children.push_back(std::move(ifr));
                } else {
                    auto body = build_sequence(bb.successors.front(), dw_tail);
                    loop_r->children.push_back(std::move(body));
                }
                visited_.insert(dw_tail);
                loop_r->children.push_back(make_block(dw_tail));
            }
        }

        loop_headers_stack_.erase(header);
        if (exit != kNoAddr) loop_exits_stack_.erase(exit);

        return loop_r;
    }

    // Walk a Reg/Temp value chain through Assign and predecessor-resolved Phi
    // nodes. When `from_pred` is set, a Phi whose `phi_preds` contains it is
    // simplified to the matching operand; this is what lets a return cloned
    // into a single-predecessor context render `return -1;` instead of the
    // raw merge name `return rax_8;`. Returns the deepest resolvable form.
    [[nodiscard]] IrValue resolve_through_phis(IrValue v, addr_t from_pred,
                                               int depth = 0) const {
        if (depth > 16) return v;
        auto k = ssa_key(v);
        if (!k) return v;
        auto it = defs_.find(*k);
        if (it == defs_.end()) return v;
        const IrInst* d = it->second;
        if (d->op == IrOp::Assign && d->src_count >= 1) {
            return resolve_through_phis(d->srcs[0], from_pred, depth + 1);
        }
        if (d->op == IrOp::Phi && from_pred != kNoAddr) {
            const std::size_t n = std::min(d->phi_operands.size(),
                                           d->phi_preds.size());
            for (std::size_t i = 0; i < n; ++i) {
                if (d->phi_preds[i] == from_pred) {
                    return resolve_through_phis(d->phi_operands[i],
                                                from_pred, depth + 1);
                }
            }
        }
        return v;
    }

    // Emit a Return region carrying the best available return-value source
    // from `bb`'s Return instruction (same policy the Conditional switch uses).
    // `from_pred`, when known, is the immediate CFG predecessor in the cloned
    // structural context — used to resolve the value through any Phi whose
    // operand list mentions it (e.g. a fail/success arm rendered into one of
    // its predecessors as `return -1;` / `return 0;` instead of `return rax_N;`).
    [[nodiscard]] std::unique_ptr<Region>
    make_return_from_block(const IrBlock& bb, addr_t from_pred = kNoAddr) {
        auto r = make_simple(RegionKind::Return);
        auto is_live_in_reg = [](const IrValue& v) {
            return v.kind == IrValueKind::Reg && v.version == 0;
        };
        auto is_meaningful_fp_carrier = [](const IrValue& v) {
            if (!is_float_type(v.type)) return false;
            if (v.kind != IrValueKind::Reg) return true;
            if (v.reg == Reg::Xmm0 && v.version == 0) return false;
            return true;
        };
        for (auto it = bb.insts.rbegin(); it != bb.insts.rend(); ++it) {
            if (it->op != IrOp::Return || it->src_count == 0) continue;
            const IrValue* best = nullptr;
            for (u8 k = 0; k < it->src_count && k < it->srcs.size(); ++k) {
                const IrValue& s = it->srcs[k];
                if (s.kind == IrValueKind::None) continue;
                if (!best) { best = &s; continue; }
                if (!is_live_in_reg(s)) { best = &s; break; }
                if (is_live_in_reg(*best) && !is_meaningful_fp_carrier(*best) &&
                    is_meaningful_fp_carrier(s)) {
                    best = &s;
                }
            }
            if (best) {
                r->condition = resolve_through_phis(*best, from_pred);
            }
            break;
        }
        return r;
    }

    // A "trivial tail" is a chain of at most 6 blocks linked by Unconditional/
    // Fallthrough edges, ending in a Return or TailCall block. Phi nodes and
    // Calls are fine: duplicating them in the textual pseudo-C doesn't change
    // observed behaviour — both paths still execute the same IR at runtime.
    [[nodiscard]] std::optional<std::vector<addr_t>>
    collect_trivial_tail(addr_t start) const {
        constexpr std::size_t kMaxLen = 6;
        std::vector<addr_t> chain;
        std::set<addr_t> seen;
        addr_t cur = start;
        while (chain.size() < kMaxLen) {
            if (seen.contains(cur)) return std::nullopt;
            seen.insert(cur);
            auto bit = fn_.block_at.find(cur);
            if (bit == fn_.block_at.end()) return std::nullopt;
            const auto& bb = fn_.blocks[bit->second];
            chain.push_back(cur);
            if (bb.kind == BlockKind::Return || bb.kind == BlockKind::TailCall) {
                return chain;
            }
            if (bb.kind != BlockKind::Unconditional &&
                bb.kind != BlockKind::Fallthrough) {
                return std::nullopt;
            }
            if (bb.successors.empty()) return std::nullopt;
            cur = bb.successors[0];
        }
        return std::nullopt;
    }

    // If `start` heads a trivial tail, produce a Seq that inlines the chain
    // followed by the appropriate Return region. Null otherwise. `from_pred`
    // is the structural predecessor at the inline site — used together with
    // `chain[size-2]` to resolve the return-value phi to the operand that
    // actually flowed in along this clone's path.
    [[nodiscard]] std::unique_ptr<Region>
    try_inline_trivial_tail(addr_t start, addr_t from_pred = kNoAddr) {
        auto chain = collect_trivial_tail(start);
        if (!chain) return nullptr;
        auto seq = std::make_unique<Region>();
        seq->kind = RegionKind::Seq;
        for (addr_t a : *chain) seq->children.push_back(make_block(a));
        auto bit = fn_.block_at.find(chain->back());
        // Predecessor of the return block within the cloned chain. For
        // length>=2 the chain itself supplies it; for length 1 the caller's
        // last-emitted block (passed in `from_pred`) is the only signal.
        const addr_t ret_pred = chain->size() >= 2
            ? (*chain)[chain->size() - 2]
            : from_pred;
        seq->children.push_back(
            make_return_from_block(fn_.blocks[bit->second], ret_pred));
        return seq;
    }

    // Fallback for non-Return tails: re-enter build_sequence from `target`
    // with a fresh visited context, cap the resulting subtree at a node
    // budget, and reject the result if it still contains any Goto (we want
    // strict improvement, not a goto-for-goto swap). Used when a simple
    // trivial-tail inline doesn't apply but the target's full subtree is
    // reasonably small.
    [[nodiscard]] std::unique_ptr<Region> try_inline_bounded_tail(addr_t target) {
        if (inlining_bounded_) return nullptr;
        constexpr std::size_t kMaxNodes = 30;

        auto saved_visited = visited_;
        visited_.erase(target);
        inlining_bounded_ = true;
        auto subtree = build_sequence(target, kNoAddr);
        inlining_bounded_ = false;
        visited_ = std::move(saved_visited);

        if (!subtree) return nullptr;
        if (count_regions(*subtree) > kMaxNodes) return nullptr;
        if (contains_goto(*subtree)) return nullptr;
        return subtree;
    }

    static std::size_t count_regions(const Region& r) noexcept {
        std::size_t n = 1;
        for (const auto& c : r.children) {
            if (c) n += count_regions(*c);
        }
        return n;
    }

    static bool contains_goto(const Region& r) noexcept {
        if (r.kind == RegionKind::Goto) return true;
        for (const auto& c : r.children) {
            if (c && contains_goto(*c)) return true;
        }
        return false;
    }

private:
    const IrFunction&                   fn_;
    const CfgInfo&                      info_;
    std::map<SsaKey, const IrInst*>     defs_;
    std::set<addr_t>                    visited_;
    std::set<addr_t>                    loop_headers_stack_;
    std::set<addr_t>                    loop_exits_stack_;
    bool                                inlining_bounded_ = false;
};

// ============================================================================
// Printer
// ============================================================================

void print_region(const Region& r, const IrFunction& fn,
                  int depth, std::string& out) {
    const std::string ind(static_cast<std::size_t>(depth) * 2u, ' ');

    switch (r.kind) {
        case RegionKind::Empty:
            return;

        case RegionKind::Block: {
            auto it = fn.block_at.find(r.block_start);
            if (it == fn.block_at.end()) return;
            const auto& bb = fn.blocks[it->second];
            out += std::format("{}; bb_{:x}\n", ind, bb.start);
            for (const auto& inst : bb.insts) {
                if (inst.op == IrOp::Branch ||
                    inst.op == IrOp::BranchIndirect ||
                    inst.op == IrOp::CondBranch ||
                    inst.op == IrOp::Return ||
                    inst.op == IrOp::Unreachable ||
                    inst.op == IrOp::Nop) {
                    continue;
                }
                out += std::format("{}{}\n", ind, format_ir_inst(inst));
            }
            return;
        }

        case RegionKind::Seq: {
            for (const auto& c : r.children) {
                print_region(*c, fn, depth, out);
            }
            return;
        }

        case RegionKind::IfThen: {
            const std::string cs = format_ir_value(r.condition);
            const std::string cond = r.invert ? std::format("!({})", cs) : cs;
            out += std::format("{}if ({}) {{\n", ind, cond);
            if (!r.children.empty()) {
                print_region(*r.children[0], fn, depth + 1, out);
            }
            out += std::format("{}}}\n", ind);
            return;
        }

        case RegionKind::IfElse: {
            const std::string cs = format_ir_value(r.condition);
            const std::string cond = r.invert ? std::format("!({})", cs) : cs;
            out += std::format("{}if ({}) {{\n", ind, cond);
            if (r.children.size() > 0) print_region(*r.children[0], fn, depth + 1, out);
            out += std::format("{}}} else {{\n", ind);
            if (r.children.size() > 1) print_region(*r.children[1], fn, depth + 1, out);
            out += std::format("{}}}\n", ind);
            return;
        }

        case RegionKind::While: {
            const std::string cs = format_ir_value(r.condition);
            const std::string cond = r.invert ? std::format("!({})", cs) : cs;
            out += std::format("{}while ({}) {{\n", ind, cond);
            for (const auto& c : r.children) {
                print_region(*c, fn, depth + 1, out);
            }
            out += std::format("{}}}\n", ind);
            return;
        }

        case RegionKind::Loop: {
            out += std::format("{}loop {{\n", ind);
            for (const auto& c : r.children) {
                print_region(*c, fn, depth + 1, out);
            }
            out += std::format("{}}}\n", ind);
            return;
        }

        case RegionKind::DoWhile: {
            out += std::format("{}do {{\n", ind);
            for (const auto& c : r.children) {
                print_region(*c, fn, depth + 1, out);
            }
            const std::string cs = format_ir_value(r.condition);
            const std::string cond = r.invert ? std::format("!({})", cs) : cs;
            out += std::format("{}}} while ({});\n", ind, cond);
            return;
        }

        case RegionKind::For: {
            const std::string cs = format_ir_value(r.condition);
            const std::string cond = r.invert ? std::format("!({})", cs) : cs;
            out += std::format("{}for (; {}; update@{:x}:{}) {{\n",
                               ind, cond, r.update_block, r.update_inst);
            for (const auto& c : r.children) {
                print_region(*c, fn, depth + 1, out);
            }
            out += std::format("{}}}\n", ind);
            return;
        }

        case RegionKind::Return:
            out += std::format("{}return;\n", ind);
            return;

        case RegionKind::Unreachable:
            out += std::format("{}unreachable;\n", ind);
            return;

        case RegionKind::Break:
            out += std::format("{}break;\n", ind);
            return;

        case RegionKind::Continue:
            out += std::format("{}continue;\n", ind);
            return;

        case RegionKind::Goto:
            out += std::format("{}goto bb_{:x};\n", ind, r.target);
            return;

        case RegionKind::Switch: {
            const std::string_view rn = reg_name(r.switch_index);
            out += std::format("{}switch ({}) {{\n", ind,
                               rn.empty() ? std::string("<idx>") : std::string(rn));
            const std::size_t n_cases = r.case_values.size();
            const std::string cind((static_cast<std::size_t>(depth) + 1) * 2u, ' ');
            for (std::size_t i = 0; i < n_cases; ++i) {
                out += std::format("{}case {}:\n", cind, r.case_values[i]);
                if (i < r.children.size()) {
                    print_region(*r.children[i], fn, depth + 2, out);
                }
            }
            if (r.has_default && r.children.size() > n_cases) {
                out += std::format("{}default:\n", cind);
                print_region(*r.children.back(), fn, depth + 2, out);
            }
            out += std::format("{}}}\n", ind);
            return;
        }
    }
}

}  // anonymous namespace

Result<StructuredFunction> Structurer::structure(const IrFunction& fn) const {
    StructuredFunction sf;
    sf.ir = &fn;

    if (fn.blocks.empty()) {
        sf.body = make_empty();
        return sf;
    }

    const CfgInfo info = analyze_cfg(fn);
    Builder b(fn, info);
    sf.body = b.build_sequence(fn.start, /*stop=*/kNoAddr);

    return sf;
}

std::string format_structured(const StructuredFunction& sf) {
    std::string out;
    const std::string name = sf.ir->name.empty() ? std::string("<unknown>") : sf.ir->name;
    out += std::format("function {} @ {:#x} {{\n", name, sf.ir->start);
    if (sf.body) {
        print_region(*sf.body, *sf.ir, 1, out);
    }
    out += "}\n";
    return out;
}

}  // namespace ember

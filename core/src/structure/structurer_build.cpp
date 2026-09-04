// Region builder: sequences, conditionals, loops, switches and tail inlining.

#include <algorithm>
#include <cstddef>
#include <format>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <unordered_map>
#include <utility>
#include <vector>

#include <ember/analysis/function.hpp>
#include <ember/common/types.hpp>
#include <ember/disasm/register.hpp>
#include <ember/ir/ir.hpp>
#include <ember/ir/ssa.hpp>
#include <ember/structure/region.hpp>

#include "structurer_internal.hpp"

namespace ember::structurer {

namespace {

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

}  // namespace

// ============================================================================
// Region helpers
// ============================================================================
std::unique_ptr<Region> make_empty() {
    return std::make_unique<Region>();
}

Builder::Builder(const IrFunction& fn, const CfgInfo& info)
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
bool Builder::is_phi_only_return(const IrBlock& bb) const noexcept {
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
    // along this branch - used by make_return_from_block's phi resolution to
    // pick the operand that actually flowed in along this path.
void Builder::sink_return_into_branch(std::unique_ptr<Region>& branch,
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

std::unique_ptr<Region> Builder::build_sequence(addr_t entry, addr_t stop,
                                                addr_t* out_last_block) {
    auto seq = std::make_unique<Region>();
    seq->kind = RegionKind::Seq;

    // Default: branch terminated internally (return / goto / break /
    // continue). Only natural fall-through exits update this with the
    // actual exit-pred - see end of function.
    if (out_last_block) *out_last_block = kNoAddr;

    addr_t current = entry;
    // Last block we just walked through, in order to identify the CFG
    // predecessor of a Return / inline target. Reset whenever we descend
    // into a sub-region whose own seq could end on multiple predecessors
    // (if/else, switch, loop) - those merge points are genuinely multi-pred
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
            // A tiny shared diamond tail often consists of one ordinary
            // block followed immediately by this sequence's merge:
            //
            //   if (a) shared(); else if (b) shared(); else unique();
            //
            // Once the first arm has visited `shared`, the second arm
            // used to become a backward-looking goto in pseudo-C. Clone
            // only that one source-level block when its sole successor is
            // exactly our stop point. This removes the label without
            // cloning the (potentially huge) continuation after the
            // merge, which is why the broader bounded-tail inliner is not
            // suitable for this shape.
            if (stop != kNoAddr) {
                auto shared_it = fn_.block_at.find(current);
                if (shared_it != fn_.block_at.end()) {
                    const IrBlock& shared = fn_.blocks[shared_it->second];
                    const bool plain_block =
                        shared.kind == BlockKind::Unconditional ||
                        shared.kind == BlockKind::Fallthrough;
                    if (plain_block && shared.successors.size() == 1 &&
                        shared.successors[0] == stop) {
                        seq->children.push_back(make_block(current));
                        if (out_last_block) *out_last_block = current;
                        return seq;
                    }
                }
            }
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
            // The block preceding the loop is not the predecessor by which
            // control reaches its exit. Preserve an exact predecessor only
            // when the exit itself proves there is a single choice; otherwise
            // leave Phi resolution in merge form.
            last_block = kNoAddr;
            if (current != kNoAddr) {
                auto exit_it = fn_.block_at.find(current);
                if (exit_it != fn_.block_at.end()) {
                    const auto& predecessors =
                        fn_.blocks[exit_it->second].predecessors;
                    if (predecessors.size() == 1) {
                        last_block = predecessors.front();
                    }
                }
            }
            continue;
        }

        visited_.insert(current);
        auto bit = fn_.block_at.find(current);
        if (bit == fn_.block_at.end()) break;
        const auto& bb = fn_.blocks[bit->second];

        switch (bb.kind) {
            case BlockKind::Return:
            case BlockKind::TailCall: {
                // TailCall was lifted as `call; return rax;` - the block
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
                // Pick a merge point for what comes after the switch -
                // approximate the post-dominator as the shortest point
                // reachable from every case target.
                addr_t merge = compute_switch_merge(bb);
                seq->children.push_back(std::move(sw));
                if (error_) return seq;
                if (merge == kNoAddr) return seq;
                auto merge_it = fn_.block_at.find(merge);
                if (merge_it != fn_.block_at.end() &&
                    is_phi_only_return(fn_.blocks[merge_it->second])) {
                    // build_switch sinks this return into each arm and marks
                    // the merge visited. Continuing at the merge would inline
                    // a duplicate block plus an unresolved extra return.
                    if (out_last_block) *out_last_block = kNoAddr;
                    return seq;
                }
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
                addr_t s_taken = !bb.successors.empty() ? bb.successors[0] : kNoAddr;
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
                // predecessor - turning `return rax_N;` into
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
                        // - the condition-false path falls through and
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
                    // Merge consumed (in branches and/or trailing) -
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
    // this branch - the caller (e.g. the if/else handler) needs it to
    // resolve a phi at the merge.
    if (out_last_block) *out_last_block = last_block;
    return seq;
}

    // The switch's merge = the immediate post-dominator of the dispatch
    // block itself: the first node every non-terminating case falls through
    // to. `kNoAddr` means every case terminates (return/unreachable) with no
    // finite merge.
addr_t Builder::compute_switch_merge(const IrBlock& sw_bb) const {
    return merge_after(info_, sw_bb.start);
}

std::unique_ptr<Region> Builder::build_switch(const IrBlock& sw_bb) {
    auto r = std::make_unique<Region>();
    r->kind         = RegionKind::Switch;
    r->has_default  = sw_bb.has_default;
    r->switch_index = sw_bb.switch_index;

    // A decoded jump table has one target per case value, followed by an
    // optional default target. Oracle-resolved indirect branches are the one
    // deliberate exception: they carry possible targets without selector
    // values. Model those as a switch over the BranchIndirect target address
    // instead of dropping every successor.
    const std::size_t expected_successors =
        sw_bb.case_values.size() + (sw_bb.has_default ? 1u : 0u);
    IrValue indirect_target;
    if (sw_bb.case_values.empty() && !sw_bb.has_default) {
        for (auto it = sw_bb.insts.rbegin(); it != sw_bb.insts.rend(); ++it) {
            if (it->op == IrOp::BranchIndirect && it->src_count >= 1 &&
                it->srcs[0].kind != IrValueKind::None) {
                indirect_target = it->srcs[0];
                break;
            }
        }
    }
    const bool unlabeled_multiway = !sw_bb.successors.empty() &&
        indirect_target.kind != IrValueKind::None;
    if (!unlabeled_multiway &&
        sw_bb.successors.size() != expected_successors) {
        error_ = Error::invalid_format(std::format(
            "structurer: switch at {:#x} has {} case values, {} successors, "
            "and has_default={}", sw_bb.start, sw_bb.case_values.size(),
            sw_bb.successors.size(), sw_bb.has_default));
        return make_simple(RegionKind::Unreachable);
    }

    std::vector<i64> case_values = sw_bb.case_values;
    if (unlabeled_multiway) {
        case_values.reserve(sw_bb.successors.size());
        for (addr_t target : sw_bb.successors) {
            case_values.push_back(static_cast<i64>(target));
        }
        r->condition = indirect_target;
    }
    // CFG switch metadata stores only the architectural selector
    // register. After SSA, recover the concrete version consumed by the
    // dispatch block (e.g. CodeWarrior's rlwinm r0,r5,2 before lwzx, or
    // the x86-64 arg register feeding `movsxd rax,[tab+rdi*4]`).
    // The emitter can then inline the selector's real producer instead of
    // leaking a bare `switch (r5)` / `switch (rdi)` into otherwise
    // source-like pseudo-C. The recovery steps are arch-neutral; only
    // the canonical register names differ.
    if (!unlabeled_multiway && sw_bb.switch_index != Reg::None) {
        const Reg selector = canonical_reg(sw_bb.switch_index);
        for (const auto& inst : sw_bb.insts) {
            for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i) {
                const IrValue& src = inst.srcs[i];
                if (src.kind == IrValueKind::Reg && src.version != 0 &&
                    canonical_reg(src.reg) == selector) {
                    r->condition = src;
                    break;
                }
            }
            if (r->condition.kind != IrValueKind::None) break;
        }
        // Cleanup may propagate the selector register away from the
        // dispatch entirely. The bounds-check predecessor still compares
        // the exact source value against the table maximum, and that
        // operand is stronger evidence than an unrelated call-clobber of
        // the same architectural register earlier in the predecessor.
        //
        // x86 lowers `cmp r/m, imm` into explicit flag math whose
        // compare operands reference a scratch Sub result rather than
        // the selector itself (`t3 = sub t0, 9; cmp.eq t3, 0`).
        // Unwrapping one such Sub level recovers the tested value, so
        // the switch reads `switch (a1)` instead of the discarded
        // difference `switch (t0 - 9)`.
        auto unwrap_sub_base = [&](const IrBlock& pred,
                                   const IrValue& v) -> IrValue {
            for (auto it = pred.insts.rbegin(); it != pred.insts.rend();
                 ++it) {
                const IrValue& dst = it->dst;
                const bool same = dst.kind == v.kind &&
                                  dst.reg == v.reg &&
                                  dst.version == v.version &&
                                  dst.temp == v.temp;
                if (!same) continue;
                if (it->op == IrOp::Sub && it->src_count >= 2 &&
                    it->srcs[1].kind == IrValueKind::Imm) {
                    return it->srcs[0];
                }
                return v;
            }
            return v;
        };
        if (r->condition.kind == IrValueKind::None) {
            for (addr_t pred_addr : sw_bb.predecessors) {
                auto pit = fn_.block_at.find(pred_addr);
                if (pit == fn_.block_at.end()) continue;
                const auto& pred = fn_.blocks[pit->second];
                for (auto it = pred.insts.rbegin(); it != pred.insts.rend(); ++it) {
                    if (it->op < IrOp::CmpEq || it->op > IrOp::CmpSge ||
                        it->src_count < 2) continue;
                    for (u8 i = 0; i < 2; ++i) {
                        if (it->srcs[i].kind != IrValueKind::Imm) {
                            r->condition = unwrap_sub_base(pred, it->srcs[i]);
                            break;
                        }
                    }
                    if (r->condition.kind != IrValueKind::None) break;
                }
                if (r->condition.kind != IrValueKind::None) break;
            }
        }
        // An unbounded/non-canonical table may have no comparison. Fall
        // back to a real predecessor definition, but never select a
        // caller-clobber: it describes call state, not table provenance.
        if (r->condition.kind == IrValueKind::None) {
            for (addr_t pred_addr : sw_bb.predecessors) {
                auto pit = fn_.block_at.find(pred_addr);
                if (pit == fn_.block_at.end()) continue;
                const auto& pred = fn_.blocks[pit->second];
                for (auto it = pred.insts.rbegin(); it != pred.insts.rend(); ++it) {
                    const IrValue& dst = it->dst;
                    if (it->op != IrOp::Clobber &&
                        dst.kind == IrValueKind::Reg && dst.version != 0 &&
                        canonical_reg(dst.reg) == selector) {
                        r->condition = dst;
                        break;
                    }
                }
                if (r->condition.kind != IrValueKind::None) break;
            }
        }
    }

    const addr_t merge = compute_switch_merge(sw_bb);

    // For sparse switches the compiler pads the jump table by pointing
    // missing-case slots at the default block. Without recognising this,
    // those slots render as `case N:` falling through to the next
    // listed body - a bald lie about control flow. Treat any case
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
    // case body, with the phi resolved per the case's exit pred -
    // typically the case's own block when it falls through to merge
    // directly, which is the common compiler-emitted shape for big
    // jump-table switches over enums returning a value.
    const IrBlock* return_merge = nullptr;
    if (merge != kNoAddr) {
        auto mit = fn_.block_at.find(merge);
        if (mit != fn_.block_at.end() &&
            is_phi_only_return(fn_.blocks[mit->second])) {
            return_merge = &fn_.blocks[mit->second];
        }
    }

    // De-duplicate cases that share the same target - the resulting
    // switch would be structurally identical. All labels of one body
    // must render CONSECUTIVELY: C fallthrough binds a bare `case N:`
    // to the *following* body, so an Empty placeholder only reads as
    // "same body" when it sits directly ahead of its own target's
    // region. Grouping in first-appearance target order keeps the
    // 1:1 values<->children shape the switch renderer walks while
    // never letting a label attach to a foreign body (the old
    // table-order encoding let `case 1:` fall into `case 2:`'s
    // body whenever the compiler merged their blocks).
    const std::size_t n_cases = case_values.size();
    std::vector<addr_t>             group_order;
    std::map<addr_t, std::vector<std::size_t>> groups;
    for (std::size_t i = 0; i < n_cases; ++i) {
        const addr_t tgt = sw_bb.successors[i];
        if (tgt == dflt_target) continue;
        auto& slot = groups[tgt];
        if (slot.empty()) group_order.push_back(tgt);
        slot.push_back(i);
    }

    auto build_case_with_optional_sink = [&](addr_t tgt) {
        if (tgt == merge) {
            if (!return_merge) return make_simple(RegionKind::Break);
            auto body = make_empty();
            sink_return_into_branch(body, *return_merge, sw_bb.start);
            return body;
        }
        addr_t case_last = kNoAddr;
        auto body = build_sequence(tgt, merge, &case_last);
        if (return_merge && case_last != kNoAddr) {
            sink_return_into_branch(body, *return_merge, case_last);
        }
        return body;
    };

    for (const addr_t tgt : group_order) {
        const auto& idxs = groups[tgt];
        for (std::size_t k = 0; k < idxs.size(); ++k) {
            r->case_values.push_back(case_values[idxs[k]]);
            if (k + 1 == idxs.size()) {
                r->children.push_back(build_case_with_optional_sink(tgt));
            } else {
                r->children.push_back(make_empty());
            }
        }
    }
    if (sw_bb.has_default && !sw_bb.successors.empty()) {
        const addr_t dflt = sw_bb.successors.back();
        r->children.push_back(build_case_with_optional_sink(dflt));
    }
    if (return_merge) visited_.insert(merge);
    return r;
}

std::unique_ptr<Region> Builder::build_loop(addr_t header) {
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
        // fall through to do_while detection - picking up the
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
            // emitter's peephole - if it matches, it'll render cleanly.
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
    // For a while, body starts at body_entry. For a pure infinite
    // loop (no recognised exit anywhere), walk the header's
    // non-back-edge successors with stop=header so multi-block
    // bodies aren't silently dropped under `for (;;) { header; }`.
    if (body_entry != kNoAddr) {
        auto body = build_sequence(body_entry, header);
        loop_r->children.push_back(std::move(body));
    } else if (loop_r->kind == RegionKind::Loop) {
        if (bb.kind == BlockKind::Conditional && bb.successors.size() == 2) {
            const addr_t s1 = bb.successors[0];
            const addr_t s2 = bb.successors[1];
            auto then_r = (s1 == header)
                ? make_simple(RegionKind::Continue)
                : build_sequence(s1, header);
            auto else_r = (s2 == header)
                ? make_simple(RegionKind::Continue)
                : build_sequence(s2, header);
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
        } else if (!bb.successors.empty()) {
            const addr_t s = bb.successors.front();
            if (s != header) {
                auto body = build_sequence(s, header);
                loop_r->children.push_back(std::move(body));
            }
        }
    } else if (do_while) {
        // Walk header → tail via the body path. Stop *before* dw_tail so
        // its cond-branch isn't rendered as `if (cond) continue; else break;`
        // - the trailing `} while (cond);` already carries the predicate.
        // Then emit dw_tail's block (non-branch insts) as the loop's last
        // body element so observable effects match the asm.
        if (header != dw_tail && !bb.successors.empty()) {
            if (bb.kind == BlockKind::Conditional &&
                bb.successors.size() == 2) {
                // Header has its own *internal* conditional (neither arm
                // is the loop exit - that's at dw_tail). Structure the
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
IrValue Builder::resolve_through_phis(IrValue v, addr_t from_pred,
                                      int depth) const {
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
    // structural context - used to resolve the value through any Phi whose
    // operand list mentions it (e.g. a fail/success arm rendered into one of
    // its predecessors as `return -1;` / `return 0;` instead of `return rax_N;`).
std::unique_ptr<Region>
Builder::make_return_from_block(const IrBlock& bb, addr_t from_pred) {
    auto r = make_simple(RegionKind::Return);
    r->block_start = bb.start;
    auto is_live_in_reg = [](const IrValue& v) {
        return v.kind == IrValueKind::Reg && v.version == 0;
    };
    auto is_meaningful_fp_carrier = [](const IrValue& v) {
        if (!is_float_type(v.type)) return false;
        if (v.kind != IrValueKind::Reg) return true;
        if (v.reg == Reg::Xmm0 && v.version == 0) return false;
        return true;
    };
    auto has_value_def = [&](const IrValue& v) {
        std::set<SsaKey> seen;
        const auto substantive = [&](const auto& self, const IrValue& value,
                                     int depth) -> bool {
            if (depth > 16) return false;
            auto key = ssa_key(value);
            if (!key || !seen.insert(*key).second) return false;
            auto found = defs_.find(*key);
            if (found == defs_.end()) return false;
            const IrInst* definition = found->second;
            if (definition->op == IrOp::Clobber) return false;
            if (definition->op == IrOp::Assign && definition->src_count >= 1) {
                return self(self, definition->srcs[0], depth + 1);
            }
            if (definition->op == IrOp::Phi) {
                return std::ranges::any_of(definition->phi_operands,
                    [&](const IrValue& operand) {
                        return self(self, operand, depth + 1);
                    });
            }
            return true;
        };
        return substantive(substantive, v, 0);
    };
    for (auto it = bb.insts.rbegin(); it != bb.insts.rend(); ++it) {
        if (it->op != IrOp::Return || it->src_count == 0) continue;
        const IrValue* best = nullptr;
        bool best_has_value_def = false;
        for (u8 k = 0; k < it->src_count && k < it->srcs.size(); ++k) {
            const IrValue& s = it->srcs[k];
            if (s.kind == IrValueKind::None) continue;
            const bool s_has_value_def = has_value_def(s);
            if (!best) {
                best = &s;
                best_has_value_def = s_has_value_def;
                continue;
            }
            // Return operands are ABI-ordered (integer/pointer first,
            // XMM second). Keep that order when both carry real local
            // values; only switch to a later source when the current best
            // is just live-in/clobber noise and the later one is defined.
            if (!best_has_value_def && s_has_value_def) {
                best = &s;
                best_has_value_def = true;
                continue;
            }
            if (!best_has_value_def && is_live_in_reg(*best) &&
                !is_meaningful_fp_carrier(*best) &&
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
    // observed behaviour - both paths still execute the same IR at runtime.
std::optional<std::vector<addr_t>>
Builder::collect_trivial_tail(addr_t start) const {
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
    // is the structural predecessor at the inline site - used together with
    // `chain[size-2]` to resolve the return-value phi to the operand that
    // actually flowed in along this clone's path.
std::unique_ptr<Region>
Builder::try_inline_trivial_tail(addr_t start, addr_t from_pred) {
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
std::unique_ptr<Region> Builder::try_inline_bounded_tail(addr_t target) {
    if (inlining_bounded_) return nullptr;
    // Larger clones look structured locally but explode at outer join
    // points (a 25-node Wii menu tail can be copied four times into a
    // 400-line function). Keep only genuinely small source-level tails;
    // larger shared regions are clearer and more faithful as one labeled
    // body reached by gotos.
    constexpr std::size_t kMaxNodes = 12;

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

std::size_t Builder::count_regions(const Region& r) noexcept {
    std::size_t n = 1;
    for (const auto& c : r.children) {
        if (c) n += count_regions(*c);
    }
    return n;
}

bool Builder::contains_goto(const Region& r) noexcept {
    if (r.kind == RegionKind::Goto) return true;
    for (const auto& c : r.children) {
        if (c && contains_goto(*c)) return true;
    }
    return false;
}

}  // namespace ember::structurer

// ABI noise, stack-canary suppression and common tail-return folding.
#include <algorithm>
#include <cstddef>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <spelunk/binary/symbol.hpp>
#include <spelunk/common/types.hpp>
#include <spelunk/disasm/register.hpp>
#include <spelunk/ir/ir.hpp>
#include <spelunk/ir/ssa.hpp>
#include <spelunk/structure/region.hpp>

#include "emitter_internal.hpp"

namespace spelunk::emit {

void Emitter::analyze_abi_noise() {
    // Pass 0: PE UNWIND_INFO-driven prologue suppression. The byte range
    // [entry, prologue_end) from .xdata is authoritative - every inst
    // whose source_addr falls there is prologue. The matching epilogue
    // is the trailing run of insts in the function whose source_addr
    // lies in [end - prologue_size, end); Win64 ABI requires epilogues
    // mirror the prologue ops in reverse and never exceed its length.
    if (options.prologue_ranges) {
        auto it = options.prologue_ranges->find(fn->start);
        if (it != options.prologue_ranges->end()) {
            const addr_t prologue_end = it->second;
            const addr_t prologue_len = prologue_end - fn->start;
            const addr_t epilogue_lo  = fn->end > prologue_len
                ? fn->end - prologue_len : fn->start;
            for (std::size_t bi = 0; bi < fn->blocks.size(); ++bi) {
                const auto& bb = fn->blocks[bi];
                for (std::size_t ii = 0; ii < bb.insts.size(); ++ii) {
                    const addr_t sa = bb.insts[ii].source_addr;
                    if (sa == 0) continue;
                    if (sa >= fn->start && sa < prologue_end) {
                        hidden.insert({bi, ii});
                    } else if (sa >= epilogue_lo && sa < fn->end) {
                        hidden.insert({bi, ii});
                    }
                }
            }
        }
    }
    // Pass 1: direct pattern matches.
    for (std::size_t bi = 0; bi < fn->blocks.size(); ++bi) {
        const auto& bb = fn->blocks[bi];
        for (std::size_t ii = 0; ii < bb.insts.size(); ++ii) {
            if (is_abi_noise(bb.insts[ii]) ||
                is_ppc_abi_helper_call(bb.insts[ii])) {
                hidden.insert({bi, ii});
            }
        }
    }
    // Pass 2: propagate. A pure temp whose every use is in a hidden inst is itself dead.
    //
    // The phase-one SSA index lets each fixpoint iteration touch O(uses)
    // instead of re-walking the entire IR.
    // The previous shape was O(N) outer × O(N) inner × up-to-16 iters,
    // which on a 50 k-inst function turns into tens of billions of
    // ssa_key comparisons.
    bool changed = true;
    int guard = 0;
    while (changed && guard++ < 16) {
        changed = false;
        for (u32 bi = 0; bi < fn->blocks.size(); ++bi) {
            const auto& bb = fn->blocks[bi];
            for (u32 ii = 0; ii < bb.insts.size(); ++ii) {
                if (hidden.contains({bi, ii})) continue;
                const auto& inst = bb.insts[ii];
                if (inst.dst.kind != IrValueKind::Temp) continue;
                if (!inlinable_op(inst.op)) continue;
                auto target_key = ssa_key(inst.dst);
                if (!target_key) continue;
                const auto users =
                    ssa_uses.semantic_user_positions(*target_key);
                // A value read only by call.args/fp_args has no semantic
                // positions, but historically still counted as an all-noise
                // value because every syntactic reader is a barrier.
                if (ssa_uses.syntactic_use_count(*target_key) == 0) continue;
                bool all_hidden = true;
                for (const auto& [bj, ij] : users) {
                    if (hidden.contains({bj, ij})) continue;
                    all_hidden = false;
                    break;
                }
                if (all_hidden) {
                    hidden.insert({bi, ii});
                    changed = true;
                }
            }
        }
    }
}

bool Emitter::is_stack_chk_guard_got_load(const IrInst& inst) const {
    if (!binary) return false;
    if (inst.op != IrOp::Load || inst.segment != Reg::None ||
        inst.src_count < 1 || inst.srcs[0].kind != IrValueKind::Imm) {
        return false;
    }
    const auto slot = static_cast<addr_t>(inst.srcs[0].imm);
    const Symbol* s = binary->import_at_got(slot);
    return s && clean_import_name(s->name) == "__stack_chk_guard";
}

bool Emitter::is_canary_load(const IrInst& inst) const {
    if (is_stack_chk_guard_got_load(inst)) return true;
    return inst.op == IrOp::Load && inst.segment == Reg::Fs &&
           inst.src_count >= 1 &&
           inst.srcs[0].kind == IrValueKind::Imm &&
           inst.srcs[0].imm == 0x28;
}

bool Emitter::is_canary_value_load(const IrInst& inst) const {
    if (is_canary_load(inst)) return true;
    if (inst.op != IrOp::Load || inst.segment != Reg::None ||
        inst.src_count < 1) {
        return false;
    }
    const IrInst* ptr = def_through_assigns(inst.srcs[0]);
    return ptr && is_stack_chk_guard_got_load(*ptr);
}

const IrInst* Emitter::def_through_assigns(const IrValue& v) const {
    const IrInst* d = def_of(v);
    while (d && d->op == IrOp::Assign && d->src_count == 1) {
        d = def_of(d->srcs[0]);
    }
    return d;
}

bool Emitter::traces_to_canary_load(const IrValue& v) const {
    if (const IrInst* d = def_through_assigns(v); d) return is_canary_value_load(*d);
    return false;
}

bool Emitter::renders_stack_chk_guard_load(const IrInst& inst) const {
    if (inst.op != IrOp::Load || inst.src_count < 1) return false;
    return format_mem(inst.srcs[0], inst.dst.type, inst.segment)
        .find("__stack_chk_guard") != std::string::npos;
}

bool Emitter::renders_stack_chk_guard_value(const IrValue& v) const {
    if (traces_to_canary_load(v)) return true;
    const IrInst* d = def_through_assigns(v);
    return d && renders_stack_chk_guard_load(*d);
}

bool Emitter::is_abi_noise(const IrInst& inst) const {
    if (stack_reservation_stores.contains(&inst)) return true;
    // Stack-base register writes → frame manipulation.
    if (inst.op == IrOp::Assign && inst.dst.kind == IrValueKind::Reg) {
        if (is_stack_base_reg(inst.dst.reg)) return true;
    }
    // Prologue canary: Store of fs:[0x28] into a stack slot.
    if (inst.op == IrOp::Store && inst.src_count >= 2) {
        if (stack_offset(inst.srcs[0]).has_value() &&
            traces_to_canary_load(inst.srcs[1])) {
            return true;
        }
    }
    // Store of a live-in callee-saved reg into a stack slot → prologue save
    if (inst.op == IrOp::Store && inst.src_count >= 2) {
        const auto& val = inst.srcs[1];
        if (val.kind == IrValueKind::Reg && val.version == 0 &&
            is_callee_saved(val.reg) && stack_offset(inst.srcs[0]).has_value())
            return true;
    }
    // callee-saved = <Load [stack]>  → epilogue restore
    if (inst.op == IrOp::Assign && inst.dst.kind == IrValueKind::Reg &&
        is_callee_saved(inst.dst.reg) && inst.src_count >= 1) {
        const IrInst* src_def = def_of(inst.srcs[0]);
        while (src_def && src_def->op == IrOp::Assign && src_def->src_count == 1)
            src_def = def_of(src_def->srcs[0]);
        if (src_def && src_def->op == IrOp::Load && src_def->src_count >= 1 &&
            stack_offset(src_def->srcs[0]).has_value())
            return true;
    }
    return false;
}

bool Emitter::is_canary_compare_inst(const IrInst& inst) const {
    if (inst.src_count < 2) return false;
    switch (inst.op) {
        case IrOp::Sub: case IrOp::Xor:
        case IrOp::CmpEq: case IrOp::CmpNe:
            break;
        default:
            return false;
    }
    const IrInst* a = def_through_assigns(inst.srcs[0]);
    const IrInst* b = def_through_assigns(inst.srcs[1]);
    if (!a || !b) return false;
    auto is_stack_load = [&](const IrInst* d) {
        return d && d->op == IrOp::Load && d->src_count >= 1 &&
               stack_offset(d->srcs[0]).has_value() && d->segment == Reg::None;
    };
    auto is_guard = [&](const IrInst* d) {
        return d && (is_canary_value_load(*d) ||
                     renders_stack_chk_guard_load(*d));
    };
    const bool ag = is_guard(a);
    const bool bg = is_guard(b);
    return (is_stack_load(a) && bg) ||
           (is_stack_load(b) && ag) ||
           (ag && bg);
}

bool Emitter::is_canary_condition(const IrValue& cond) const {
    IrValue cur = cond;
    for (int step = 0; step < 10; ++step) {
        const IrInst* d = def_of(cur);
        if (!d) return false;
        if (is_canary_compare_inst(*d)) return true;
        // Follow Assign, Not, and Cmp chains.
        if (d->op == IrOp::Assign && d->src_count >= 1) { cur = d->srcs[0]; continue; }
        if (d->op == IrOp::Not && d->src_count >= 1)    { cur = d->srcs[0]; continue; }
        if ((d->op == IrOp::CmpEq || d->op == IrOp::CmpNe) && d->src_count >= 1) {
            // Compare against a constant (`cmp.eq(x, 0)` / zf). Peek through
            // to x and try again - the real canary compare is one step up.
            if (d->src_count >= 2 &&
                d->srcs[1].kind == IrValueKind::Imm && d->srcs[1].imm == 0) {
                cur = d->srcs[0];
                continue;
            }
            return false;
        }
        return false;
    }
    return false;
}

bool Emitter::region_always_calls_stack_chk_fail(const Region& r) const {
    // Suppressing a canary arm is safe only when every path reaches
    // __stack_chk_fail and everything before that call is removable compiler
    // plumbing. Keep the distinction explicit: a conditional exit is neither
    // harmless fallthrough nor guaranteed failure, and an audit/store/call
    // before the failure must remain visible even though the process aborts.
    enum class CanaryFlow { RemovableFallthrough, GuaranteedFail, Unsafe };
    const auto classify_block = [&](addr_t block_addr) {
        auto it = fn->block_at.find(block_addr);
        if (it == fn->block_at.end()) return CanaryFlow::Unsafe;
        const auto& bb = fn->blocks[it->second];
        for (std::size_t ii = 0; ii < bb.insts.size(); ++ii) {
            const IrInst& inst = bb.insts[ii];
            if (inst.op == IrOp::Call && binary) {
                if (const Symbol* s = binary->import_at_plt(inst.target1);
                    s && clean_import_name(s->name) == "__stack_chk_fail") {
                    return CanaryFlow::GuaranteedFail;
                }
            }
            if (hidden.contains({it->second, ii}) || inst.op == IrOp::Nop ||
                inst.op == IrOp::Clobber ||
                SsaUseIndex::is_call_arg_barrier(inst)) continue;
            return CanaryFlow::Unsafe;
        }
        return CanaryFlow::RemovableFallthrough;
    };

    const auto classify = [&](const auto& self,
                              const Region& region) -> CanaryFlow {
        switch (region.kind) {
            case RegionKind::Empty:
                return CanaryFlow::RemovableFallthrough;
            case RegionKind::Block:
                return classify_block(region.block_start);
            case RegionKind::Seq:
                for (const auto& child : region.children) {
                    if (!child) continue;
                    const CanaryFlow flow = self(self, *child);
                    if (flow != CanaryFlow::RemovableFallthrough) return flow;
                }
                return CanaryFlow::RemovableFallthrough;
            case RegionKind::IfThen: {
                if (region.children.empty() || !region.children[0]) {
                    return CanaryFlow::RemovableFallthrough;
                }
                return self(self, *region.children[0]) ==
                               CanaryFlow::RemovableFallthrough
                    ? CanaryFlow::RemovableFallthrough
                    : CanaryFlow::Unsafe;
            }
            case RegionKind::IfElse: {
                if (region.children.size() < 2 || !region.children[0] ||
                    !region.children[1]) return CanaryFlow::Unsafe;
                const CanaryFlow first = self(self, *region.children[0]);
                const CanaryFlow second = self(self, *region.children[1]);
                if (first == CanaryFlow::GuaranteedFail &&
                    second == CanaryFlow::GuaranteedFail) {
                    return CanaryFlow::GuaranteedFail;
                }
                if (first == CanaryFlow::RemovableFallthrough &&
                    second == CanaryFlow::RemovableFallthrough) {
                    return CanaryFlow::RemovableFallthrough;
                }
                return CanaryFlow::Unsafe;
            }
            case RegionKind::Switch: {
                if (region.children.empty()) return CanaryFlow::Unsafe;
                bool all_removable = true;
                bool all_fail = region.has_default &&
                    region.children.size() > region.case_values.size();
                for (const auto& child : region.children) {
                    if (!child) return CanaryFlow::Unsafe;
                    const CanaryFlow flow = self(self, *child);
                    all_removable &= flow == CanaryFlow::RemovableFallthrough;
                    all_fail &= flow == CanaryFlow::GuaranteedFail;
                }
                if (all_fail) return CanaryFlow::GuaranteedFail;
                if (all_removable) return CanaryFlow::RemovableFallthrough;
                return CanaryFlow::Unsafe;
            }
            case RegionKind::While:
            case RegionKind::DoWhile:
            case RegionKind::For:
            case RegionKind::Loop:
            case RegionKind::Return:
            case RegionKind::Unreachable:
            case RegionKind::Break:
            case RegionKind::Continue:
            case RegionKind::Goto:
                return CanaryFlow::Unsafe;
        }
        return CanaryFlow::Unsafe;
    };

    return classify(classify, r) == CanaryFlow::GuaranteedFail;
}

void Emitter::suppress_canary_regions(Region& r) const {
    for (auto& c : r.children) {
        if (c) suppress_canary_regions(*c);
    }
    if (r.kind != RegionKind::IfThen && r.kind != RegionKind::IfElse) return;
    if (!is_canary_condition(r.condition)) return;

    const bool has_else = r.kind == RegionKind::IfElse;
    auto* then_branch = r.children.empty() ? nullptr : r.children[0].get();
    auto* else_branch = (has_else && r.children.size() >= 2) ? r.children[1].get() : nullptr;

    const bool then_fails = then_branch &&
        region_always_calls_stack_chk_fail(*then_branch);
    const bool else_fails = else_branch &&
        region_always_calls_stack_chk_fail(*else_branch);
    if (!then_fails && !else_fails) return;

    // Pull the surviving branch up; if neither survives, collapse to Empty.
    std::unique_ptr<Region> keep;
    if (then_fails && else_branch) keep = std::move(r.children[1]);
    else if (else_fails && !r.children.empty()) keep = std::move(r.children[0]);

    if (keep) {
        r = std::move(*keep);
    } else {
        r.kind = RegionKind::Empty;
        r.children.clear();
        r.condition = {};
    }
}

bool Emitter::return_matches(const Region& r,
                             const IrValue& value) const noexcept {
    return r.kind == RegionKind::Return &&
           r.condition.kind != IrValueKind::None &&
           same_ssa(r.condition, value);
}

bool Emitter::always_returns_value(const Region& r,
                                   const IrValue& value) const noexcept {
    switch (r.kind) {
        case RegionKind::Return:
            return return_matches(r, value);
        case RegionKind::Seq:
            return !r.children.empty() &&
                   r.children.back() &&
                   always_returns_value(*r.children.back(), value);
        case RegionKind::IfElse:
            return r.children.size() >= 2 &&
                   r.children[0] && r.children[1] &&
                   always_returns_value(*r.children[0], value) &&
                   always_returns_value(*r.children[1], value);
        default:
            return false;
    }
}

void Emitter::strip_matching_tail_returns(Region& r, const IrValue& value) const {
    if (return_matches(r, value)) {
        r.kind = RegionKind::Empty;
        r.condition = {};
        r.children.clear();
        return;
    }
    if (r.kind == RegionKind::Seq) {
        if (!r.children.empty() && r.children.back()) {
            strip_matching_tail_returns(*r.children.back(), value);
        }
        while (!r.children.empty()) {
            auto& last = r.children.back();
            if (!last || last->kind == RegionKind::Empty ||
                return_matches(*last, value)) {
                r.children.pop_back();
                continue;
            }
            break;
        }
        if (r.children.empty()) {
            r.kind = RegionKind::Empty;
        }
        return;
    }
    if (r.kind == RegionKind::IfElse && r.children.size() >= 2) {
        if (r.children[0]) strip_matching_tail_returns(*r.children[0], value);
        if (r.children[1]) strip_matching_tail_returns(*r.children[1], value);
    }
}

void Emitter::fold_common_tail_returns(Region& r) const {
    for (auto& c : r.children) {
        if (c) fold_common_tail_returns(*c);
    }
    if (r.kind != RegionKind::Seq || r.children.size() < 3) return;
    Region* tail = r.children.back().get();
    if (!tail || tail->kind != RegionKind::Return ||
        tail->condition.kind == IrValueKind::None) {
        return;
    }
    const IrValue tail_value = tail->condition;
    for (std::size_t i = 0; i + 2 < r.children.size(); ++i) {
        Region* cur = r.children[i].get();
        if (!cur || cur->kind != RegionKind::IfThen ||
            cur->children.empty() || !cur->children[0]) {
            continue;
        }
        if (!always_returns_value(*cur->children[0], tail_value)) continue;

        auto rewritten = std::make_unique<Region>();
        rewritten->kind = RegionKind::IfElse;
        rewritten->condition = cur->condition;
        rewritten->invert = cur->invert;
        rewritten->target = cur->target;
        rewritten->block_start = cur->block_start;
        rewritten->children.push_back(std::move(cur->children[0]));
        strip_matching_tail_returns(*rewritten->children[0], tail_value);

        auto else_seq = std::make_unique<Region>();
        else_seq->kind = RegionKind::Seq;
        for (std::size_t j = i + 1; j + 1 < r.children.size(); ++j) {
            else_seq->children.push_back(std::move(r.children[j]));
        }
        rewritten->children.push_back(std::move(else_seq));

        std::vector<std::unique_ptr<Region>> next;
        next.reserve(i + 2);
        for (std::size_t j = 0; j < i; ++j) {
            next.push_back(std::move(r.children[j]));
        }
        next.push_back(std::move(rewritten));
        next.push_back(std::move(r.children.back()));
        r.children = std::move(next);
        fold_common_tail_returns(r);
        return;
    }
}

}  // namespace spelunk::emit

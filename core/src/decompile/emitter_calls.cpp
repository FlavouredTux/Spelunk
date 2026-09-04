// Call sites: signatures, return lanes, return folding and result binding.
#include <algorithm>
#include <cctype>
#include <cstddef>
#include <format>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <ember/analysis/import_sigs.hpp>
#include <ember/analysis/sig_inference.hpp>
#include <ember/binary/symbol.hpp>
#include <ember/common/annotations.hpp>
#include <ember/common/types.hpp>
#include <ember/disasm/register.hpp>
#include <ember/ir/abi.hpp>
#include <ember/ir/ir.hpp>
#include <ember/ir/ssa.hpp>
#include <ember/ir/types.hpp>
#include <ember/structure/region.hpp>

#include "emitter_internal.hpp"
#include "emitter_tables.hpp"

namespace ember::emit {

const FunctionSig*
Emitter::call_annotation_signature(const IrInst& inst) const noexcept {
    if (!annotations) return nullptr;
    if (inst.op == IrOp::Call) {
        return annotations->signature_for(inst.target1);
    }
    if (inst.op == IrOp::CallIndirect && options.call_resolutions &&
        inst.source_addr != 0) {
        auto it = options.call_resolutions->find(inst.source_addr);
        if (it != options.call_resolutions->end()) {
            return annotations->signature_for(it->second);
        }
    }
    return nullptr;
}

const InferredSig*
Emitter::call_inferred_signature(const IrInst& inst) const noexcept {
    if (!options.signatures) return nullptr;
    std::optional<addr_t> target;
    if (inst.op == IrOp::Call) {
        target = inst.target1;
    } else if (inst.op == IrOp::CallIndirect && options.call_resolutions &&
               inst.source_addr != 0) {
        if (auto found = options.call_resolutions->find(inst.source_addr);
            found != options.call_resolutions->end()) {
            target = found->second;
        }
    }
    if (!target) return nullptr;
    auto found = options.signatures->find(*target);
    return found != options.signatures->end() ? &found->second : nullptr;
}

bool Emitter::call_has_inferred_signature(const IrInst& inst) const {
    const InferredSig* signature = call_inferred_signature(inst);
    if (!signature || !options.type_arena) return false;
    if (!signature->return_type.is_top()) return true;
    return std::ranges::any_of(signature->params, [](TypeRef type) {
        return !type.is_top();
    });
}

std::optional<std::string>
Emitter::call_known_name(const IrInst& inst) const {
    if (auto imported = call_import_name(inst); imported) return imported;
    if (inst.op == IrOp::Call) return function_display_name(inst.target1);
    if (inst.op == IrOp::CallIndirect && options.call_resolutions &&
        inst.source_addr != 0) {
        auto it = options.call_resolutions->find(inst.source_addr);
        if (it != options.call_resolutions->end()) {
            return function_display_name(it->second);
        }
    }
    return std::nullopt;
}

std::optional<CallReturnLane>
Emitter::known_call_return_lane(const IrInst& inst) const {
    if (const FunctionSig* sig = call_annotation_signature(inst); sig) {
        const std::string normalized = normalize_c_type_alias(sig->return_type);
        const std::string_view ret = trim_line_view(normalized);
        if (ret == "void") return CallReturnLane::Void;
        if (is_declared_fp_scalar(ret)) return CallReturnLane::Floating;
        if (!ret.empty()) return CallReturnLane::Integer;
    }
    auto name = call_known_name(inst);
    if (name) {
        TypeArena arena;
        auto spec = lookup_import_sig(*name, arena);
        if (spec && !spec->ret.is_top() && !spec->ret.is_bottom()) {
            switch (arena.kind(spec->ret)) {
                case TypeKind::Void:  return CallReturnLane::Void;
                case TypeKind::Float: return CallReturnLane::Floating;
                default:              return CallReturnLane::Integer;
            }
        }
    }
    if (const InferredSig* signature = call_inferred_signature(inst);
        signature && options.type_arena && !signature->return_type.is_top()) {
        switch (options.type_arena->kind(signature->return_type)) {
            case TypeKind::Void: {
                // A scoped callee with no substantive return can still be
                // an ABI helper whose r3/f1 result is clearly consumed at
                // this call site. Caller dataflow is stronger than the
                // absence-based void inference.
                if (fn) {
                    for (const IrBlock& block : fn->blocks) {
                        for (std::size_t i = 0; i < block.insts.size(); ++i) {
                            if (&block.insts[i] != &inst) continue;
                            for (std::size_t j = i + 1; j < block.insts.size(); ++j) {
                                const IrInst& clobber = block.insts[j];
                                if (clobber.op != IrOp::Clobber) break;
                                if (clobber.dst.kind == IrValueKind::Reg) {
                                    auto key = ssa_key(clobber.dst);
                                    if (key && count_uses_with_call_args(*key) > 0) {
                                        return std::nullopt;
                                    }
                                }
                            }
                        }
                    }
                }
                return CallReturnLane::Void;
            }
            case TypeKind::Float: return CallReturnLane::Floating;
            default:              return CallReturnLane::Integer;
        }
    }
    return std::nullopt;
}

Reg Emitter::call_result_reg(const IrInst& inst) const {
    const auto lane = known_call_return_lane(inst);
    if (lane == CallReturnLane::Void) return Reg::None;
    if (lane == CallReturnLane::Floating) return fp_return_reg(abi);
    if (!lane && is_ppc_abi() && fn) {
        // Stripped Wii routines often have no prototype, but the lane is
        // still observable: a used f1 clobber with an unused r3 clobber
        // is strong evidence of a scalar floating return.  Keep the
        // established integer default when both lanes survive.
        for (const auto& bb : fn->blocks) {
            for (std::size_t ii = 0; ii < bb.insts.size(); ++ii) {
                if (&bb.insts[ii] != &inst) continue;
                u32 int_uses = 0;
                u32 fp_uses = 0;
                for (std::size_t jj = ii + 1; jj < bb.insts.size(); ++jj) {
                    const IrInst& clobber = bb.insts[jj];
                    if (clobber.op != IrOp::Clobber) break;
                    if (clobber.dst.kind != IrValueKind::Reg) continue;
                    const Reg reg = canonical_reg(clobber.dst.reg);
                    if (reg == canonical_reg(int_return_reg(abi))) {
                        int_uses += visible_use_count(clobber.dst);
                    } else if (reg == canonical_reg(fp_return_reg(abi))) {
                        fp_uses += visible_use_count(clobber.dst);
                    }
                }
                if (fp_uses > 0 && int_uses == 0) return fp_return_reg(abi);
                return int_return_reg(abi);
            }
        }
    }
    // Preserve the established behavior for an unknown call: its used
    // integer lane is still a plausible return, while f1 requires proof.
    return int_return_reg(abi);
}

std::optional<std::string>
Emitter::known_call_return_c_type(const IrInst& inst) const {
    if (const FunctionSig* sig = call_annotation_signature(inst); sig &&
        !sig->return_type.empty()) {
        std::string declared = normalize_c_type_alias(sig->return_type);
        std::string compact = declared;
        compact.erase(std::remove_if(compact.begin(), compact.end(),
            [](unsigned char c) { return std::isspace(c) != 0; }), compact.end());
        if (compact == "void*" && inst.op == IrOp::Call) {
            if (auto it = inferred_call_return_types.find(inst.target1);
                it != inferred_call_return_types.end() && it->second != "void*") {
                return it->second;
            }
        }
        return declared;
    }
    auto name = call_known_name(inst);
    if (name) {
        TypeArena arena;
        auto spec = lookup_import_sig(*name, arena);
        if (spec && !spec->ret.is_top() && !spec->ret.is_bottom()) {
            const TypeNode& ret = arena.node(spec->ret);
            if (ret.kind == TypeKind::Void) return std::string{"void"};
            if (ret.kind == TypeKind::Float) {
                return ret.f.bits <= 32 ? std::string{"float"}
                                        : std::string{"double"};
            }
            if (ret.kind == TypeKind::Struct && !ret.s.name.empty()) {
                return ret.s.name;
            }
            if (ret.kind == TypeKind::Int) {
                const std::string_view prefix = ret.i.sign_known && ret.i.is_signed
                    ? "int" : "uint";
                return std::format("{}{}_t", prefix, ret.i.bits);
            }
        }
    }
    if (const InferredSig* signature = call_inferred_signature(inst);
        signature && !signature->return_type.is_top()) {
        std::string inferred = ipa_type_name(signature->return_type);
        if (!inferred.empty()) return inferred;
    }
    std::optional<addr_t> target;
    if (inst.op == IrOp::Call) {
        target = inst.target1;
    } else if (inst.op == IrOp::CallIndirect && options.call_resolutions &&
               inst.source_addr != 0) {
        if (auto it = options.call_resolutions->find(inst.source_addr);
            it != options.call_resolutions->end()) {
            target = it->second;
        }
    }
    if (target) {
        if (auto it = inferred_call_return_types.find(*target);
            it != inferred_call_return_types.end()) {
            return it->second;
        }
    }
    return std::nullopt;
}

bool Emitter::is_ppc_abi_helper_call(const IrInst& inst) const {
    if (!binary || inst.op != IrOp::Call ||
        (abi != Abi::Ppc32Sysv && abi != Abi::Ppc64ElfV1Be &&
         abi != Abi::Ppc64ElfV2Le)) {
        return false;
    }
    const Symbol* sym = binary->defined_object_at(inst.target1);
    if (!sym) return false;
    const std::string_view name = sym->name;
    return name.starts_with("_savegpr_") || name.starts_with("_restgpr_") ||
           name.starts_with("_savefpr_") || name.starts_with("_restfpr_") ||
           name.starts_with("__save_gpr") || name.starts_with("__rest_gpr") ||
           name.starts_with("__save_fpr") || name.starts_with("__rest_fpr");
}

bool Emitter::call_inst_returns_void(const IrInst& inst) const {
    if (is_ppc_abi_helper_call(inst)) return true;
    if (auto lane = known_call_return_lane(inst); lane) {
        return *lane == CallReturnLane::Void;
    }
    auto name = call_import_name(inst);
    return name && import_returns_void(*name);
}

bool Emitter::is_call_arg_barrier(const IrInst& inst) noexcept {
    return SsaUseIndex::is_call_arg_barrier(inst);
}

bool Emitter::is_callee_saved(Reg r) noexcept {
    const Reg c = canonical_reg(r);
    return c == Reg::Rbx || c == Reg::Rbp ||
           c == Reg::R12 || c == Reg::R13 ||
           c == Reg::R14 || c == Reg::R15 ||
           (c >= Reg::PpcR14 && c <= Reg::PpcR31);
}

bool Emitter::is_stack_base_reg(Reg r) noexcept {
    const Reg c = canonical_reg(r);
    return c == Reg::Rsp || c == Reg::Rbp ||
           c == Reg::PpcR1;
}

bool Emitter::is_void_call_result(const IrValue& v) const {
    if (v.kind != IrValueKind::Reg) return false;
    const IrInst* def = def_of(v);
    if (!def || def->op != IrOp::Clobber) return false;
    auto k = ssa_key(v);
    if (!k) return false;
    const auto position = ssa_uses.definition_position(*k);
    if (!position) return false;
    auto [bi, ii] = *position;
    const auto& bb = fn->blocks[bi];
    while (ii > 0) {
        --ii;
        const IrInst& prev = bb.insts[ii];
        if (prev.op == IrOp::Clobber || prev.op == IrOp::Nop) continue;
        if (prev.op == IrOp::Call || prev.op == IrOp::CallIndirect) {
            return call_inst_returns_void(prev);
        }
        return false;
    }
    return false;
}

bool Emitter::is_unbound_clobber_result(const IrValue& v) const {
    if (v.kind != IrValueKind::Reg) return false;
    const IrInst* def = def_of(v);
    if (!def || def->op != IrOp::Clobber) return false;
    auto k = ssa_key(v);
    if (!k) return false;
    if (call_return_names.contains(*k) ||
        fold_return_expr.contains(*k) ||
        fold_void_call_stmt.contains(*k)) {
        return false;
    }
    const auto position = ssa_uses.definition_position(*k);
    if (!position) return true;
    auto [bi, ii] = *position;
    const auto& bb = fn->blocks[bi];
    while (ii > 0) {
        --ii;
        const IrInst& prev = bb.insts[ii];
        if (prev.op == IrOp::Clobber || prev.op == IrOp::Nop) continue;
        return prev.op != IrOp::Call && prev.op != IrOp::CallIndirect;
    }
    return true;
}

bool Emitter::is_msvc_cookie_return_clobber(const IrValue& value) const {
    const auto key = ssa_key(value);
    return key && msvc_cookie_return_clobbers.contains(*key);
}

std::optional<IrValue>
Emitter::return_value_before_msvc_cookie(const IrValue& value) const {
    const auto key = ssa_key(value);
    if (!key) return std::nullopt;
    auto found = msvc_cookie_preserved_returns.find(*key);
    if (found == msvc_cookie_preserved_returns.end()) return std::nullopt;
    return found->second;
}

bool Emitter::is_incidental_x86_fp_return(const IrValue& value) const {
    if (abi != Abi::SysVAmd64 && abi != Abi::Win64) return false;
    if (value.kind != IrValueKind::Reg ||
        canonical_reg(value.reg) != canonical_reg(fp_return_reg(abi))) {
        return false;
    }
    const IrInst* root = def_of(value);
    if (!root || root->op != IrOp::Phi) return false;
    std::set<SsaKey> seen;
    const auto transport_only = [&](const auto& self, const IrValue& candidate,
                                    int depth) -> bool {
        if (depth > 16) return false;
        if (candidate.kind == IrValueKind::Reg && candidate.version == 0 &&
            canonical_reg(candidate.reg) == canonical_reg(fp_return_reg(abi))) {
            return true;
        }
        auto key = ssa_key(candidate);
        if (key && !seen.insert(*key).second) return true;
        const IrInst* definition = def_of(candidate);
        if (!definition) return false;
        if (definition->op == IrOp::Clobber) return true;
        if (definition->op == IrOp::Assign && definition->src_count == 1) {
            return self(self, definition->srcs[0], depth + 1);
        }
        if (definition->op != IrOp::Phi || definition->phi_operands.empty()) {
            return false;
        }
        return std::ranges::all_of(definition->phi_operands,
            [&](const IrValue& operand) {
                return self(self, operand, depth + 1);
            });
    };
    return transport_only(transport_only, value, 0);
}

bool Emitter::has_incidental_ppc_return_merge() const {
    if (!fn || (abi != Abi::Ppc32Sysv && abi != Abi::Ppc64ElfV1Be &&
                abi != Abi::Ppc64ElfV2Le)) {
        return false;
    }
    const Reg ret_reg = int_return_reg(abi);
    for (const auto& bb : fn->blocks) {
        for (const auto& inst : bb.insts) {
            if (inst.op != IrOp::Return || inst.src_count == 0) continue;
            const IrValue& rv = inst.srcs[0];
            if (rv.kind != IrValueKind::Reg ||
                canonical_reg(rv.reg) != ret_reg) {
                continue;
            }
            const IrInst* phi = def_of(rv);
            if (!phi || phi->op != IrOp::Phi || phi->phi_operands.size() < 2) continue;
            bool saw_live_in = false;
            std::size_t clobbers = 0;
            bool saw_side_effect_value = false;
            bool small_merge_is_incidental = true;
            for (std::size_t op_index = 0;
                 op_index < phi->phi_operands.size(); ++op_index) {
                IrValue op = phi->phi_operands[op_index];
                if (auto key = ssa_key(op); key) {
                    if (ssa_uses.visible_use_count(*key) > 0) {
                        saw_side_effect_value = true;
                    }
                }
                bool classified = false;
                if (op.kind == IrValueKind::Imm &&
                    op_index < phi->phi_preds.size()) {
                    auto pred_it = fn->block_at.find(phi->phi_preds[op_index]);
                    if (pred_it != fn->block_at.end()) {
                        const auto& pred = fn->blocks[pred_it->second];
                        for (const auto& pred_inst : pred.insts) {
                            if (pred_inst.op != IrOp::Store ||
                                pred_inst.src_count < 2) {
                                continue;
                            }
                            const IrValue& stored = pred_inst.srcs[1];
                            if (stored.kind == IrValueKind::Imm &&
                                stored.imm == op.imm && stored.type == op.type) {
                                saw_side_effect_value = true;
                                classified = true;
                                break;
                            }
                        }
                    }
                }
                for (int depth = 0; depth < 6; ++depth) {
                    if (classified) break;
                    if (op.kind == IrValueKind::Reg && op.version == 0 &&
                        canonical_reg(op.reg) == ret_reg) {
                        saw_live_in = true;
                        classified = true;
                        break;
                    }
                    const IrInst* d = def_of(op);
                    if (!d) break;
                    if (d->op == IrOp::Clobber) {
                        auto key = ssa_key(op);
                        // bind_call_returns gives every unknown call a
                        // provisional name, even if the trailing dead-
                        // declaration pass later removes it. A real
                        // non-Phi use is the stronger evidence that this
                        // clobber is an intentional return value.
                        if (!key || ssa_uses.visible_use_count(*key) == 0) {
                            ++clobbers;
                            classified = true;
                        }
                        break;
                    }
                    if (d->op == IrOp::Assign && d->src_count == 1) {
                        // The assigned register can feed a store while its
                        // source is an immediate with no SSA key.
                        if (auto key = ssa_key(op); key) {
                            if (ssa_uses.visible_use_count(*key) > 0) {
                                classified = true;
                                break;
                            }
                        }
                        op = d->srcs[0];
                        continue;
                    }
                    break;
                }
                if (!classified) small_merge_is_incidental = false;
            }
            if (phi->phi_operands.size() >= 6 && saw_live_in && clobbers >= 2) {
                return true;
            }
            if (small_merge_is_incidental && clobbers + (saw_live_in ? 1u : 0u) > 0 &&
                saw_side_effect_value) {
                return true;
            }
        }
    }
    return false;
}

bool Emitter::has_incidental_ppc_stored_return() const {
    if (!fn || !is_ppc_abi()) return false;
    const auto source_value = [&](IrValue value) {
        for (int depth = 0; depth < 12; ++depth) {
            const IrInst* definition = def_of(value);
            if (!definition || definition->src_count < 1) break;
            if (definition->op != IrOp::Assign &&
                definition->op != IrOp::ZExt &&
                definition->op != IrOp::SExt &&
                definition->op != IrOp::Trunc) {
                break;
            }
            value = definition->srcs[0];
        }
        return value;
    };
    for (const auto& bb : fn->blocks) {
        for (const IrInst& inst : bb.insts) {
            if (inst.op != IrOp::Return || inst.src_count == 0) continue;
            for (u8 source_index = 0;
                 source_index < inst.src_count &&
                 source_index < inst.srcs.size(); ++source_index) {
                const IrValue value = source_value(inst.srcs[source_index]);
                auto key = ssa_key(value);
                if (!key) continue;
                u32 replicated_stores = 0;
                u32 total_stores = 0;
                for (const auto& candidate_bb : fn->blocks) {
                    for (const IrInst& candidate : candidate_bb.insts) {
                        if (candidate.op != IrOp::Store ||
                            candidate.src_count < 2) continue;
                        ++total_stores;
                        if (auto stored_key = ssa_key(
                                source_value(candidate.srcs[1]));
                            stored_key && *stored_key == *key) {
                            ++replicated_stores;
                        }
                    }
                }
                if (replicated_stores >= 2 ||
                    (replicated_stores >= 1 && total_stores >= 6)) {
                    return true;
                }
            }
        }
    }
    return false;
}

void Emitter::analyze_return_folds(const Region& r) {
    for (const auto& c : r.children) analyze_return_folds(*c);
    if (r.kind != RegionKind::Return) return;
    const IrValue& cond = r.condition;
    if (cond.kind != IrValueKind::Reg) return;
    auto cond_key = ssa_key(cond);
    if (!cond_key) return;
    const IrInst* def = def_of(cond);
    if (!def || def->op != IrOp::Clobber) return;
    // Folding `return foo(args);` requires that the call's return value
    // has no other readers - otherwise we'd silently re-emit the call
    // expression at the return site and unbind the only name the other
    // readers had to refer to it. Phi resolution at the structurer can
    // surface a return whose value the surrounding `if` already tested,
    // creating exactly this hazard.
    if (count_uses_with_call_args(*cond_key) > 1) return;
    const auto position = ssa_uses.definition_position(*cond_key);
    if (!position) return;
    auto [bi, ii] = *position;
    const auto& bb = fn->blocks[bi];
    // Walk back past the clobber sequence the lifter emits after a call.
    while (ii > 0) {
        --ii;
        const IrInst& prev = bb.insts[ii];
        if (prev.op == IrOp::Clobber || prev.op == IrOp::Nop) continue;
        if (prev.op == IrOp::Call || prev.op == IrOp::CallIndirect) {
            if (canonical_reg(cond.reg) !=
                canonical_reg(call_result_reg(prev))) {
                return;
            }
            fold_call_positions.insert({bi, ii});
            fold_call_ssa_key.emplace(std::pair{bi, ii}, *cond_key);
        }
        return;  // first non-clobber: either the Call we want, or abort
    }
}

void Emitter::collect_structured_return_values(const Region& region) {
    if (region.kind == RegionKind::Return) {
        if (auto key = ssa_key(region.condition); key) {
            structured_return_values.insert(*key);
        }
    }
    for (const auto& child : region.children) {
        if (child) collect_structured_return_values(*child);
    }
}

void Emitter::analyze_return_expr_call_folds(const Region& r) {
    for (const auto& c : r.children) analyze_return_expr_call_folds(*c);
    if (r.kind != RegionKind::Return) return;
    if (r.condition.kind == IrValueKind::None) return;
    auto ret_key = single_call_return_key_in_expr(r.condition);
    if (!ret_key) return;
    if (fold_return_expr.contains(*ret_key) ||
        fold_void_call_stmt.contains(*ret_key)) {
        return;
    }
    if (count_uses_with_call_args(*ret_key) != 1) return;
    auto pos = call_position_for_return_key(*ret_key);
    if (!pos) return;
    if (fold_call_positions.contains(*pos)) return;
    if (auto slot = self_funcptr_slot_for_call_pos(*pos); slot) {
        if (auto ty = narrowed_call_return_type_in_expr(r.condition, *ret_key); ty) {
            record_funcptr_return_type(*slot, *ty);
        }
    }
    inline_call_positions.insert(*pos);
    inline_call_ssa_key.emplace(*pos, *ret_key);
}

void Emitter::bind_call_returns() {
    // When a call's return-register clobber flows into a Phi that
    // name_merge_values has labelled (`v0`, `v1`, …) AND the merge
    // name will actually be read by the body, bind the call to that
    // merge name instead of inventing `r_<callee>`. The call statement
    // then becomes `v0 = sub_X(...);`, which:
    //   - actually defines the merge variable declared at the function
    //     head (otherwise `v0` is uninitialized, and every read prints
    //     `v0` with no producer in sight),
    //   - escapes the trailing dead-decl pass, which only strips lines
    //     of the `TYPE NAME = ...;` shape - `v0 = ...` has no type
    //     prefix, so it stays.
    // Without this, calls whose result fans out through a phi got
    // emitted as `u64 r_sub_X = ...;`, the use site rendered the phi
    // as `v0`, `r_sub_X` appeared nowhere else, and the dead-decl pass
    // silently deleted the call statement (side effect and all).
    //
    // The "merge name will be read by body" gate matters: when the
    // phi's only readers are Return regions, the structurer folds each
    // path's return value independently and the merge name is never
    // referenced. In that case the original `r_<callee>` binding
    // reads better - e.g. `char* r_getenv = getenv("HOME"); if
    // (r_getenv) ...; return r_getenv;` instead of an arbitrary `v5`.
    const auto phi_has_non_return_user = [&](SsaKey pk) {
        std::set<SsaKey> seen;
        const auto walk = [&](SsaKey cur, auto& self) -> bool {
            if (!seen.insert(cur).second) return false;
            for (const auto& bb : fn->blocks) {
                for (const auto& inst : bb.insts) {
                    if (inst.op == IrOp::Return) continue;
                    if (inst.op == IrOp::Phi) {
                        for (const auto& op : inst.phi_operands) {
                            if (auto ok = ssa_key(op); ok && *ok == cur) {
                                if (auto dpk = ssa_key(inst.dst); dpk) {
                                    if (self(*dpk, self)) return true;
                                }
                            }
                        }
                        continue;
                    }
                    for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i) {
                        if (auto ok = ssa_key(inst.srcs[i]); ok && *ok == cur) {
                            return true;
                        }
                    }
                }
            }
            return false;
        };
        return walk(pk, walk);
    };

    std::map<SsaKey, std::string> ret_key_to_merge_name;
    std::map<std::pair<std::size_t, std::size_t>, std::string> objc_return_base;
    for (const auto& bb : fn->blocks) {
        for (const auto& inst : bb.insts) {
            if (inst.op != IrOp::Phi) continue;
            auto pk = ssa_key(inst.dst);
            if (!pk) continue;
            auto mit = merge_value_names.find(*pk);
            if (mit == merge_value_names.end()) continue;
            if (!phi_has_non_return_user(*pk)) continue;
            for (const auto& op : inst.phi_operands) {
                // A call result commonly reaches an FP phi through
                // `frsp`/Trunc and a register Assign. Follow those
                // transparent unary conversions back to the call's
                // Clobber so emit_call_binding can initialize the merge
                // local directly instead of letting dead-decl cleanup
                // erase the only visible call.
                IrValue origin = op;
                for (int depth = 0; depth < 8; ++depth) {
                    auto ok = ssa_key(origin);
                    if (!ok) break;
                    ret_key_to_merge_name.emplace(*ok, mit->second);
                    const IrInst* d = def_of(origin);
                    if (!d || d->src_count != 1) break;
                    if (d->op != IrOp::Assign && d->op != IrOp::Trunc &&
                        d->op != IrOp::ZExt && d->op != IrOp::SExt) {
                        break;
                    }
                    origin = d->srcs[0];
                }
            }
        }
    }

    for (std::size_t bi = 0; bi < fn->blocks.size(); ++bi) {
        const auto& bb = fn->blocks[bi];
        std::vector<IrValue> args;
        args.reserve(kMaxAbiIntArgs);
        for (std::size_t ii = 0; ii < bb.insts.size(); ++ii) {
            const auto& inst = bb.insts[ii];
            if (inst.op == IrOp::Intrinsic && inst.name == "call.args.1") {
                args.clear();
                for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i) {
                    args.push_back(inst.srcs[i]);
                }
                continue;
            }
            if (inst.op == IrOp::Intrinsic &&
                (inst.name == "call.args.2" || inst.name == "call.args.3")) {
                for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i) {
                    args.push_back(inst.srcs[i]);
                }
                continue;
            }
            if (inst.op == IrOp::Call || inst.op == IrOp::CallIndirect) {
                if (auto base = objc_return_base_for_call(inst, args); base) {
                    objc_return_base.emplace(std::pair{bi, ii}, *base);
                }
                args.clear();
            }
        }
    }

    std::set<std::string> used;
    for (std::size_t bi = 0; bi < fn->blocks.size(); ++bi) {
        const auto& bb = fn->blocks[bi];
        for (std::size_t ii = 0; ii < bb.insts.size(); ++ii) {
            const auto& inst = bb.insts[ii];
            if (inst.op != IrOp::Call && inst.op != IrOp::CallIndirect) continue;
            if (hidden.contains({bi, ii})) continue;
            if (fold_call_positions.contains({bi, ii})) continue;
            if (inline_call_positions.contains({bi, ii})) continue;
            if (arc_claim_producer_positions.contains({bi, ii})) continue;
            if (call_inst_returns_void(inst)) continue;
            const Reg ret_reg = call_result_reg(inst);
            if (ret_reg == Reg::None) continue;

            // The return-register clobber for this call is the next inst
            // (Clobbers
            // run immediately post-Call in the lifter's output).
            std::optional<SsaKey> ret_key;
            for (std::size_t jj = ii + 1; jj < bb.insts.size(); ++jj) {
                const auto& c = bb.insts[jj];
                if (c.op != IrOp::Clobber) break;
                if (c.dst.kind != IrValueKind::Reg) continue;
                if (canonical_reg(c.dst.reg) != ret_reg) continue;
                ret_key = ssa_key(c.dst);
                break;
            }
            if (!ret_key) continue;
            // Always bind a name for the return-register clobber when the call wasn't
            // folded into a Return. Reads that happen only through
            // structured-region conditions (e.g. `return r3;`) don't
            // appear in IR srcs and so can't be counted up-front; the
            // dead-decl pass at the end strips any binding nothing ended
            // up referencing.

            std::string name;
            if (auto mit = ret_key_to_merge_name.find(*ret_key);
                mit != ret_key_to_merge_name.end()) {
                name = mit->second;
                merge_bound_calls.insert({bi, ii});
            } else {
                std::string base = callee_display_short(inst);
                if (auto oit = objc_return_base.find({bi, ii});
                    oit != objc_return_base.end()) {
                    base = oit->second;
                }
                std::string semantic;
                if (is_ppc_abi()) {
                    std::string lower = base;
                    for (char& c : lower) {
                        c = static_cast<char>(std::tolower(
                            static_cast<unsigned char>(c)));
                    }
                    if (lower.find("alloc") != std::string::npos) {
                        semantic = "allocation";
                    } else if (lower.find("animposeentry") != std::string::npos) {
                        semantic = "pose_entry";
                    } else if (lower.find("camgetcurptr") != std::string::npos) {
                        semantic = "camera";
                    } else if (lower.find("gettexbuffersize") != std::string::npos) {
                        semantic = "buffer_size";
                    }
                }
                const std::string stem = semantic.empty()
                    ? "r_" + base
                    : semantic;
                name = stem;
                for (int n = 2; used.contains(name); ++n) {
                    name = std::format("{}_{}", stem, n);
                }
                used.insert(name);
            }
            call_return_names.emplace(*ret_key, name);
            bound_call_key.emplace(std::pair{bi, ii}, *ret_key);
        }
    }
}

void Emitter::infer_shared_call_return_types() {
    if (!fn || !is_ppc_abi()) return;
    for (std::size_t bi = 0; bi < fn->blocks.size(); ++bi) {
        const auto& bb = fn->blocks[bi];
        for (std::size_t ii = 0; ii < bb.insts.size(); ++ii) {
            const IrInst& call = bb.insts[ii];
            std::optional<addr_t> target;
            if (call.op == IrOp::Call) {
                target = call.target1;
            } else if (call.op == IrOp::CallIndirect &&
                       options.call_resolutions && call.source_addr != 0) {
                if (auto it = options.call_resolutions->find(call.source_addr);
                    it != options.call_resolutions->end()) {
                    target = it->second;
                }
            }
            if (!target) continue;

            const IrValue* result = nullptr;
            for (std::size_t jj = ii + 1; jj < bb.insts.size(); ++jj) {
                const IrInst& clobber = bb.insts[jj];
                if (clobber.op != IrOp::Clobber) break;
                if (clobber.dst.kind == IrValueKind::Reg &&
                    canonical_reg(clobber.dst.reg) ==
                        canonical_reg(int_return_reg(abi))) {
                    result = &clobber.dst;
                    break;
                }
            }
            if (!result) continue;
            auto pointer_type = pointer_type_from_memory_uses(*result);
            if (!pointer_type || !pointer_type->ends_with('*')) continue;

            auto [it, inserted] = inferred_call_return_types.emplace(
                *target, *pointer_type);
            if (!inserted && it->second != *pointer_type) {
                const bool old_generic = it->second == "void*";
                const bool new_generic = *pointer_type == "void*";
                if (old_generic && !new_generic) {
                    it->second = *pointer_type;
                } else if (!old_generic && new_generic) {
                    // Preserve the concrete shape found at a sibling
                    // call site; an unobserved/generic use adds no
                    // contradictory field evidence.
                } else {
                    it->second = "void*";
                }
            }
        }
    }
}

u32 Emitter::use_count_by_key(const SsaKey& k) const {
    return ssa_uses.semantic_use_count(k);
}

u32 Emitter::count_uses_with_call_args(const SsaKey& k) const {
    return ssa_uses.syntactic_use_count(k);
}

std::optional<std::pair<std::size_t, std::size_t>>
Emitter::call_position_for_return_key(const SsaKey& k) const {
    const auto position = ssa_uses.definition_position(k);
    if (!position) return std::nullopt;
    auto [bi, ii] = *position;
    const auto& bb = fn->blocks[bi];
    while (ii > 0) {
        --ii;
        const IrInst& prev = bb.insts[ii];
        if (prev.op == IrOp::Clobber || prev.op == IrOp::Nop) continue;
        if (prev.op == IrOp::Call || prev.op == IrOp::CallIndirect) {
            return std::pair{bi, ii};
        }
        return std::nullopt;
    }
    return std::nullopt;
}

void Emitter::analyze_arc_claim_folds() {
    if (!fn) return;
    for (std::size_t bi = 0; bi < fn->blocks.size(); ++bi) {
        const auto& bb = fn->blocks[bi];
        std::vector<IrValue> args;
        args.reserve(kMaxAbiIntArgs);
        for (std::size_t ii = 0; ii < bb.insts.size(); ++ii) {
            const auto& inst = bb.insts[ii];
            if (inst.op == IrOp::Intrinsic && inst.name == "call.args.1") {
                args.clear();
                for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i) {
                    args.push_back(inst.srcs[i]);
                }
                continue;
            }
            if (inst.op == IrOp::Intrinsic &&
                (inst.name == "call.args.2" || inst.name == "call.args.3")) {
                for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i) {
                    args.push_back(inst.srcs[i]);
                }
                continue;
            }
            if (inst.op != IrOp::Call && inst.op != IrOp::CallIndirect) continue;
            auto name = call_import_name(inst);
            if (name && *name == "objc_unsafeClaimAutoreleasedReturnValue" &&
                !args.empty()) {
                if (auto key = ssa_key(args[0]);
                    key && count_uses_with_call_args(*key) == 1) {
                    if (auto producer = call_position_for_return_key(*key); producer) {
                        arc_claim_producer_positions.insert(*producer);
                        suppressed_call_positions.insert({bi, ii});
                    }
                }
            }
            args.clear();
        }
    }
}

std::optional<u8>
Emitter::self_funcptr_slot_for_call_pos(std::pair<std::size_t, std::size_t> pos) const {
    if (pos.first >= fn->blocks.size()) return std::nullopt;
    const auto& bb = fn->blocks[pos.first];
    if (pos.second >= bb.insts.size()) return std::nullopt;
    const IrInst& inst = bb.insts[pos.second];
    if (inst.op != IrOp::CallIndirect || inst.src_count < 1) return std::nullopt;
    auto slot = trace_to_self_arg_slot(inst.srcs[0]);
    if (!slot || *slot >= self_funcptr_return_type.size()) return std::nullopt;
    return slot;
}

std::optional<IrType>
Emitter::narrowed_call_return_type_in_expr(const IrValue& v,
                                           const SsaKey& ret_key,
                                           int depth) const {
    if (depth > 8) return std::nullopt;
    if (auto k = ssa_key(v); k) {
        const IrInst* d = def_of(v);
        if (d && d->op == IrOp::Clobber && *k == ret_key) return v.type;
        if (!d) return std::nullopt;
        if ((d->op == IrOp::Trunc || d->op == IrOp::ZExt || d->op == IrOp::SExt) &&
            d->src_count >= 1) {
            if (auto sk = ssa_key(d->srcs[0]); sk && *sk == ret_key) {
                return d->dst.type;
            }
        }
        for (u8 i = 0; i < d->src_count && i < d->srcs.size(); ++i) {
            if (auto t = narrowed_call_return_type_in_expr(d->srcs[i],
                                                           ret_key,
                                                           depth + 1)) {
                return t;
            }
        }
    }
    return std::nullopt;
}

std::optional<SsaKey>
Emitter::single_call_return_key_in_expr(const IrValue& v, int depth) const {
    if (depth > 8) return std::nullopt;
    std::optional<SsaKey> found;
    auto merge = [&](std::optional<SsaKey> k) {
        if (!k) return true;
        if (!found) {
            found = *k;
            return true;
        }
        return *found == *k;
    };

    if (auto k = ssa_key(v); k) {
        const IrInst* d = def_of(v);
        if (d && d->op == IrOp::Clobber &&
            v.kind == IrValueKind::Reg &&
            call_position_for_return_key(*k)) {
            auto pos = call_position_for_return_key(*k);
            if (pos && pos->first < fn->blocks.size() &&
                pos->second < fn->blocks[pos->first].insts.size()) {
                const IrInst& call = fn->blocks[pos->first].insts[pos->second];
                if (canonical_reg(v.reg) == canonical_reg(call_result_reg(call))) {
                    return *k;
                }
            }
        }
        if (!d) return std::nullopt;
        switch (d->op) {
            case IrOp::Assign:
            case IrOp::Add:
            case IrOp::Sub:
            case IrOp::Mul:
            case IrOp::And:
            case IrOp::Or:
            case IrOp::Xor:
            case IrOp::Shl:
            case IrOp::Lshr:
            case IrOp::Ashr:
            case IrOp::Trunc:
            case IrOp::ZExt:
            case IrOp::SExt:
            case IrOp::FpToInt:
                for (u8 i = 0; i < d->src_count && i < d->srcs.size(); ++i) {
                    if (!merge(single_call_return_key_in_expr(d->srcs[i],
                                                              depth + 1))) {
                        return std::nullopt;
                    }
                }
                return found;
            default:
                return std::nullopt;
        }
    }
    return std::nullopt;
}

std::string Emitter::callee_display_short(const IrInst& call_inst) const {
    std::string raw = call_import_name(call_inst).value_or("");
    if (call_inst.op == IrOp::Call) {
        if (raw.empty()) raw = function_display_name(call_inst.target1);
    } else if (call_inst.op == IrOp::CallIndirect && call_inst.src_count >= 1) {
        if (raw.empty()) raw = "ind";
    } else {
        raw = "call";
    }
    // Keep only the last `::`-separated segment for qualified names.
    // Operators (`operator+`, `operator new`) and destructors (`~T`)
    // are kept whole on the right side - they're already short.
    if (auto pos = raw.rfind("::"); pos != std::string::npos) {
        raw.erase(0, pos + 2);
    }
    std::string out;
    out.reserve(raw.size());
    for (char c : raw) {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '_') {
            out += c;
        }
    }
    return out.empty() ? std::string("call") : out;
}

}  // namespace ember::emit

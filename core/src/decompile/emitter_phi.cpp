// Explicit SSA destruction for integer and SSE2 vector loops. Copies belong to edges,
// and every right-hand side is evaluated before any phi destination changes.
#include "emitter_internal.hpp"
#include "emitter_text.hpp"
#include <spelunk/analysis/import_sigs.hpp>

#include <algorithm>
#include <format>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace spelunk::emit {

namespace {
bool has_cyclic_phi(const IrFunction& fn) {
    for (const auto& block : fn.blocks) {
        if (!std::ranges::any_of(block.insts, [](const IrInst& inst) {
                return inst.op == IrOp::Phi;
            })) continue;
        std::vector<addr_t> pending = block.successors;
        std::set<addr_t> seen;
        while (!pending.empty()) {
            const addr_t address = pending.back();
            pending.pop_back();
            if (address == block.start) return true;
            if (!seen.insert(address).second) continue;
            const auto found = fn.block_at.find(address);
            if (found == fn.block_at.end()) continue;
            const auto& successors = fn.blocks[found->second].successors;
            pending.insert(pending.end(), successors.begin(), successors.end());
        }
    }
    return false;
}
}  // namespace

const std::string* Emitter::scoped_ssa_name(const IrValue& value) const {
    auto key = ssa_key(value);
    if (!key) return nullptr;
    auto found = scoped_ssa_values.find(*key);
    return found == scoped_ssa_values.end() ? nullptr : &found->second.second;
}

bool Emitter::prepare_scalar_join_copies() {
    if (!fn || (abi != Abi::SysVAmd64 && abi != Abi::Win64)) return false;
    const bool cyclic_phi = has_cyclic_phi(*fn);
    std::set<SsaKey> visiting;
    const auto scalar_type = [&](auto&& self, const IrValue& value) -> std::optional<IrType> {
        const auto key = ssa_key(value);
        if (key) {
            if (auto it = scalar_join_types.find(*key); it != scalar_join_types.end()) return it->second;
            if (!visiting.insert(*key).second) return std::nullopt;
        }
        const auto* definition = def_of(value);
        std::optional<IrType> type;
        if (!definition) {
            if (is_float_type(value.type) || value.kind == IrValueKind::Imm ||
                (value.kind == IrValueKind::Reg && value.version == 0 &&
                 type_bits(value.type) <= 64 && arg_name_for_live_in(value.reg)))
                type = value.type;
        } else if (definition->op == IrOp::Assign && definition->src_count) {
            type = self(self, definition->srcs[0]);
        } else if (definition->op == IrOp::Phi) {
            for (const auto& operand : definition->phi_operands) {
                auto incoming = self(self, operand);
                if (!incoming || (type && type != incoming)) { type.reset(); break; }
                type = incoming;
            }
        } else if (definition->op == IrOp::Clobber && key &&
                   definition->dst.kind == IrValueKind::Reg &&
                   canonical_reg(definition->dst.reg) == fp_return_reg(abi)) {
            if (auto position = call_position_for_return_key(*key)) {
                const auto declared = known_call_return_c_type(fn->blocks[position->first].insts[position->second]);
                if (declared == "float") type = IrType::F32;
                if (declared == "double") type = IrType::F64;
            }
        } else if (definition->dst.type == IrType::F32 || definition->dst.type == IrType::F64) {
            type = definition->dst.type;
        } else if (inlinable_op(definition->op) &&
                   type_bits(definition->dst.type) <= 64) {
            type = definition->dst.type;
        }
        if (key) {
            visiting.erase(*key);
            if (type && is_float_type(*type)) scalar_join_types.emplace(*key, *type);
        }
        return type;
    };
    std::vector<const IrInst*> phis;
    for (const auto& block : fn->blocks) for (const auto& inst : block.insts) {
        if (inst.op != IrOp::Phi) continue;
        const auto key = ssa_key(inst.dst);
        const bool constant_call_argument = key && !use_count(inst.dst) &&
            ssa_uses.syntactic_use_count(*key) &&
            std::ranges::all_of(inst.phi_operands, [](const IrValue& value) {
                return value.kind == IrValueKind::Imm;
            });
        const auto type = scalar_type(scalar_type, inst.dst);
        const bool snapshot_join = options.c_source && key &&
            ssa_uses.syntactic_use_count(*key) &&
            std::ranges::any_of(inst.phi_operands, [&](const IrValue& operand) {
                const auto operand_key = ssa_key(operand);
                return operand_key && memory_snapshot_loads.contains(*operand_key);
            });
        const bool conditional_integer_join = !cyclic_phi && type && !is_float_type(*type) &&
            key && merge_value_names.contains(*key) && use_count(inst.dst) &&
            std::ranges::any_of(ssa_uses.visible_user_positions(*key), [&](const auto& user) {
                return fn->blocks[user.first].insts[user.second].op != IrOp::Return;
            }) &&
            std::ranges::any_of(inst.phi_preds, [&](addr_t pred) {
                const auto found = fn->block_at.find(pred);
                if (found == fn->block_at.end()) return false;
                const auto& incoming = fn->blocks[found->second];
                return !incoming.insts.empty() &&
                    incoming.insts.back().op == IrOp::CondBranch;
            });
        if (type && ((is_float_type(*type) && use_count(inst.dst)) ||
                     constant_call_argument || snapshot_join || conditional_integer_join)) {
            phis.push_back(&inst);
            if (key) scalar_join_types.insert_or_assign(*key, *type);
        }
    }
    if (phis.empty()) return false;
    std::set<std::string> replaced;
    const auto remember = [&](const IrValue& original, std::string_view prefix) {
        const auto key = ssa_key(original);
        if (!key || scoped_ssa_values.contains(*key)) return;
        const auto type = scalar_type(scalar_type, original);
        if (!type) return;
        IrValue value = original;
        value.type = *type;
        std::string name = std::format("{}_{}", prefix, scoped_ssa_values.size());
        while (std::ranges::find(self_arg_names, name) != self_arg_names.end()) name += "_";
        scoped_ssa_values.emplace(*key, std::pair{value, std::move(name)});
        if (auto old = merge_value_names.find(*key); old != merge_value_names.end()) {
            replaced.insert(old->second);
            merge_value_names.erase(old);
        }
    };
    for (const auto* phi : phis) {
        remember(phi->dst, is_float_type(*scalar_type(scalar_type, phi->dst)) ? "phi_fp" : "phi_arg");
        for (const auto& operand : phi->phi_operands) {
            if (def_of(operand)) remember(operand, "ssa_fp");
        }
    }
    for (const auto& name : replaced) merge_locals.erase(name);
    for (auto& [_, copies] : merge_edge_assignments) {
        std::erase_if(copies, [&](const auto& copy) { return replaced.contains(copy.first); });
    }
    for (const auto& [key, item] : scoped_ssa_values) {
        const auto* definition = ssa_uses.definition(key);
        if (!definition || definition->op != IrOp::Clobber) continue;
        const auto position = call_position_for_return_key(key);
        if (!position) continue;
        fold_call_positions.erase(*position);
        inline_call_positions.erase(*position);
        fold_call_ssa_key.erase(*position);
        inline_call_ssa_key.erase(*position);
        bound_call_key[*position] = key;
        call_return_names[key] = item.second;
        merge_bound_calls.insert(*position);
    }
    scalar_join_copies = true;
    return true;
}

void Emitter::prepare_phi_copies() {
    if (!fn || (abi != Abi::SysVAmd64 && abi != Abi::Win64 && !is_x86_32_abi(abi) &&
                !is_ppc_abi())) return;
    // A snapshot join can coexist with other loop-carried values. Do not
    // stop after lowering just that one Phi and lose the remaining updates.
    if (prepare_scalar_join_copies() && !has_cyclic_phi(*fn)) return;
    // Calls are eligible only when their declared x64 signature establishes
    // scalar register arguments. Unknown/FP/aggregate calls keep the existing
    // path rather than treating their conservative ABI snapshots as real uses.
    std::map<addr_t, std::size_t> call_arities;
    std::set<addr_t> void_calls;
    for (const auto& block : fn->blocks) {
        for (const auto& inst : block.insts) {
            if (inst.op == IrOp::CallIndirect) return;
            if (inst.op != IrOp::Call) continue;
            if (is_ppc_abi()) return;
            const FunctionSig* signature = call_annotation_signature(inst);
            if (!signature && binary) {
                auto found = binary->debug_signatures().find(inst.target1);
                if (found != binary->debug_signatures().end()) signature = &found->second;
            }
            if (!signature && binary) {
                if (const auto* imported = binary->import_at_plt(inst.target1)) {
                    TypeArena types;
                    const auto spec = lookup_import_sig(strip_import_name_decorations(imported->name), types);
                    const auto scalar_type = [&](TypeRef type) {
                        const auto kind = types.kind(type);
                        return kind == TypeKind::Int || kind == TypeKind::Ptr;
                    };
                    if (spec && !spec->variadic &&
                        (types.kind(spec->ret) == TypeKind::Void || scalar_type(spec->ret)) &&
                        std::ranges::all_of(spec->params, scalar_type) && spec->params.size() <= int_arg_regs(abi).size()) {
                        call_arities[inst.target1] = spec->params.size();
                        if (types.kind(spec->ret) == TypeKind::Void) void_calls.insert(inst.target1);
                        continue;
                    }
                }
            }
            const auto scalar = [&](std::string_view type) {
                const std::string normalized = normalize_c_type_alias(type);
                return normalized.ends_with('*') ||
                    (!is_declared_fp_scalar(normalized) && declared_scalar_size(normalized).has_value());
            };
            if (!signature || signature->variadic ||
                (signature->return_type != "void" && !scalar(signature->return_type)) ||
                signature->params.size() > int_arg_regs(abi).size()) return;
            for (const auto& param : signature->params) if (!scalar(param.type)) return;
            call_arities[inst.target1] = signature->params.size();
            if (signature->return_type == "void") void_calls.insert(inst.target1);
        }
    }
    const bool with_calls = !call_arities.empty();
    std::set<SsaKey> live;
    std::vector<IrValue> call_arguments;
    {
        live = structured_return_values;
        const auto root = [&](const IrValue& value) { if (auto key = ssa_key(value)) live.insert(*key); };
        for (std::size_t bi = 0; bi < fn->blocks.size(); ++bi) {
            std::vector<IrValue> args;
            const auto& block = fn->blocks[bi];
            for (std::size_t ii = 0; ii < block.insts.size(); ++ii) {
                const auto& inst = block.insts[ii];
                if (is_call_arg_barrier(inst)) {
                    if (inst.name == "call.args.1") args.clear();
                    if (inst.name.starts_with("call.args."))
                        for (u8 i = 0; i < inst.src_count; ++i) args.push_back(inst.srcs[i]);
                    continue;
                }
                if (inst.op == IrOp::Call) {
                    const auto count = call_arities.at(inst.target1);
                    if (count > args.size()) return;
                    for (std::size_t i = 0; i < count; ++i) { root(args[i]); call_arguments.push_back(args[i]); }
                    args.clear();
                    continue;
                }
                if (hidden.contains({bi, ii}) || inst.op == IrOp::Phi || inst.op == IrOp::Return) continue;
                for (u8 i = 0; i < inst.src_count; ++i) root(inst.srcs[i]);
            }
        }
        std::vector<SsaKey> pending(live.begin(), live.end());
        while (!pending.empty()) {
            const auto key = pending.back(); pending.pop_back();
            const auto* definition = ssa_uses.definition(key);
            if (!definition) continue;
            if (with_calls && (is_float_type(definition->dst.type) || type_bits(definition->dst.type) > 64)) return;
            if (with_calls && definition->op == IrOp::Clobber) {
                const auto position = call_position_for_return_key(key);
                if (!position || definition->dst.kind != IrValueKind::Reg ||
                    canonical_reg(definition->dst.reg) != int_return_reg(abi) ||
                    void_calls.contains(fn->blocks[position->first].insts[position->second].target1) ||
                    call_inst_returns_void(fn->blocks[position->first].insts[position->second])) return;
            }
            const auto use = [&](const IrValue& value) {
                if (auto source = ssa_key(value); source && live.insert(*source).second) pending.push_back(*source);
            };
            for (u8 i = 0; i < definition->src_count; ++i) use(definition->srcs[i]);
            for (const auto& value : definition->phi_operands) use(value);
        }
    }
    for (const auto& block : fn->blocks) {
        if (block.insts.empty() ||
            (block.successors.size() > 1 && block.insts.back().op != IrOp::CondBranch))
            return;
        for (const auto& inst : block.insts) {
            if (inst.op == IrOp::BranchIndirect) return;
            if (inst.op == IrOp::Phi &&
                (is_float_type(inst.dst.type) ||
                 (type_bits(inst.dst.type) > 64 &&
                  (inst.dst.type != IrType::I128 || is_ppc_abi() || with_calls))) &&
                (!with_calls || (ssa_key(inst.dst) && live.contains(*ssa_key(inst.dst))))) return;
        }
    }
    if (!has_cyclic_phi(*fn)) return;
    explicit_phi_copies = true;
    scalar_join_copies = false;
    scoped_ssa_values.clear();
    merge_value_names.clear();
    merge_locals.clear();
    merge_edge_assignments.clear();
    for_update_positions.clear();

    std::map<SsaKey, std::pair<addr_t, const IrInst*>> definitions;
    std::set<std::string> used_names(self_arg_names.begin(), self_arg_names.end());
    const auto remember = [&](const IrValue& value, std::string_view prefix) {
        auto key = ssa_key(value);
        if (!key || scoped_ssa_values.contains(*key) ||
            ((with_calls || type_bits(value.type) > 64) && !live.contains(*key))) return;
        // Frame addresses already render as named local storage. Hoisting
        // their register definitions would expose the hidden RSP prologue.
        if (stack_offset(value)) return;
        if (traces_to_canary_load(value) || is_canary_condition(value)) return;
        std::size_t index = scoped_ssa_values.size();
        std::string name;
        do { name = std::format("{}_{}", prefix, index++); }
        while (!used_names.insert(name).second);
        scoped_ssa_values.emplace(*key, std::pair{value, std::move(name)});
        fold_return_expr.erase(*key);
    };
    for (const auto& block : fn->blocks) {
        for (const auto& inst : block.insts) {
            if (auto key = ssa_key(inst.dst); key) {
                definitions.emplace(*key, std::pair{block.start, &inst});
                if (inst.op == IrOp::Phi) remember(inst.dst, base_name_for(merge_role_for_phi(inst)));
            }
        }
    }
    for (const auto& block : fn->blocks) {
        for (const auto& inst : block.insts) {
            if (with_calls && is_call_arg_barrier(inst)) continue;
            const auto require_value = [&](const IrValue& value, bool force) {
                auto key = ssa_key(value);
                if (!key) return;
                auto definition = definitions.find(*key);
                if (definition == definitions.end()) return;
                if (force || definition->second.first != block.start)
                    remember(definition->second.second->dst, "ssa");
            };
            for (const IrValue& value : inst.phi_operands) require_value(value, true);
            for (u8 i = 0; i < inst.src_count; ++i)
                require_value(inst.srcs[i], inst.op == IrOp::CondBranch);
        }
    }
    for (const auto& value : call_arguments) if (def_of(value)) remember(value, "ssa");
    for (const auto& [key, item] : scoped_ssa_values) {
        const auto* definition = ssa_uses.definition(key);
        if (!definition || definition->op != IrOp::Clobber) continue;
        const auto position = call_position_for_return_key(key);
        if (!position) continue;
        fold_call_positions.erase(*position);
        inline_call_positions.erase(*position);
        fold_call_ssa_key.erase(*position);
        inline_call_ssa_key.erase(*position);
        bound_call_key[*position] = key;
        call_return_names[key] = item.second;
        merge_bound_calls.insert(*position); // declaration is now at function scope
    }
}

std::string Emitter::scoped_ssa_declarations() const {
    std::string out;
    for (const auto& [_, item] : scoped_ssa_values)
        out += std::format("  {} {};\n", c_type_name_for(item.first), item.second);
    return out;
}

void Emitter::emit_phi_copies(const IrBlock& block, std::string_view ind,
                             std::string& out) const {
    if (block.insts.empty()) return;
    const IrInst& terminator = block.insts.back();
    for (addr_t target : block.successors) {
        auto found = fn->block_at.find(target);
        if (found == fn->block_at.end()) continue;
        std::vector<std::pair<IrValue, IrValue>> copies;
        for (const auto& phi : fn->blocks[found->second].insts) {
            if (phi.op != IrOp::Phi || !scoped_ssa_name(phi.dst)) continue;
            for (std::size_t i = 0; i < phi.phi_preds.size(); ++i) {
                if (phi.phi_preds[i] == block.start && i < phi.phi_operands.size() &&
                    !same_ssa_value(phi.dst, phi.phi_operands[i]))
                    copies.emplace_back(phi.dst, phi.phi_operands[i]);
            }
        }
        if (copies.empty()) continue;
        std::vector<std::string> values;
        for (const auto& [destination, source] : copies) {
            std::string value = expr(source);
            if (options.c_source && !is_float_type(destination.type) &&
                type_bits(destination.type) <= 64) {
                value = std::format("({})(uintptr_t)({})", c_type_name_for(destination), value);
            }
            values.push_back(std::move(value));
        }
        std::set<std::string> reserved(self_arg_names.begin(), self_arg_names.end());
        bool independent = true;
        for (const auto& [destination, source] : copies) {
            (void)source;
            const auto& name = *scoped_ssa_name(destination);
            for (const auto& value : values)
                independent &= !text_contains_identifier_in_code(value, name);
        }
        if (independent || copies.size() == 1) {
            std::string inner(ind);
            if (terminator.op == IrOp::CondBranch) {
                const auto condition = render_condition(terminator.srcs[0], target != terminator.target1);
                out += std::format("{}if ({}) {{\n", ind, condition);
                inner += "  ";
            }
            for (std::size_t i = 0; i < copies.size(); ++i)
                out += std::format("{}{} = {};\n", inner, *scoped_ssa_name(copies[i].first), values[i]);
            if (terminator.op == IrOp::CondBranch) out += std::format("{}}}\n", ind);
            continue;
        }
        for (const auto& [_, value] : scoped_ssa_values) reserved.insert(value.second);
        std::vector<std::string> scratch;
        std::size_t number = 0;
        for (std::size_t i = 0; i < copies.size(); ++i) {
            for (;;) {
                std::string name = std::format("next_phi_{}", number++);
                bool conflict = reserved.contains(name);
                for (const auto& value : values)
                    conflict |= text_contains_identifier_in_code(value, name);
                if (conflict) continue;
                reserved.insert(name);
                scratch.push_back(std::move(name));
                break;
            }
        }
        if (terminator.op == IrOp::CondBranch) {
            const std::string condition = render_condition(terminator.srcs[0],
                                                           target != terminator.target1);
            out += std::format("{}if ({}) {{\n", ind, condition);
        } else {
            out += std::format("{}{{\n", ind);
        }
        const std::string inner = std::string(ind) + "  ";
        for (std::size_t i = 0; i < copies.size(); ++i) {
            out += std::format("{}{} {} = {};\n", inner,
                c_type_name_for(copies[i].first), scratch[i], values[i]);
        }
        for (std::size_t i = 0; i < copies.size(); ++i) {
            out += std::format("{}{} = {};\n", inner,
                *scoped_ssa_name(copies[i].first), scratch[i]);
        }
        out += std::format("{}}}\n", ind);
    }
}

}  // namespace spelunk::emit

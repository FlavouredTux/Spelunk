// Explicit SSA destruction for scalar x86 loops. Copies belong to edges,
// and every right-hand side is evaluated before any phi destination changes.
#include "emitter_internal.hpp"
#include "emitter_text.hpp"

#include <format>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace ember::emit {

const std::string* Emitter::scoped_ssa_name(const IrValue& value) const {
    auto key = ssa_key(value);
    if (!key) return nullptr;
    auto found = scoped_ssa_values.find(*key);
    return found == scoped_ssa_values.end() ? nullptr : &found->second.second;
}

void Emitter::prepare_phi_copies() {
    if (!fn || (abi != Abi::SysVAmd64 && abi != Abi::Win64)) return;
    // Call-result binding and aggregate return recovery use their own locals.
    // Keep that path until it can participate in explicit SSA destruction.
    for (const auto& block : fn->blocks) {
        if (block.insts.empty() ||
            (block.successors.size() > 1 && block.insts.back().op != IrOp::CondBranch))
            return;
        for (const auto& inst : block.insts) {
            if (inst.op == IrOp::BranchIndirect) return;
            if (inst.op == IrOp::Call || inst.op == IrOp::CallIndirect) return;
            if (inst.op == IrOp::Phi &&
                (is_float_type(inst.dst.type) || type_bits(inst.dst.type) > 64)) return;
        }
    }
    bool cyclic_phi = false;
    for (const auto& block : fn->blocks) {
        bool has_phi = false;
        for (const auto& inst : block.insts) has_phi |= inst.op == IrOp::Phi;
        if (!has_phi) continue;
        std::vector<addr_t> pending = block.successors;
        std::set<addr_t> seen;
        while (!pending.empty() && !cyclic_phi) {
            const addr_t address = pending.back();
            pending.pop_back();
            if (address == block.start) { cyclic_phi = true; break; }
            if (!seen.insert(address).second) continue;
            auto next = fn->block_at.find(address);
            if (next == fn->block_at.end()) continue;
            const auto& successors = fn->blocks[next->second].successors;
            pending.insert(pending.end(), successors.begin(), successors.end());
        }
        if (cyclic_phi) break;
    }
    if (!cyclic_phi) return;
    explicit_phi_copies = true;
    merge_value_names.clear();
    merge_locals.clear();
    merge_edge_assignments.clear();
    for_update_positions.clear();

    std::map<SsaKey, std::pair<addr_t, const IrInst*>> definitions;
    std::set<std::string> used_names(self_arg_names.begin(), self_arg_names.end());
    const auto remember = [&](const IrValue& value, std::string_view prefix) {
        auto key = ssa_key(value);
        if (!key || scoped_ssa_values.contains(*key)) return;
        // Frame addresses already render as named local storage. Hoisting
        // their register definitions would expose the hidden RSP prologue.
        if (stack_offset(value)) return;
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
                if (inst.op == IrOp::Phi) remember(inst.dst, "phi");
            }
        }
    }
    for (const auto& block : fn->blocks) {
        for (const auto& inst : block.insts) {
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
        for (const auto& [_, source] : copies) values.push_back(expr(source));
        std::set<std::string> reserved(self_arg_names.begin(), self_arg_names.end());
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

}  // namespace ember::emit

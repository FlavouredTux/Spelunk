// Inlining decisions, materialization and immediate formatting.
#include <algorithm>
#include <bit>
#include <cctype>
#include <cmath>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <format>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include <spelunk/common/types.hpp>
#include <spelunk/disasm/register.hpp>
#include <spelunk/ir/abi.hpp>
#include <spelunk/ir/ir.hpp>
#include <spelunk/ir/ssa.hpp>

#include "emitter_internal.hpp"
#include "emitter_text.hpp"

namespace spelunk::emit {

const IrInst* Emitter::def_of(const IrValue& v) const {
    auto k = ssa_key(v);
    if (!k) return nullptr;
    return ssa_uses.definition(*k);
}

u32 Emitter::use_count(const IrValue& v) const {
    auto k = ssa_key(v);
    if (!k) return 0;
    return ssa_uses.semantic_use_count(*k);
}

u32 Emitter::visible_use_count(const IrValue& v) const {
    auto key = ssa_key(v);
    if (!key) return 0u;
    return ssa_uses.visible_use_count(*key);
}

bool Emitter::inlinable_op(IrOp op) noexcept {
    switch (op) {
        case IrOp::Load:
        case IrOp::Assign:
        case IrOp::Add: case IrOp::Sub: case IrOp::Mul:
        case IrOp::Div: case IrOp::Mod:
        case IrOp::SDiv: case IrOp::SMod:
        case IrOp::And: case IrOp::Or:  case IrOp::Xor:
        case IrOp::Neg: case IrOp::Not: case IrOp::Clz:
        case IrOp::Shl: case IrOp::Lshr: case IrOp::Ashr:
        case IrOp::Select:
        case IrOp::CmpEq: case IrOp::CmpNe:
        case IrOp::CmpSlt: case IrOp::CmpSle:
        case IrOp::CmpSgt: case IrOp::CmpSge:
        case IrOp::CmpUlt: case IrOp::CmpUle:
        case IrOp::CmpUgt: case IrOp::CmpUge:
        case IrOp::ZExt:  case IrOp::SExt:  case IrOp::Trunc:
        case IrOp::FpToInt:
        case IrOp::AddCarry:    case IrOp::SubBorrow:
        case IrOp::AddOverflow: case IrOp::SubOverflow:
            return true;
        default:
            return false;
    }
}

bool Emitter::every_use_is_flag_assign(const IrValue& v) const {
    if (v.kind != IrValueKind::Temp) return false;
    auto k = ssa_key(v);
    if (!k) return false;
    return ssa_uses.every_visible_use_is_flag_assign(*k);
}

bool Emitter::is_flag_feeder_temp(const IrValue& v) const {
    if (v.kind != IrValueKind::Temp) return false;
    auto k = ssa_key(v);
    if (!k) return false;
    const auto users = ssa_uses.visible_user_positions(*k);
    if (users.empty()) return false;
    for (const auto& [bi, ii] : users) {
        const auto& inst = fn->blocks[bi].insts[ii];
        if (inst.dst.kind != IrValueKind::Temp) return false;
        if (!every_use_is_flag_assign(inst.dst)) return false;
    }
    return true;
}

bool Emitter::should_inline(const IrValue& v) const {
    if (scoped_ssa_name(v)) return false;
    if (v.kind != IrValueKind::Temp) return false;
    const auto* d = def_of(v);
    if (!d) return false;
    if (!inlinable_op(d->op)) return false;
    if (d->op == IrOp::Load) {
        if (auto key = ssa_key(v); key && memory_snapshot_loads.contains(*key)) {
            return false;
        }
    }
    // format_stmt binds such a value at its definition; flag feeders and
    // low-byte carriers never bind there, so they stay inline.
    if ((d->op == IrOp::Load ||
         (!is_flag_feeder_temp(v) && !match_low_byte_setcc_merge(v))) &&
        inline_crosses_merge_assignment(v)) {
        return false;
    }
    if (visible_use_count(v) > 1) {
        // Flag-feeder temps are an exception: their multiple uses are
        // all flag-set computations that themselves render inline.
        // Duplicating the underlying expression at each flag-set site
        // is a small textual cost for a much cleaner output.
        if (is_flag_feeder_temp(v)) return true;
        // A Load whose address is a stack slot just renders as the
        // slot's `local_X` name - duplicating that string at each use
        // is no worse than the original `tN = local_X; ... use tN ...`
        // pair, and lets compound flag-set patterns (sub.overflow +
        // sub feeding the same slt rendering) collapse cleanly without
        // leaving a dangling `tN = local_X;` line. Skip if the slot
        // has an unknown segment (fs:[…] etc.) - those carry side
        // effects we shouldn't replay.
        if (d->op == IrOp::Load && d->src_count >= 1 &&
            d->segment == Reg::None && stack_offset(d->srcs[0]).has_value()) {
            return true;
        }
        return false;
    }
    return true;
}

const std::vector<bool>&
Emitter::blocks_reachable_avoiding(std::size_t from, std::size_t avoid) const {
    if (reachable_memo_fn != fn) {
        reachable_from_memo.clear();
        reachable_memo_fn = fn;
    }
    auto [it, inserted] = reachable_from_memo.try_emplace(std::pair{from, avoid});
    if (!inserted) return it->second;
    std::vector<bool>& reached = it->second;
    reached.assign(fn->blocks.size(), false);
    std::vector<std::size_t> pending{from};
    while (!pending.empty()) {
        const std::size_t current = pending.back();
        pending.pop_back();
        for (const addr_t successor : fn->blocks[current].successors) {
            const auto found = fn->block_at.find(successor);
            if (found == fn->block_at.end() || reached[found->second]) continue;
            reached[found->second] = true;
            if (found->second != avoid) pending.push_back(found->second);
        }
    }
    return reached;
}

bool Emitter::edge_write_interferes_with_web(std::size_t target_block, const SsaMergeLocal& web,
                                             const SsaKey& phi,
                                             const std::optional<SsaKey>& value) const {
    constexpr std::size_t kBlockEnd = static_cast<std::size_t>(-1);
    for (const SsaKey& member : web.keys) {
        if (member == phi || (value && member == *value)) continue;
        const auto member_position = ssa_uses.definition_position(member);
        if (!member_position) continue;
        const auto [member_block, member_index] = *member_position;
        // The write lands on entry to the target block; a read is stale when
        // it can follow the write without the member being defined again.
        const auto reads_stale = [&](std::size_t block, std::size_t index) {
            if (member_block == target_block) return block == target_block && index < member_index;
            if (block == target_block) return true;
            if (block == member_block && index > member_index) return false;
            return static_cast<bool>(blocks_reachable_avoiding(target_block, member_block)[block]);
        };
        for (const auto& [user_block, user_index] : ssa_uses.syntactic_user_positions(member)) {
            const IrInst& user = fn->blocks[user_block].insts[user_index];
            if (user.op == IrOp::Phi) {
                for (std::size_t i = 0; i < user.phi_operands.size() && i < user.phi_preds.size(); ++i) {
                    const auto operand = ssa_key(user.phi_operands[i]);
                    if (!operand || *operand != member) continue;
                    const auto pred = fn->block_at.find(user.phi_preds[i]);
                    if (pred == fn->block_at.end() || reads_stale(pred->second, kBlockEnd)) return true;
                }
                continue;
            }
            if (reads_stale(user_block, user_index)) return true;
        }
    }
    return false;
}

bool Emitter::step_interferes_with_web(const IrInst& step, const SsaMergeLocal& web,
                                       const SsaKey& phi) const {
    const auto step_key = ssa_key(step.dst);
    const auto step_position = step_key ? ssa_uses.definition_position(*step_key) : std::nullopt;
    if (!step_position) return true;
    const auto [step_block, step_index] = *step_position;
    constexpr std::size_t kBlockEnd = static_cast<std::size_t>(-1);
    // The Phi itself counts: a read of it after the step (the loop test
    // on the old counter after `i--`) would see the updated local.
    std::vector<SsaKey> members = web.keys;
    if (std::ranges::find(members, phi) == members.end()) members.push_back(phi);
    for (const SsaKey& member : members) {
        if (member == *step_key) continue;
        const auto member_position = ssa_uses.definition_position(member);
        if (!member_position) continue;
        const auto [member_block, member_index] = *member_position;
        // Reaching the member's own block runs its definition before any
        // later read there.
        const auto reads_stale = [&](std::size_t block, std::size_t index) {
            if (block == step_block && step_index < index &&
                !(block == member_block && step_index < member_index && member_index < index)) {
                return true;
            }
            if (block == member_block && index > member_index) return false;
            return static_cast<bool>(blocks_reachable_avoiding(step_block, member_block)[block]);
        };
        for (const auto& [user_block, user_index] : ssa_uses.syntactic_user_positions(member)) {
            // A Phi reads its operand at the end of that operand's edge.
            const IrInst& user = fn->blocks[user_block].insts[user_index];
            if (user.op == IrOp::Phi) {
                for (std::size_t i = 0; i < user.phi_operands.size() && i < user.phi_preds.size(); ++i) {
                    const auto operand = ssa_key(user.phi_operands[i]);
                    if (!operand || *operand != member) continue;
                    const auto pred = fn->block_at.find(user.phi_preds[i]);
                    if (pred == fn->block_at.end()) return true;
                    if (reads_stale(pred->second, kBlockEnd)) return true;
                }
                continue;
            }
            if (reads_stale(user_block, user_index)) return true;
        }
    }
    return false;
}

void Emitter::collect_merge_names_read(const IrValue& value, int depth,
                                       std::set<std::string>& names,
                                       std::set<SsaKey>& seen) const {
    // Bound values read their binding instead, so the walk stops at them.
    const auto value_key = ssa_key(value);
    if (!value_key || !seen.insert(*value_key).second) return;
    if (auto named = merge_value_names.find(*value_key); named != merge_value_names.end()) {
        names.insert(named->second);
        return;
    }
    if (depth > 8) return;
    const IrInst* d = ssa_uses.definition(*value_key);
    if (!d || d->op == IrOp::Call || d->op == IrOp::CallIndirect ||
        d->op == IrOp::Clobber) return;
    if (d->op == IrOp::Phi) {
        for (const IrValue& operand : d->phi_operands) {
            collect_merge_names_read(operand, depth + 1, names, seen);
        }
        return;
    }
    if (value.kind == IrValueKind::Temp && visible_use_count(value) > 1 &&
        !is_flag_feeder_temp(value)) return;
    for (u8 i = 0; i < d->src_count && i < d->srcs.size(); ++i) {
        collect_merge_names_read(d->srcs[i], depth + 1, names, seen);
    }
}

bool Emitter::inline_crosses_merge_assignment(const IrValue& v) const {
    if (!fn || explicit_phi_copies || merge_locals.empty()) return false;
    const auto key = ssa_key(v);
    if (!key || merge_value_names.contains(*key)) return false;
    if (crossing_memo_fn != fn || crossing_memo_names != merge_value_names.size()) {
        crossing_memo.clear();
        crossing_memo_fn = fn;
        crossing_memo_names = merge_value_names.size();
    }
    if (auto found = crossing_memo.find(*key); found != crossing_memo.end()) {
        return found->second;
    }
    const auto remember = [&](bool crosses) {
        crossing_memo.emplace(*key, crosses);
        return crosses;
    };
    const auto def_position = ssa_uses.definition_position(*key);
    const auto users = ssa_uses.visible_user_positions(*key);
    const IrInst* definition = ssa_uses.definition(*key);
    if (!def_position || !definition || users.size() != 1) return remember(false);

    std::set<std::string> names;
    std::set<SsaKey> seen{*key};
    for (u8 i = 0; i < definition->src_count && i < definition->srcs.size(); ++i) {
        collect_merge_names_read(definition->srcs[i], 0, names, seen);
    }
    if (names.empty()) return remember(false);

    const auto [def_block, def_index] = *def_position;
    const auto [use_block, use_index] = users[0];
    // Can an assignment at (block, index) run after the definition and
    // before the use? A path back through the defining block recomputes
    // the value, so only paths that avoid it count.
    constexpr std::size_t kBlockEnd = static_cast<std::size_t>(-1);
    const auto between = [&](std::size_t block, std::size_t index) {
        if (def_block == use_block) {
            return block == def_block && def_index < index && index < use_index;
        }
        if (block == def_block) return index > def_index;
        if (block == use_block) {
            return index < use_index ||
                blocks_reachable_avoiding(use_block, def_block)[use_block];
        }
        return blocks_reachable_avoiding(def_block, def_block)[block] &&
            blocks_reachable_avoiding(block, def_block)[use_block];
    };
    for (const std::string& name : names) {
        const auto local = merge_locals.find(name);
        if (local == merge_locals.end()) continue;
        for (const SsaKey& member : local->second.keys) {
            const IrInst* member_def = ssa_uses.definition(member);
            const auto position = ssa_uses.definition_position(member);
            if (!member_def || !position || member_def->op == IrOp::Phi) continue;
            if (between(position->first, position->second)) return remember(true);
        }
        for (const auto& [pred, assignments] : merge_edge_assignments) {
            if (std::ranges::none_of(assignments, [&](const auto& assignment) {
                    return assignment.first == name;
                })) continue;
            const auto block = fn->block_at.find(pred);
            if (block != fn->block_at.end() && between(block->second, kBlockEnd)) {
                return remember(true);
            }
        }
        for (const auto& [pred, assignments] : merge_guarded_edge_assignments) {
            if (std::ranges::none_of(assignments, [&](const auto& assignment) {
                    return assignment.name == name;
                })) continue;
            const auto block = fn->block_at.find(pred);
            if (block != fn->block_at.end() && between(block->second, kBlockEnd)) {
                return remember(true);
            }
        }
    }
    return remember(false);
}

std::optional<std::string> Emitter::fallback_ssa_name(const IrValue& v) const {
    if (auto k = ssa_key(v); k) {
        if (auto it = merge_value_names.find(*k); it != merge_value_names.end()) {
            return it->second;
        }
    }
    switch (v.kind) {
        case IrValueKind::Reg:
            if (v.version == 0) return std::nullopt;
            return std::format("{}_{}", display_reg_name(v.reg), v.version);
        case IrValueKind::Temp:
            return std::format("t{}", v.temp);
        default:
            return std::nullopt;
    }
}

void Emitter::mark_binding_emitted(const IrValue& v) const {
    if (auto k = ssa_key(v); k) emitted_bindings.insert(*k);
}

bool Emitter::renders_raw_arch_reg_name(const IrValue& v) const {
    if (v.kind != IrValueKind::Reg || v.version == 0) return false;
    const std::string raw = std::format("{}_{}", display_reg_name(v.reg), v.version);
    return expr(v, 1, 0) == raw;
}

std::string_view Emitter::display_reg_name(Reg r) const noexcept {
    if (is_x86_32_abi(abi) && r >= Reg::Rax && r <= Reg::Rdi) {
        return reg_name(static_cast<Reg>(static_cast<unsigned>(Reg::Eax) +
                                         (static_cast<unsigned>(r) - static_cast<unsigned>(Reg::Rax))));
    }
    return reg_name(r);
}

std::optional<std::string>
Emitter::merge_assignment_name_for(const IrInst& inst) const {
    if (inst.op == IrOp::Phi || inst.op == IrOp::Clobber ||
        inst.op == IrOp::Call || inst.op == IrOp::CallIndirect ||
        inst.op == IrOp::Store || is_terminator(inst.op)) {
        return std::nullopt;
    }
    auto k = ssa_key(inst.dst);
    if (!k) return std::nullopt;
    auto it = merge_value_names.find(*k);
    if (it == merge_value_names.end()) return std::nullopt;
    auto local_it = merge_locals.find(it->second);
    if (local_it == merge_locals.end()) return std::nullopt;
    // An in-place update feeding this same merge web is observable on the
    // next loop iteration even when its only visible reader is a Phi.
    for (u8 i = 0; i < inst.src_count; ++i) {
        if (auto source = ssa_key(inst.srcs[i]); source) {
            auto named = merge_value_names.find(*source);
            if (named != merge_value_names.end() && named->second == it->second &&
                inst.op != IrOp::Assign) return it->second;
        }
    }
    bool has_non_return_reader = false;
    for (const auto& local_key : local_it->second.keys) {
        for (const auto& [bi, ii] :
             ssa_uses.syntactic_user_positions(local_key)) {
            if (!fn || bi >= fn->blocks.size()) continue;
            const auto& bb = fn->blocks[bi];
            if (ii >= bb.insts.size()) continue;
            if (!hidden.contains({bi, ii}) &&
                bb.insts[ii].op != IrOp::Return && bb.insts[ii].op != IrOp::Phi) {
                has_non_return_reader = true;
                break;
            }
        }
        if (has_non_return_reader) break;
    }
    if (!has_non_return_reader) return std::nullopt;
    return it->second;
}

std::string
Emitter::format_merge_assignment(const IrInst& inst, std::string_view name) const {
    if (inst.src_count >= 2) {
        const bool commutative =
            inst.op == IrOp::Add || inst.op == IrOp::Mul ||
            inst.op == IrOp::And || inst.op == IrOp::Or ||
            inst.op == IrOp::Xor;
        std::string_view op_text;
        switch (inst.op) {
            case IrOp::Add:  op_text = "+"; break;
            case IrOp::Sub:  op_text = "-"; break;
            case IrOp::Mul:  op_text = "*"; break;
            case IrOp::And:  op_text = "&"; break;
            case IrOp::Or:   op_text = "|"; break;
            case IrOp::Xor:  op_text = "^"; break;
            case IrOp::Shl:  op_text = "<<"; break;
            case IrOp::Lshr: op_text = ">>"; break;
            case IrOp::Ashr: op_text = ">>"; break;
            default: break;
        }
        auto is_same_merge_local = [&](const IrValue& v) {
            auto k = ssa_key(v);
            if (!k) return false;
            auto it = merge_value_names.find(*k);
            return it != merge_value_names.end() && it->second == name;
        };
        const IrValue* delta = nullptr;
        if (!op_text.empty() && is_same_merge_local(inst.srcs[0])) {
            delta = &inst.srcs[1];
        } else if (!op_text.empty() && commutative &&
                   is_same_merge_local(inst.srcs[1])) {
            delta = &inst.srcs[0];
        }
        if (delta) {
            const auto merge_local = merge_locals.find(std::string(name));
            if ((inst.op == IrOp::Add || inst.op == IrOp::Sub) &&
                delta->kind == IrValueKind::Imm &&
                merge_local != merge_locals.end() &&
                pointer_step_matches(merge_local->second.type_value,
                                     std::abs(delta->imm))) {
                const bool increment =
                    (inst.op == IrOp::Add && delta->imm > 0) ||
                    (inst.op == IrOp::Sub && delta->imm < 0);
                return std::format("{}{};", name,
                                   increment ? "++" : "--");
            }
            // On a pointer local `++`/`+=` scale by the pointee, so a step
            // that is not a whole element spells out the byte arithmetic.
            const bool pointer_local = merge_local != merge_locals.end() &&
                c_type_name_for(merge_local->second.type_value).ends_with('*');
            if (!pointer_local && (inst.op == IrOp::Add || inst.op == IrOp::Sub) &&
                delta->kind == IrValueKind::Imm && delta->imm == 1 &&
                !is_float_type(inst.dst.type)) {
                const char* sym = (inst.op == IrOp::Add) ? "++" : "--";
                return std::format("{}{};", name, sym);
            }
            if (!pointer_local) {
                return std::format("{} {}= {};", name, op_text, expr(*delta));
            }
        }
    }

    std::string rhs;
    if (inst.op == IrOp::Assign) {
        if (inst.src_count < 1) return "";
        rhs = expr(inst.srcs[0]);
    } else if (inst.op == IrOp::Load) {
        if (inst.src_count < 1) return "";
        rhs = format_load_rhs(inst);
    } else if (inst.op == IrOp::Intrinsic) {
        rhs = render_intrinsic_call(inst);
    } else if (inlinable_op(inst.op)) {
        rhs = expand(inst, 0);
    }
    if (rhs.empty()) return "";
    if (options.c_source && scoped_ssa_name(inst.dst) &&
        !is_float_type(inst.dst.type) && type_bits(inst.dst.type) <= 64)
        rhs = std::format("({})(uintptr_t)({})", c_type_name_for(inst.dst), rhs);
    const auto merge_local = merge_locals.find(std::string(name));
    if (merge_local != merge_locals.end()) {
        const std::string type = c_type_name_for(merge_local->second.type_value);
        if (type.ends_with('*') && rhs.starts_with('&')) {
            rhs = std::format("({}){}", type, rhs);
        }
    }
    return std::format("{} = {};", name, rhs);
}

void Emitter::emit_materializations_for_value(const IrValue& v,
                                              int depth,
                                              std::string& out,
                                              std::string_view ind) const {
    if (scoped_ssa_name(v)) return;
    if (depth > 12) return;
    if (v.kind != IrValueKind::Reg && v.kind != IrValueKind::Temp) return;
    auto k = ssa_key(v);
    if (!k || emitted_bindings.contains(*k)) return;
    const IrInst* d = def_of(v);
    if (!d) return;
    if (renders_stack_chk_guard_value(v)) {
        emitted_bindings.insert(*k);
        return;
    }

    // If the regular expression renderer can produce anything better
    // than the raw SSA fallback name, use that at the use site instead
    // of inventing a redundant binding.
    const auto fallback = fallback_ssa_name(v);
    if (!fallback) return;
    if (expr(v, depth + 1, 0) != *fallback) {
        return;
    }

    // Phi and clobber defs need path/call-site context. Calls should be
    // handled by call_return_names; divergent phis are better left as a
    // stable SSA name than rendered as a misleading unconditional assign.
    if (d->op == IrOp::Phi || d->op == IrOp::Clobber) return;
    if (d->op != IrOp::Assign && d->op != IrOp::Load &&
        d->op != IrOp::Intrinsic && !inlinable_op(d->op)) {
        return;
    }

    for (u8 i = 0; i < d->src_count && i < d->srcs.size(); ++i) {
        emit_materializations_for_value(d->srcs[i], depth + 1, out, ind);
    }

    std::string rhs;
    if (d->op == IrOp::Intrinsic) {
        rhs = render_intrinsic_call(*d);
    } else if (d->op == IrOp::Load) {
        if (d->src_count < 1) return;
        rhs = format_load_rhs(*d);
    } else if (d->op == IrOp::Assign) {
        if (d->src_count < 1) return;
        rhs = expr(d->srcs[0]);
    } else {
        rhs = expand(*d, 0);
    }
    if (rhs.empty()) return;
    out += std::format("{}{} {} = {};\n",
                       ind, c_type_name_for(v), *fallback, rhs);
    emitted_bindings.insert(*k);
}

void Emitter::emit_materializations_for_inst(const IrInst& inst,
                                             std::string& out,
                                             std::string_view ind) const {
    if (inst.op == IrOp::Phi || is_call_arg_barrier(inst)) return;
    for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i) {
        emit_materializations_for_value(inst.srcs[i], 0, out, ind);
    }
}

void Emitter::emit_raw_temp_binding(u32 temp, std::string& out,
                                    std::string_view ind) const {
    const SsaKey key{u8{2}, temp, 0};
    if (emitted_bindings.contains(key)) return;
    const IrInst* d = ssa_uses.definition(key);
    if (!d) return;
    if (d->dst.kind != IrValueKind::Temp || d->dst.temp != temp) return;
    if (d->op == IrOp::Phi || d->op == IrOp::Clobber) return;
    if (d->op != IrOp::Assign && d->op != IrOp::Load &&
        d->op != IrOp::Intrinsic && !inlinable_op(d->op)) {
        return;
    }

    for (u8 i = 0; i < d->src_count && i < d->srcs.size(); ++i) {
        emit_materializations_for_value(d->srcs[i], 0, out, ind);
    }

    std::string rhs;
    if (d->op == IrOp::Intrinsic) {
        std::string args;
        for (u8 i = 0; i < d->src_count && i < d->srcs.size(); ++i) {
            if (i > 0) args += ", ";
            args += expr(d->srcs[i]);
        }
        rhs = std::format("{}({})", d->name, args);
    } else if (d->op == IrOp::Load) {
        if (d->src_count < 1) return;
        rhs = format_load_rhs(*d);
    } else if (d->op == IrOp::Assign) {
        if (d->src_count < 1) return;
        rhs = expr(d->srcs[0]);
    } else {
        rhs = expand(*d, 0);
    }
    if (rhs.empty()) return;
    out += std::format("{}{} t{} = {};\n",
                       ind, c_type_name_for(d->dst), temp, rhs);
    emitted_bindings.insert(key);
}

void Emitter::emit_materializations_for_raw_temps(std::string_view rendered,
                                                  std::string& out,
                                                  std::string_view ind) const {
    for (std::size_t i = 0; i + 1 < rendered.size(); ++i) {
        if (rendered[i] != 't' ||
            (i > 0 && c_ident_char(rendered[i - 1])) ||
            !std::isdigit(static_cast<unsigned char>(rendered[i + 1]))) {
            continue;
        }
        std::size_t j = i + 1;
        u32 temp = 0;
        while (j < rendered.size() &&
               std::isdigit(static_cast<unsigned char>(rendered[j]))) {
            temp = temp * 10u + static_cast<u32>(rendered[j] - '0');
            ++j;
        }
        if (j < rendered.size() && c_ident_char(rendered[j])) {
            i = j;
            continue;
        }
        emit_raw_temp_binding(temp, out, ind);
        i = j;
    }
}

void Emitter::emit_materializations_for_rendered_value(const IrValue& v,
                                                       std::string_view rendered,
                                                       std::string& out,
                                                       std::string_view ind) const {
    if (const auto fallback = fallback_ssa_name(v);
        fallback && text_contains_identifier(rendered, *fallback)) {
        emit_materializations_for_value(v, 0, out, ind);
    }
    emit_materializations_for_raw_temps(rendered, out, ind);
}

std::optional<i64>
Emitter::entry_stack_offset(const IrValue& v, int depth) const {
    if (depth > 1024) {
        entry_offset_capped = true;
        return std::nullopt;
    }
    const auto key = ssa_key(v);
    if (!key) return entry_stack_offset_uncached(v, depth);
    if (entry_offset_memo_fn != fn) {
        entry_offset_memo.clear();
        entry_offset_deferred.clear();
        entry_offset_memo_fn = fn;
    }
    if (auto memo = entry_offset_memo.find(*key); memo != entry_offset_memo.end()) {
        return memo->second;
    }
    const bool outer_assumed = entry_offset_assumed;
    const bool outer_capped = entry_offset_capped;
    entry_offset_assumed = false;
    entry_offset_capped = false;
    const auto result = entry_stack_offset_uncached(v, depth);
    if (!entry_offset_capped) {
        if (entry_offset_assumed) entry_offset_deferred.emplace_back(*key, result);
        else entry_offset_memo.emplace(*key, result);
    }
    entry_offset_assumed = entry_offset_assumed || outer_assumed;
    entry_offset_capped = entry_offset_capped || outer_capped;
    return result;
}

std::optional<i64>
Emitter::entry_stack_offset_uncached(const IrValue& v, int depth) const {
    if (v.kind == IrValueKind::Reg) {
        if (!is_stack_base_reg(v.reg)) {
            const IrInst* d = def_of(v);
            if (d && d->op == IrOp::Assign && d->src_count >= 1) {
                return entry_stack_offset(d->srcs[0], depth + 1);
            }
            return std::nullopt;
        }
        if (v.version == 0) return i64{0};
        const IrInst* d = def_of(v);
        if (d && d->op == IrOp::Phi) return entry_stack_offset_of_phi(v, *d, depth);
        if (!d || d->op != IrOp::Assign || d->src_count < 1) {
            return std::nullopt;
        }
        return entry_stack_offset(d->srcs[0], depth + 1);
    }
    if (v.kind != IrValueKind::Temp) return std::nullopt;
    const IrInst* d = def_of(v);
    if (!d) return std::nullopt;
    if (d->op == IrOp::Assign && d->src_count >= 1) {
        return entry_stack_offset(d->srcs[0], depth + 1);
    }
    if ((d->op == IrOp::Add || d->op == IrOp::Sub) &&
        d->src_count >= 2 && d->srcs[1].kind == IrValueKind::Imm) {
        auto base = entry_stack_offset(d->srcs[0], depth + 1);
        if (!base) return std::nullopt;
        return d->op == IrOp::Add
            ? *base + d->srcs[1].imm
            : *base - d->srcs[1].imm;
    }
    if (d->op == IrOp::Add && d->src_count >= 2 &&
        d->srcs[0].kind == IrValueKind::Imm) {
        auto base = entry_stack_offset(d->srcs[1], depth + 1);
        if (base) return *base + d->srcs[0].imm;
    }
    if (is_stack_realignment(*d)) {
        auto base = entry_stack_offset(d->srcs[0], depth + 1);
        if (base) return *base & d->srcs[1].imm;
    }
    return std::nullopt;
}

// `and esp, -N` realigning the frame. The entry alignment is unknown, so
// offsets through it assume an aligned entry pointer: consistent for every
// access made through the realigned pointer, which is all of them.
bool Emitter::is_stack_realignment(const IrInst& d) {
    if (d.op != IrOp::And || d.src_count < 2 ||
        d.srcs[1].kind != IrValueKind::Imm) {
        return false;
    }
    const i64 mask = d.srcs[1].imm;
    return mask < 0 && mask >= -4096 && std::has_single_bit(static_cast<u64>(-mask));
}

// A stack pointer merged from paths that agree on its offset, as after a
// branch that calls a callee-pop function. Loop phis see themselves through
// the back edge: assume the offset the other edges agree on, then check it.
std::optional<i64>
Emitter::entry_stack_offset_of_phi(const IrValue& v, const IrInst& phi, int depth) const {
    const auto key = ssa_key(v);
    if (!key) return std::nullopt;
    if (auto assumed = stack_phi_assumptions.find(*key);
        assumed != stack_phi_assumptions.end()) {
        entry_offset_assumed = true;
        return assumed->second;
    }
    const std::size_t deferred_mark = entry_offset_deferred.size();
    stack_phi_assumptions.emplace(*key, std::nullopt);
    std::optional<i64> agreed;
    std::vector<const IrValue*> deferred;
    bool consistent = true;
    for (const auto& operand : phi.phi_operands) {
        if (ssa_key(operand) == key) continue;
        const auto offset = entry_stack_offset(operand, depth + 1);
        if (!offset) {
            deferred.push_back(&operand);
            continue;
        }
        if (agreed && *agreed != *offset) consistent = false;
        agreed = offset;
    }
    if (agreed && consistent && !deferred.empty()) {
        // What the first pass derived from the unset assumption is stale.
        entry_offset_deferred.resize(deferred_mark);
        stack_phi_assumptions[*key] = agreed;
        for (const IrValue* operand : deferred) {
            if (entry_stack_offset(*operand, depth + 1) != agreed) consistent = false;
        }
    }
    stack_phi_assumptions.erase(*key);
    // Values derived under a refuted assumption are wrong; ones derived
    // under a confirmed one settle when no outer assumption remains.
    if (!consistent) {
        entry_offset_deferred.resize(deferred_mark);
    } else if (stack_phi_assumptions.empty()) {
        if (!entry_offset_capped) {
            for (auto& [deferred_key, offset] : entry_offset_deferred)
                entry_offset_memo.emplace(deferred_key, offset);
        }
        entry_offset_deferred.clear();
    }
    if (stack_phi_assumptions.empty()) entry_offset_assumed = false;
    return consistent ? agreed : std::nullopt;
}

std::optional<i64> Emitter::stack_offset(const IrValue& v, int depth) const {
    if (depth > 16) return std::nullopt;
    if (v.kind == IrValueKind::Reg) {
        if (is_stack_base_reg(v.reg)) {
            // Optimized code may use RBP as an induction variable. A merged
            // register value is not evidence of a fixed frame base - unless
            // it is the stack pointer and every path agrees on its offset,
            // as after branches that push and pop.
            if (const auto* definition = def_of(v); definition && definition->op == IrOp::Phi) {
                if (canonical_reg(v.reg) != Reg::Rsp) return std::nullopt;
                return entry_stack_offset(v);
            }
            return 0;
        }
        return std::nullopt;
    }
    if (v.kind != IrValueKind::Temp) return std::nullopt;
    const auto* d = def_of(v);
    if (!d) return std::nullopt;
    switch (d->op) {
        case IrOp::Assign:
            return d->src_count >= 1
                ? stack_offset(d->srcs[0], depth + 1)
                : std::nullopt;
        case IrOp::Add: {
            if (d->src_count < 2) return std::nullopt;
            auto base = stack_offset(d->srcs[0], depth + 1);
            if (base && d->srcs[1].kind == IrValueKind::Imm) {
                return *base + d->srcs[1].imm;
            }
            auto base2 = stack_offset(d->srcs[1], depth + 1);
            if (base2 && d->srcs[0].kind == IrValueKind::Imm) {
                return *base2 + d->srcs[0].imm;
            }
            return std::nullopt;
        }
        case IrOp::Sub: {
            if (d->src_count < 2) return std::nullopt;
            auto base = stack_offset(d->srcs[0], depth + 1);
            if (base && d->srcs[1].kind == IrValueKind::Imm) {
                return *base - d->srcs[1].imm;
            }
            return std::nullopt;
        }
        case IrOp::And: {
            if (!is_stack_realignment(*d)) return std::nullopt;
            auto base = stack_offset(d->srcs[0], depth + 1);
            if (base) return *base & d->srcs[1].imm;
            return std::nullopt;
        }
        default:
            return std::nullopt;
    }
}

std::string Emitter::stack_name(i64 off) {
    if (off < 0) {
        return std::format("local_{:x}", static_cast<u64>(-off));
    }
    if (off == 0) return "stack_top";
    return std::format("arg_{:x}", static_cast<u64>(off));
}

std::string Emitter::format_imm(const IrValue& v) const {
    return format_imm_impl(v, /*allow_string_literals=*/true);
}

std::string Emitter::format_numeric_imm(const IrValue& v) const {
    return format_imm_impl(v, /*allow_string_literals=*/false);
}

std::string Emitter::format_imm_impl(const IrValue& v,
                                     bool allow_string_literals) const {
    // Annotated constant? Lets users name a hash, magic value, or
    // sentinel without touching the binary. The original hex stays
    // in a trailing comment so the user can audit the substitution.
    // Skip for tiny values where the name would be misleading
    // (loop bounds, struct offsets etc. are not worth annotating).
    if (annotations && v.kind == IrValueKind::Imm &&
        v.imm >= 0 && static_cast<u64>(v.imm) >= 0x10) {
        const u64 uv = static_cast<u64>(v.imm);
        if (const std::string* nm = annotations->constant_name_for(uv); nm) {
            return std::format("{} /* {:#x} */", *nm, uv);
        }
    }
    // Float-typed immediates arrive as an i64 bit pattern; decode into
    // a decimal literal so `xmm0 = 0x40490fdb` becomes `3.141593f`.
    if (v.type == IrType::F32) {
        float f;
        const u32 bits = static_cast<u32>(static_cast<u64>(v.imm));
        std::memcpy(&f, &bits, sizeof(f));
        if (!std::isfinite(f)) {
            return std::format("((union {{ uint32_t bits; float value; }}){{ .bits = {:#x}u }}).value", bits);
        }
        std::string literal = std::format("{}", f);
        if (literal.find_first_of(".eE") == std::string::npos) literal += ".0";
        return literal + "f";
    }
    if (v.type == IrType::F64) {
        double d;
        const u64 bits = static_cast<u64>(v.imm);
        std::memcpy(&d, &bits, sizeof(d));
        if (!std::isfinite(d)) {
            return std::format("((union {{ uint64_t bits; double value; }}){{ .bits = {:#x}ULL }}).value", bits);
        }
        std::string literal = std::format("{}", d);
        if (literal.find_first_of(".eE") == std::string::npos) literal += ".0";
        return literal;
    }
    const addr_t address = normalized_address(v.imm);
    const bool plausible_address = binary &&
        ((v.imm > 0 && static_cast<u64>(v.imm) >= 0x100) ||
         (abi == Abi::Ppc32Sysv && v.type == IrType::I32 &&
          address >= 0x100));
    // Core Foundation string literal? `__DATA,__cfstring` holds 32-byte
    // `{isa, flags, data, length}` records for compile-time NSString/
    // CFString constants. Rendering as `@"..."` matches what the
    // source-level code actually wrote.
    if (allow_string_literals && plausible_address) {
        if (auto s = string_literals.try_cfstring_at(address); s) {
            return "@" + escape_string(*s);
        }
    }
    // If the immediate points into the binary and resolves to a NUL-terminated
    // printable string, render as a C string literal.
    if (allow_string_literals && plausible_address) {
        if (auto s = string_literals.try_c_string_at(address); s) {
            return escape_string(*s);
        }
    }
    if (allow_string_literals && plausible_address) {
        const addr_t a = address;
        if (auto it = objc_block_by_literal.find(a);
            it != objc_block_by_literal.end()) {
            std::string out = objc_block_literal_name(a);
            out += std::format(" /* invoke: {}", function_display_name(it->second->invoke));
            if (!it->second->signature.empty()) {
                out += std::format(", sig: {}", it->second->signature);
            }
            out += " */";
            return out;
        }
    }
    if (allow_string_literals && plausible_address) {
        if (auto n = named_address_for_imm(address); n) {
            return std::format("{} /* {:#x} */", *n,
                               static_cast<u64>(address));
        }
    }
    // Small single-digit ints read much better as decimal; larger values
    // are generally addresses, masks, or byte counts where hex carries
    // information.
    if (v.imm >= 0 && v.imm <= 9) return std::format("{}", v.imm);
    if (v.imm < 0 && v.imm >= -9) return std::format("{}", v.imm);
    // Sub-i64 values whose bit pattern is "clearly a small negative"
    // when interpreted in their declared type (e.g. an i32 holding
    // 0xFFFFFFFF that's actually -1) render as signed decimal. Limit
    // to small magnitudes so genuine bitmasks and addresses keep their
    // hex form; -1..-32 covers the common return-error sentinels and
    // signed-imm constants without false-positiving on masks.
    if (v.type != IrType::I64 && v.imm > 0) {
        const unsigned bits = type_bits(v.type);
        if (bits > 0 && bits < 64) {
            const u64 mask = (u64(1) << bits) - 1;
            const u64 sign_bit = u64(1) << (bits - 1);
            const u64 u = static_cast<u64>(v.imm) & mask;
            if (u & sign_bit) {
                const i64 as_signed = static_cast<i64>(u | ~mask);
                if (as_signed >= -32) {
                    return std::format("{}", as_signed);
                }
            }
        }
    }
    // i64 imms in the small-negative-as-i32 range come from `mov eax,
    // -1; ret`-style returns the lifter widened into rax - the high
    // 32 bits are zero, the low 32 are the signed value. Render those
    // as their signed form too. Same -32 threshold as above so genuine
    // 32-bit bitmasks (0xFFFFFFFE used as ~1, etc.) keep their hex.
    if (v.type == IrType::I64) {
        const u64 u = static_cast<u64>(v.imm);
        if ((u >> 32) == 0 && (u & 0x80000000u)) {
            const i64 as_signed =
                static_cast<i64>(u | 0xFFFFFFFF00000000ull);
            if (as_signed >= -32) {
                return std::format("{}", as_signed);
            }
        }
    }
    if (v.imm < 0) {
        const u64 abs_v = static_cast<u64>(0) - static_cast<u64>(v.imm);
        return std::format("-{:#x}", abs_v);
    }
    return std::format("{:#x}", static_cast<u64>(v.imm));
}

}  // namespace spelunk::emit

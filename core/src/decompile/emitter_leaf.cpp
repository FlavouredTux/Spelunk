// Leaf rendering of registers, phis and display names.

#include <algorithm>
#include <cstddef>
#include <format>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include <spelunk/analysis/demangle.hpp>
#include <spelunk/analysis/import_sigs.hpp>
#include <spelunk/binary/symbol.hpp>
#include <spelunk/common/annotations.hpp>
#include <spelunk/common/types.hpp>
#include <spelunk/disasm/register.hpp>
#include <spelunk/ir/ir.hpp>
#include <spelunk/ir/ssa.hpp>
#include <spelunk/ir/types.hpp>

#include "emitter_internal.hpp"
#include "emitter_text.hpp"
#include "emitter_tables.hpp"

namespace spelunk::emit {

std::optional<std::string>
Emitter::render_selection_phi(const IrInst& phi, int depth) const {
    if (!fn || phi.op != IrOp::Phi || phi.phi_operands.size() != 2 ||
        phi.phi_preds.size() != 2 || depth >= kMaxExprDepth) {
        return std::nullopt;
    }
    auto key = ssa_key(phi.dst);
    if (!key) return std::nullopt;
    const auto position = ssa_uses.definition_position(*key);
    if (!position || position->first >= fn->blocks.size()) {
        return std::nullopt;
    }
    const addr_t merge = fn->blocks[position->first].start;
    const auto operand = [&](const IrValue& value) {
        std::string rendered = expr(value, depth + 1, std::to_underlying(Prec::Cond));
        const auto* definition = def_of(value);
        const auto value_key = ssa_key(value);
        // Loads in a selection arm stay conditional when substituted into
        // the ternary. Phi-only uses need not leave an undeclared temp behind.
        if (value.kind == IrValueKind::Temp && definition &&
            definition->op == IrOp::Load && value_key &&
            !memory_snapshot_loads.contains(*value_key) &&
            rendered == std::format("t{}", value.temp)) {
            rendered = expand(*definition, depth + 1, std::to_underlying(Prec::Cond));
        }
        if (options.c_source && !is_float_type(phi.dst.type) && type_bits(phi.dst.type) <= 64) {
            rendered = std::format("({})(uintptr_t)({})", c_type_name_for(phi.dst), rendered);
        }
        return rendered;
    };
    for (std::size_t direct_i = 0; direct_i < 2; ++direct_i) {
        const addr_t direct_pred = phi.phi_preds[direct_i];
        const addr_t arm_pred = phi.phi_preds[1 - direct_i];
        const auto block_named = [&](addr_t start) -> const IrBlock* {
            const auto found = fn->block_at.find(start);
            return found != fn->block_at.end() ? &fn->blocks[found->second] : nullptr;
        };
        const IrBlock* condition_block = block_named(direct_pred);
        const IrBlock* arm_block = block_named(arm_pred);
        if (!condition_block || !arm_block || condition_block->insts.empty()) continue;
        const IrInst& branch = condition_block->insts.back();
        if (branch.op != IrOp::CondBranch || branch.src_count < 1) continue;
        const bool true_to_arm = branch.target1 == arm_pred && branch.target2 == merge;
        const bool false_to_arm = branch.target2 == arm_pred && branch.target1 == merge;
        if (!true_to_arm && !false_to_arm) continue;
        if (arm_block->successors.size() != 1 || arm_block->successors[0] != merge) continue;

        const std::string condition = expr(branch.srcs[0], depth + 1,
                                           std::to_underlying(Prec::Cond));
        const std::string direct = operand(phi.phi_operands[direct_i]);
        const std::string arm = operand(phi.phi_operands[1 - direct_i]);
        if (condition.empty() || direct.empty() || arm.empty()) continue;
        return true_to_arm
            ? std::format("({} ? {} : {})", condition, arm, direct)
            : std::format("({} ? {} : {})", condition, direct, arm);
    }

    // Full two-arm diamond:
    //
    //        condition
    //       /        (other arm)
    //      arm A   arm B
    //        \      /
    //          phi
    //
    // Both operands are real definitions, so the one-arm/direct-edge
    // matcher above cannot select either as the "direct" value. Recover
    // the shared predecessor and preserve the choice as a ternary.
    const auto block_at = [&](addr_t address) -> const IrBlock* {
        auto found = fn->block_at.find(address);
        return found != fn->block_at.end() ? &fn->blocks[found->second] : nullptr;
    };
    const IrBlock* first_arm = block_at(phi.phi_preds[0]);
    const IrBlock* second_arm = block_at(phi.phi_preds[1]);
    if (first_arm && second_arm && first_arm->successors.size() == 1 &&
        second_arm->successors.size() == 1 &&
        first_arm->successors[0] == merge && second_arm->successors[0] == merge) {
        for (addr_t predecessor : first_arm->predecessors) {
            if (std::ranges::find(second_arm->predecessors, predecessor) ==
                second_arm->predecessors.end()) {
                continue;
            }
            const IrBlock* condition_block = block_at(predecessor);
            if (!condition_block || condition_block->insts.empty()) continue;
            const IrInst& branch = condition_block->insts.back();
            if (branch.op != IrOp::CondBranch || branch.src_count < 1) continue;
            const bool first_is_true =
                branch.target1 == first_arm->start && branch.target2 == second_arm->start;
            const bool second_is_true =
                branch.target1 == second_arm->start && branch.target2 == first_arm->start;
            if (!first_is_true && !second_is_true) continue;
            const std::string condition = expr(
                branch.srcs[0], depth + 1, std::to_underlying(Prec::Cond));
            const std::string first = operand(phi.phi_operands[0]);
            const std::string second = operand(phi.phi_operands[1]);
            if (condition.empty() || first.empty() || second.empty()) continue;
            return first_is_true
                ? std::format("({} ? {} : {})", condition, first, second)
                : std::format("({} ? {} : {})", condition, second, first);
        }
    }
    return std::nullopt;
}

std::string Emitter::render_reg_leaf(Reg r, u32 version,
                                     int depth,
                                     int min_prec) const {
    Reg cur_reg = r;
    u32 cur_ver = version;
    for (int hop = 0; hop < 8; ++hop) {
        SsaKey k{u8{0}, static_cast<u32>(canonical_reg(cur_reg)), cur_ver};
        if (auto it = scoped_ssa_values.find(k); it != scoped_ssa_values.end()) return it->second.second;
        if (auto it = inline_call_expr.find(k); it != inline_call_expr.end()) {
            return it->second;
        }
        if (auto it = call_return_names.find(k); it != call_return_names.end()) {
            return it->second;
        }
        if (auto arg = preserved_call_arg_for_clobber(cur_reg, cur_ver);
            arg && depth < kMaxExprDepth) {
            // Keep the caller's expression-depth budget. Resetting it to
            // zero lets mutually preserved call lanes recurse forever in
            // large PPC functions.
            return expr(*arg, depth + 1);
        }
        if (cur_ver == 0) {
            if (auto n = arg_name_for_live_in(cur_reg)) return *n;
            break;
        }
        IrValue v{};
        v.kind = IrValueKind::Reg;
        v.reg = cur_reg;
        v.version = cur_ver;
        const IrInst* d = def_of(v);
        if (!d) break;
        if (d->op == IrOp::Assign && d->src_count >= 1) {
            const auto& src = d->srcs[0];
            if (src.kind == IrValueKind::Reg) {
                cur_reg = src.reg;
                cur_ver = src.version;
                continue;
            }
            if (depth < kMaxExprDepth) return expr(src, depth + 1, min_prec);
            break;
        }
        // Phi-merged reg: if every incoming operand renders to the
        // same expression (common for `rax = phi(rax_v1, t17)` where
        // t17 traces back to the same call's return), emit that.
        if (d->op == IrOp::Phi && depth < kMaxExprDepth && !d->phi_operands.empty()) {
            std::optional<u8> common_self_arg;
            bool all_self_arg_aliases = true;
            for (const auto& op : d->phi_operands) {
                auto opk = ssa_key(op);
                if (opk && *opk == k) continue;  // self-reference
                auto slot = trace_to_self_arg_slot(op, depth + 1);
                if (!slot) { all_self_arg_aliases = false; break; }
                if (!common_self_arg) common_self_arg = *slot;
                else if (*common_self_arg != *slot) {
                    all_self_arg_aliases = false;
                    break;
                }
            }
            if (all_self_arg_aliases && common_self_arg) {
                const std::size_t slot = *common_self_arg;
                if (slot < self_arg_names.size() && !self_arg_names[slot].empty()) {
                    return self_arg_names[slot];
                }
                return std::format("a{}", slot + 1);
            }

            std::optional<i64> common_slot;
            bool all_slot_aliases = true;
            for (const auto& op : d->phi_operands) {
                auto opk = ssa_key(op);
                if (opk && *opk == k) continue;  // self-reference
                auto off = single_write_slot_alias_for_value(op);
                if (!off) { all_slot_aliases = false; break; }
                if (!common_slot) common_slot = *off;
                else if (*common_slot != *off) {
                    all_slot_aliases = false;
                    break;
                }
            }
            if (all_slot_aliases && common_slot) return stack_name(*common_slot);

            std::optional<IrValue> common_root;
            bool all_same_root = true;
            for (const auto& op : d->phi_operands) {
                auto opk = ssa_key(op);
                if (opk && *opk == k) continue;  // self-reference
                auto root = alias_root_for_value(op);
                if (!root) { all_same_root = false; break; }
                if (!common_root) common_root = *root;
                else if (!same_value_key(*common_root, *root)) {
                    all_same_root = false;
                    break;
                }
            }
            if (all_same_root && common_root) return expr(*common_root, depth + 1);

            std::string unified;
            bool all_match = true;
            for (const auto& op : d->phi_operands) {
                auto opk = ssa_key(op);
                if (opk && *opk == k) continue;  // self-reference
                const std::string s = expr(op, depth + 1);
                if (s.empty()) { all_match = false; break; }
                if (unified.empty()) unified = s;
                else if (s != unified) { all_match = false; break; }
            }
            if (all_match && !unified.empty()) return unified;
            if (auto selected = render_selection_phi(*d, depth + 1); selected) {
                return *selected;
            }
        }
        break;
    }
    // Phi/merged value with divergent incoming edges or a non-inlinable
    // producer: render a stable name rather than a raw register so the
    // output never mentions architectural names like `rax`, `rdx`.
    if (version > 0) {
        SsaKey k{u8{0}, static_cast<u32>(canonical_reg(r)), version};
        if (auto it = merge_value_names.find(k); it != merge_value_names.end()) {
            return it->second;
        }
        return std::format("{}_{}", display_reg_name(r), version);
    }
    return std::string(display_reg_name(r));
}

std::string Emitter::function_display_name(addr_t target) const {
    if (annotations) {
        if (const std::string* n = annotations->name_for(target); n) return *n;
    }
    // Obj-C IMPs outrank the ELF / Mach-O symbol table - a class method
    // with `-[Foo bar:]` shape reads at the call site better than any
    // mangled function-pointer name.
    if (auto it = objc_by_imp.find(target); it != objc_by_imp.end()) {
        return std::format("{}[{} {}]",
                           it->second->is_class ? '+' : '-',
                           it->second->cls,
                           it->second->selector);
    }
    if (auto it = objc_block_by_invoke.find(target);
        it != objc_block_by_invoke.end()) {
        return objc_block_invoke_name(target);
    }
    // Itanium RTTI-derived virtual-method label: `Class::vfn_<idx>`.
    // Beats the generic symbol-table lookup for stripped C++ binaries
    // where only typeinfos survive.
    if (options.rtti_methods) {
        auto it = options.rtti_methods->find(target);
        if (it != options.rtti_methods->end()) return it->second;
    }
    if (binary) {
        if (const Symbol* s = binary->defined_object_at(target); s) {
            if (s->kind == SymbolKind::Function && s->addr == target &&
                !s->name.empty()) {
                return pretty_symbol_base(s->name);
            }
        }
    }
    return std::format("sub_{:x}", target);
}

std::string Emitter::observed_targets_comment(addr_t site) const {
    if (!binary || site == 0) return {};
    auto targets = binary->indirect_edges_from(site);
    if (targets.size() <= 1) return {};
    std::string out = " /* observed targets: ";
    for (std::size_t i = 0; i < targets.size(); ++i) {
        if (i > 0) out += ", ";
        out += function_display_name(targets[i]);
    }
    out += " */";
    return out;
}

std::string Emitter::escape_string(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 2);
    out += '"';
    for (std::size_t i = 0; i < s.size(); ++i) {
        const auto c = static_cast<unsigned char>(s[i]);
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '"':  out += "\\\""; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (c >= 0x20 && c <= 0x7e) {
                    out += static_cast<char>(c);
                    break;
                }
                out += std::format("\\x{:02x}", c);
                // A C hex escape consumes every following hex digit. End
                // this token before a literal byte such as the B in
                // `\x80` + `B`; adjacent string literals preserve the bytes.
                if (i + 1 < s.size()) {
                    const auto next = static_cast<unsigned char>(s[i + 1]);
                    const bool next_is_hex =
                        (next >= '0' && next <= '9') ||
                        (next >= 'A' && next <= 'F') ||
                        (next >= 'a' && next <= 'f');
                    if (next_is_hex) out += "\" \"";
                }
                break;
        }
    }
    out += '"';
    return out;
}

bool Emitter::same_value_key(const IrValue& a,
                             const IrValue& b) const noexcept {
    auto ak = ssa_key(a);
    auto bk = ssa_key(b);
    return ak && bk && *ak == *bk;
}

std::optional<i64>
Emitter::single_write_slot_alias_for_value(const IrValue& v) const {
    if (const IrInst* d = def_stripped(v);
        d && d->op == IrOp::Load && d->segment == Reg::None &&
        d->src_count >= 1) {
        if (auto off = stack_offset(d->srcs[0]); off) return off;
    }
    for (const auto& [off, stored] : single_write_slot_value) {
        if (same_value_key(v, stored)) return off;
    }
    return std::nullopt;
}

std::optional<IrValue>
Emitter::alias_root_for_value(const IrValue& v, int depth) const {
    if (depth > 12) return std::nullopt;
    // Every phi operand branches the search, and rendering asks again for
    // each operand of each phi it meets: memoize per value and depth. The
    // answer reads only the IR and the single-write slot map.
    if (alias_root_memo_fn != fn || alias_root_memo_slots != single_write_slot_value.size()) {
        alias_root_memo.clear();
        alias_root_memo_fn = fn;
        alias_root_memo_slots = single_write_slot_value.size();
    }
    const auto key = ssa_key(v);
    if (key) {
        if (auto found = alias_root_memo.find({*key, depth}); found != alias_root_memo.end())
            return found->second;
    }
    auto root = alias_root_for_value_uncached(v, depth);
    if (key) alias_root_memo.emplace(std::pair{*key, depth}, root);
    return root;
}

std::optional<IrValue>
Emitter::alias_root_for_value_uncached(const IrValue& v, int depth) const {
    const IrInst* d = def_stripped(v);
    if (!d) return v;
    if (d->op == IrOp::Assign && d->src_count >= 1) {
        return alias_root_for_value(d->srcs[0], depth + 1);
    }
    if (d->op == IrOp::Load && d->segment == Reg::None && d->src_count >= 1) {
        if (auto off = stack_offset(d->srcs[0]); off) {
            if (auto it = single_write_slot_value.find(*off);
                it != single_write_slot_value.end()) {
                return alias_root_for_value(it->second, depth + 1);
            }
        }
    }
    if (d->op == IrOp::Phi && !d->phi_operands.empty()) {
        auto self_key = ssa_key(v);
        std::optional<IrValue> common;
        for (const auto& op : d->phi_operands) {
            auto opk = ssa_key(op);
            if (self_key && opk && *self_key == *opk) continue;
            auto root = alias_root_for_value(op, depth + 1);
            if (!root) return std::nullopt;
            if (!common) common = *root;
            else if (!same_value_key(*common, *root)) return std::nullopt;
        }
        return common;
    }
    return v;
}

bool Emitter::is_stale_arg_reg(const IrValue& a, int depth) const {
    if (depth > 8) return false;
    if (a.kind != IrValueKind::Reg) return false;
    if (a.version == 0) {
        if (annotations && fn) {
            if (const FunctionSig* sig = annotations->signature_for(fn->start); sig) {
                if (abi_param_for(*sig, a.reg)) return false;
            }
        }
        // Fall back to the inferred mixed-register layout: a live-in FPR
        // forwarded by a PPC wrapper is just as real as a GPR argument.
        const Reg canon = canonical_reg(a.reg);
        for (u8 i = 0; i < self_arg_layout.size() && i < self_arity; ++i) {
            if (canonical_reg(self_arg_layout[i].reg) == canon) return false;
        }
        return true;
    }
    if (const IrInst* d = def_of(a); d && d->op == IrOp::Clobber) {
        // Bound call returns (rax → r_strlen, etc.) are real values
        // even though their def is a Clobber - the binding name
        // proves a downstream reader picked the value up.
        if (auto k = ssa_key(a); k &&
            call_return_names.find(*k) != call_return_names.end()) {
            return false;
        }
        return true;
    }
    if (const IrInst* d = def_stripped(a);
        d && d->op == IrOp::Phi && !d->phi_operands.empty()) {
        const auto self = ssa_key(a);
        for (const auto& op : d->phi_operands) {
            if (auto ok = ssa_key(op); self && ok && *ok == *self) {
                continue;
            }
            // A conservative call snapshot is not a real argument when
            // even one incoming path leaves its register clobbered.
            if (is_stale_arg_reg(op, depth + 1)) return true;
        }
        return false;
    }
    return false;
}

std::optional<u8>
Emitter::import_arity(addr_t plt_addr, std::string_view name) const {
    if (annotations) {
        if (const FunctionSig* sig = annotations->signature_for(plt_addr); sig) {
            return static_cast<u8>(sig->params.size());
        }
    }
    {
        TypeArena arena;
        if (auto spec = lookup_import_sig(name, arena, import_pointer_bits()); spec) {
            // Variadic call width comes from the existing format-string
            // parser. Returning only the fixed prototype prefix here
            // would truncate printf/scanf payload arguments.
            if (spec->variadic) return std::nullopt;
            return static_cast<u8>(std::min<std::size_t>(
                spec->params.size(), std::numeric_limits<u8>::max()));
        }
    }
    if (auto a = libc_arity_by_name(name); a) return a;
    if (binary) {
        if (const Symbol* s = binary->import_at_plt(plt_addr); s) {
            if (auto a = arity_from_mangled(s->name); a) {
                return static_cast<u8>(*a);
            }
        }
    }
    return std::nullopt;
}

}  // namespace spelunk::emit

// Region-level helpers: for-update collection and structured control flow.
#include <algorithm>
#include <cstddef>
#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include <spelunk/common/types.hpp>
#include <spelunk/disasm/register.hpp>
#include <spelunk/ir/ir.hpp>
#include <spelunk/ir/ssa.hpp>
#include <spelunk/structure/region.hpp>

#include "emitter_internal.hpp"
#include "emitter_text.hpp"
#include "emitter_render_chunk.hpp"

namespace spelunk::emit {

namespace {
void append_if_opening(const Emitter& e, const IrValue& condition,
                       std::string_view cond, std::string_view ind, std::string& out) {
    const std::string opening = std::format("{}if ({}) {{\n", ind, cond);
    const std::string closing = std::format("{}}}\n", ind);
    if (!e.options.line_map) {
        if (const auto* condition_name = e.scoped_ssa_name(condition);
            condition_name && out.ends_with(closing)) {
            const auto previous = out.rfind(opening);
            if (previous != std::string::npos) {
                auto assignments = std::string_view(out).substr(previous + opening.size(),
                    out.size() - closing.size() - previous - opening.size());
                bool copies_only = assignments.find_first_of("{}") == std::string_view::npos &&
                    !text_contains_identifier_in_code(assignments, *condition_name);
                while (copies_only && !assignments.empty()) {
                    const auto end = assignments.find('\n');
                    auto line = assignments.substr(0, end);
                    const auto begin = line.find_first_not_of(" \t");
                    if (begin != std::string_view::npos) {
                        line.remove_prefix(begin);
                        const auto equals = line.find(" = ");
                        copies_only = equals != std::string_view::npos &&
                            std::ranges::any_of(e.scoped_ssa_values, [&](const auto& entry) {
                                return entry.second.second == line.substr(0, equals);
                            });
                    }
                    if (end == std::string_view::npos) break;
                    assignments.remove_prefix(end + 1);
                }
                if (copies_only) {
                    out.resize(out.size() - closing.size());
                    return;
                }
            }
        }
    }
    out += opening;
}
}  // namespace

void Emitter::collect_for_updates(const Region& r) {
    if (r.kind == RegionKind::For && r.has_update) {
        auto it = fn->block_at.find(r.update_block);
        u32 resolved_inst = r.update_inst;
        if (it != fn->block_at.end() &&
            !render_update_inst(r.update_block, r.update_inst,
                                &resolved_inst).empty()) {
            for_update_positions.emplace(it->second, resolved_inst);
        }
    }
    for (const auto& c : r.children) if (c) collect_for_updates(*c);
}

void Emitter::collect_goto_targets(const Region& r) {
    if (r.kind == RegionKind::Block && fn && binary &&
        ++rendered_block_counts[r.block_start] > 1) {
        const auto found = fn->block_at.find(r.block_start);
        if (found != fn->block_at.end()) {
            const auto& block = fn->blocks[found->second];
            if (!block.insts.empty() && block.insts.back().op == IrOp::Unreachable) {
                for (const auto& inst : block.insts) {
                    if (inst.op != IrOp::Call) continue;
                    const auto* imported = binary->import_at_plt(inst.target1);
                    if (imported && (strip_import_name_decorations(imported->name) == "__cxa_throw" ||
                                     strip_import_name_decorations(imported->name) == "__cxa_rethrow")) {
                        shared_throw_blocks.insert(r.block_start);
                        goto_targets.insert(r.block_start);
                    }
                }
            }
        }
    }
    if (r.kind == RegionKind::Goto) {
        goto_targets.insert(r.target);
    }
    for (const auto& c : r.children) if (c) collect_goto_targets(*c);
}

std::string
Emitter::render_update_inst(addr_t block_addr, u32 inst_idx,
                            u32* resolved_inst) const {
    if (explicit_phi_copies) return {};
    auto it = fn->block_at.find(block_addr);
    if (it == fn->block_at.end()) return {};
    const auto& bb = fn->blocks[it->second];
    const auto render_at = [&](u32 index) -> std::string {
        if (index >= bb.insts.size()) return {};
        const auto& inst = bb.insts[index];
        if (auto name = merge_assignment_name_for(inst); name) {
            std::string statement = format_merge_assignment(inst, *name);
            while (!statement.empty() &&
                   (statement.back() == ';' || statement.back() == '\n')) {
                statement.pop_back();
            }
            return statement;
        }
        if (inst.op != IrOp::Store || inst.src_count < 2) return {};
        const auto& addr = inst.srcs[0];
        const auto& val  = inst.srcs[1];
        std::string lhs;
        if (auto off = stack_offset(addr); off) lhs = stack_name(*off);
        if (lhs.empty()) lhs = format_mem(addr, val.type, inst.segment);
        std::string statement = try_compound_store(lhs, addr, val);
        while (!statement.empty() &&
               (statement.back() == ';' || statement.back() == '\n')) {
            statement.pop_back();
        }
        return statement;
    };
    if (std::string direct = render_at(inst_idx); !direct.empty()) {
        if (resolved_inst) *resolved_inst = inst_idx;
        return direct;
    }
    for (u32 index = 0; index < bb.insts.size(); ++index) {
        std::string candidate = render_at(index);
        if (!candidate.ends_with("++") && !candidate.ends_with("--")) continue;
        if (resolved_inst) *resolved_inst = index;
        return candidate;
    }
    return {};
}

std::optional<u8>
Emitter::trace_to_self_arg_slot(const IrValue& v, int depth) const {
    if (depth > 8) return std::nullopt;
    IrValue cur = v;
    for (int hop = 0; hop < 8; ++hop) {
        if (cur.kind == IrValueKind::Temp) {
            auto k = ssa_key(cur);
            if (!k) return std::nullopt;
            const IrInst* d = ssa_uses.definition(*k);
            if (!d) return std::nullopt;
            if ((d->op == IrOp::Assign || d->op == IrOp::Trunc ||
                 d->op == IrOp::ZExt   || d->op == IrOp::SExt) &&
                d->src_count == 1) {
                cur = d->srcs[0];
                continue;
            }
            if (d->op == IrOp::Load && d->segment == Reg::None &&
                d->src_count >= 1) {
                if (auto entry = entry_stack_offset(d->srcs[0])) {
                    for (u8 i = 0; i < self_arg_layout.size(); ++i) {
                        if (self_arg_layout[i].stack_offset == entry) return i;
                    }
                }
                if (auto off = stack_offset(d->srcs[0]); off) {
                    if (auto init = init_only_slot_value.find(*off);
                        init != init_only_slot_value.end()) {
                        cur = init->second;
                        continue;
                    }
                }
            }
            return std::nullopt;
        }
        if (cur.kind != IrValueKind::Reg) return std::nullopt;
        const Reg canon = canonical_reg(cur.reg);
        if (cur.version == 0) {
            for (u8 i = 0; i < self_arg_layout.size(); ++i) {
                if (canonical_reg(self_arg_layout[i].reg) == canon) return i;
            }
            return std::nullopt;
        }
        if (auto preserved = preserved_call_arg_for_clobber(cur.reg, cur.version);
            preserved) {
            return trace_to_self_arg_slot(*preserved, depth + 1);
        }
        const IrInst* d = def_of(cur);
        if (!d) return std::nullopt;
        if (d->op == IrOp::Assign && d->src_count == 1) {
            cur = d->srcs[0];
            continue;
        }
        if (d->op == IrOp::Load && d->segment == Reg::None &&
            d->src_count >= 1) {
            if (auto entry = entry_stack_offset(d->srcs[0])) {
                for (u8 i = 0; i < self_arg_layout.size(); ++i) {
                    if (self_arg_layout[i].stack_offset == entry) return i;
                }
            }
            if (auto off = stack_offset(d->srcs[0]); off) {
                if (auto init = init_only_slot_value.find(*off);
                    init != init_only_slot_value.end()) {
                    cur = init->second;
                    continue;
                }
            }
        }
        if (d->op == IrOp::Phi && !d->phi_operands.empty()) {
            std::optional<u8> common;
            for (const auto& op : d->phi_operands) {
                auto opk = ssa_key(op);
                if (opk && *opk == ssa_key(cur)) continue;  // self-ref
                auto slot = trace_to_self_arg_slot(op, depth + 1);
                if (!slot) return std::nullopt;
                if (!common) common = *slot;
                else if (*common != *slot) return std::nullopt;
            }
            return common;
        }
        return std::nullopt;
    }
    return std::nullopt;
}

std::optional<u8>
Emitter::trace_pointer_alias_to_self_arg_slot(const IrValue& v,
                                              int depth) const {
    if (depth > 8) return std::nullopt;
    if (v.kind == IrValueKind::Reg && v.version == 0) {
        const Reg wanted = canonical_reg(v.reg);
        for (u8 i = 0; i < self_arg_layout.size(); ++i) {
            if (canonical_reg(self_arg_layout[i].reg) != wanted) continue;
            if (annotations && fn) {
                if (const FunctionSig* signature =
                        annotations->signature_for(fn->start);
                    signature && i < signature->params.size()) {
                    const std::string declared = normalize_c_type_alias(
                        signature->params[i].type);
                    return declared.ends_with('*')
                        ? std::optional<u8>{i} : std::nullopt;
                }
            }
            return c_type_name_for(v).ends_with('*')
                ? std::optional<u8>{i} : std::nullopt;
        }
        return std::nullopt;
    }
    if (v.kind == IrValueKind::Reg) {
        if (auto preserved = preserved_call_arg_for_clobber(v.reg, v.version)) {
            return trace_pointer_alias_to_self_arg_slot(*preserved, depth + 1);
        }
    }
    const IrInst* definition = def_of(v);
    if (!definition) return std::nullopt;
    if (definition->op == IrOp::Assign && definition->src_count == 1) {
        return trace_pointer_alias_to_self_arg_slot(
            definition->srcs[0], depth + 1);
    }
    if ((definition->op == IrOp::Add || definition->op == IrOp::Sub) &&
        definition->src_count >= 2 && c_type_name_for(v).ends_with('*')) {
        const auto lhs = trace_pointer_alias_to_self_arg_slot(
            definition->srcs[0], depth + 1);
        const auto rhs = trace_pointer_alias_to_self_arg_slot(
            definition->srcs[1], depth + 1);
        if (definition->op == IrOp::Sub) {
            if (lhs && !rhs) return lhs;
        } else if (lhs.has_value() != rhs.has_value()) {
            return lhs ? lhs : rhs;
        }
        return std::nullopt;
    }
    if (definition->op == IrOp::Load && definition->segment == Reg::None &&
        definition->src_count >= 1) {
        if (auto off = stack_offset(definition->srcs[0]); off) {
            if (auto init = init_only_slot_value.find(*off);
                init != init_only_slot_value.end()) {
                return trace_pointer_alias_to_self_arg_slot(
                    init->second, depth + 1);
            }
        }
        return std::nullopt;
    }
    if (definition->op != IrOp::Phi || definition->phi_operands.empty()) {
        return std::nullopt;
    }
    const auto self_key = ssa_key(v);
    std::optional<u8> common;
    for (const IrValue& operand : definition->phi_operands) {
        const auto operand_key = ssa_key(operand);
        if (self_key && operand_key && *self_key == *operand_key) continue;
        const auto slot = trace_pointer_alias_to_self_arg_slot(
            operand, depth + 1);
        if (!slot) return std::nullopt;
        if (!common) common = slot;
        else if (*common != *slot) return std::nullopt;
    }
    return common;
}

bool Emitter::region_always_exits(const Region& r) noexcept {
    const Region* cur = &r;
    while (cur && cur->kind == RegionKind::Seq && !cur->children.empty()) {
        cur = cur->children.back().get();
    }
    if (!cur) return false;
    switch (cur->kind) {
        case RegionKind::Return:
        case RegionKind::Break:
        case RegionKind::Continue:
        case RegionKind::Unreachable:
        case RegionKind::Goto:
            return true;
        case RegionKind::IfElse:
            // Both arms must always exit for the if to always exit.
            return cur->children.size() >= 2 &&
                   cur->children[0] && cur->children[1] &&
                   region_always_exits(*cur->children[0]) &&
                   region_always_exits(*cur->children[1]);
        default:
            return false;
    }
}

bool Emitter::region_has_deferred_call(const Region& r) const {
    if (r.kind == RegionKind::Block && fn) {
        auto block = fn->block_at.find(r.block_start);
        if (block != fn->block_at.end()) {
            for (std::size_t i = 0;
                 i < fn->blocks[block->second].insts.size(); ++i) {
                const auto position = std::pair{block->second, i};
                if (fold_call_positions.contains(position) ||
                    inline_call_positions.contains(position)) {
                    return true;
                }
            }
        }
    }
    return std::ranges::any_of(r.children, [&](const auto& child) {
        return child && region_has_deferred_call(*child);
    });
}

bool Emitter::rendered_region_empty(std::string_view s) noexcept {
    std::size_t line_start = 0;
    while (line_start <= s.size()) {
        std::size_t line_end = s.find('\n', line_start);
        if (line_end == std::string_view::npos) line_end = s.size();
        std::string_view line = trim_line_view(s.substr(line_start, line_end - line_start));
        if (!line.empty()) {
            if (!line_semantically_empty(line)) return false;
        }
        if (line_end == s.size()) break;
        line_start = line_end + 1;
    }
    return true;
}

void Emitter::emit_region(const Region& r, int depth, std::string& out) const {
    const std::string ind(static_cast<std::size_t>(depth) * 2u, ' ');

    switch (r.kind) {
        case RegionKind::Empty:                                              return;
        case RegionKind::Block:        emit_block(r.block_start, depth, out); return;
        case RegionKind::Seq: {
            // Void-tail guard recovery.  A common PPC CFG shape is
            //
            //   if (body_condition) { ...large body... }
            //   return;
            //
            // because both the entry guard and the body converge on one blr
            // epilogue.  Preserve the semantics while recovering the much
            // clearer source shape: `if (!body_condition) return; ...body`.
            // This also prevents a single initial check from indenting an
            // entire callback by another level.
            if (current_return_is_void && r.children.size() >= 2) {
                const Region* tail = r.children.back().get();
                std::size_t guard_index = r.children.size() - 1;
                bool suffix_has_deferred_call = false;
                const auto bindings_before_suffix = emitted_bindings;
                auto suffix = RenderChunk::capture(
                    options.line_map, [&](std::string& text) {
                        while (guard_index > 0) {
                            const Region* candidate =
                                r.children[guard_index - 1].get();
                            if (!candidate ||
                                (candidate->kind != RegionKind::Block &&
                                 candidate->kind != RegionKind::Empty)) {
                                break;
                            }
                            --guard_index;
                            suffix_has_deferred_call |=
                                region_has_deferred_call(*candidate);
                            emit_region(*candidate, depth, text);
                        }
                    });
                emitted_bindings = bindings_before_suffix;
                const Region* guarded = guard_index > 0
                    ? r.children[guard_index - 1].get() : nullptr;
                const bool suffix_empty =
                    rendered_region_empty(suffix.text()) &&
                    !suffix_has_deferred_call;
                suffix.discard();
                if (suffix_empty && guarded && tail &&
                    guarded->kind == RegionKind::IfThen &&
                    tail->kind == RegionKind::Return && !guarded->children.empty() &&
                    guarded->children[0]) {
                    for (std::size_t i = 0; i + 1 < guard_index; ++i) {
                        emit_region(*r.children[i], depth, out);
                    }
                    const std::string cond =
                        render_condition(guarded->condition, !guarded->invert);
                    emit_materializations_for_rendered_value(
                        guarded->condition, cond, out, ind);
                    out += std::format("{}if ({}) {{\n", ind, cond);
                    out += std::format("{}  return;\n", ind);
                    out += std::format("{}}}\n", ind);
                    emit_region(*guarded->children[0], depth, out);
                    return;
                }
            }
            for (const auto& c : r.children) emit_region(*c, depth, out);
            return;
        }
        case RegionKind::IfThen:       emit_region_if_then  (r, depth, out); return;
        case RegionKind::IfElse:       emit_region_if_else  (r, depth, out); return;
        case RegionKind::While:        emit_region_while    (r, depth, out); return;
        case RegionKind::Loop:
            emit_loop_entry_assignments(r, depth, out);
            out += std::format("{}for (;;) {{\n", ind);
            for (const auto& c : r.children) emit_region(*c, depth + 1, out);
            out += std::format("{}}}\n", ind);
            return;
        case RegionKind::DoWhile:      emit_region_do_while (r, depth, out); return;
        case RegionKind::For:          emit_region_for      (r, depth, out); return;
        case RegionKind::Return:       emit_region_return   (r, depth, out); return;
        case RegionKind::Unreachable:  out += std::format("{}__unreachable();\n",   ind); return;
        case RegionKind::Break:        out += std::format("{}break;\n",             ind); return;
        case RegionKind::Continue:     out += std::format("{}continue;\n",          ind); return;
        case RegionKind::Goto:         out += std::format("{}goto bb_{:x};\n", ind, r.target); return;
        case RegionKind::Switch:       emit_region_switch   (r, depth, out); return;
    }
}

void Emitter::emit_region_if_then(const Region& r, int depth, std::string& out) const {
    if (auto constant = resolve_imm(r.condition); constant) {
        const bool take = (*constant != 0) != r.invert;
        if (take && !r.children.empty()) emit_region(*r.children[0], depth, out);
        return;
    }
    // Rendering the arm replaces the copy blocks the condition's block
    // ended with; keep them for the `if` itself.
    auto pending_copies = std::move(trailing_edge_copies);
    trailing_edge_copies.clear();
    // Pre-render the body and skip the whole if when nothing survived. The
    // body can collapse to empty after store/decl suppression (e.g. an
    // -O0 prologue's xmm spill block that becomes literally `if (rax) {}`)
    // - emitting the dead conditional is just visual noise, since the
    // condition itself has no observable effect.
    const auto bindings_before_body = emitted_bindings;
    auto body = RenderChunk::capture(options.line_map, [&](std::string& text) {
        if (!r.children.empty()) emit_region(*r.children[0], depth + 1, text);
    });
    const auto bindings_after_body = emitted_bindings;
    emitted_bindings = bindings_before_body;
    if (rendered_region_empty(body.text())) {
        body.discard();
        return;
    }
    const std::string ind(static_cast<std::size_t>(depth) * 2u, ' ');
    const std::string cond = render_condition(r.condition, r.invert);
    trailing_edge_copies = std::move(pending_copies);
    const auto [then_copies, else_copies] = take_arm_copies(r.condition, cond, r.invert, ind, out);
    append_if_opening(*this, r.condition, cond, ind, out);
    out += then_copies;
    std::move(body).append_to(out);
    emitted_bindings.insert(bindings_after_body.begin(), bindings_after_body.end());
    if (!else_copies.empty()) out += std::format("{}}} else {{\n{}", ind, else_copies);
    out += std::format("{}}}\n", ind);
}

std::pair<std::string, std::string>
Emitter::take_arm_copies(const IrValue& condition, std::string_view cond, bool invert,
                         std::string_view ind, std::string& out) const {
    // The branch's edge copies run on entry to the arm for that edge.
    // Moving them past bindings the condition needs would reorder reads,
    // so they stay put unless there are none.
    std::string materialized;
    emit_materializations_for_rendered_value(condition, cond, materialized, ind);
    std::pair<std::string, std::string> arms;
    if (materialized.empty()) {
        for (auto& copy : take_trailing_edge_copies(out, condition)) {
            (copy.when_true != invert ? arms.first : arms.second) += copy.body;
        }
    }
    out += materialized;
    return arms;
}

void Emitter::emit_region_if_else(const Region& r, int depth, std::string& out) const {
    if (auto constant = resolve_imm(r.condition); constant) {
        const bool take_then = (*constant != 0) != r.invert;
        const std::size_t child = take_then ? 0u : 1u;
        if (child < r.children.size() && r.children[child]) {
            emit_region(*r.children[child], depth, out);
        }
        return;
    }
    auto pending_copies = std::move(trailing_edge_copies);
    trailing_edge_copies.clear();
    const std::string ind(static_cast<std::size_t>(depth) * 2u, ' ');
    const auto bindings_before_children = emitted_bindings;
    auto then_buf = RenderChunk::capture(
        options.line_map, [&](std::string& text) {
            if (!r.children.empty()) {
                emit_region(*r.children[0], depth + 1, text);
            }
        });
    auto bindings_after_then = emitted_bindings;
    emitted_bindings = bindings_before_children;
    // Early-return collapse: when the then arm always exits (last statement
    // is `return …;` or `goto …;`), the else arm is unreachable AFTER the
    // if, so we can drop the `else` wrapper and let the else body run at
    // the surrounding indent. Cascaded across nested if/elses this turns
    // a goto-fail ladder back into an early-return chain - the same shape
    // the user originally wrote. Render the else only at the outer depth:
    // also rendering it nested doubles the work at every rung of the ladder.
    if (r.children.size() > 1 && r.children[0] && r.children[1] &&
        region_always_exits(*r.children[0]) &&
        !rendered_region_empty(then_buf.text())) {
        const std::string cond = render_condition(r.condition, r.invert);
        emit_materializations_for_rendered_value(r.condition, cond, out, ind);
        auto else_outer = RenderChunk::capture(
            options.line_map, [&](std::string& text) {
                emit_region(*r.children[1], depth, text);
            });
        const auto bindings_after_else_outer = emitted_bindings;
        emitted_bindings = bindings_before_children;
        append_if_opening(*this, r.condition, cond, ind, out);
        std::move(then_buf).append_to(out);
        emitted_bindings.insert(bindings_after_then.begin(), bindings_after_then.end());
        out += std::format("{}}}\n", ind);
        if (rendered_region_empty(else_outer.text())) {
            else_outer.discard();
            return;
        }
        std::move(else_outer).append_to(out);
        emitted_bindings.insert(bindings_after_else_outer.begin(),
                               bindings_after_else_outer.end());
        return;
    }
    auto else_buf = RenderChunk::capture(
        options.line_map, [&](std::string& text) {
            if (r.children.size() > 1) {
                emit_region(*r.children[1], depth + 1, text);
            }
        });
    auto bindings_after_else = emitted_bindings;
    emitted_bindings = bindings_before_children;
    bool then_empty = rendered_region_empty(then_buf.text());
    bool else_empty = rendered_region_empty(else_buf.text());
    if (then_empty && else_empty) {
        then_buf.discard();
        else_buf.discard();
        return;
    }
    // If only the else arm has content, invert the condition and drop the
    // dead then. Reads much cleaner than `if (!x) {} else {…}`.
    bool invert_effective = r.invert;
    if (then_empty && !else_empty) {
        invert_effective = !invert_effective;
        then_buf.swap(else_buf);
        std::swap(bindings_after_then, bindings_after_else);
        std::swap(then_empty, else_empty);
    }
    const std::string cond = render_condition(r.condition, invert_effective);
    trailing_edge_copies = std::move(pending_copies);
    auto [then_copies, else_copies] =
        take_arm_copies(r.condition, cond, invert_effective, ind, out);
    // An empty then arm swapped the else into it above; the collapse still
    // keys off the original then region.
    if (r.children.size() > 1 && r.children[0] && r.children[1] &&
        region_always_exits(*r.children[0])) {
        const auto bindings_before_else_outer = emitted_bindings;
        auto else_outer = RenderChunk::capture(
            options.line_map, [&](std::string& text) {
                emit_region(*r.children[1], depth, text);
            });
        const auto bindings_after_else_outer = emitted_bindings;
        emitted_bindings = bindings_before_else_outer;
        if (!rendered_region_empty(else_outer.text()) && else_copies.empty()) {
            append_if_opening(*this, r.condition, cond, ind, out);
            out += then_copies;
            std::move(then_buf).append_to(out);
            emitted_bindings.insert(bindings_after_then.begin(), bindings_after_then.end());
            out += std::format("{}}}\n", ind);
            std::move(else_outer).append_to(out);
            else_buf.discard();
            emitted_bindings.insert(bindings_after_else_outer.begin(),
                                   bindings_after_else_outer.end());
            return;
        }
        else_outer.discard();
    }
    append_if_opening(*this, r.condition, cond, ind, out);
    out += then_copies;
    std::move(then_buf).append_to(out);
    emitted_bindings.insert(bindings_after_then.begin(), bindings_after_then.end());
    if (!else_empty || !else_copies.empty()) {
        out += std::format("{}}} else {{\n", ind);
        out += else_copies;
        std::move(else_buf).append_to(out);
        emitted_bindings.insert(bindings_after_else.begin(), bindings_after_else.end());
    } else {
        else_buf.discard();
    }
    out += std::format("{}}}\n", ind);
}

// A loop phi whose entry value was not coalesced into its local - a guarded
// rotated loop, `if (!p) return; do { ... } while (p)`, where the guard
// also reads the value - has nothing assigning the local before the first
// iteration. Seed it at the loop head, which only the entry edges reach.
void Emitter::emit_loop_entry_assignments(const Region& r, int depth, std::string& out) const {
    if (!fn || explicit_phi_copies) return;
    // The header is the loop's first block.
    const Region* first = &r;
    while (first->block_start == 0 && !first->children.empty() && first->children[0])
        first = first->children[0].get();
    const auto header = fn->block_at.find(first->block_start);
    if (header == fn->block_at.end()) return;
    std::set<addr_t> inside;
    const auto collect = [&](this const auto& self, const Region& region) -> void {
        inside.insert(region.block_start);
        for (const auto& child : region.children) {
            if (child) self(*child);
        }
    };
    collect(r);
    const std::string ind(static_cast<std::size_t>(depth) * 2u, ' ');
    for (const IrInst& phi : fn->blocks[header->second].insts) {
        if (phi.op != IrOp::Phi || phi.phi_operands.size() != phi.phi_preds.size()) continue;
        const auto key = ssa_key(phi.dst);
        const auto named = key ? merge_value_names.find(*key) : merge_value_names.end();
        if (named == merge_value_names.end()) continue;
        // A local declared with its entry value needs no seed, nor does one
        // the body never reads.
        const auto local = merge_locals.find(named->second);
        if (local == merge_locals.end() || local->second.initializer ||
            std::ranges::none_of(local->second.keys, [&](const SsaKey& k) {
                return ssa_uses.visible_use_count(k) > 0;
            })) continue;
        std::optional<IrValue> seed;
        bool usable = true;
        for (std::size_t i = 0; i < phi.phi_preds.size() && usable; ++i) {
            if (inside.contains(phi.phi_preds[i])) continue;
            const IrValue& operand = phi.phi_operands[i];
            const auto predecessor = fn->block_at.find(phi.phi_preds[i]);
            const auto edge = merge_edge_assignments.find(phi.phi_preds[i]);
            const auto guarded = merge_guarded_edge_assignments.find(phi.phi_preds[i]);
            usable = predecessor != fn->block_at.end() &&
                (edge == merge_edge_assignments.end() ||
                 std::ranges::none_of(edge->second, [&](const auto& assignment) {
                     return assignment.first == named->second;
                 })) &&
                (guarded == merge_guarded_edge_assignments.end() ||
                 std::ranges::none_of(guarded->second, [&](const auto& assignment) {
                     return assignment.name == named->second;
                 })) &&
                (!seed || same_value_key(*seed, operand) ||
                 (seed->kind == IrValueKind::Imm && operand.kind == IrValueKind::Imm &&
                  seed->imm == operand.imm));
            seed = operand;
        }
        if (!usable || !seed) continue;
        if (auto seed_key = ssa_key(*seed)) {
            // A coalesced feeder already assigns the merge local.
            if (auto same = merge_value_names.find(*seed_key);
                same != merge_value_names.end() && same->second == named->second) continue;
        }
        const IrInst* definition = def_of(*seed);
        if (definition && definition->op == IrOp::Clobber) continue;
        if (renders_raw_arch_reg_name(*seed)) continue;
        const std::string value = expr(*seed);
        if (seed->kind == IrValueKind::Reg && value == display_reg_name(seed->reg)) continue;
        emit_materializations_for_rendered_value(*seed, value, out, ind);
        out += std::format("{}{} = {};\n", ind, named->second, value);
    }
}

void Emitter::emit_region_while(const Region& r, int depth, std::string& out) const {
    // Two render shapes for a top-tested loop:
    //
    //   `while (cond) { body }`     - preferred, source-shape.
    //   `for (;;) { header; if (!cond) break; body }`
    //          - fallback when the header block has live statements that
    //            need to stay in the loop's scope (typically a Load or
    //            Call whose result the condition reads).
    //
    // We pre-render the header into a buffer and pick by emptiness. The
    // common case at -O2 is an empty header - the cond uses live-in args
    // or pre-loop locals - and the cleaner `while (cond)` reads as the
    // user originally wrote.
    const std::string ind(static_cast<std::size_t>(depth) * 2u, ' ');
    const std::string inner_ind(static_cast<std::size_t>(depth + 1) * 2u, ' ');
    emit_loop_entry_assignments(r, depth, out);

    const auto bindings_before_header = emitted_bindings;
    auto header_buf = RenderChunk::capture(
        options.line_map, [&](std::string& text) {
            if (!r.children.empty()) {
                emit_region(*r.children[0], depth + 1, text);
            }
        });
    const auto bindings_after_header = emitted_bindings;
    emitted_bindings = bindings_before_header;
    if (header_buf.text().empty()) {
        header_buf.discard();
        const std::string cond = render_condition(r.condition, r.invert);
        emit_materializations_for_rendered_value(r.condition, cond, out, ind);
        out += std::format("{}while ({}) {{\n", ind, cond);
        for (std::size_t i = 1; i < r.children.size(); ++i) {
            emit_region(*r.children[i], depth + 1, out);
        }
        out += std::format("{}}}\n", ind);
        return;
    }
    // Everything runs before the test: `for (;;) { H; if (!c) break; }`
    // is exactly `do { H } while (c);` - unless H has its own `continue`,
    // which would then run the test instead of restarting H.
    const auto has_own_continue = [](this const auto& self, const Region& region) -> bool {
        if (region.kind == RegionKind::Continue) return true;
        if (region.kind == RegionKind::While || region.kind == RegionKind::DoWhile ||
            region.kind == RegionKind::For || region.kind == RegionKind::Loop) return false;
        return std::ranges::any_of(region.children, [&](const auto& child) {
            return child && self(*child);
        });
    };
    const auto structurally_empty = [](this const auto& self, const Region* region) -> bool {
        return !region || region->kind == RegionKind::Empty ||
            (region->kind == RegionKind::Seq &&
             std::ranges::all_of(region->children, [&](const auto& child) {
                 return self(child.get());
             }));
    };
    const bool header_only = std::all_of(
        r.children.begin() + 1, r.children.end(),
        [&](const auto& child) { return structurally_empty(child.get()); });
    if (header_only && r.children[0] && !has_own_continue(*r.children[0])) {
        // The test sits outside the body's scope, so it may not read a
        // name the body declares, nor need a binding of its own there.
        const auto saved_bindings = emitted_bindings;
        emitted_bindings.insert(bindings_after_header.begin(), bindings_after_header.end());
        const std::string cond = render_condition(r.condition, r.invert);
        std::string materialized;
        emit_materializations_for_rendered_value(r.condition, cond, materialized, inner_ind);
        emitted_bindings = saved_bindings;
        // A body declaration the test reads moves in front of the loop when
        // it sits at the body's top level: `T x; do { x = ...; } while (x);`.
        bool test_in_scope = materialized.empty();
        std::string hoisted;
        std::string body_text = header_buf.text();
        for (const std::string& name : declared_identifiers(body_text)) {
            if (!test_in_scope) break;
            if (!text_contains_identifier(cond, name)) continue;
            test_in_scope = false;
            if (options.line_map) break;
            const std::string needle = std::format(" {} = ", name);
            for (std::size_t line = 0; line < body_text.size();) {
                const std::size_t end = std::min(body_text.find('\n', line), body_text.size());
                const std::string_view text(body_text.data() + line, end - line);
                const std::size_t at = text.find(needle);
                if (text.starts_with(inner_ind) && text.size() > inner_ind.size() &&
                    text[inner_ind.size()] != ' ' && at != std::string_view::npos &&
                    at > inner_ind.size()) {
                    const std::string_view type = text.substr(inner_ind.size(), at - inner_ind.size());
                    if (std::ranges::all_of(type, [](char c) {
                            return c_ident_char(c) || c == '*' || c == ' ';
                        })) {
                        hoisted += std::format("{}{} {};\n", ind, type, name);
                        body_text.erase(line + inner_ind.size(), type.size() + 1);
                        test_in_scope = true;
                        break;
                    }
                }
                line = end + 1;
            }
        }
        if (test_in_scope) {
            if (!hoisted.empty()) header_buf.text() = std::move(body_text);
            out += hoisted;
            out += std::format("{}do {{\n", ind);
            std::move(header_buf).append_to(out);
            emitted_bindings.insert(bindings_after_header.begin(), bindings_after_header.end());
            out += std::format("{}}} while ({});\n", ind, cond);
            return;
        }
    }
    const std::string break_cond = render_condition(r.condition, !r.invert);
    out += std::format("{}for (;;) {{\n", ind);
    std::move(header_buf).append_to(out);
    emitted_bindings.insert(bindings_after_header.begin(), bindings_after_header.end());
    emit_materializations_for_rendered_value(r.condition, break_cond, out, inner_ind);
    out += std::format("{}if ({}) break;\n", inner_ind, break_cond);
    for (std::size_t i = 1; i < r.children.size(); ++i) {
        emit_region(*r.children[i], depth + 1, out);
    }
    out += std::format("{}}}\n", ind);
}

void Emitter::emit_region_do_while(const Region& r, int depth, std::string& out) const {
    // Body runs at least once, condition tested at the tail. r.invert is
    // set when the decoded back-edge is a "loop-on-false" test - mirror it
    // here so the rendered `while (...)` expresses the actual continue
    // condition.
    const std::string ind(static_cast<std::size_t>(depth) * 2u, ' ');
    const auto condition_key = ssa_key(r.condition);
    if (condition_key) deferred_ctr_conditions.insert(*condition_key);
    emit_loop_entry_assignments(r, depth, out);
    out += std::format("{}do {{\n", ind);
    for (const auto& c : r.children) emit_region(*c, depth + 1, out);
    if (condition_key) active_ctr_tail_conditions.insert(*condition_key);
    const std::string cond = render_condition(r.condition, r.invert);
    if (condition_key) {
        active_ctr_tail_conditions.erase(*condition_key);
        deferred_ctr_conditions.erase(*condition_key);
    }
    emit_materializations_for_rendered_value(
        r.condition, cond, out,
        std::string(static_cast<std::size_t>(depth + 1) * 2u, ' '));
    out += std::format("{}}} while ({});\n", ind, cond);
}

void Emitter::emit_region_for(const Region& r, int depth, std::string& out) const {
    // The update slot renders the increment inst. If rendering fails
    // (pattern didn't reduce), degrade gracefully to a plain while - the
    // body will include the update statement at its natural spot.
    const std::string ind(static_cast<std::size_t>(depth) * 2u, ' ');
    const std::string update = r.has_update
        ? render_update_inst(r.update_block, r.update_inst)
        : std::string{};
    if (update.empty()) {
        emit_region_while(r, depth, out);
        return;
    }
    emit_loop_entry_assignments(r, depth, out);
    const std::string cond = render_condition(r.condition, r.invert);
    emit_materializations_for_rendered_value(r.condition, cond, out, ind);
    out += std::format("{}for (; {}; {}) {{\n", ind, cond, update);
    for (const auto& c : r.children) emit_region(*c, depth + 1, out);
    out += std::format("{}}}\n", ind);
}

void Emitter::emit_region_return(const Region& r, int depth, std::string& out) const {
    const std::string ind(static_cast<std::size_t>(depth) * 2u, ' ');
    addr_t return_source = 0;
    IrValue returned = r.condition;
    if (fn) {
        auto block = fn->block_at.find(r.block_start);
        if (block != fn->block_at.end()) {
            const auto& instructions = fn->blocks[block->second].insts;
            for (auto it = instructions.rbegin(); it != instructions.rend(); ++it) {
                if (it->op == IrOp::Return) {
                    return_source = it->source_addr;
                    // Duplicated return regions can resolve a phi using one
                    // predecessor even when several loop exits reach this
                    // copy. Explicit edge copies already selected the value.
                    if (explicit_phi_copies && it->src_count > 0 &&
                        !is_float_type(returned.type) && scoped_ssa_name(it->srcs[0])) {
                        if (const IrInst* source = def_of(it->srcs[0]);
                            source && source->op == IrOp::Phi) returned = it->srcs[0];
                    }
                    break;
                }
            }
        }
    }
    const auto append_return = [&](std::string statement) {
        if (options.line_map && return_source != 0) {
            options.line_map->hits.push_back({out.size(), return_source});
        }
        out += ind + std::move(statement) + "\n";
    };
    if (returned.kind == IrValueKind::None) {
        append_return("return;");
        return;
    }
    if (auto k = ssa_key(returned); k) {
        auto s = fold_void_call_stmt.find(*k);
        if (s != fold_void_call_stmt.end()) {
            record_folded_call_hit(*k, out.size());
            out += std::format("{}{};\n", ind, s->second);
            append_return("return;");
            return;
        }
    }
    if (current_return_is_void) {
        if (auto k = ssa_key(returned); k) {
            auto f = fold_return_expr.find(*k);
            if (f != fold_return_expr.end()) {
                emit_materializations_for_rendered_value(returned, f->second, out, ind);
                record_folded_call_hit(*k, out.size());
                out += std::format("{}{};\n", ind, f->second);
            }
        }
        append_return("return;");
        return;
    }
    if (current_return_is_unknown) {
        append_return(std::format("return; /* return register: {}; source return value unproven */", expr(returned)));
        return;
    }
    if (is_void_call_result(returned)) {
        append_return("return;");
        return;
    }
    if (is_unbound_clobber_result(returned)) {
        append_return("return;");
        return;
    }
    if (is_incidental_x86_fp_return(returned)) {
        append_return("return;");
        return;
    }
    if (renders_stack_chk_guard_value(returned)) {
        append_return("return;");
        return;
    }
    if (auto k = ssa_key(returned); k) {
        auto f = fold_return_expr.find(*k);
        if (f != fold_return_expr.end()) {
            emit_materializations_for_rendered_value(returned, f->second, out, ind);
            record_folded_call_hit(*k, out.size());
            append_return(std::format("return {};", f->second));
            return;
        }
    }
    // Strip a redundant outer widen: in a return context the caller's
    // declared type already coerces, so `return (u64)x;` where `x` has the
    // return type reads as noise. One hop only - deeper casts are
    // semantically real.
    IrValue v = returned;
    if (auto payload = low_byte_return_payload(v); payload) {
        v = *payload;
    }
    if (const IrInst* d = def_of(v); d && d->src_count >= 1
            && (d->op == IrOp::ZExt || d->op == IrOp::SExt)
            && type_bits(d->srcs[0].type) <= type_bits(d->dst.type)) {
        v = d->srcs[0];
    }
    std::string rendered = expr(v);
    emit_materializations_for_rendered_value(v, rendered, out, ind);
    if (renders_stack_chk_guard_value(v)) {
        append_return("return;");
        return;
    }
    record_inline_call_hit(v, out.size());
    append_return(std::format("return {};", rendered));
}

void Emitter::emit_region_switch(const Region& r, int depth, std::string& out) const {
    const std::string ind(static_cast<std::size_t>(depth) * 2u, ' ');
    const std::string_view rn = display_reg_name(r.switch_index);
    const std::string selector = r.condition.kind != IrValueKind::None
        ? expr(r.condition)
        : (rn.empty() ? std::string("<idx>") : std::string(rn));
    out += std::format("{}switch ({}) {{\n", ind,
                       selector);
    const std::string cind(static_cast<std::size_t>(depth + 1) * 2u, ' ');
    const std::size_t n_cases = r.case_values.size();

    auto ends_in_terminator = [](const Region& body) {
        const Region* cur = &body;
        while (cur && cur->kind == RegionKind::Seq && !cur->children.empty()) {
            cur = cur->children.back().get();
        }
        if (!cur) return false;
        switch (cur->kind) {
            case RegionKind::Return:
            case RegionKind::Break:
            case RegionKind::Continue:
            case RegionKind::Unreachable:
                return true;
            default:
                return false;
        }
    };

    for (std::size_t i = 0; i < n_cases; ++i) {
        out += std::format("{}case {}:", cind, r.case_values[i]);
        const Region* child = i < r.children.size() ? r.children[i].get() : nullptr;
        const bool is_empty_child =
            !child || child->kind == RegionKind::Empty ||
            (child->kind == RegionKind::Seq && child->children.empty());
        if (is_empty_child) {
            out += "\n";
            continue;
        }
        out += options.c_source ? " {\n" : "\n";
        emit_region(*child, depth + 2, out);
        if (!ends_in_terminator(*child)) {
            out += std::format("{}  break;\n", cind);
        }
        if (options.c_source) out += std::format("{}}}\n", cind);
    }
    if (r.has_default && r.children.size() > n_cases) {
        out += std::format("{}default:{}\n", cind, options.c_source ? " {" : "");
        const Region& dflt = *r.children.back();
        emit_region(dflt, depth + 2, out);
        if (!ends_in_terminator(dflt)) {
            out += std::format("{}  break;\n", cind);
        }
        if (options.c_source) out += std::format("{}}}\n", cind);
    }
    out += std::format("{}}}\n", ind);
}

}  // namespace spelunk::emit

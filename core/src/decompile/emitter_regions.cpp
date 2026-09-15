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
    emit_materializations_for_rendered_value(r.condition, cond, out, ind);
    out += std::format("{}if ({}) {{\n", ind, cond);
    std::move(body).append_to(out);
    emitted_bindings.insert(bindings_after_body.begin(), bindings_after_body.end());
    out += std::format("{}}}\n", ind);
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
    emit_materializations_for_rendered_value(r.condition, cond, out, ind);
    // Early-return collapse: when the then arm always exits (last statement
    // is `return …;` or `goto …;`), the else arm is unreachable AFTER the
    // if, so we can drop the `else` wrapper and let the else body run at
    // the surrounding indent. Cascaded across nested if/elses this turns
    // a goto-fail ladder back into an early-return chain - the same shape
    // the user originally wrote. Re-emit the else at the outer depth so
    // the indentation matches the new flat layout.
    if (r.children.size() > 1 && r.children[0] && r.children[1] &&
        region_always_exits(*r.children[0])) {
        const auto bindings_before_else_outer = emitted_bindings;
        auto else_outer = RenderChunk::capture(
            options.line_map, [&](std::string& text) {
                emit_region(*r.children[1], depth, text);
            });
        const auto bindings_after_else_outer = emitted_bindings;
        emitted_bindings = bindings_before_else_outer;
        if (!rendered_region_empty(else_outer.text())) {
            out += std::format("{}if ({}) {{\n", ind, cond);
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
    out += std::format("{}if ({}) {{\n", ind, cond);
    std::move(then_buf).append_to(out);
    emitted_bindings.insert(bindings_after_then.begin(), bindings_after_then.end());
    if (!else_empty) {
        out += std::format("{}}} else {{\n", ind);
        std::move(else_buf).append_to(out);
        emitted_bindings.insert(bindings_after_else.begin(), bindings_after_else.end());
    } else {
        else_buf.discard();
    }
    out += std::format("{}}}\n", ind);
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
    const std::string cond = render_condition(r.condition, r.invert);
    emit_materializations_for_rendered_value(r.condition, cond, out, ind);
    if (update.empty()) {
        out += std::format("{}while ({}) {{\n", ind, cond);
    } else {
        out += std::format("{}for (; {}; {}) {{\n", ind, cond, update);
    }
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
    const std::string_view rn = reg_name(r.switch_index);
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
        out += "\n";
        emit_region(*child, depth + 2, out);
        if (!ends_in_terminator(*child)) {
            out += std::format("{}  break;\n", cind);
        }
    }
    if (r.has_default && r.children.size() > n_cases) {
        out += std::format("{}default:\n", cind);
        const Region& dflt = *r.children.back();
        emit_region(dflt, depth + 2, out);
        if (!ends_in_terminator(dflt)) {
            out += std::format("{}  break;\n", cind);
        }
    }
    out += std::format("{}}}\n", ind);
}

}  // namespace spelunk::emit

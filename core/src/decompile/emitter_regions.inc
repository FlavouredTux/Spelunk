void Emitter::emit_region(const Region& r, int depth, std::string& out) const {
    const std::string ind(static_cast<std::size_t>(depth) * 2u, ' ');

    switch (r.kind) {
        case RegionKind::Empty:                                              return;
        case RegionKind::Block:        emit_block(r.block_start, depth, out); return;
        case RegionKind::Seq:
            for (const auto& c : r.children) emit_region(*c, depth, out);
            return;
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
    // Pre-render the body and skip the whole if when nothing survived. The
    // body can collapse to empty after store/decl suppression (e.g. an
    // -O0 prologue's xmm spill block that becomes literally `if (rax) {}`)
    // — emitting the dead conditional is just visual noise, since the
    // condition itself has no observable effect.
    std::string body;
    const auto bindings_before_body = emitted_bindings;
    if (!r.children.empty()) emit_region(*r.children[0], depth + 1, body);
    const auto bindings_after_body = emitted_bindings;
    emitted_bindings = bindings_before_body;
    if (rendered_region_empty(body)) return;
    const std::string ind(static_cast<std::size_t>(depth) * 2u, ' ');
    emit_materializations_for_value(r.condition, 0, out, ind);
    const std::string cond = render_condition(r.condition, r.invert);
    out += std::format("{}if ({}) {{\n", ind, cond);
    out += body;
    emitted_bindings.insert(bindings_after_body.begin(), bindings_after_body.end());
    out += std::format("{}}}\n", ind);
}

void Emitter::emit_region_if_else(const Region& r, int depth, std::string& out) const {
    const std::string ind(static_cast<std::size_t>(depth) * 2u, ' ');
    const auto bindings_before_children = emitted_bindings;
    std::string then_buf;
    if (r.children.size() > 0) emit_region(*r.children[0], depth + 1, then_buf);
    auto bindings_after_then = emitted_bindings;
    emitted_bindings = bindings_before_children;
    std::string else_buf;
    if (r.children.size() > 1) emit_region(*r.children[1], depth + 1, else_buf);
    auto bindings_after_else = emitted_bindings;
    emitted_bindings = bindings_before_children;
    bool then_empty = rendered_region_empty(then_buf);
    bool else_empty = rendered_region_empty(else_buf);
    if (then_empty && else_empty) return;
    // If only the else arm has content, invert the condition and drop the
    // dead then. Reads much cleaner than `if (!x) {} else {…}`.
    bool invert_effective = r.invert;
    if (then_empty && !else_empty) {
        invert_effective = !invert_effective;
        std::swap(then_buf, else_buf);
        std::swap(bindings_after_then, bindings_after_else);
        std::swap(then_empty, else_empty);
    }
    emit_materializations_for_value(r.condition, 0, out, ind);
    const std::string cond = render_condition(r.condition, invert_effective);
    // Early-return collapse: when the then arm always exits (last statement
    // is `return …;` or `goto …;`), the else arm is unreachable AFTER the
    // if, so we can drop the `else` wrapper and let the else body run at
    // the surrounding indent. Cascaded across nested if/elses this turns
    // a goto-fail ladder back into an early-return chain — the same shape
    // the user originally wrote. Re-emit the else at the outer depth so
    // the indentation matches the new flat layout.
    if (r.children.size() > 1 && r.children[0] && r.children[1] &&
        region_always_exits(*r.children[0])) {
        std::string else_outer;
        const auto bindings_before_else_outer = emitted_bindings;
        emit_region(*r.children[1], depth, else_outer);
        const auto bindings_after_else_outer = emitted_bindings;
        emitted_bindings = bindings_before_else_outer;
        if (!rendered_region_empty(else_outer)) {
            out += std::format("{}if ({}) {{\n", ind, cond);
            out += then_buf;
            emitted_bindings.insert(bindings_after_then.begin(), bindings_after_then.end());
            out += std::format("{}}}\n", ind);
            out += else_outer;
            emitted_bindings.insert(bindings_after_else_outer.begin(),
                                   bindings_after_else_outer.end());
            return;
        }
    }
    out += std::format("{}if ({}) {{\n", ind, cond);
    out += then_buf;
    emitted_bindings.insert(bindings_after_then.begin(), bindings_after_then.end());
    if (!else_empty) {
        out += std::format("{}}} else {{\n", ind);
        out += else_buf;
        emitted_bindings.insert(bindings_after_else.begin(), bindings_after_else.end());
    }
    out += std::format("{}}}\n", ind);
}

void Emitter::emit_region_while(const Region& r, int depth, std::string& out) const {
    // Two render shapes for a top-tested loop:
    //
    //   `while (cond) { body }`     — preferred, source-shape.
    //   `for (;;) { header; if (!cond) break; body }`
    //          — fallback when the header block has live statements that
    //            need to stay in the loop's scope (typically a Load or
    //            Call whose result the condition reads).
    //
    // We pre-render the header into a buffer and pick by emptiness. The
    // common case at -O2 is an empty header — the cond uses live-in args
    // or pre-loop locals — and the cleaner `while (cond)` reads as the
    // user originally wrote.
    const std::string ind(static_cast<std::size_t>(depth) * 2u, ' ');
    const std::string inner_ind(static_cast<std::size_t>(depth + 1) * 2u, ' ');

    std::string header_buf;
    const auto bindings_before_header = emitted_bindings;
    if (!r.children.empty()) {
        emit_region(*r.children[0], depth + 1, header_buf);
    }
    const auto bindings_after_header = emitted_bindings;
    emitted_bindings = bindings_before_header;
    if (header_buf.empty()) {
        emit_materializations_for_value(r.condition, 0, out, ind);
        const std::string cond = render_condition(r.condition, r.invert);
        out += std::format("{}while ({}) {{\n", ind, cond);
        for (std::size_t i = 1; i < r.children.size(); ++i) {
            emit_region(*r.children[i], depth + 1, out);
        }
        out += std::format("{}}}\n", ind);
        return;
    }
    const std::string break_cond = render_condition(r.condition, !r.invert);
    out += std::format("{}for (;;) {{\n", ind);
    out += header_buf;
    emitted_bindings.insert(bindings_after_header.begin(), bindings_after_header.end());
    emit_materializations_for_value(r.condition, 0, out, inner_ind);
    out += std::format("{}if ({}) break;\n", inner_ind, break_cond);
    for (std::size_t i = 1; i < r.children.size(); ++i) {
        emit_region(*r.children[i], depth + 1, out);
    }
    out += std::format("{}}}\n", ind);
}

void Emitter::emit_region_do_while(const Region& r, int depth, std::string& out) const {
    // Body runs at least once, condition tested at the tail. r.invert is
    // set when the decoded back-edge is a "loop-on-false" test — mirror it
    // here so the rendered `while (...)` expresses the actual continue
    // condition.
    const std::string ind(static_cast<std::size_t>(depth) * 2u, ' ');
    out += std::format("{}do {{\n", ind);
    for (const auto& c : r.children) emit_region(*c, depth + 1, out);
    const std::string cond = render_condition(r.condition, r.invert);
    out += std::format("{}}} while ({});\n", ind, cond);
}

void Emitter::emit_region_for(const Region& r, int depth, std::string& out) const {
    // The update slot renders the increment inst. If rendering fails
    // (pattern didn't reduce), degrade gracefully to a plain while — the
    // body will include the update statement at its natural spot.
    const std::string ind(static_cast<std::size_t>(depth) * 2u, ' ');
    const std::string update = r.has_update
        ? render_update_inst(r.update_block, r.update_inst)
        : std::string{};
    emit_materializations_for_value(r.condition, 0, out, ind);
    const std::string cond = render_condition(r.condition, r.invert);
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
    if (r.condition.kind == IrValueKind::None) {
        out += std::format("{}return;\n", ind);
        return;
    }
    if (auto k = ssa_key(r.condition); k) {
        auto s = fold_void_call_stmt.find(*k);
        if (s != fold_void_call_stmt.end()) {
            out += std::format("{}{};\n", ind, s->second);
            out += std::format("{}return;\n", ind);
            return;
        }
    }
    if (is_void_call_result(r.condition)) {
        out += std::format("{}return;\n", ind);
        return;
    }
    if (is_unbound_clobber_result(r.condition)) {
        out += std::format("{}return;\n", ind);
        return;
    }
    if (auto k = ssa_key(r.condition); k) {
        auto f = fold_return_expr.find(*k);
        if (f != fold_return_expr.end()) {
            out += std::format("{}return {};\n", ind, f->second);
            return;
        }
    }
    // Strip a redundant outer widen: in a return context the caller's
    // declared type already coerces, so `return (u64)x;` where `x` has the
    // return type reads as noise. One hop only — deeper casts are
    // semantically real.
    IrValue v = r.condition;
    if (const IrInst* d = def_of(v); d && d->src_count >= 1
            && (d->op == IrOp::ZExt || d->op == IrOp::SExt)
            && type_bits(d->srcs[0].type) <= type_bits(d->dst.type)) {
        v = d->srcs[0];
    }
    emit_materializations_for_value(v, 0, out, ind);
    out += std::format("{}return {};\n", ind, expr(v));
}

void Emitter::emit_region_switch(const Region& r, int depth, std::string& out) const {
    const std::string ind(static_cast<std::size_t>(depth) * 2u, ' ');
    const std::string_view rn = reg_name(r.switch_index);
    out += std::format("{}switch ({}) {{\n", ind,
                       rn.empty() ? std::string("<idx>") : std::string(rn));
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

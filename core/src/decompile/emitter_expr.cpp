// Expression, operator and statement rendering.

#include <algorithm>
#include <bit>
#include <cstddef>
#include <format>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include <spelunk/binary/symbol.hpp>
#include <spelunk/common/types.hpp>
#include <spelunk/disasm/register.hpp>
#include <spelunk/ir/ir.hpp>
#include <spelunk/ir/ssa.hpp>

#include "emitter_internal.hpp"
#include "emitter_text.hpp"
#include "emitter_tables.hpp"

namespace spelunk::emit {

std::string Emitter::expr(const IrValue& v, int depth, int min_prec) const {
    if (expr_memo_nesting == 0) expr_memo.clear();
    ++expr_memo_nesting;
    struct NestingGuard {
        unsigned& nesting;
        ~NestingGuard() { --nesting; }
    } guard{expr_memo_nesting};

    const auto key = ssa_key(v);
    if (!key || v.kind == IrValueKind::Imm) {
        return expr_uncached(v, depth, min_prec);
    }
    const ExprMemoKey memo_key{*key, v.type, depth, min_prec};
    if (auto found = expr_memo.find(memo_key); found != expr_memo.end()) {
        return found->second;
    }
    std::string result = expr_uncached(v, depth, min_prec);
    expr_memo.emplace(memo_key, result);
    return result;
}

std::string Emitter::expr_uncached(const IrValue& v, int depth, int min_prec) const {
    if (const auto* name = scoped_ssa_name(v)) return *name;
    if (options.c_source && is_float_type(v.type)) {
        const auto* definition = def_stripped(v);
        if (definition && definition->dst.type == IrType::I128 &&
            c_type_name_for(definition->dst) == "__m128i" &&
            !is_fp_call_return(definition->dst)) {
            const auto vector = expr(definition->dst, depth + 1);
            return v.type == IrType::F32
                ? std::format("_mm_cvtss_f32(_mm_castsi128_ps({}))", vector)
                : std::format("_mm_cvtsd_f64(_mm_castsi128_pd({}))", vector);
        }
    }
    // Recognize compiler flag-based compare idioms and emit direct C comparisons.
    if (v.type == IrType::I1 &&
        (v.kind == IrValueKind::Temp || v.kind == IrValueKind::Flag)) {
        if (auto s = try_simplify_flag(v, depth, false, false, min_prec); s) return *s;
    }
    switch (v.kind) {
        case IrValueKind::None:
            return "";
        case IrValueKind::Reg: {
            // For versioned regs, inline a trivial Imm assignment - lets the
            // absorbed call() show the actual constant instead of an orphan reg name.
            if (v.version > 0 && depth < kMaxExprDepth) {
                const IrInst* d = def_of(v);
                while (d && d->op == IrOp::Assign && d->src_count == 1) {
                    const auto& src = d->srcs[0];
                    if (src.kind == IrValueKind::Imm) return expr(src, depth + 1, min_prec);
                    if (src.kind == IrValueKind::Reg && src.version == 0) {
                        return render_reg_leaf(src.reg, src.version, depth + 1,
                                               min_prec);
                    }
                    break;
                }
            }
            return render_reg_leaf(v.reg, v.version, depth, min_prec);
        }
        case IrValueKind::Flag:
            return std::string(flag_name(v.flag));
        case IrValueKind::Imm:
            return format_imm(v);
        case IrValueKind::Temp: {
            if (auto key = ssa_key(v); key) {
                if (auto merged = merge_value_names.find(*key);
                    merged != merge_value_names.end()) return merged->second;
            }
            // A temp whose value is a stack-relative address renders as &local_X
            // at every use, so we don't need a named def line like "u64 tN = &local_X;".
            if (auto off = stack_offset(v); off) {
                return stack_address_expr(*off, &v);
            }
            // Stack loads are already a short source-level leaf.  Render
            // them even at the recursion cap so a long PPC register shuffle
            // ends at `local_34` rather than an undeclared `t14`.
            if (const IrInst* d = def_of(v);
                d && d->op == IrOp::Load && d->src_count >= 1 &&
                d->segment == Reg::None && stack_offset(d->srcs[0])) {
                return format_load_rhs(*d, depth, min_prec);
            }
            if (depth < kMaxExprDepth && should_inline(v)) {
                if (const auto* d = def_of(v)) return expand(*d, depth + 1, min_prec);
            }
            return std::format("t{}", v.temp);
        }
    }
    return "";
}

    std::string Emitter::format_load_rhs(const IrInst& d,
                                     int depth,
                                     int min_prec) const {
    if (d.op != IrOp::Load || d.src_count < 1) return "";
    if (binary && d.segment == Reg::None &&
        (d.dst.type == IrType::F32 || d.dst.type == IrType::F64)) {
        if (auto address = try_resolve_imm_addr(d.srcs[0])) {
            const addr_t va = static_cast<addr_t>(*address);
            for (const auto& section : binary->sections()) {
                const std::size_t width = type_bits(d.dst.type) / 8;
                if (section.flags.writable || section.flags.executable ||
                    va < section.vaddr || va - section.vaddr > section.size ||
                    width > section.size - (va - section.vaddr)) continue;
                const auto bytes = binary->bytes_at(va);
                if (bytes.size() < width) break;
                const u64 bits = width == 4
                    ? (binary->endian() == Endian::Little ? read_le_at<u32>(bytes.data()) : read_be_at<u32>(bytes.data()))
                    : (binary->endian() == Endian::Little ? read_le_at<u64>(bytes.data()) : read_be_at<u64>(bytes.data()));
                return format_numeric_imm(IrValue::make_imm(static_cast<i64>(bits), d.dst.type));
            }
        }
    }
    const std::string refined = c_type_name_for(d.dst);
    if (options.c_source && binary && d.segment == Reg::None &&
        (abi == Abi::SysVAmd64 || abi == Abi::Win64) &&
        d.dst.type == IrType::I128 && binary->endian() == Endian::Little) {
        if (auto address = try_resolve_imm_addr(d.srcs[0])) {
            const auto va = static_cast<addr_t>(*address);
            for (const auto& section : binary->sections()) {
                if (!section.flags.readable || section.flags.writable || section.flags.executable || va < section.vaddr ||
                    va - section.vaddr > section.size || 16 > section.size - (va - section.vaddr)) continue;
                const auto bytes = binary->bytes_at(va);
                if (bytes.size() < 16) break;
                return std::format("_mm_set_epi64x((int64_t)UINT64_C({:#x}), (int64_t)UINT64_C({:#x}))",
                    read_le_at<u64>(bytes.data() + 8), read_le_at<u64>(bytes.data()));
            }
        }
    }
    if (options.c_source && d.segment == Reg::None && !stack_offset(d.srcs[0])) {
        std::string loaded = std::format("spelunk_read_{}({})", c_memory_suffix(d.dst.type), c_address(d.srcs[0]));
        if (refined.ends_with('*')) loaded = std::format("({})(uintptr_t){}", refined, loaded);
        return loaded;
    }
    // Init-only stack slot: forward to the live-in value the entry prologue
    // stored. Keeping this in one helper prevents merge-local materializers
    // from rendering the same load as a raw `local_X` while normal expr()
    // rendering correctly says `a2`.
    if (d.segment == Reg::None) {
        if (auto off = stack_offset(d.srcs[0]); off) {
            // The forwarded value can be a reload of this same slot (a
            // register spilled back to its home); depth ends that cycle.
            if (auto it = init_only_slot_value.find(*off);
                it != init_only_slot_value.end() && depth < kMaxExprDepth) {
                return expr(it->second, depth + 1, min_prec);
            }
        }
        // The load width describes pointer storage, not its pointee.  If
        // downstream uses refined this result to T*, seed the exact global
        // slot with T* before format_mem records the raw integer width.
        if (binary && refined.ends_with('*')) {
            if (auto imm = try_resolve_imm_addr(d.srcs[0]); imm) {
                const addr_t address = normalized_address(*imm);
                if (const Symbol* symbol = binary->defined_object_at(address);
                    symbol && symbol->kind == SymbolKind::Object &&
                    symbol->addr == address) {
                    note_global_decl(*symbol, refined);
                }
            }
        }
    }
    return format_mem(d.srcs[0], d.dst.type, d.segment, depth, refined);
}

std::optional<std::string>
Emitter::try_render_ppc_int_to_float(const IrInst& subtraction,
                                     int depth) const {
    if (!is_ppc_abi() || !fn || subtraction.op != IrOp::Sub ||
        subtraction.src_count < 2 || !is_float_type(subtraction.dst.type)) {
        return std::nullopt;
    }
    const IrInst* payload_load = def_stripped(subtraction.srcs[0]);
    if (!payload_load || payload_load->op != IrOp::Load ||
        payload_load->dst.type != IrType::F64 || payload_load->src_count < 1) {
        return std::nullopt;
    }
    const auto high_word_offset = stack_offset(payload_load->srcs[0]);
    if (!high_word_offset) return std::nullopt;
    const i64 low_word_offset = *high_word_offset + 4;
    const IrValue* best_source = nullptr;
    addr_t best_address = 0;
    for (const auto& block : fn->blocks) {
        for (const IrInst& store : block.insts) {
            if (store.op != IrOp::Store || store.src_count < 2) continue;
            auto offset = stack_offset(store.srcs[0]);
            if (!offset || *offset != low_word_offset) continue;
            const IrInst* xor_value = def_stripped(store.srcs[1]);
            if (!xor_value || xor_value->op != IrOp::Xor ||
                xor_value->src_count < 2) continue;
            const IrValue* source = nullptr;
            for (u8 i = 0; i < 2; ++i) {
                if (auto mask = resolve_imm(xor_value->srcs[i]);
                    mask && static_cast<u32>(*mask) == 0x80000000u) {
                    source = &xor_value->srcs[1 - i];
                    break;
                }
            }
            if (!source) continue;
            if (payload_load->source_addr != 0 && store.source_addr != 0) {
                if (store.source_addr > payload_load->source_addr) continue;
                if (best_source && store.source_addr < best_address) continue;
            } else if (best_source) {
                continue;
            }
            best_source = source;
            best_address = store.source_addr;
        }
    }
    if (!best_source) return std::nullopt;
    const std::string target_type = subtraction.dst.type == IrType::F32
        ? "float" : "double";
    return std::format("({})(int32_t)({})", target_type,
                       expr(*best_source, depth + 1));
}

std::string Emitter::expand(const IrInst& d, int depth, int min_prec) const {
    switch (d.op) {
        case IrOp::Assign:
            return d.src_count >= 1 ? expr(d.srcs[0], depth, min_prec) : "";

        case IrOp::Add: {
            if (auto off = stack_offset(d.dst); off) {
                return stack_address_expr(*off, &d.dst);
            }
            if (is_ppc_abi()) {
                if (auto navigation = try_render_ppc_navigation_table_address(
                        d.dst, depth); navigation) return *navigation;
                if (auto table = try_render_ppc_strided_table_address(
                        d.dst, depth); table) return *table;
                if (auto address = try_resolve_imm_addr(d.dst); address) {
                    if (auto named = named_address_for_imm(normalized_address(*address)); named) {
                        return *named;
                    }
                }
            }
            if (d.src_count >= 2) {
                if (auto ivar = try_render_objc_ivar_addr_pair(d.srcs[0], d.srcs[1])) {
                    return wrap_if_lt(*ivar, Prec::Postfix, min_prec);
                }
                if (auto ivar = try_render_objc_ivar_addr_pair(d.srcs[1], d.srcs[0])) {
                    return wrap_if_lt(*ivar, Prec::Postfix, min_prec);
                }
            }
            // `Add(x, negative_imm)` reads cleaner as `Sub(x, |imm|)`:
            // `a - 7` beats `a + -7`. Skip INT64_MIN (no safe negation).
            if (d.src_count >= 2 && d.srcs[1].kind == IrValueKind::Imm &&
                d.srcs[1].imm < 0 &&
                d.srcs[1].imm > std::numeric_limits<i64>::min()) {
                IrInst rebuilt = d;
                rebuilt.op           = IrOp::Sub;
                rebuilt.srcs[1].imm  = -d.srcs[1].imm;
                return format_binop(rebuilt, "-", depth, min_prec,
                                    Prec::Add, /*commutative=*/false);
            }
            return format_binop(d, "+", depth, min_prec, Prec::Add, /*commutative=*/true);
        }
        case IrOp::Sub: {
            if (auto converted = try_render_ppc_int_to_float(d, depth); converted) {
                return wrap_if_lt(std::move(*converted), Prec::Unary, min_prec);
            }
            if (auto off = stack_offset(d.dst); off) {
                return stack_address_expr(*off, &d.dst);
            }
            if (is_ppc_abi()) {
                if (auto address = try_resolve_imm_addr(d.dst); address) {
                    if (auto named = named_address_for_imm(normalized_address(*address)); named) {
                        return *named;
                    }
                }
            }
            return format_binop(d, "-", depth, min_prec, Prec::Add, /*commutative=*/false);
        }
        case IrOp::Mul:  return format_binop(d, "*", depth, min_prec, Prec::Mul,   true);
        case IrOp::Div:  return format_binop(d, "/", depth, min_prec, Prec::Mul,   false);
        case IrOp::Mod:  return format_binop(d, "%", depth, min_prec, Prec::Mul,   false);
        case IrOp::SDiv:
        case IrOp::SMod: {
            const auto bits = type_bits(d.srcs[0].type);
            const auto left = expr(d.srcs[0], depth, 0);
            const auto right = expr(d.srcs[1], depth, 0);
            return wrap_if_lt(std::format("(int{}_t)({}) {} (int{}_t)({})",
                bits, left, d.op == IrOp::SDiv ? "/" : "%", bits, right),
                Prec::Mul, min_prec);
        }
        case IrOp::And: {
            if (is_ppc_abi()) {
                const IrValue value = d.dst.kind == IrValueKind::Temp
                    ? IrValue::make_temp(d.dst.temp, d.dst.type) : d.dst;
                if (auto scaled = match_ppc_scaled_index(value); scaled) {
                    std::string rendered = std::format(
                        "{} * {}",
                        expr(scaled->index, depth,
                             std::to_underlying(Prec::Mul)),
                        scaled->scale);
                    return wrap_if_lt(std::move(rendered), Prec::Mul, min_prec);
                }
            }
            return format_bitop(d, "&", depth, min_prec, Prec::BitAnd);
        }
        case IrOp::Or:   return format_bitop(d, "|", depth, min_prec, Prec::BitOr);
        case IrOp::Xor:  return format_bitop(d, "^", depth, min_prec, Prec::BitXor);
        case IrOp::Shl: {
            if (auto count = bounded_loop_shift_count(d)) {
                IrInst bounded = d;
                bounded.srcs[1] = *count;
                return format_binop(bounded, "<<", depth, min_prec, Prec::Shift, false);
            }
            return format_binop(d, "<<", depth, min_prec, Prec::Shift, false);
        }
        case IrOp::Lshr:
        case IrOp::Ashr: {
            const unsigned bits = type_bits(d.srcs[0].type);
            if (bits < 8 || bits > 64)
                return format_binop(d, ">>", depth, min_prec, Prec::Shift, false);
            const std::string type = std::format("{}int{}_t",
                d.op == IrOp::Ashr ? "" : "u", bits);
            std::string left = expr(d.srcs[0], depth,
                                    std::to_underlying(Prec::Unary));
            const std::string right = expr(d.srcs[1], depth,
                std::to_underlying(Prec::Shift) + 1);
            return wrap_if_lt(std::format("({}){} >> {}", type, left, right),
                               Prec::Shift, min_prec);
        }

        case IrOp::Neg: {
            std::string inner = expr(d.srcs[0], depth, std::to_underlying(Prec::Unary));
            return wrap_if_lt("-" + inner, Prec::Unary, min_prec);
        }
        case IrOp::Not: {
            const char* op = (d.dst.type == IrType::I1) ? "!" : "~";
            std::string inner = expr(d.srcs[0], depth, std::to_underlying(Prec::Unary));
            return wrap_if_lt(std::string(op) + inner, Prec::Unary, min_prec);
        }
        case IrOp::Clz:
            return std::format("count_leading_zeros({})",
                               expr(d.srcs[0], depth, 0));

        case IrOp::CmpEq:  return format_binop(d, "==", depth, min_prec, Prec::Eq,  true);
        case IrOp::CmpNe:  return format_binop(d, "!=", depth, min_prec, Prec::Eq,  true);
        case IrOp::CmpSlt:
            return render_cmp("<", d.srcs[0], d.srcs[1], depth, true, false, min_prec);
        case IrOp::CmpUlt: return format_binop(d, "<",  depth, min_prec, Prec::Rel, false);
        case IrOp::CmpSle:
            return render_cmp("<=", d.srcs[0], d.srcs[1], depth, true, false, min_prec);
        case IrOp::CmpUle: return format_binop(d, "<=", depth, min_prec, Prec::Rel, false);
        case IrOp::CmpSgt:
            return render_cmp(">", d.srcs[0], d.srcs[1], depth, true, false, min_prec);
        case IrOp::CmpUgt: return format_binop(d, ">",  depth, min_prec, Prec::Rel, false);
        case IrOp::CmpSge:
            return render_cmp(">=", d.srcs[0], d.srcs[1], depth, true, false, min_prec);
        case IrOp::CmpUge: return format_binop(d, ">=", depth, min_prec, Prec::Rel, false);

        case IrOp::ZExt:
        case IrOp::SExt:
        case IrOp::Trunc: {
            const IrValue& src = d.srcs[0];
            // No-op: cast to the same type the value already has.
            if (src.type == d.dst.type) {
                return expr(src, depth, min_prec);
            }
            // If the header already narrowed this live-in arg to the cast's
            // destination type, repeating `(u32)a1` at every use just leaks
            // ABI width back into otherwise source-like output.
            if (auto slot = trace_to_self_arg_slot(src);
                d.op != IrOp::SExt && slot && *slot < self_arg_type_overrides.size() &&
                self_arg_type_overrides[*slot] &&
                *self_arg_type_overrides[*slot] == d.dst.type) {
                return expr(src, depth, min_prec);
            }
            // A generated source-level parameter name is already a semantic
            // value, not an architectural register width. When a call
            // argument was packed as zext(trunc(param)), render the param
            // directly instead of `(u32)x`.
            if ((d.op == IrOp::ZExt || d.op == IrOp::SExt) &&
                (type_bits(d.dst.type) > type_bits(src.type))) {
                if (const IrInst* inner = def_stripped(src);
                    inner && inner->op == IrOp::Trunc && inner->src_count >= 1) {
                    if (auto slot = trace_to_self_arg_slot(inner->srcs[0]);
                        slot && *slot < self_arg_names.size() &&
                        !self_arg_names[*slot].empty()) {
                        const auto declared_signedness =
                            declared_arg_signedness_for_width(
                                *slot, inner->dst.type);
                        const bool signed_extension = d.op == IrOp::SExt;
                        if (declared_signedness &&
                            *declared_signedness == signed_extension) {
                            return expr(inner->srcs[0], depth, min_prec);
                        }
                    }
                }
            }
            // The call-result inliner already proved this call has exactly
            // one use inside this return expression. If the compiler then
            // narrows it for a 32-bit add, prefer `foo(x) + 1` over
            // `(u32)foo(x) + 1`; the source-level call carries the intent.
            if (d.op == IrOp::Trunc) {
                if (auto k = ssa_key(src); k && inline_call_expr.contains(*k)) {
                    return expr(src, depth, min_prec);
                }
                if (d.dst.type == IrType::I8) {
                    if (auto b = match_low_byte_setcc_merge(src); b) {
                        std::string pred;
                        if (auto s = try_simplify_flag(*b, depth + 1,
                                                       /*negate=*/false,
                                                       /*in_bool_ctx=*/false,
                                                       std::to_underlying(Prec::Unary));
                            s) {
                            pred = *s;
                        } else {
                            pred = expr(*b, depth + 1, std::to_underlying(Prec::Unary));
                        }
                        return wrap_if_lt(std::format("({})({})",
                                                      c_type_name(IrType::I8),
                                                      pred),
                                          Prec::Unary, min_prec);
                    }
                }
            }
            // `zext(trunc(x, T))` → `(T)x`. The trunc already produces the
            // observable value; widening back to a bigger type is redundant
            // for the reader.
            if (d.op == IrOp::ZExt) {
                if (const IrInst* inner = def_stripped(src);
                    inner && inner->op == IrOp::Trunc && inner->src_count >= 1 &&
                    type_bits(inner->dst.type) <= type_bits(d.dst.type)) {
                    std::string casted = std::format(
                        "({}){}",
                        c_type_name(inner->dst.type),
                        expr(inner->srcs[0], depth, std::to_underlying(Prec::Unary)));
                    return wrap_if_lt(std::move(casted), Prec::Unary, min_prec);
                }
            }
            if (d.op == IrOp::SExt && type_bits(src.type) < type_bits(d.dst.type) &&
                type_bits(d.dst.type) <= 64) {
                // Interpret the source sign bit before widening; casting an
                // unsigned source straight to the destination zero-extends it.
                const std::string value = expr(src, depth, std::to_underlying(Prec::Unary));
                const std::string signed_value = src.type == IrType::I1
                    ? std::format("(-({}))", value)
                    : std::format("(int{}_t){}", type_bits(src.type), value);
                return wrap_if_lt(std::format("({}){}", c_type_name(d.dst.type), signed_value),
                                  Prec::Unary, min_prec);
            }
            std::string casted = std::format(
                "({}){}",
                c_type_name(d.dst.type),
                expr(src, depth, std::to_underlying(Prec::Unary)));
            return wrap_if_lt(std::move(casted), Prec::Unary, min_prec);
        }

        case IrOp::FpToInt: {
            std::string casted = std::format(
                "(int32_t){}",
                expr(d.srcs[0], depth, std::to_underlying(Prec::Unary)));
            return wrap_if_lt(std::move(casted), Prec::Unary, min_prec);
        }

        case IrOp::Load: {
            return format_load_rhs(d, depth, min_prec);
        }

        case IrOp::AddCarry:
            return std::format("carry_add({}, {})",
                               expr(d.srcs[0], depth, 0), expr(d.srcs[1], depth, 0));
        case IrOp::SubBorrow:
            return std::format("borrow_sub({}, {})",
                               expr(d.srcs[0], depth, 0), expr(d.srcs[1], depth, 0));
        case IrOp::AddOverflow:
            return std::format("overflow_add({}, {})",
                               expr(d.srcs[0], depth, 0), expr(d.srcs[1], depth, 0));
        case IrOp::SubOverflow:
            return std::format("overflow_sub({}, {})",
                               expr(d.srcs[0], depth, 0), expr(d.srcs[1], depth, 0));

        case IrOp::Intrinsic:
            return render_intrinsic_call(d, depth);

        case IrOp::Select: {
            if (d.src_count < 3) return std::format("t{}", d.dst.temp);
            // C's `?:` precedence sits above assignment but below most other
            // operators; wrap in parens whenever the surrounding context isn't
            // already paren-bounded so the reader doesn't have to think.
            std::string c = expr(d.srcs[0], depth, std::to_underlying(Prec::LogOr));
            std::string a = expr(d.srcs[1], depth, std::to_underlying(Prec::Cond));
            std::string b = expr(d.srcs[2], depth, std::to_underlying(Prec::Cond));
            if (options.c_source && !is_float_type(d.dst.type) && type_bits(d.dst.type) <= 64) {
                const auto type = c_type_name_for(d.dst);
                a = std::format("({})(uintptr_t)({})", type, a);
                b = std::format("({})(uintptr_t)({})", type, b);
            }
            return wrap_if_lt(std::format("{} ? {} : {}", c, a, b),
                              Prec::Cond, min_prec);
        }

        default:
            return std::format("t{}", d.dst.temp);
    }
}

// Peephole: `store addr, (op load(addr), K)` → `<name> += K;` / `--name;` etc.
// `lhs_text` is the already-rendered name of the storage location (stack,
// global, or `*(T*)…`). Returns empty if no idiom match; caller falls back
// to `lhs = expr;`.
std::string Emitter::try_compound_store(std::string_view lhs_text,
                                        const IrValue& addr,
                                        const IrValue& val) const {
    // val must be a binary op we know how to compound-assign.
    IrValue core = val;
    const IrInst* d = def_stripped(core);
    for (int depth = 0; d && depth < 6 &&
         (d->op == IrOp::Trunc || d->op == IrOp::ZExt || d->op == IrOp::SExt) &&
         d->src_count >= 1; ++depth) {
        core = d->srcs[0];
        d = def_stripped(core);
    }
    if (!d || d->src_count < 2) return {};

    std::string_view op_text;
    switch (d->op) {
        case IrOp::Add:  op_text = "+"; break;
        case IrOp::Sub:  op_text = "-"; break;
        case IrOp::Mul:  op_text = "*"; break;
        case IrOp::And:  op_text = "&"; break;
        case IrOp::Or:   op_text = "|"; break;
        case IrOp::Xor:  op_text = "^"; break;
        case IrOp::Shl:  op_text = "<<"; break;
        case IrOp::Lshr: op_text = ">>"; break;
        case IrOp::Ashr: op_text = ">>"; break;
        default: return {};
    }

    // LHS of the binop must be a Load of the same storage as `addr`. For
    // commutative ops we also accept the RHS as the load.
    const bool commutative = d->op == IrOp::Add || d->op == IrOp::Mul ||
                             d->op == IrOp::And || d->op == IrOp::Or  ||
                             d->op == IrOp::Xor;

    auto is_load_of_same_addr = [&](const IrValue& v) {
        IrValue candidate = v;
        const IrInst* ld = def_stripped(candidate);
        for (int depth = 0; ld && depth < 6 &&
             (ld->op == IrOp::Trunc || ld->op == IrOp::ZExt ||
              ld->op == IrOp::SExt) && ld->src_count >= 1; ++depth) {
            candidate = ld->srcs[0];
            ld = def_stripped(candidate);
        }
        if (!ld || ld->op != IrOp::Load || ld->src_count < 1) return false;
        if (same_ssa(ld->srcs[0], addr)) return true;
        return format_mem(ld->srcs[0], ld->dst.type, ld->segment) == lhs_text;
    };

    const IrValue* delta = nullptr;
    if (is_load_of_same_addr(d->srcs[0])) {
        delta = &d->srcs[1];
    } else if (commutative && is_load_of_same_addr(d->srcs[1])) {
        delta = &d->srcs[0];
    } else {
        return {};
    }

    // Integer +/- 1 collapses further to ++/--.
    if ((d->op == IrOp::Add || d->op == IrOp::Sub) &&
        delta->kind == IrValueKind::Imm && delta->imm == 1 &&
        !is_float_type(val.type)) {
        const char* sym = (d->op == IrOp::Add) ? "++" : "--";
        return std::format("{}{};", lhs_text, sym);
    }
    if (d->op == IrOp::And && delta->kind == IrValueKind::Imm) {
        const unsigned bits = std::min<unsigned>(32, std::max<unsigned>(
            1, type_bits(val.type)));
        const u64 width_mask = bits == 32
            ? 0xffffffffull : ((u64{1} << bits) - 1);
        const u64 cleared = (~static_cast<u64>(delta->imm)) & width_mask;
        if (cleared != 0 && std::has_single_bit(cleared)) {
            return std::format("{} &= ~{:#x};", lhs_text, cleared);
        }
    }
    return std::format("{} {}= {};", lhs_text, op_text, expr(*delta));
}

std::string Emitter::format_store(const IrInst& inst) const {
    if (inst.src_count < 2) return "";
    const auto& addr = inst.srcs[0];
    const auto& val  = inst.srcs[1];
    // An SEH frame's try level says which __try block is active.
    if (seh_try_level && !options.c_source && inst.segment == Reg::None &&
        entry_stack_offset(addr) == seh_try_level) {
        if (const auto level = resolve_imm(val)) {
            if (inst.source_addr == seh_frame_store) {
                const auto name = [&](const std::optional<u64>& at) {
                    return at ? function_display_name(static_cast<addr_t>(*at))
                              : std::string("?");
                };
                return std::format("/* SEH frame: handler {}, scope table {:#x} */",
                                   name(seh_handler), seh_scope_table.value_or(0));
            }
            if (*level < 0) return "/* leave __try */";
            return std::format("/* __try level {} */", *level);
        }
    }
    if (options.c_source && inst.segment == Reg::None && !stack_offset(addr)) {
        const std::string value = (is_float_type(val.type) || type_bits(val.type) > 64) ? expr(val)
            : std::format("({})(uintptr_t)({})", c_type_name(val.type), expr(val));
        return std::format("spelunk_write_{}({}, {});", c_memory_suffix(val.type), c_address(addr), value);
    }
    std::string lhs;
    if (inst.segment == Reg::None) {
        if (auto off = stack_offset(addr); off) {
            // Dead-spill suppression: drop the store only when the slot has no
            // explicit reader and its address never escapes. Escaped slots are
            // observable through calls, returned/stored pointers, and other
            // indirect consumers even when no IR Load reads them locally.
            const bool observable = loaded_stack_slots.contains(*off);
            const bool init_only  = init_only_slot_value.contains(*off);
            if (!observable || init_only) {
                auto it = frame_layout.slots.find(*off);
                const bool user_named =
                    it != frame_layout.slots.end() &&
                    !it->second.type_override.empty();
                if (!user_named) return "";
            }
            if (auto field = imported_stack_field(*off, val.type); field) {
                lhs = *field;
            } else if (auto interior = stack_storage_access(*off, val.type);
                       !interior.empty()) {
                lhs = std::move(interior);
            } else {
                // Same precedence as format_mem: a real frame-layout name,
                // then the incoming parameter the slot holds, then the
                // synthetic slot name.
                auto it = frame_layout.slots.find(*off);
                const bool has_name =
                    it != frame_layout.slots.end() && !it->second.name.empty();
                if (has_name && it->second.name != stack_name(*off)) {
                    lhs = it->second.name;
                } else if (auto arg = incoming_stack_arg_name(addr, *off)) {
                    lhs = *arg;
                } else {
                    lhs = has_name ? it->second.name : stack_name(*off);
                }
            }
        }
    }
    if (lhs.empty()) {
        lhs = format_mem(addr, val.type, inst.segment, 0, c_type_name_for(val));
    }
    if (annotations && inst.segment == Reg::None) {
        if (auto off = stack_offset(addr); off) {
            auto slot = frame_layout.slots.find(*off);
            if (slot != frame_layout.slots.end() &&
                !slot->second.type_override.empty() &&
                lhs == slot->second.name) {
                const std::string record_name = imported_record_base(
                    slot->second.type_override);
                auto record = annotations->imported_records.find(record_name);
                const std::size_t value_size = std::max<unsigned>(
                    1, type_bits(val.type) / 8);
                if (record != annotations->imported_records.end() &&
                    record->second.size == value_size &&
                    (value_size == 1 || value_size == 2 ||
                     value_size == 4 || value_size == 8)) {
                    return std::format("{} = ({}){{ ._raw = {} }};",
                                       lhs, record_name, expr(val));
                }
            }
        }
    }
    if (auto compound = try_compound_store(lhs, addr, val); !compound.empty()) {
        return compound;
    }
    const std::string rhs = options.c_source && !is_float_type(val.type) && type_bits(val.type) <= 64
        ? std::format("({})(uintptr_t)({})", c_type_name(val.type), expr(val)) : expr(val);
    // A register reloaded from its stack home and spilled straight back.
    if (lhs == rhs && inst.segment == Reg::None && stack_offset(addr)) return "";
    return std::format("{} = {};", lhs, rhs);
}

namespace {

// Bytes per element of a REP MOVS/STOS intrinsic; 0 for anything else.
u64 rep_string_element(std::string_view name) noexcept {
    if (!name.starts_with("rep.movs") && !name.starts_with("rep.stos")) return 0;
    switch (name.back()) {
        case 'b': return 1;
        case 'w': return 2;
        case 'd': return 4;
        case 'q': return 8;
        default:  return 0;
    }
}

}  // namespace

// MSVC inlines memcpy/memset of n bytes as `rep movsd` of n >> 2 dwords and
// then `rep movsb` of the n & 3 bytes left. Returns the tail's index after
// the head at `index`, with nothing observable between them.
std::optional<std::size_t>
Emitter::rep_string_tail(const IrBlock& block, std::size_t index) const {
    const IrInst& head = block.insts[index];
    const u64 element = rep_string_element(head.name);
    if (element <= 1 || head.src_count < 3) return std::nullopt;
    const IrInst* split = def_stripped(head.srcs[2]);
    if (!split || split->op != IrOp::Lshr || split->src_count < 2 ||
        resolve_imm(split->srcs[1]) != std::countr_zero(element)) return std::nullopt;
    const auto whole = [&](const IrValue& value) -> std::optional<SsaKey> {
        const IrInst* d = def_stripped(value);
        return d ? ssa_key(d->dst) : ssa_key(value);
    };
    const auto total = whole(split->srcs[0]);
    if (!total) return std::nullopt;
    const std::string tail_name = std::format("{}b", head.name.substr(0, head.name.size() - 1));
    for (std::size_t i = index + 1; i < block.insts.size(); ++i) {
        const IrInst& inst = block.insts[i];
        if (inst.op == IrOp::Intrinsic) {
            if (inst.name != tail_name || inst.src_count < 3) return std::nullopt;
            const IrInst* rest = def_stripped(inst.srcs[2]);
            if (!rest || rest->op != IrOp::And || rest->src_count < 2 ||
                resolve_imm(rest->srcs[1]) != static_cast<i64>(element - 1) ||
                whole(rest->srcs[0]) != total) return std::nullopt;
            return i;
        }
        if (inst.op == IrOp::Store || inst.op == IrOp::Call ||
            inst.op == IrOp::CallIndirect || is_terminator(inst.op)) return std::nullopt;
    }
    return std::nullopt;
}

// `rep movs` / `rep stos` as the memcpy / memset they perform.
std::optional<std::string> Emitter::render_rep_string_statement(const IrInst& inst) const {
    const u64 element = rep_string_element(inst.name);
    if (!element || inst.src_count < 3 || !fn) return std::nullopt;
    const IrBlock* block = nullptr;
    std::size_t index = 0;
    for (const auto& bb : fn->blocks) {
        if (bb.insts.empty() || &inst < &bb.insts.front() || &inst > &bb.insts.back()) continue;
        block = &bb;
        index = static_cast<std::size_t>(&inst - bb.insts.data());
    }
    if (!block) return std::nullopt;
    const bool fill = inst.name.starts_with("rep.stos");
    // A fill value replicated into every byte is a memset; others are not.
    std::optional<std::string> fill_byte;
    if (fill) {
        if (element == 1) {
            fill_byte = expr(inst.srcs[1]);
        } else if (auto value = resolve_imm(inst.srcs[1])) {
            const u64 bits = static_cast<u64>(*value) & (element == 8 ? ~u64{0}
                : (u64{1} << (element * 8)) - 1);
            const u64 low = bits & 0xff;
            u64 splat = 0;
            for (u64 i = 0; i < element; ++i) splat |= low << (i * 8);
            if (splat == bits) fill_byte = format_numeric_imm(IrValue::make_imm(static_cast<i64>(low), IrType::I32));
        }
        if (!fill_byte) return std::nullopt;
    }
    if (element == 1 && index > 0) {
        // The tail of a merged pair renders with its head.
        for (std::size_t i = index; i-- > 0;) {
            const IrInst& prior = block->insts[i];
            if (prior.op != IrOp::Intrinsic) continue;
            if (rep_string_tail(*block, i) == index) return std::string{};
            break;
        }
    }
    std::string bytes;
    if (auto tail = rep_string_tail(*block, index)) {
        bytes = expr(def_stripped(inst.srcs[2])->srcs[0]);
    } else if (auto count = resolve_imm(inst.srcs[2])) {
        bytes = format_numeric_imm(IrValue::make_imm(
            static_cast<i64>(static_cast<u64>(*count) * element), IrType::I32));
    } else if (element == 1) {
        bytes = expr(inst.srcs[2]);
    } else {
        bytes = std::format("{} * {}", expr(inst.srcs[2], 0, std::to_underlying(Prec::Mul)), element);
    }
    if (fill) return std::format("memset({}, {}, {});", expr(inst.srcs[0]), *fill_byte, bytes);
    return std::format("memcpy({}, {}, {});", expr(inst.srcs[0]), expr(inst.srcs[1]), bytes);
}

std::string Emitter::format_stmt(const IrInst& inst) const {
    if (auto name = merge_assignment_name_for(inst)) {
        return format_merge_assignment(inst, *name);
    }
    switch (inst.op) {
        case IrOp::Store:
            return format_store(inst);

        case IrOp::Assign: {
            if (inst.src_count < 1) return "";
            if (inst.dst.kind == IrValueKind::Reg) {
                // Register Assigns are aliases.  When render_reg_leaf can
                // already chase the destination to a source expression, an
                // explicit `f31 = value;`/`r30 = ptr;` line is dead
                // architectural noise even when the alias has several uses.
                if ((is_ppc_abi() || options.c_source) &&
                    !renders_raw_arch_reg_name(inst.dst)) return "";
                // With rvalue forwarding in render_reg_leaf, a single reader
                // inlines the source expression directly. The `reg = expr;`
                // line becomes redundant in that case.
                //
                // Exception: a Reg assign whose only readers are Phi
                // operands is the per-iteration update of a loop induction
                // variable - visible_use_count excludes phi reads, so the
                // count looks like 0 even though the value drives the loop.
                // Without surfacing the assign, accumulator loops decompile
                // to `do { } while (cond)` with the body work invisible.
                // Detect by comparing the visible count (excludes phi) to
                // the broader semantic count (includes phi).
                if (visible_use_count(inst.dst) <= 1) {
                    auto k = ssa_key(inst.dst);
                    const u32 vis = visible_use_count(inst.dst);
                    const u32 all = k ? use_count_by_key(*k) : 0u;
                    if (all <= vis) return "";
                }
                return std::format("{} = {};",
                                   display_reg_name(inst.dst.reg), expr(inst.srcs[0]));
            }
            if (inst.dst.kind == IrValueKind::Flag) {
                if (use_count(inst.dst) == 0) return "";
                return std::format("{} = {};",
                                   flag_name(inst.dst.flag), expr(inst.srcs[0]));
            }
            if (inst.dst.kind == IrValueKind::Temp) {
                if (use_count(inst.dst) <= 1) return "";
                return std::format("{} t{} = {};",
                                   c_type_name_for(inst.dst),
                                   inst.dst.temp,
                                   expr(inst.srcs[0]));
            }
            return "";
        }

        case IrOp::Load: {
            if (is_canary_value_load(inst) || renders_stack_chk_guard_load(inst)) return "";
            const auto load_key = ssa_key(inst.dst);
            const bool snapshot = load_key &&
                memory_snapshot_loads.contains(*load_key);
            if (use_count(inst.dst) == 0 && !snapshot) return "";
            // Loads that cross a possible memory mutation must bind here even
            // with one eventual use. Other single-use and cheap multi-use
            // loads remain inline.
            if (should_inline(inst.dst)) return "";
            const std::string type = c_type_name_for(inst.dst);
            std::string initializer = format_load_rhs(inst);
            bool already_typed = !options.c_source && declared_pointer_type(inst.dst) == type;
            if (auto access = canonical_struct_access(inst.srcs[0]); access) {
                if (auto member = synthetic_member_type(
                        access->first, access->second); member) {
                    already_typed = normalize_c_type_alias(*member) == type;
                }
            }
            if (type.ends_with('*') && !already_typed &&
                !initializer.starts_with('(') && initializer != "NULL") {
                initializer = std::format("({}){}", type, initializer);
            }
            return std::format("{} t{} = {};", type, inst.dst.temp,
                               initializer);
        }

        case IrOp::Intrinsic: {
            // CET markers are emitted at every function entry on toolchains
            // with -fcf-protection (Ubuntu 24.04's gcc-14 defaults to it).
            // They're NOPs semantically, so suppress them from the output.
            if (inst.name == "endbr64" || inst.name == "endbr32") return "";
            std::string args;
            for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i) {
                if (i > 0) args += ", ";
                args += expr(inst.srcs[i], 0, 0);
            }
            // `x64.*` tags a raw x86 mnemonic the lifter couldn't model
            // in the IR (SIMD, FPU, system ops). Render it as a block
            // comment so the reader sees the elision rather than an
            // imaginary C call. The rest - explicit intrinsics like
            // `sqrtss(x)` that the lifter emits deliberately - stay as
            // calls because they carry real dataflow.
            if (inst.name.starts_with("x64.")) {
                if (options.c_source) {
                    return std::format("/* unresolved intrinsic: {}({}) */", inst.name, args);
                }
                return std::format("/* {}({}) */", inst.name, args);
            }
            if (inst.name.starts_with("ppc.ps_cmp") &&
                inst.dst.kind == IrValueKind::Flag && use_count(inst.dst) == 0) {
                // Paired-single compare helpers are pure value producers for
                // the four CR bits. Do not print unused LT/GT/EQ lanes as
                // misleading standalone calls when only one condition flows
                // into the structured branch.
                return "";
            }
            if (!options.c_source && inst.dst.kind == IrValueKind::None) {
                if (auto memory = render_rep_string_statement(inst)) return *memory;
            }
            // If the intrinsic produces a value that survives downstream,
            // bind it to a named temp so subsequent reads have something
            // to refer to. Otherwise emit as a void statement.
            const std::string call = render_intrinsic_call(inst);
            if (inst.dst.kind == IrValueKind::Temp &&
                visible_use_count(inst.dst) > 0) {
                return std::format("{} t{} = {};",
                                   c_type_name_for(inst.dst),
                                   inst.dst.temp, call);
            }
            if (inst.dst.kind == IrValueKind::Reg &&
                visible_use_count(inst.dst) > 0) {
                return std::format("{} = {};", display_reg_name(inst.dst.reg), call);
            }
            if (inst.dst.kind == IrValueKind::Flag && use_count(inst.dst) > 0) {
                return std::format("{} = {};", flag_name(inst.dst.flag), call);
            }
            return std::format("{};", call);
        }

        default:
            if (inlinable_op(inst.op) && inst.dst.kind == IrValueKind::Temp) {
                if (visible_use_count(inst.dst) <= 1) return "";
                if (stack_offset(inst.dst).has_value()) return "";
                // Suppress the declaration when this temp's only consumers
                // are flag-set instructions - those will inline the
                // expression when they themselves render.
                if (is_flag_feeder_temp(inst.dst)) return "";
                // Low-byte boolean merges (`x & ~0xff | bool`) are usually
                // compiler plumbing before a byte test. Rendering the carrier
                // temp as `tN = ...` leaves dead-looking noise after the
                // condition itself has simplified.
                if (match_low_byte_setcc_merge(inst.dst)) return "";
                const std::string type = c_type_name_for(inst.dst);
                std::string initializer = expand(inst, 0);
                if (type.ends_with('*') && (options.c_source || declared_pointer_type(inst.dst) != type) &&
                    !initializer.starts_with('(') &&
                    initializer != "NULL") {
                    initializer = std::format("({})({})", type, initializer);
                }
                return std::format("{} t{} = {};", type, inst.dst.temp,
                                   initializer);
            }
            return "";
    }
}

std::string Emitter::format_binop(const IrInst& d, std::string_view op,
                                        int depth, int min_prec,
                                        Prec self_prec,
                                        bool commutative) const {
    const int p = static_cast<int>(self_prec);
    if (options.c_source && (d.op == IrOp::Add || d.op == IrOp::Sub || d.op == IrOp::Mul) &&
        !is_float_type(d.dst.type) && type_bits(d.dst.type) <= 64) {
        return std::format("({})((uint64_t)(uintptr_t)({}) {} (uint64_t)(uintptr_t)({}))",
            c_type_name_for(d.dst), expr(d.srcs[0], depth + 1), op, expr(d.srcs[1], depth + 1));
    }
    if (is_ppc_abi() && binary && d.op == IrOp::Add && d.src_count >= 2) {
        for (u8 base_i = 0; base_i < 2; ++base_i) {
            auto address = try_resolve_imm_addr(d.srcs[base_i]);
            auto scaled = match_ppc_scaled_index(d.srcs[1 - base_i]);
            if (!address || !scaled || scaled->scale <= 0) continue;
            const Symbol* symbol = binary->defined_object_at(
                normalized_address(*address));
            if (!symbol || symbol->addr != normalized_address(*address) ||
                symbol->name.empty()) continue;
            const std::string name = global_display_name(*symbol);
            auto table = ppc_strided_tables.find(name);
            if (table == ppc_strided_tables.end()) {
                if (symbol->size == 0 || scaled->scale <= 4 ||
                    symbol->size % static_cast<u64>(scaled->scale) != 0) {
                    continue;
                }
                auto [created, _] = ppc_strided_tables.try_emplace(name);
                created->second.type_name = ppc_strided_tables.size() == 1
                    ? "PpcDataEntry"
                    : std::format("PpcDataEntry{}", ppc_strided_tables.size());
                created->second.stride =
                    static_cast<std::size_t>(scaled->scale);
                global_decls[name] = created->second.type_name + "[]";
                table = created;
            }
            if (table->second.stride !=
                static_cast<std::size_t>(scaled->scale)) continue;
            return wrap_if_lt(std::format("&{}[{}]", name,
                expr(scaled->index, depth + 1,
                     std::to_underlying(Prec::Postfix))),
                Prec::Unary, min_prec);
        }
    }
    if (d.op == IrOp::Add && d.src_count >= 2) {
        if (auto off = resolve_imm(d.srcs[1]); off) {
            if (auto field = imported_global_object_field(d.srcs[0], *off); field) {
                return wrap_if_lt(*field, Prec::Postfix, min_prec);
            }
            if (auto field = imported_global_pointer_field(d.srcs[0], *off); field) {
                return wrap_if_lt(*field, Prec::Postfix, min_prec);
            }
            if (auto field = imported_typed_pointer_field(d.srcs[0], *off, depth); field) {
                return wrap_if_lt(*field, Prec::Postfix, min_prec);
            }
        }
        if (auto off = resolve_imm(d.srcs[0]); off) {
            if (auto field = imported_global_object_field(d.srcs[1], *off); field) {
                return wrap_if_lt(*field, Prec::Postfix, min_prec);
            }
            if (auto field = imported_global_pointer_field(d.srcs[1], *off); field) {
                return wrap_if_lt(*field, Prec::Postfix, min_prec);
            }
            if (auto field = imported_typed_pointer_field(d.srcs[1], *off, depth); field) {
                return wrap_if_lt(*field, Prec::Postfix, min_prec);
            }
        }
    }
    if ((d.op == IrOp::Add || d.op == IrOp::Sub) && d.src_count >= 2) {
        const auto declared_pointer_type = [&](const IrValue& value) {
            std::string type = c_type_name_for(value);
            if (!annotations || !fn) return type;
            const auto slot = trace_pointer_alias_to_self_arg_slot(value);
            const FunctionSig* signature = annotations->signature_for(fn->start);
            if (!slot || !signature || *slot >= signature->params.size()) {
                return type;
            }
            const std::string declared =
                normalize_c_type_alias(signature->params[*slot].type);
            return declared.ends_with('*') ? declared : type;
        };
        const std::string lhs_type = declared_pointer_type(d.srcs[0]);
        const std::string rhs_type = declared_pointer_type(d.srcs[1]);
        const bool lhs_pointer = lhs_type.ends_with('*') ||
            pointer_pointee_size(d.srcs[0]).has_value();
        const bool rhs_pointer = rhs_type.ends_with('*') ||
            pointer_pointee_size(d.srcs[1]).has_value();
        const auto byte_pointer_type_for = [](std::string_view first,
                                              std::string_view second = {}) {
            std::string result;
            const auto pointee = [](std::string_view type) {
                return type.substr(0, type.rfind('*'));
            };
            const std::string_view first_pointee = pointee(first);
            const std::string_view second_pointee = pointee(second);
            if (text_contains_identifier(first_pointee, "const") ||
                text_contains_identifier(second_pointee, "const")) {
                result += "const ";
            }
            if (text_contains_identifier(first_pointee, "volatile") ||
                text_contains_identifier(second_pointee, "volatile")) {
                result += "volatile ";
            }
            result += "uint8_t*";
            return result;
        };

        if (d.op == IrOp::Sub && lhs_pointer && rhs_pointer) {
            const std::string byte_pointer_type =
                byte_pointer_type_for(lhs_type, rhs_type);
            std::string rendered = std::format(
                "({}){} - ({}){}",
                byte_pointer_type,
                expr(d.srcs[0], depth, std::to_underlying(Prec::Unary)),
                byte_pointer_type,
                expr(d.srcs[1], depth, std::to_underlying(Prec::Unary)));
            return wrap_if_lt(std::move(rendered), Prec::Add, min_prec);
        }

        const IrValue* base = nullptr;
        const IrValue* offset = nullptr;
        bool subtract = d.op == IrOp::Sub;
        if (lhs_pointer) {
            base = &d.srcs[0];
            offset = &d.srcs[1];
        } else if (!subtract && rhs_pointer) {
            base = &d.srcs[1];
            offset = &d.srcs[0];
        }
        if (base && offset) {
            if (auto size = pointer_pointee_size(*base); size && *size != 0) {
                std::optional<IrValue> index;
                if (offset->kind == IrValueKind::Imm &&
                    offset->imm % static_cast<i64>(*size) == 0) {
                    index = IrValue::make_imm(
                        offset->imm / static_cast<i64>(*size), offset->type);
                } else if (auto scaled = match_ppc_scaled_index(*offset);
                           scaled && scaled->scale == static_cast<i64>(*size)) {
                    index = scaled->index;
                } else if (const IrInst* fallback_scale = def_stripped(*offset);
                           fallback_scale && fallback_scale->src_count >= 2) {
                    if (fallback_scale->op == IrOp::Mul) {
                        for (u8 i = 0; i < 2; ++i) {
                            if (auto factor = resolve_imm(fallback_scale->srcs[i]);
                                factor == static_cast<i64>(*size)) {
                                index = fallback_scale->srcs[1 - i];
                                break;
                            }
                        }
                    } else if (fallback_scale->op == IrOp::Shl) {
                        if (auto shift = resolve_imm(fallback_scale->srcs[1]);
                            shift && *shift >= 0 && *shift < 63 &&
                            (u64{1} << *shift) == *size) {
                            index = fallback_scale->srcs[0];
                        }
                    }
                }
                if (index) {
                    std::string rendered = std::format(
                        "{} {} {}",
                        expr(*base, depth, std::to_underlying(Prec::Add)),
                        subtract ? "-" : "+",
                        expr(*index, depth, std::to_underlying(Prec::Add)));
                    return wrap_if_lt(std::move(rendered), Prec::Add, min_prec);
                }
            }
            const std::string base_type = declared_pointer_type(*base);
            const std::string byte_pointer_type =
                byte_pointer_type_for(base_type);
            const auto finish_byte_address = [&](std::string rendered) {
                if (!base_type.ends_with('*')) {
                    return wrap_if_lt(
                        std::move(rendered), Prec::Add, min_prec);
                }
                return wrap_if_lt(
                    std::format("({})({})", base_type, rendered),
                    Prec::Unary, min_prec);
            };
            if (offset->kind != IrValueKind::Imm) {
                std::string rendered = std::format(
                    "({}){} {} {}",
                    byte_pointer_type,
                    expr(*base, depth, std::to_underlying(Prec::Unary)),
                    subtract ? "-" : "+",
                    expr(*offset, depth, std::to_underlying(Prec::Add) +
                        (subtract ? 1 : 0)));
                return finish_byte_address(std::move(rendered));
            }
            std::string rendered = std::format(
                "({}){} {} {}",
                byte_pointer_type,
                expr(*base, depth, std::to_underlying(Prec::Unary)),
                subtract ? "-" : "+", format_numeric_imm(*offset));
            return finish_byte_address(std::move(rendered));
        }
    }
    // Left operand can share our precedence (left-assoc). Right operand
    // of a non-commutative op must bind strictly tighter to avoid
    // reassociation — e.g. `a - (b - c)` must stay parenthesized.
    const bool pointer_arith =
        (d.op == IrOp::Add || d.op == IrOp::Sub) &&
        (d.srcs[0].type == IrType::I64 || d.srcs[1].type == IrType::I64 ||
         d.dst.type == IrType::I64);
    auto render = [&](const IrValue& v, int operand_prec) {
        return pointer_arith && v.kind == IrValueKind::Imm
            ? format_numeric_imm(v)
            : expr(v, depth, operand_prec);
    };
    std::string L = render(d.srcs[0], p);
    std::string R = render(d.srcs[1], commutative ? p : p + 1);
    std::string result = std::format("{} {} {}", L, op, R);
    return wrap_if_lt(std::move(result), self_prec, min_prec);
}

std::string Emitter::format_bitop(const IrInst& d, std::string_view op,
                                        int depth, int min_prec,
                                        Prec self_prec) const {
    const int p = static_cast<int>(self_prec);
    // A comparison binds tighter than `& | ^`, so C reads `a < b ^ c` the way
    // the flag semantics mean it - but both gcc and clang warn, and a reader
    // has to stop and check. Parenthesize comparison operands explicitly.
    const auto comparison = [&](const IrValue& v) {
        const IrInst* definition = def_stripped(v);
        if (!definition) return false;
        switch (definition->op) {
            case IrOp::CmpEq:  case IrOp::CmpNe:
            case IrOp::CmpSlt: case IrOp::CmpUlt:
            case IrOp::CmpSle: case IrOp::CmpUle:
            case IrOp::CmpSgt: case IrOp::CmpUgt:
            case IrOp::CmpSge: case IrOp::CmpUge:
            case IrOp::SubBorrow: return true;
            default: return false;
        }
    };
    auto render = [&](const IrValue& v) -> std::string {
        if (comparison(v)) {
            return std::format("({})", expr(v, depth, 0));
        }
        if (v.kind == IrValueKind::Imm && v.imm < 0) {
            const u64 absv =
                static_cast<u64>(0) - static_cast<u64>(v.imm);
            if (absv >= 2 && (absv & (absv - 1)) == 0) {
                return std::format("~{:#x}", absv - 1);
            }
        }
        return expr(v, depth, p);
    };
    std::string L = render(d.srcs[0]);
    std::string R = render(d.srcs[1]);
    return wrap_if_lt(std::format("{} {} {}", L, op, R),
                      self_prec, min_prec);
}

}  // namespace spelunk::emit

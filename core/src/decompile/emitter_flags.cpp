// x86 flag pattern matching and condition rendering.
#include <algorithm>
#include <array>
#include <cstddef>
#include <format>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <ember/binary/symbol.hpp>
#include <ember/common/types.hpp>
#include <ember/disasm/register.hpp>
#include <ember/ir/ir.hpp>
#include <ember/ir/ssa.hpp>

#include "emitter_internal.hpp"

namespace ember::emit {

const IrInst* Emitter::def_stripped(const IrValue& v) const noexcept {
    const IrInst* d = def_of(v);
    std::array<const IrInst*, 64> visited{};
    std::size_t visited_count = 0;
    while (d && d->op == IrOp::Assign && d->src_count == 1) {
        if (visited_count == visited.size() ||
            std::find(visited.begin(), visited.begin() + visited_count, d) !=
                visited.begin() + visited_count) {
            return nullptr;
        }
        visited[visited_count++] = d;
        const IrInst* n = def_of(d->srcs[0]);
        if (!n) return d;
        d = n;
    }
    return d;
}

bool Emitter::same_ssa(const IrValue& a, const IrValue& b) const noexcept {
    if (a.kind != b.kind) return false;
    if (a.kind == IrValueKind::Imm) return a.imm == b.imm && a.type == b.type;
    return ssa_key(a) == ssa_key(b);
}

std::optional<Emitter::SubOps> Emitter::match_sub_result(const IrValue& v) const {
    const IrInst* d = def_stripped(v);
    if (!d || d->op != IrOp::Sub || d->src_count < 2) return std::nullopt;
    return SubOps{d->srcs[0], d->srcs[1]};
}

std::optional<Emitter::SubOps> Emitter::match_zf(const IrValue& v) const {
    const IrInst* d = def_stripped(v);
    if (!d || d->op != IrOp::CmpEq || d->src_count < 2) return std::nullopt;
    if (d->srcs[1].kind != IrValueKind::Imm || d->srcs[1].imm != 0) return std::nullopt;
    return match_sub_result(d->srcs[0]);
}

std::optional<Emitter::SubOps> Emitter::match_sf(const IrValue& v) const {
    const IrInst* d = def_stripped(v);
    if (!d || d->op != IrOp::CmpSlt || d->src_count < 2) return std::nullopt;
    if (d->srcs[1].kind != IrValueKind::Imm || d->srcs[1].imm != 0) return std::nullopt;
    return match_sub_result(d->srcs[0]);
}

std::optional<Emitter::SubOps> Emitter::match_cf(const IrValue& v) const {
    const IrInst* d = def_stripped(v);
    if (!d || d->op != IrOp::SubBorrow || d->src_count < 2) return std::nullopt;
    return SubOps{d->srcs[0], d->srcs[1]};
}

std::optional<Emitter::SubOps> Emitter::match_of(const IrValue& v) const {
    const IrInst* d = def_stripped(v);
    if (!d || d->op != IrOp::SubOverflow || d->src_count < 2) return std::nullopt;
    return SubOps{d->srcs[0], d->srcs[1]};
}

bool Emitter::same_ops(const SubOps& x, const SubOps& y) const {
    return same_ssa(x.a, y.a) && same_ssa(x.b, y.b);
}

std::optional<Emitter::SubOps> Emitter::match_sf_xor_of(const IrValue& v) const {
    const IrInst* d = def_stripped(v);
    if (!d || d->op != IrOp::Xor || d->src_count < 2) return std::nullopt;
    auto sf1 = match_sf(d->srcs[0]);
    auto of1 = match_of(d->srcs[1]);
    if (sf1 && of1 && same_ops(*sf1, *of1)) return *sf1;
    auto sf2 = match_sf(d->srcs[1]);
    auto of2 = match_of(d->srcs[0]);
    if (sf2 && of2 && same_ops(*sf2, *of2)) return *sf2;
    return std::nullopt;
}

std::optional<Emitter::SubOps> Emitter::match_or_cf_zf(const IrValue& v) const {
    const IrInst* d = def_stripped(v);
    if (!d || d->op != IrOp::Or || d->src_count < 2) return std::nullopt;
    auto c1 = match_cf(d->srcs[0]); auto z1 = match_zf(d->srcs[1]);
    if (c1 && z1 && same_ops(*c1, *z1)) return *c1;
    auto c2 = match_cf(d->srcs[1]); auto z2 = match_zf(d->srcs[0]);
    if (c2 && z2 && same_ops(*c2, *z2)) return *c2;
    return std::nullopt;
}

std::optional<Emitter::SubOps> Emitter::match_or_zf_sfxorof(const IrValue& v) const {
    const IrInst* d = def_stripped(v);
    if (!d || d->op != IrOp::Or || d->src_count < 2) return std::nullopt;
    auto z1 = match_zf(d->srcs[0]); auto x1 = match_sf_xor_of(d->srcs[1]);
    if (z1 && x1 && same_ops(*z1, *x1)) return *z1;
    auto z2 = match_zf(d->srcs[1]); auto x2 = match_sf_xor_of(d->srcs[0]);
    if (z2 && x2 && same_ops(*z2, *x2)) return *z2;
    return std::nullopt;
}

std::optional<Emitter::SubOps> Emitter::match_and_notzf_notcf(const IrValue& v) const {
    const IrInst* d = def_stripped(v);
    if (!d || d->op != IrOp::And || d->src_count < 2) return std::nullopt;
    // Each operand should be Not(zf) or Not(cf)
    auto try_match = [&](const IrValue& left, const IrValue& right) -> std::optional<SubOps> {
        const IrInst* ld = def_stripped(left);
        const IrInst* rd = def_stripped(right);
        if (!ld || !rd) return std::nullopt;
        if (ld->op != IrOp::Not || rd->op != IrOp::Not) return std::nullopt;
        auto zf = match_zf(ld->srcs[0]);
        auto cf = match_cf(rd->srcs[0]);
        if (zf && cf && same_ops(*zf, *cf)) return *zf;
        return std::nullopt;
    };
    if (auto r = try_match(d->srcs[0], d->srcs[1]); r) return r;
    if (auto r = try_match(d->srcs[1], d->srcs[0]); r) return r;
    return std::nullopt;
}

std::optional<Emitter::SubOps> Emitter::match_and_notzf_not_sfxorof(const IrValue& v) const {
    const IrInst* d = def_stripped(v);
    if (!d || d->op != IrOp::And || d->src_count < 2) return std::nullopt;
    auto try_match = [&](const IrValue& left, const IrValue& right) -> std::optional<SubOps> {
        const IrInst* ld = def_stripped(left);
        const IrInst* rd = def_stripped(right);
        if (!ld || !rd) return std::nullopt;
        if (ld->op != IrOp::Not || rd->op != IrOp::Not) return std::nullopt;
        auto zf = match_zf(ld->srcs[0]);
        auto xr = match_sf_xor_of(rd->srcs[0]);
        if (zf && xr && same_ops(*zf, *xr)) return *zf;
        return std::nullopt;
    };
    if (auto r = try_match(d->srcs[0], d->srcs[1]); r) return r;
    if (auto r = try_match(d->srcs[1], d->srcs[0]); r) return r;
    return std::nullopt;
}

std::optional<IrValue> Emitter::match_eq_zero_value(const IrValue& v) const {
    const IrInst* d = def_stripped(v);
    if (!d || d->op != IrOp::CmpEq || d->src_count < 2) return std::nullopt;
    if (d->srcs[1].kind == IrValueKind::Imm && d->srcs[1].imm == 0) return d->srcs[0];
    if (d->srcs[0].kind == IrValueKind::Imm && d->srcs[0].imm == 0) return d->srcs[1];
    return std::nullopt;
}

std::optional<IrValue> Emitter::match_slt_zero_value(const IrValue& v) const {
    const IrInst* d = def_stripped(v);
    if (!d || d->op != IrOp::CmpSlt || d->src_count < 2) return std::nullopt;
    if (d->srcs[1].kind != IrValueKind::Imm || d->srcs[1].imm != 0) return std::nullopt;
    return d->srcs[0];
}

std::optional<IrValue> Emitter::match_or_eq_zero_slt_zero(const IrValue& v) const {
    const IrInst* d = def_stripped(v);
    if (!d || d->op != IrOp::Or || d->dst.type != IrType::I1 || d->src_count < 2) {
        return std::nullopt;
    }
    auto try_match = [&](const IrValue& eq_side,
                         const IrValue& lt_side) -> std::optional<IrValue> {
        auto eq = match_eq_zero_value(eq_side);
        auto lt = match_slt_zero_value(lt_side);
        if (eq && lt && same_ssa(*eq, *lt)) return *eq;
        return std::nullopt;
    };
    if (auto r = try_match(d->srcs[0], d->srcs[1]); r) return r;
    if (auto r = try_match(d->srcs[1], d->srcs[0]); r) return r;
    return std::nullopt;
}

std::optional<IrValue>
Emitter::match_low_byte_setcc_merge(const IrValue& v, int depth) const {
    if (depth > 8) return std::nullopt;
    const IrInst* d = def_stripped(v);
    if (!d) return std::nullopt;
    if ((d->op == IrOp::Trunc || d->op == IrOp::ZExt ||
         d->op == IrOp::SExt) && d->src_count >= 1) {
        if (d->srcs[0].type == IrType::I1) return d->srcs[0];
        return match_low_byte_setcc_merge(d->srcs[0], depth + 1);
    }
    if (d->op != IrOp::Or || d->src_count < 2) return std::nullopt;
    auto is_low_byte_clear = [&](const IrValue& x) {
        const IrInst* xd = def_stripped(x);
        if (!xd || xd->op != IrOp::And || xd->src_count < 2) return false;
        auto is_mask = [](const IrValue& m) {
            return m.kind == IrValueKind::Imm &&
                   static_cast<u64>(m.imm) == 0xffffffffffffff00ull;
        };
        return is_mask(xd->srcs[0]) || is_mask(xd->srcs[1]);
    };
    auto bool_cast_src = [&](const IrValue& x) -> std::optional<IrValue> {
        if (x.kind == IrValueKind::Imm && (x.imm == 0 || x.imm == 1)) {
            return IrValue::make_imm(x.imm, IrType::I8);
        }
        const IrInst* xd = def_stripped(x);
        if (!xd) return std::nullopt;
        if ((xd->op == IrOp::ZExt || xd->op == IrOp::SExt ||
             xd->op == IrOp::Trunc || xd->op == IrOp::Assign) &&
            xd->src_count >= 1) {
            if (xd->srcs[0].type == IrType::I1 ||
                xd->srcs[0].type == IrType::I8) {
                return xd->srcs[0];
            }
        }
        if (x.type == IrType::I1 || x.type == IrType::I8) return x;
        return std::nullopt;
    };
    if (is_low_byte_clear(d->srcs[0])) return bool_cast_src(d->srcs[1]);
    if (is_low_byte_clear(d->srcs[1])) return bool_cast_src(d->srcs[0]);
    return std::nullopt;
}

std::optional<IrValue>
Emitter::low_byte_return_payload(const IrValue& value, int depth) const {
    if (depth > 10) return std::nullopt;
    if (auto merged = match_low_byte_setcc_merge(value, depth); merged) {
        return *merged;
    }
    const IrInst* definition = def_stripped(value);
    if (!definition) {
        if (value.type == IrType::I1 || value.type == IrType::I8) return value;
        return std::nullopt;
    }
    if ((definition->op == IrOp::Assign || definition->op == IrOp::Trunc ||
         definition->op == IrOp::ZExt || definition->op == IrOp::SExt) &&
        definition->src_count >= 1) {
        if (definition->srcs[0].type == IrType::I1 ||
            definition->srcs[0].type == IrType::I8) {
            return definition->srcs[0];
        }
        return low_byte_return_payload(definition->srcs[0], depth + 1);
    }
    if (definition->op == IrOp::And && definition->src_count >= 2) {
        const auto clears_low_byte = [](const IrValue& mask) {
            return mask.kind == IrValueKind::Imm &&
                   static_cast<u64>(mask.imm) == 0xffffffffffffff00ull;
        };
        if (clears_low_byte(definition->srcs[0]) ||
            clears_low_byte(definition->srcs[1])) {
            return IrValue::make_imm(0, IrType::I8);
        }
    }
    return std::nullopt;
}

bool Emitter::low_byte_merge_has_raw_carrier(
    const IrValue& value) const {
    const IrInst* merge = def_stripped(value);
    if (!merge || merge->op != IrOp::Or || merge->src_count < 2) return false;
    const auto raw_clear = [&](const IrValue& candidate) {
        const IrInst* clear = def_stripped(candidate);
        if (!clear || clear->op != IrOp::And || clear->src_count < 2) return false;
        const auto mask = [](const IrValue& operand) {
            return operand.kind == IrValueKind::Imm &&
                   static_cast<u64>(operand.imm) == 0xffffffffffffff00ull;
        };
        if (mask(clear->srcs[0])) return renders_raw_arch_reg_name(clear->srcs[1]);
        if (mask(clear->srcs[1])) return renders_raw_arch_reg_name(clear->srcs[0]);
        return false;
    };
    return raw_clear(merge->srcs[0]) || raw_clear(merge->srcs[1]);
}

std::optional<std::string>
Emitter::render_bool_byte_value(const IrValue& v, int depth, bool negate,
                                int min_prec) const {
    if (depth > 8) return std::nullopt;
    if (auto b = match_low_byte_setcc_merge(v); b) {
        return render_bool_operand(*b, depth + 1, negate, min_prec);
    }
    const IrInst* d = def_stripped(v);
    if (!d) return std::nullopt;
    if ((d->op == IrOp::Trunc || d->op == IrOp::ZExt ||
         d->op == IrOp::SExt || d->op == IrOp::Assign) &&
        d->src_count >= 1) {
        return render_bool_byte_value(d->srcs[0], depth + 1, negate, min_prec);
    }
    if (d->op == IrOp::And && d->src_count >= 2) {
        const IrValue* masked = nullptr;
        if (d->srcs[0].kind == IrValueKind::Imm && d->srcs[0].imm == 1) {
            masked = &d->srcs[1];
        } else if (d->srcs[1].kind == IrValueKind::Imm && d->srcs[1].imm == 1) {
            masked = &d->srcs[0];
        }
        if (masked) {
            IrValue core = *masked;
            if (auto merged = match_low_byte_setcc_merge(core); merged) {
                core = *merged;
            }
            if (core.type == IrType::I1) {
                return render_bool_operand(core, depth + 1, negate, min_prec);
            }
            std::string inner = expr(core, depth + 1,
                                     std::to_underlying(Prec::BitAnd) + 1);
            std::string bit = inner + " & 1";
            if (negate) {
                return wrap_if_lt("!(" + bit + ")", Prec::Unary, min_prec);
            }
            return wrap_if_lt(std::move(bit), Prec::BitAnd, min_prec);
        }
    }
    if ((d->op == IrOp::Or || d->op == IrOp::And) && d->src_count >= 2) {
        auto left = render_bool_byte_value(d->srcs[0], depth + 1, negate,
                                           std::to_underlying(negate
                                               ? (d->op == IrOp::Or ? Prec::LogAnd : Prec::LogOr)
                                               : (d->op == IrOp::Or ? Prec::LogOr : Prec::LogAnd)) + 1);
        auto right = render_bool_byte_value(d->srcs[1], depth + 1, negate,
                                            std::to_underlying(negate
                                                ? (d->op == IrOp::Or ? Prec::LogAnd : Prec::LogOr)
                                                : (d->op == IrOp::Or ? Prec::LogOr : Prec::LogAnd)) + 1);
        if (!left || !right) return std::nullopt;
        const bool or_op = d->op == IrOp::Or;
        const Prec own = negate
            ? (or_op ? Prec::LogAnd : Prec::LogOr)
            : (or_op ? Prec::LogOr : Prec::LogAnd);
        const std::string op = negate
            ? (or_op ? " && " : " || ")
            : (or_op ? " || " : " && ");
        return wrap_if_lt(*left + op + *right, own, min_prec);
    }
    return std::nullopt;
}

std::string Emitter::render_cmp(std::string_view op, const IrValue& a,
                                const IrValue& b, int depth,
                                bool signed_cmp,
                                bool in_bool_ctx,
                                int min_prec) const {
    // In boolean context, `x != 0` is spelled `x` and `x == 0` is `!x`.
    // Applies to either operand being an Imm(0). Strip casts on the
    // nonzero operand and recognise `xor(y, 1)` as a boolean negation
    // of `y`, so the compiler's `xor eax, 1; test al, al; jnz` lowering
    // of `if (!flag)` collapses from `if (!(u8)((u32)flag ^ 1))` back
    // to a plain `if (flag)` instead of leaving the bitwise-xor noise
    // visible at every is_open / is_eof / has_X check.
    if (in_bool_ctx && (op == "!=" || op == "==")) {
        const IrValue* nonzero = nullptr;
        if (a.kind == IrValueKind::Imm && a.imm == 0) nonzero = &b;
        else if (b.kind == IrValueKind::Imm && b.imm == 0) nonzero = &a;
        if (nonzero) {
            if (auto byte_bool = render_bool_byte_value(
                    *nonzero, depth + 1, op == "==", min_prec);
                byte_bool) {
                return *byte_bool;
            }
            // Strip surrounding cast chain to find a `xor(y, 1)` core.
            IrValue core = *nonzero;
            for (int hop = 0; hop < 6; ++hop) {
                const IrInst* d = def_stripped(core);
                if (!d) break;
                if (d->op == IrOp::ZExt || d->op == IrOp::SExt ||
                    d->op == IrOp::Trunc) {
                    if (d->src_count < 1) break;
                    core = d->srcs[0];
                    continue;
                }
                break;
            }
            if (const IrInst* dx = def_stripped(core);
                dx && dx->op == IrOp::Xor && dx->src_count == 2) {
                const IrValue& a2 = dx->srcs[0];
                const IrValue& b2 = dx->srcs[1];
                const IrValue* y = nullptr;
                if (a2.kind == IrValueKind::Imm && a2.imm == 1) y = &b2;
                else if (b2.kind == IrValueKind::Imm && b2.imm == 1) y = &a2;
                if (y) {
                    // `(xor(y, 1) == 0)` ⇔ `y` (truthy when bit 0 set).
                    // `(xor(y, 1) != 0)` ⇔ `!y`. The conclusion holds
                    // exactly when y ∈ {0, 1}; any other value would
                    // never have led the compiler to emit the
                    // `xor reg, 1` idiom in the first place.
                    if (op == "==") {
                        return expr(*y, depth + 1, min_prec);
                    }
                    std::string rendered = expr(*y, depth + 1,
                                                std::to_underlying(Prec::Unary));
                    return wrap_if_lt("!" + rendered, Prec::Unary, min_prec);
                }
            }
            if (op == "!=") {
                return expr(*nonzero, depth + 1, min_prec);
            }
            std::string rendered = expr(*nonzero, depth + 1,
                                        std::to_underlying(Prec::Unary));
            return wrap_if_lt("!" + rendered, Prec::Unary, min_prec);
        }
    }
    if (a.kind == IrValueKind::Imm && b.kind != IrValueKind::Imm) {
        if (op == "<")  return render_cmp(">",  b, a, depth, signed_cmp, in_bool_ctx, min_prec);
        if (op == "<=") return render_cmp(">=", b, a, depth, signed_cmp, in_bool_ctx, min_prec);
        if (op == ">")  return render_cmp("<",  b, a, depth, signed_cmp, in_bool_ctx, min_prec);
        if (op == ">=") return render_cmp("<=", b, a, depth, signed_cmp, in_bool_ctx, min_prec);
    }
    const Prec own = (op == "==" || op == "!=") ? Prec::Eq : Prec::Rel;
    const int p = std::to_underlying(own);
    const std::string_view c = "int64_t";
    // CmpS* also represents ordered floating-point comparisons in the
    // IR. Signed integer casts are appropriate for integer flags, but
    // applying them to FPR operands destroys the source semantics.
    const bool signed_integer_cmp =
        signed_cmp && !is_float_type(a.type) && !is_float_type(b.type);
    const bool cast_l = signed_integer_cmp && a.kind != IrValueKind::Imm;
    const bool cast_r = signed_integer_cmp && b.kind != IrValueKind::Imm;
    // If we're going to wrap in `(int64_t)`, the inner must bind at Unary;
    // otherwise the compare's own precedence is enough.
    const int lp = cast_l ? std::to_underlying(Prec::Unary) : p;
    const int rp = cast_r ? std::to_underlying(Prec::Unary) : p + 1;
    auto cmp_expr = [&](const IrValue& v, int prec) {
        if (v.kind == IrValueKind::Imm) return format_numeric_imm(v);
        if (const IrInst* d = def_stripped(v);
            d && (d->op == IrOp::ZExt || d->op == IrOp::SExt ||
                  d->op == IrOp::Trunc)) {
            return expand(*d, depth + 1, prec);
        }
        return expr(v, depth + 1, prec);
    };
    std::string left  = cmp_expr(a, lp);
    std::string right = cmp_expr(b, rp);
    if (cast_l) left  = std::format("({}){}", c, left);
    if (cast_r) right = std::format("({}){}", c, right);
    return wrap_if_lt(std::format("{} {} {}", left, op, right), own, min_prec);
}

std::string Emitter::render_bool_operand(const IrValue& v, int depth,
                                         bool negate, int min_prec) const {
    if (auto s = try_simplify_flag(v, depth + 1, negate,
                                   /*in_bool_ctx=*/true, min_prec);
        s) return *s;
    if (negate) {
        std::string inner = expr(v, depth + 1, std::to_underlying(Prec::Unary));
        return wrap_if_lt("!" + inner, Prec::Unary, min_prec);
    }
    return expr(v, depth + 1, min_prec);
}

std::optional<std::string>
Emitter::try_simplify_flag(const IrValue& v, int depth, bool negate,
                           bool in_bool_ctx, int min_prec) const {
    if (depth >= 12) return std::nullopt;
    if (v.type != IrType::I1) return std::nullopt;

    auto emit_sub = [&](std::string_view op, std::string_view neg_op,
                        const SubOps& s, bool sign_cmp) {
        return render_cmp(negate ? neg_op : op, s.a, s.b, depth, sign_cmp,
                          in_bool_ctx, min_prec);
    };
    auto emit_cmp = [&](std::string_view op, std::string_view neg_op,
                        const IrValue& a, const IrValue& b, bool sign_cmp) {
        return render_cmp(negate ? neg_op : op, a, b, depth, sign_cmp,
                          in_bool_ctx, min_prec);
    };

    // Compound sub-flag patterns (most specific first)
    if (auto s = match_sf_xor_of(v); s)              return emit_sub("<",  ">=", *s, true);
    if (auto s = match_or_cf_zf(v); s)               return emit_sub("<=", ">",  *s, false);
    if (auto s = match_or_zf_sfxorof(v); s)          return emit_sub("<=", ">",  *s, true);
    if (auto s = match_and_notzf_notcf(v); s)        return emit_sub(">",  "<=", *s, false);
    if (auto s = match_and_notzf_not_sfxorof(v); s)  return emit_sub(">",  "<=", *s, true);
    if (auto x = match_or_eq_zero_slt_zero(v); x) {
        IrValue zero = IrValue::make_imm(0, x->type);
        return render_cmp(negate ? ">" : "<=", *x, zero, depth, true,
                          in_bool_ctx, min_prec);
    }

    const IrInst* d = def_stripped(v);

    // Not(x): recurse with flipped negate (cancels double-negation cleanly).
    if (d && d->op == IrOp::Not && d->src_count == 1) {
        if (auto r = try_simplify_flag(d->srcs[0], depth + 1, !negate,
                                       in_bool_ctx, min_prec);
            r) return r;
    }

    // Atomic sub-flag patterns
    if (auto s = match_zf(v); s) return emit_sub("==", "!=", *s, false);
    if (auto s = match_cf(v); s) return emit_sub("<",  ">=", *s, false);

    // Direct Cmp* ops (with negate, emit complementary)
    if (d && d->src_count >= 2) {
        switch (d->op) {
            case IrOp::CmpEq:  return emit_cmp("==", "!=", d->srcs[0], d->srcs[1], false);
            case IrOp::CmpNe:  return emit_cmp("!=", "==", d->srcs[0], d->srcs[1], false);
            case IrOp::CmpSlt: return emit_cmp("<",  ">=", d->srcs[0], d->srcs[1], true);
            case IrOp::CmpSle: return emit_cmp("<=", ">",  d->srcs[0], d->srcs[1], true);
            case IrOp::CmpSgt: return emit_cmp(">",  "<=", d->srcs[0], d->srcs[1], true);
            case IrOp::CmpSge: return emit_cmp(">=", "<",  d->srcs[0], d->srcs[1], true);
            case IrOp::CmpUlt: return emit_cmp("<",  ">=", d->srcs[0], d->srcs[1], false);
            case IrOp::CmpUle: return emit_cmp("<=", ">",  d->srcs[0], d->srcs[1], false);
            case IrOp::CmpUgt: return emit_cmp(">",  "<=", d->srcs[0], d->srcs[1], false);
            case IrOp::CmpUge: return emit_cmp(">=", "<",  d->srcs[0], d->srcs[1], false);
            default: break;
        }
    }
    if (d && d->dst.type == IrType::I1 && d->src_count >= 2) {
        if (d->op == IrOp::Or) {
            const Prec own = negate ? Prec::LogAnd : Prec::LogOr;
            const std::string op = negate ? " && " : " || ";
            const int child_prec = std::to_underlying(own) + 1;
            return wrap_if_lt(
                render_bool_operand(d->srcs[0], depth, negate, child_prec) + op +
                render_bool_operand(d->srcs[1], depth, negate, child_prec),
                own, min_prec);
        }
        if (d->op == IrOp::And) {
            const Prec own = negate ? Prec::LogOr : Prec::LogAnd;
            const std::string op = negate ? " || " : " && ";
            const int child_prec = std::to_underlying(own) + 1;
            return wrap_if_lt(
                render_bool_operand(d->srcs[0], depth, negate, child_prec) + op +
                render_bool_operand(d->srcs[1], depth, negate, child_prec),
                own, min_prec);
        }
    }

    return std::nullopt;
}

std::optional<std::string>
Emitter::render_ppc_ctr_condition(const IrValue& v, bool invert) const {
    if (!is_ppc_abi()) return std::nullopt;
    if (auto key = ssa_key(v); key && deferred_ctr_conditions.contains(*key) &&
        !active_ctr_tail_conditions.contains(*key)) {
        return std::nullopt;
    }
    const IrInst* compare = def_stripped(v);
    if (!compare || (compare->op != IrOp::CmpEq && compare->op != IrOp::CmpNe) ||
        compare->src_count < 2) {
        return std::nullopt;
    }
    const IrValue* decremented = nullptr;
    if (compare->srcs[0].kind == IrValueKind::Imm &&
        compare->srcs[0].imm == 0) {
        decremented = &compare->srcs[1];
    } else if (compare->srcs[1].kind == IrValueKind::Imm &&
               compare->srcs[1].imm == 0) {
        decremented = &compare->srcs[0];
    }
    if (!decremented) return std::nullopt;
    const IrInst* sub = def_stripped(*decremented);
    if (!sub || sub->op != IrOp::Sub || sub->src_count < 2 ||
        sub->srcs[1].kind != IrValueKind::Imm || sub->srcs[1].imm != 1) {
        return std::nullopt;
    }
    const IrInst* phi = def_stripped(sub->srcs[0]);
    if (!phi || phi->op != IrOp::Phi || phi->dst.kind != IrValueKind::Reg ||
        canonical_reg(phi->dst.reg) != Reg::PpcCtr) {
        return std::nullopt;
    }
    auto key = ssa_key(phi->dst);
    if (!key) return std::nullopt;
    auto named = merge_value_names.find(*key);
    if (named == merge_value_names.end()) return std::nullopt;
    const bool nonzero = (compare->op == IrOp::CmpNe) != invert;
    return std::format("--{} {} 0", named->second, nonzero ? "!=" : "==");
}

std::optional<std::string>
Emitter::imported_i64_field_from_low_word(const IrValue& value) const {
    if (!annotations || !binary) return std::nullopt;
    const IrInst* load = def_stripped(value);
    if (!load || load->op != IrOp::Load || load->dst.type != IrType::I32 ||
        load->src_count < 1) return std::nullopt;
    auto access = canonical_struct_access(load->srcs[0]);
    if (!access || access->second < 4) return std::nullopt;
    const Symbol* slot = global_object_for_load(access->first);
    if (!slot) return std::nullopt;
    const std::string* type = annotations->global_type_for(slot->addr);
    if (!type) {
        auto found = annotations->imported_global_types_by_name.find(slot->name);
        if (found != annotations->imported_global_types_by_name.end()) {
            type = &found->second;
        }
    }
    if (!type || type->find('*') == std::string::npos) return std::nullopt;
    const std::string record_name = imported_record_base(*type);
    auto record = annotations->imported_records.find(record_name);
    if (record == annotations->imported_records.end()) return std::nullopt;
    const i64 high_offset = access->second - 4;
    auto field = record->second.fields.find(high_offset);
    if (field == record->second.fields.end() || field->second.size != 8 ||
        field->second.name.empty()) return std::nullopt;
    note_global_decl(*slot, *type);
    return std::format("{}->{}", global_display_name(*slot),
                       field->second.name);
}

bool Emitter::match_ppc_ticks_per_millisecond(
    const IrValue& value) const {
    const IrInst* masked = def_stripped(value);
    if (!masked || masked->op != IrOp::And || masked->src_count < 2) {
        return false;
    }
    const IrValue* rotated = nullptr;
    for (u8 i = 0; i < 2; ++i) {
        if (auto mask = resolve_imm(masked->srcs[i]);
            mask && static_cast<u32>(*mask) == 0x03ffffffu) {
            rotated = &masked->srcs[1 - i];
            break;
        }
    }
    const IrInst* joined = rotated ? def_stripped(*rotated) : nullptr;
    if (!joined || joined->op != IrOp::Or || joined->src_count < 2) {
        return false;
    }
    const IrInst* shifted_right = nullptr;
    const IrInst* shifted_left = nullptr;
    for (u8 i = 0; i < 2; ++i) {
        const IrInst* shift = def_stripped(joined->srcs[i]);
        if (!shift || shift->src_count < 2) return false;
        if (shift->op == IrOp::Lshr && resolve_imm(shift->srcs[1]) == 6) {
            shifted_right = shift;
        } else if (shift->op == IrOp::Shl &&
                   resolve_imm(shift->srcs[1]) == 26) {
            shifted_left = shift;
        }
    }
    if (!shifted_right || !shifted_left ||
        !same_ssa(shifted_right->srcs[0], shifted_left->srcs[0])) {
        return false;
    }
    const IrInst* truncated = def_stripped(shifted_right->srcs[0]);
    if (!truncated || truncated->op != IrOp::Trunc ||
        truncated->src_count < 1) return false;
    const IrInst* high = def_stripped(truncated->srcs[0]);
    if (!high || high->op != IrOp::Lshr || high->src_count < 2 ||
        resolve_imm(high->srcs[1]) != 32) return false;
    const IrInst* product = def_stripped(high->srcs[0]);
    if (!product || product->op != IrOp::Mul || product->src_count < 2) {
        return false;
    }
    const auto strip_integer_cast = [&](const IrValue& candidate) {
        const IrInst* cast = def_stripped(candidate);
        return cast && (cast->op == IrOp::ZExt || cast->op == IrOp::SExt ||
                        cast->op == IrOp::Trunc) && cast->src_count >= 1
            ? cast->srcs[0] : candidate;
    };
    IrValue numerator;
    bool found_magic = false;
    for (u8 i = 0; i < 2; ++i) {
        const IrValue stripped = strip_integer_cast(product->srcs[i]);
        if (auto immediate = resolve_imm(stripped);
            immediate && static_cast<u32>(*immediate) == 0x10624dd3u) {
            numerator = strip_integer_cast(product->srcs[1 - i]);
            found_magic = true;
            break;
        }
    }
    if (!found_magic) return false;
    const IrInst* clock_mask = def_stripped(numerator);
    if (!clock_mask || clock_mask->op != IrOp::And ||
        clock_mask->src_count < 2) return false;
    const IrValue* clock_rotated = nullptr;
    for (u8 i = 0; i < 2; ++i) {
        if (auto mask = resolve_imm(clock_mask->srcs[i]);
            mask && static_cast<u32>(*mask) == 0x3fffffffu) {
            clock_rotated = &clock_mask->srcs[1 - i];
            break;
        }
    }
    const IrInst* clock_joined = clock_rotated
        ? def_stripped(*clock_rotated) : nullptr;
    if (!clock_joined || clock_joined->op != IrOp::Or ||
        clock_joined->src_count < 2) return false;
    const IrValue* clock_value = nullptr;
    bool saw_left = false;
    bool saw_right = false;
    for (u8 i = 0; i < 2; ++i) {
        const IrInst* shift = def_stripped(clock_joined->srcs[i]);
        if (!shift || shift->src_count < 2) return false;
        if (shift->op == IrOp::Lshr && resolve_imm(shift->srcs[1]) == 2) {
            clock_value = &shift->srcs[0];
            saw_right = true;
        } else if (shift->op == IrOp::Shl &&
                   resolve_imm(shift->srcs[1]) == 30) {
            if (clock_value && !same_ssa(*clock_value, shift->srcs[0])) {
                return false;
            }
            clock_value = &shift->srcs[0];
            saw_left = true;
        }
    }
    if (!clock_value || !saw_left || !saw_right) return false;
    const IrInst* clock_load = def_stripped(*clock_value);
    if (!clock_load || clock_load->op != IrOp::Load ||
        clock_load->src_count < 1) return false;
    auto address = try_resolve_imm_addr(clock_load->srcs[0]);
    return address && normalized_address(*address) == 0x800000f8u;
}

bool Emitter::value_depends_on_any(
    const IrValue& value, const std::set<SsaKey>& wanted,
    std::set<SsaKey>& seen, int depth) const {
    if (depth > 32) return false;
    auto key = ssa_key(value);
    if (key && wanted.contains(*key)) return true;
    if (key && !seen.insert(*key).second) return false;
    const IrInst* definition = def_of(value);
    if (!definition) return false;
    for (u8 i = 0; i < definition->src_count; ++i) {
        if (value_depends_on_any(definition->srcs[i], wanted, seen, depth + 1)) {
            return true;
        }
    }
    for (const IrValue& operand : definition->phi_operands) {
        if (value_depends_on_any(operand, wanted, seen, depth + 1)) return true;
    }
    return false;
}

bool Emitter::value_contains_immediate(const IrValue& value, i64 wanted,
                                       std::set<SsaKey>& seen,
                                       int depth) const {
    if (depth > 32) return false;
    if (value.kind == IrValueKind::Imm && value.imm == wanted) return true;
    auto key = ssa_key(value);
    if (key && !seen.insert(*key).second) return false;
    const IrInst* definition = def_of(value);
    if (!definition) return false;
    for (u8 i = 0; i < definition->src_count; ++i) {
        if (value_contains_immediate(
                definition->srcs[i], wanted, seen, depth + 1)) return true;
    }
    return false;
}

std::optional<std::string>
Emitter::try_render_ppc_tick_elapsed_condition(const IrValue& condition,
                                               bool invert) const {
    if (!is_ppc_abi() || !fn || !annotations) return std::nullopt;
    const IrInst* condition_def = def_stripped(condition);
    if (!condition_def || condition_def->source_addr == 0) return std::nullopt;
    std::set<SsaKey> immediate_seen;
    if (!value_contains_immediate(condition, 500, immediate_seen)) {
        return std::nullopt;
    }
    for (const auto& block : fn->blocks) {
        for (std::size_t call_i = 0; call_i < block.insts.size(); ++call_i) {
            const IrInst& call = block.insts[call_i];
            if (call.op != IrOp::Call || call.source_addr == 0 ||
                condition_def->source_addr <= call.source_addr ||
                condition_def->source_addr - call.source_addr > 0x30 ||
                function_display_name(call.target1) != "__div2i") continue;

            std::vector<IrValue> args;
            for (std::size_t i = call_i; i > 0;) {
                const IrInst& previous = block.insts[--i];
                if (previous.op == IrOp::Intrinsic &&
                    previous.name.starts_with("call.args.")) {
                    std::vector<IrValue> part;
                    for (u8 source = 0; source < previous.src_count; ++source) {
                        part.push_back(previous.srcs[source]);
                    }
                    args.insert(args.begin(), part.begin(), part.end());
                    if (previous.name == "call.args.1") break;
                    continue;
                }
                if (previous.op == IrOp::Call || previous.op == IrOp::CallIndirect) {
                    break;
                }
            }
            if (args.size() < 4 || !match_ppc_ticks_per_millisecond(args[3])) {
                continue;
            }
            const IrInst* low_delta = def_stripped(args[1]);
            if (!low_delta || low_delta->op != IrOp::Sub ||
                low_delta->src_count < 2) continue;
            auto current = imported_i64_field_from_low_word(low_delta->srcs[0]);
            auto started = imported_i64_field_from_low_word(low_delta->srcs[1]);
            if (!current || !started) continue;

            std::set<SsaKey> result_keys;
            for (std::size_t i = call_i + 1; i < block.insts.size(); ++i) {
                const IrInst& result = block.insts[i];
                if (result.op != IrOp::Clobber) break;
                if (result.dst.kind != IrValueKind::Reg) continue;
                const Reg reg = canonical_reg(result.dst.reg);
                if (reg != Reg::PpcR3 && reg != Reg::PpcR4) continue;
                if (auto key = ssa_key(result.dst); key) result_keys.insert(*key);
            }
            std::set<SsaKey> dependency_seen;
            if (result_keys.empty() || !value_depends_on_any(
                    condition, result_keys, dependency_seen)) continue;
            const std::string elapsed = std::format(
                "OSTicksToMilliseconds({} - {})", *current, *started);
            return std::format("{} {} 500", elapsed, invert ? ">" : "<=");
        }
    }
    return std::nullopt;
}

std::string Emitter::render_condition(const IrValue& v, bool invert) const {
    if (const auto* name = scoped_ssa_name(v)) return invert ? "!" + *name : *name;
    // Condition is rendered into `if (...)`, so no outer wrapping needed.
    if (auto ctr = render_ppc_ctr_condition(v, invert); ctr) return *ctr;
    if (auto elapsed = try_render_ppc_tick_elapsed_condition(v, invert);
        elapsed) return *elapsed;
    if (auto s = try_simplify_flag(v, 0, invert, /*in_bool_ctx=*/true, 0); s) return *s;
    if (invert) {
        std::string base = expr(v, 0, std::to_underlying(Prec::Unary));
        return std::format("!{}", base);
    }
    return expr(v, 0, 0);
}

}  // namespace ember::emit

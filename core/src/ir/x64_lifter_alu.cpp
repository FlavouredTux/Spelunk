// Integer ALU: moves, arithmetic, logic, shifts, rotates, multiply, divide.

#include <format>
#include <utility>

#include <ember/common/types.hpp>
#include <ember/disasm/instruction.hpp>
#include <ember/disasm/register.hpp>
#include <ember/ir/ir.hpp>

#include "x64_lifter_internal.hpp"

namespace ember::x64_lift {

void lift_mov(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2) return;
    IrValue src = materialize_rvalue(insn.operands[1], ctx);
    const IrType dst_t = operand_type(insn.operands[0]);
    src = ctx.match_size(src, dst_t, /*sign_ext=*/true);
    store_lvalue(insn.operands[0], src, ctx);
}

void lift_movzx(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2) return;
    IrValue src = materialize_rvalue(insn.operands[1], ctx);
    const IrType dst_t = operand_type(insn.operands[0]);
    if (src.type != dst_t) src = ctx.emit_convert(IrOp::ZExt, src, dst_t);
    store_lvalue(insn.operands[0], src, ctx);
}

void lift_movsx(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2) return;
    IrValue src = materialize_rvalue(insn.operands[1], ctx);
    const IrType dst_t = operand_type(insn.operands[0]);
    if (src.type != dst_t) src = ctx.emit_convert(IrOp::SExt, src, dst_t);
    store_lvalue(insn.operands[0], src, ctx);
}

void lift_lea(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2 ||
        insn.operands[1].kind != Operand::Kind::Memory ||
        insn.operands[0].kind != Operand::Kind::Register) {
        return;
    }
    IrValue ea = compute_ea(insn.operands[1].mem, ctx);
    const IrType dst_t = operand_type(insn.operands[0]);
    ea = ctx.match_size(ea, dst_t, false);
    store_lvalue(insn.operands[0], ea, ctx);
}

void lift_arith(LiftCtx& ctx, IrOp op, IrOp carry_op, IrOp overflow_op,
                bool store_result, bool set_flags) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2) return;
    IrValue a = materialize_rvalue(insn.operands[0], ctx);
    IrValue b = materialize_rvalue(insn.operands[1], ctx);
    b = ctx.match_size(b, a.type, /*sign_ext=*/true);

    if (set_flags) {
        ctx.emit_set_flag(Flag::Cf, ctx.emit_binop_i1(carry_op, a, b));
        ctx.emit_set_flag(Flag::Of, ctx.emit_binop_i1(overflow_op, a, b));
    }

    IrValue result = ctx.emit_binop(op, a, b);

    if (set_flags) ctx.set_zf_sf(result);
    if (store_result) store_lvalue(insn.operands[0], result, ctx);
}

void lift_add(LiftCtx& ctx) {
    lift_arith(ctx, IrOp::Add, IrOp::AddCarry, IrOp::AddOverflow, true, true);
}

void lift_sub(LiftCtx& ctx) {
    lift_arith(ctx, IrOp::Sub, IrOp::SubBorrow, IrOp::SubOverflow, true, true);
}

void lift_cmp(LiftCtx& ctx) {
    lift_arith(ctx, IrOp::Sub, IrOp::SubBorrow, IrOp::SubOverflow, false, true);
}

void lift_bitwise(LiftCtx& ctx, IrOp op, bool store_result) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2) return;
    IrValue a = materialize_rvalue(insn.operands[0], ctx);
    IrValue b = materialize_rvalue(insn.operands[1], ctx);
    b = ctx.match_size(b, a.type, /*sign_ext=*/true);
    IrValue r = ctx.emit_binop(op, a, b);
    ctx.set_zf_sf(r);
    ctx.clear_cf_of();
    if (store_result) store_lvalue(insn.operands[0], r, ctx);
}

void lift_and(LiftCtx& ctx) { lift_bitwise(ctx, IrOp::And, true);  }

void lift_or (LiftCtx& ctx) { lift_bitwise(ctx, IrOp::Or,  true);  }

void lift_xor(LiftCtx& ctx) { lift_bitwise(ctx, IrOp::Xor, true);  }

void lift_test(LiftCtx& ctx) { lift_bitwise(ctx, IrOp::And, false); }

void lift_inc(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 1) return;
    IrValue a = materialize_rvalue(insn.operands[0], ctx);
    IrValue one = ctx.imm(1, a.type);
    ctx.emit_set_flag(Flag::Of, ctx.emit_binop_i1(IrOp::AddOverflow, a, one));
    IrValue r = ctx.emit_binop(IrOp::Add, a, one);
    ctx.set_zf_sf(r);
    store_lvalue(insn.operands[0], r, ctx);
}

void lift_dec(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 1) return;
    IrValue a = materialize_rvalue(insn.operands[0], ctx);
    IrValue one = ctx.imm(1, a.type);
    ctx.emit_set_flag(Flag::Of, ctx.emit_binop_i1(IrOp::SubOverflow, a, one));
    IrValue r = ctx.emit_binop(IrOp::Sub, a, one);
    ctx.set_zf_sf(r);
    store_lvalue(insn.operands[0], r, ctx);
}

void lift_neg(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 1) return;
    IrValue a = materialize_rvalue(insn.operands[0], ctx);
    ctx.emit_set_flag(Flag::Cf, ctx.emit_cmp(IrOp::CmpNe, a, ctx.imm(0, a.type)));
    const i64 sign_bit = static_cast<i64>(1ULL << (type_bits(a.type) - 1));
    ctx.emit_set_flag(Flag::Of, ctx.emit_cmp(IrOp::CmpEq, a,
                                              ctx.imm(sign_bit, a.type)));
    IrValue r = ctx.emit_unop(IrOp::Neg, a);
    ctx.set_zf_sf(r);
    store_lvalue(insn.operands[0], r, ctx);
}

void lift_not(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 1) return;
    IrValue a = materialize_rvalue(insn.operands[0], ctx);
    IrValue r = ctx.emit_unop(IrOp::Not, a);
    store_lvalue(insn.operands[0], r, ctx);
}

// CF/OF for shift instructions. CF holds the last bit shifted out:
//   shl: bit (W - count) of the original value
//   shr/sar: bit (count - 1) of the original value
// OF is only well-defined for 1-bit shifts; we compute it unconditionally
// because the common case is `shl/shr ..., 1` where the value is meaningful,
// and at higher counts OF is documented as undefined anyway.
//   shl OF = MSB(result) ^ CF
//   shr OF = MSB(original)
//   sar OF = 0
//
void lift_shift(LiftCtx& ctx, IrOp op) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2) return;
    IrValue a = materialize_rvalue(insn.operands[0], ctx);
    IrValue cnt = materialize_rvalue(insn.operands[1], ctx);
    const IrValue original_count = cnt;
    cnt = ctx.match_size(cnt, a.type, /*sign_ext=*/false);

    const unsigned width = type_bits(a.type);
    const i64 count_mask = width == 64 ? 0x3f : 0x1f;
    cnt = ctx.emit_binop(IrOp::And, cnt, ctx.imm(count_mask, a.type));
    IrValue width_imm = ctx.imm(static_cast<i64>(width), a.type);
    IrValue one_t     = ctx.imm(1, a.type);
    IrValue zero_t    = ctx.imm(0, a.type);
    IrValue nonzero = ctx.emit_cmp(IrOp::CmpNe, cnt, zero_t);

    // Avoid constructing a width-sized shift in the flag expression when
    // the effective count is zero. Architectural state is selected back to
    // its old value in that case.
    IrValue safe_cnt = ctx.select(nonzero, cnt, one_t);

    IrValue cf_bit;
    if (op == IrOp::Shl) {
        IrValue shift = ctx.emit_binop(IrOp::Sub, width_imm, safe_cnt);
        IrValue out_bit = ctx.emit_binop(IrOp::Lshr, a, shift);
        cf_bit = ctx.emit_binop(IrOp::And, out_bit, one_t);
    } else {
        IrValue shift = ctx.emit_binop(IrOp::Sub, safe_cnt, one_t);
        IrValue out_bit = ctx.emit_binop(IrOp::Lshr, a, shift);
        cf_bit = ctx.emit_binop(IrOp::And, out_bit, one_t);
    }
    IrValue cf_new = ctx.emit_cmp(IrOp::CmpNe, cf_bit, zero_t);
    ctx.emit_set_flag(Flag::Cf,
        ctx.select(nonzero, cf_new, ctx.flag_val(Flag::Cf)));

    IrValue shifted = ctx.emit_binop(op, a, safe_cnt);
    IrValue r = ctx.select(nonzero, shifted, a);

    IrValue of_new;
    if (op == IrOp::Shl) {
        IrValue msb_shift = ctx.imm(static_cast<i64>(width - 1), a.type);
        IrValue msb = ctx.emit_binop(IrOp::Lshr, r, msb_shift);
        IrValue msb_bit = ctx.emit_binop(IrOp::And, msb, one_t);
        IrValue msb_i1  = ctx.emit_cmp(IrOp::CmpNe, msb_bit, zero_t);
        of_new = ctx.emit_binop_i1(IrOp::Xor, msb_i1, cf_new);
    } else if (op == IrOp::Lshr) {
        IrValue msb_shift = ctx.imm(static_cast<i64>(width - 1), a.type);
        IrValue msb = ctx.emit_binop(IrOp::Lshr, a, msb_shift);
        IrValue msb_bit = ctx.emit_binop(IrOp::And, msb, one_t);
        of_new = ctx.emit_cmp(IrOp::CmpNe, msb_bit, zero_t);
    } else {
        of_new = ctx.imm(0, IrType::I1);
    }
    ctx.emit_set_flag(Flag::Of,
        ctx.select(nonzero, of_new, ctx.flag_val(Flag::Of)));

    IrValue zf_new = ctx.emit_cmp(IrOp::CmpEq, shifted, zero_t);
    IrValue sf_new = ctx.emit_cmp(IrOp::CmpSlt, shifted, zero_t);
    ctx.emit_set_flag(Flag::Zf,
        ctx.select(nonzero, zf_new, ctx.flag_val(Flag::Zf)));
    ctx.emit_set_flag(Flag::Sf,
        ctx.select(nonzero, sf_new, ctx.flag_val(Flag::Sf)));
    update_shift_parity(ctx, shifted, original_count, nonzero);
    store_lvalue(insn.operands[0], r, ctx);
}

void lift_shl(LiftCtx& ctx) { lift_shift(ctx, IrOp::Shl);  }

void lift_shr(LiftCtx& ctx) { lift_shift(ctx, IrOp::Lshr); }

void lift_sar(LiftCtx& ctx) { lift_shift(ctx, IrOp::Ashr); }

// ROL/ROR are common in hashes, PRNGs, checksums, and crypto-ish mixers.
// Preserve their value flow as rotate intrinsics instead of falling back to
// a side-effect-only `/* x64.rol(...) */` comment. A masked zero count preserves
// CF/OF; OF is defined only for count one. ZF/SF/PF remain unchanged.
void lift_rotate(LiftCtx& ctx, bool right) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2) return;

    IrValue a = materialize_rvalue(insn.operands[0], ctx);
    IrValue cnt = materialize_rvalue(insn.operands[1], ctx);
    if (a.kind == IrValueKind::None || cnt.kind == IrValueKind::None) return;
    cnt = ctx.match_size(cnt, a.type, /*sign_ext=*/false);

    const unsigned width = type_bits(a.type);
    const IrValue masked_count = ctx.emit_binop(IrOp::And, cnt,
        ctx.imm(width == 64 ? 63 : 31, a.type));
    const IrValue nonzero = ctx.emit_cmp(IrOp::CmpNe, masked_count,
                                         ctx.imm(0, a.type));
    IrInst i;
    i.op   = IrOp::Intrinsic;
    i.name = std::format("{}{}", right ? "rotr" : "rotl", width);
    i.dst  = ctx.temp(a.type);
    i.srcs[0]   = a;
    i.srcs[1]   = masked_count;
    i.src_count = 2;
    IrValue r = i.dst;
    ctx.emit(std::move(i));

    IrValue one_t  = ctx.imm(1, a.type);
    IrValue zero_t = ctx.imm(0, a.type);
    IrValue cf_bit;
    if (right) {
        IrValue msb_shift = ctx.imm(static_cast<i64>(width - 1), a.type);
        cf_bit = ctx.emit_binop(IrOp::And,
                                ctx.emit_binop(IrOp::Lshr, r, msb_shift),
                                one_t);
    } else {
        cf_bit = ctx.emit_binop(IrOp::And, r, one_t);
    }
    IrValue cf_i1 = ctx.emit_cmp(IrOp::CmpNe, cf_bit, zero_t);
    ctx.emit_set_flag(Flag::Cf, ctx.select(nonzero, cf_i1, ctx.flag_val(Flag::Cf)));

    if (width > 1) {
        IrValue msb_shift = ctx.imm(static_cast<i64>(width - 1), a.type);
        IrValue msb_bit = ctx.emit_binop(IrOp::And,
                                         ctx.emit_binop(IrOp::Lshr, r, msb_shift),
                                         one_t);
        IrValue msb_i1 = ctx.emit_cmp(IrOp::CmpNe, msb_bit, zero_t);
        if (right) {
            IrValue next_shift = ctx.imm(static_cast<i64>(width - 2), a.type);
            IrValue next_bit = ctx.emit_binop(IrOp::And,
                                             ctx.emit_binop(IrOp::Lshr, r, next_shift),
                                             one_t);
            IrValue next_i1 = ctx.emit_cmp(IrOp::CmpNe, next_bit, zero_t);
            ctx.emit_set_flag(Flag::Of, ctx.select(nonzero,
                ctx.emit_binop_i1(IrOp::Xor, msb_i1, next_i1), ctx.flag_val(Flag::Of)));
        } else {
            ctx.emit_set_flag(Flag::Of, ctx.select(nonzero,
                ctx.emit_binop_i1(IrOp::Xor, msb_i1, cf_i1), ctx.flag_val(Flag::Of)));
        }
    }

    store_lvalue(insn.operands[0], r, ctx);
}

// RCL/RCR are rotates through the carry flag. For count==1 we can lower them
// exactly with ordinary IR; for wider counts preserve value flow with an
// explicit carry-aware intrinsic instead of discarding the destination update.
void lift_rotate_through_carry(LiftCtx& ctx, bool right) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2) return;

    IrValue a = materialize_rvalue(insn.operands[0], ctx);
    IrValue cnt = materialize_rvalue(insn.operands[1], ctx);
    if (a.kind == IrValueKind::None || cnt.kind == IrValueKind::None) return;
    const bool count_is_one =
        cnt.kind == IrValueKind::Imm && cnt.imm == 1;
    cnt = ctx.match_size(cnt, a.type, /*sign_ext=*/false);

    const unsigned width = type_bits(a.type);
    IrValue one_t  = ctx.imm(1, a.type);
    IrValue zero_t = ctx.imm(0, a.type);
    IrValue cf_in  = ctx.flag_val(Flag::Cf);
    IrValue r;

    if (count_is_one) {
        IrValue cf_w = ctx.emit_convert(IrOp::ZExt, cf_in, a.type);
        if (right) {
            IrValue hi_shift = ctx.imm(static_cast<i64>(width - 1), a.type);
            IrValue hi = ctx.emit_binop(IrOp::Shl, cf_w, hi_shift);
            r = ctx.emit_binop(IrOp::Or,
                               ctx.emit_binop(IrOp::Lshr, a, one_t),
                               hi);
        } else {
            r = ctx.emit_binop(IrOp::Or,
                               ctx.emit_binop(IrOp::Shl, a, one_t),
                               cf_w);
        }
    } else {
        IrInst i;
        i.op   = IrOp::Intrinsic;
        i.name = std::format("{}{}", right ? "rcr" : "rcl", width);
        i.dst  = ctx.temp(a.type);
        i.srcs[0]   = a;
        i.srcs[1]   = cnt;
        i.srcs[2]   = cf_in;
        i.src_count = 3;
        r = i.dst;
        ctx.emit(std::move(i));
    }

    IrValue cf_out;
    if (count_is_one) {
        IrValue cf_bit;
        if (right) {
            cf_bit = ctx.emit_binop(IrOp::And, a, one_t);
        } else {
            IrValue msb_shift = ctx.imm(static_cast<i64>(width - 1), a.type);
            cf_bit = ctx.emit_binop(IrOp::And,
                                    ctx.emit_binop(IrOp::Lshr, a, msb_shift),
                                    one_t);
        }
        cf_out = ctx.emit_cmp(IrOp::CmpNe, cf_bit, zero_t);
    } else {
        // The value intrinsic cannot expose a second result. Preserve the
        // exact carry transition in a companion intrinsic, including the
        // architectural effective-count-zero case where CF is unchanged.
        IrInst c;
        c.op = IrOp::Intrinsic;
        c.name = std::format("{}_cf{}", right ? "rcr" : "rcl", width);
        c.dst = ctx.temp(IrType::I1);
        c.srcs[0] = a; c.srcs[1] = cnt; c.srcs[2] = cf_in; c.src_count = 3;
        cf_out = c.dst;
        ctx.emit(std::move(c));
    }
    ctx.emit_set_flag(Flag::Cf, cf_out);

    // OF is architecturally defined only for a one-bit rotate.
    if (width > 1 && count_is_one) {
        IrValue msb_shift = ctx.imm(static_cast<i64>(width - 1), a.type);
        IrValue msb_bit = ctx.emit_binop(IrOp::And,
                                         ctx.emit_binop(IrOp::Lshr, r, msb_shift),
                                         one_t);
        IrValue msb_i1 = ctx.emit_cmp(IrOp::CmpNe, msb_bit, zero_t);
        if (right) {
            IrValue next_shift = ctx.imm(static_cast<i64>(width - 2), a.type);
            IrValue next_bit = ctx.emit_binop(IrOp::And,
                                             ctx.emit_binop(IrOp::Lshr, r, next_shift),
                                             one_t);
            IrValue next_i1 = ctx.emit_cmp(IrOp::CmpNe, next_bit, zero_t);
            ctx.emit_set_flag(Flag::Of, ctx.emit_binop_i1(IrOp::Xor, msb_i1, next_i1));
        } else {
            ctx.emit_set_flag(Flag::Of, ctx.emit_binop_i1(IrOp::Xor, msb_i1, cf_out));
        }
    }

    store_lvalue(insn.operands[0], r, ctx);
}

// SHLD/SHRD use masked counts; effective zero preserves the value and flags.
void lift_double_shift(LiftCtx& ctx, bool right) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 3) return;
    IrValue dst = materialize_rvalue(insn.operands[0], ctx);
    IrValue src = materialize_rvalue(insn.operands[1], ctx);
    IrValue cnt = materialize_rvalue(insn.operands[2], ctx);
    const IrValue original_count = cnt;
    src = ctx.match_size(src, dst.type, /*sign_ext=*/false);
    cnt = ctx.match_size(cnt, dst.type, /*sign_ext=*/false);

    const unsigned width = type_bits(dst.type);
    const IrValue zero = ctx.imm(0, dst.type);
    const IrValue one = ctx.imm(1, dst.type);
    cnt = ctx.emit_binop(IrOp::And, cnt, ctx.imm(width == 64 ? 63 : 31, dst.type));
    const IrValue nonzero = ctx.emit_cmp(IrOp::CmpNe, cnt, zero);
    const IrValue safe_count = ctx.select(nonzero, cnt, one);
    const IrValue complement = ctx.emit_binop(IrOp::Sub,
        ctx.imm(static_cast<i64>(width), dst.type), safe_count);
    const IrValue lo = ctx.emit_binop(right ? IrOp::Lshr : IrOp::Shl, dst, safe_count);
    const IrValue hi = ctx.emit_binop(right ? IrOp::Shl : IrOp::Lshr, src, complement);
    const IrValue shifted = ctx.emit_binop(IrOp::Or, lo, hi);
    const IrValue result = ctx.select(nonzero, shifted, dst);

    const IrValue carry_shift = right
        ? ctx.emit_binop(IrOp::Sub, safe_count, one) : complement;
    const IrValue carry_bit = ctx.emit_binop(IrOp::And,
        ctx.emit_binop(IrOp::Lshr, dst, carry_shift), one);
    const IrValue carry = ctx.emit_cmp(IrOp::CmpNe, carry_bit, zero);
    const IrValue sign_change = ctx.emit_cmp(IrOp::CmpSlt,
        ctx.emit_binop(IrOp::Xor, dst, shifted), zero);
    ctx.emit_set_flag(Flag::Cf, ctx.select(nonzero, carry, ctx.flag_val(Flag::Cf)));
    // OF is defined for count one; larger nonzero counts leave it undefined.
    ctx.emit_set_flag(Flag::Of, ctx.select(nonzero, sign_change, ctx.flag_val(Flag::Of)));
    ctx.emit_set_flag(Flag::Zf, ctx.select(nonzero,
        ctx.emit_cmp(IrOp::CmpEq, shifted, zero), ctx.flag_val(Flag::Zf)));
    ctx.emit_set_flag(Flag::Sf, ctx.select(nonzero,
        ctx.emit_cmp(IrOp::CmpSlt, shifted, zero), ctx.flag_val(Flag::Sf)));
    update_shift_parity(ctx, shifted, original_count, nonzero);
    store_lvalue(insn.operands[0], result, ctx);
}

// 1-op MUL/IMUL: rax = rax * src, with the high half going into rdx (or
// AH for byte form). We model this by widening both operands to 2W and
// computing the full product, then assigning the low half back to rax/eax/...
// and the high half to rdx/edx/... For 64-bit we don't have I128, so the
// high half degrades to a named `mulh.{s,u}` intrinsic that still carries
// both source operands so the reader can see what's being multiplied.
//
// `signed_mul` selects IMUL (SExt) vs MUL (ZExt).
void lift_mul_one_op(LiftCtx& ctx, bool signed_mul) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 1) return;
    IrValue b = materialize_rvalue(insn.operands[0], ctx);
    const IrType t = b.type;
    const unsigned bits = type_bits(t);

    Reg lo_a, lo_dst, hi_dst;
    switch (bits) {
        case 8:  lo_a = Reg::Al;  lo_dst = Reg::Ax;  hi_dst = Reg::None; break;
        case 16: lo_a = Reg::Ax;  lo_dst = Reg::Ax;  hi_dst = Reg::Dx;   break;
        case 32: lo_a = Reg::Eax; lo_dst = Reg::Eax; hi_dst = Reg::Edx;  break;
        default: lo_a = Reg::Rax; lo_dst = Reg::Rax; hi_dst = Reg::Rdx;  break;
    }
    IrValue a = ctx.read_reg(lo_a);

    if (bits <= 32) {
        const IrType wide = type_for_bits(bits * 2);
        IrOp ext = signed_mul ? IrOp::SExt : IrOp::ZExt;
        IrValue aw = ctx.emit_convert(ext, a, wide);
        IrValue bw = ctx.emit_convert(ext, b, wide);
        IrValue prod = ctx.emit_binop(IrOp::Mul, aw, bw);
        if (bits == 8) {
            // mul al, r/m8 → ax = al * r/m. Whole AX is the product.
            ctx.write_reg(lo_dst, prod);
        } else {
            IrValue lo = ctx.emit_convert(IrOp::Trunc, prod, t);
            IrValue shift = ctx.emit_binop(IrOp::Lshr, prod,
                                            ctx.imm(static_cast<i64>(bits), wide));
            IrValue hi = ctx.emit_convert(IrOp::Trunc, shift, t);
            ctx.write_reg(lo_dst, lo);
            ctx.write_reg(hi_dst, hi);
        }
    } else {
        // Both products must read the original registers before either write.
        IrValue lo = ctx.emit_binop(IrOp::Mul, a, b);

        IrInst high;
        high.op   = IrOp::Intrinsic;
        high.name = signed_mul ? "mulh.s.64" : "mulh.u.64";
        high.dst  = ctx.temp(t);
        high.srcs[0] = a;
        high.srcs[1] = b;
        high.src_count = 2;
        IrValue hi_v = high.dst;
        ctx.emit(std::move(high));
        ctx.write_reg(lo_dst, lo);
        ctx.write_reg(hi_dst, hi_v);
    }
}

void lift_imul(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands == 2) {
        IrValue a = materialize_rvalue(insn.operands[0], ctx);
        IrValue b = materialize_rvalue(insn.operands[1], ctx);
        b = ctx.match_size(b, a.type, /*sign_ext=*/true);
        IrValue r = ctx.emit_binop(IrOp::Mul, a, b);
        store_lvalue(insn.operands[0], r, ctx);
    } else if (insn.num_operands == 3) {
        IrValue a = materialize_rvalue(insn.operands[1], ctx);
        IrValue b = materialize_rvalue(insn.operands[2], ctx);
        b = ctx.match_size(b, a.type, /*sign_ext=*/true);
        IrValue r = ctx.emit_binop(IrOp::Mul, a, b);
        store_lvalue(insn.operands[0], r, ctx);
    } else {
        lift_mul_one_op(ctx, /*signed_mul=*/true);
    }
}

void lift_mul(LiftCtx& ctx) {
    lift_mul_one_op(ctx, /*signed_mul=*/false);
}

// DIV / IDIV r/m: divides (rdx:rax) by r/m, writes quotient to rax/al and
// remainder to rdx/ah. Dividend is built by combining the implicit register
// pair widened to 2W; for 64-bit we don't have I128 so we degrade to named
// `divq.{s,u}.64` / `divr.{s,u}.64` intrinsics that carry both halves of
// the dividend explicitly (same shape as the 64-bit MUL path's
// `mulh.{s,u}.64`).
void lift_div_one_op(LiftCtx& ctx, bool signed_div) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 1) return;
    IrValue divisor = materialize_rvalue(insn.operands[0], ctx);
    const IrType t = divisor.type;
    const unsigned bits = type_bits(t);

    Reg lo_a, hi_a, lo_dst, hi_dst;
    switch (bits) {
        case 8:  lo_a = Reg::Al;  hi_a = Reg::None; lo_dst = Reg::Al;  hi_dst = Reg::Ah;  break;
        case 16: lo_a = Reg::Ax;  hi_a = Reg::Dx;   lo_dst = Reg::Ax;  hi_dst = Reg::Dx;  break;
        case 32: lo_a = Reg::Eax; hi_a = Reg::Edx;  lo_dst = Reg::Eax; hi_dst = Reg::Edx; break;
        default: lo_a = Reg::Rax; hi_a = Reg::Rdx;  lo_dst = Reg::Rax; hi_dst = Reg::Rdx; break;
    }

    if (bits == 8) {
        // 8-bit divide: AX / r/m8 → AL=quot, AH=rem. AX is already a wider
        // version of the dividend register pair.
        IrValue ax = ctx.read_reg(Reg::Ax);
        IrOp ext = signed_div ? IrOp::SExt : IrOp::ZExt;
        IrValue dw = ctx.emit_convert(ext, divisor, IrType::I16);
        IrValue q  = ctx.emit_binop(IrOp::Div, ax, dw);
        IrValue r  = ctx.emit_binop(IrOp::Mod, ax, dw);
        IrValue ql = ctx.emit_convert(IrOp::Trunc, q, IrType::I8);
        IrValue rl = ctx.emit_convert(IrOp::Trunc, r, IrType::I8);
        ctx.write_reg(lo_dst, ql);
        ctx.write_reg(hi_dst, rl);
        return;
    }

    if (bits <= 32) {
        const IrType wide = type_for_bits(bits * 2);
        IrOp ext = signed_div ? IrOp::SExt : IrOp::ZExt;
        IrValue lo = ctx.read_reg(lo_a);
        IrValue dividend;
        if (signed_div && ctx.last_signext_dividend_valid &&
            ctx.last_signext_dividend_type == t) {
            dividend = ctx.emit_convert(IrOp::SExt, lo, wide);
        } else {
            IrValue hi = ctx.read_reg(hi_a);
            IrValue lo_w = ctx.emit_convert(IrOp::ZExt, lo, wide);
            IrValue hi_w = ctx.emit_convert(ext,        hi, wide);
            IrValue hi_shift = ctx.emit_binop(IrOp::Shl, hi_w,
                                               ctx.imm(static_cast<i64>(bits), wide));
            dividend = ctx.emit_binop(IrOp::Or, hi_shift, lo_w);
        }
        IrValue dw = ctx.emit_convert(ext, divisor, wide);
        IrValue q  = ctx.emit_binop(IrOp::Div, dividend, dw);
        IrValue r  = ctx.emit_binop(IrOp::Mod, dividend, dw);
        IrValue ql = ctx.emit_convert(IrOp::Trunc, q, t);
        IrValue rl = ctx.emit_convert(IrOp::Trunc, r, t);
        ctx.write_reg(lo_dst, ql);
        ctx.write_reg(hi_dst, rl);
        return;
    }

    // 64-bit: no I128, so we degrade to named intrinsics that carry both
    // halves of the dividend explicitly - same shape as the 64-bit MUL
    // path's `mulh.{s,u}.64`. The reader sees `divq_u64(rdx, rax, b)` so
    // it's visible that RDX participates; the constant folder skips
    // intrinsics, so the wrong-arithmetic class of bug from folding
    // `Div(rax, b)` against a sign-extended i64 imm goes away too.
    //
    // `xor edx, edx; div r64` and `cqo; idiv r64` both still render
    // correctly - the reader sees the constant 0 (or the sign-extended
    // RAX high half) flowing into the high arg.
    IrValue rax = ctx.read_reg(Reg::Rax);
    IrValue rdx = ctx.read_reg(Reg::Rdx);

    IrInst qi;
    qi.op   = IrOp::Intrinsic;
    qi.name = signed_div ? "divq.s.64" : "divq.u.64";
    qi.dst  = ctx.temp(t);
    qi.srcs[0] = rdx;
    qi.srcs[1] = rax;
    qi.srcs[2] = divisor;
    qi.src_count = 3;
    IrValue q = qi.dst;
    ctx.emit(std::move(qi));

    IrInst ri;
    ri.op   = IrOp::Intrinsic;
    ri.name = signed_div ? "divr.s.64" : "divr.u.64";
    ri.dst  = ctx.temp(t);
    ri.srcs[0] = rdx;
    ri.srcs[1] = rax;
    ri.srcs[2] = divisor;
    ri.src_count = 3;
    IrValue r = ri.dst;
    ctx.emit(std::move(ri));

    ctx.write_reg(lo_dst, q);
    ctx.write_reg(hi_dst, r);
}

// CDQ / CQO: sign-extend the implicit low dividend register into the high
// half consumed by IDIV. Model it as a select so signed `/` and `%` can fold
// through real RDX/EDX dataflow instead of an opaque side-effect intrinsic.
void lift_sign_extend_dividend_high(LiftCtx& ctx, IrType t) {
    const Reg lo = t == IrType::I64 ? Reg::Rax : Reg::Eax;
    const Reg hi = t == IrType::I64 ? Reg::Rdx : Reg::Edx;
    IrValue v = ctx.read_reg(lo);
    IrValue neg = ctx.emit_cmp(IrOp::CmpSlt, v, ctx.imm(0, t));

    IrInst sel;
    sel.op        = IrOp::Select;
    sel.dst       = ctx.temp(t);
    sel.srcs[0]   = neg;
    sel.srcs[1]   = ctx.imm(-1, t);
    sel.srcs[2]   = ctx.imm(0, t);
    sel.src_count = 3;
    IrValue high = sel.dst;
    ctx.emit(std::move(sel));
    ctx.write_reg(hi, high);
    ctx.last_signext_dividend_valid = true;
    ctx.last_signext_dividend_type = t;
}

// ADC dst, src: dst = dst + src + CF. Update CF/OF/ZF/SF.
// SBB dst, src: dst = dst - src - CF.
// We model carry by widening to I1 and adding into the result; CF/OF for the
// combined operation are computed against (a OP b) - the second-step carry
// from adding the cf bit is folded in via OR with the first-step carry.
// That's an approximation: in cases where (a+b) doesn't overflow but
// (a+b+1) does, OF will miss the second step. The dataflow side (the actual
// sum/difference) is exact.
void lift_adc_sbb(LiftCtx& ctx, bool subtract) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2) return;
    IrValue a = materialize_rvalue(insn.operands[0], ctx);
    IrValue b = materialize_rvalue(insn.operands[1], ctx);
    b = ctx.match_size(b, a.type, /*sign_ext=*/true);
    IrValue cf  = ctx.flag_val(Flag::Cf);
    IrValue cf_w = ctx.emit_convert(IrOp::ZExt, cf, a.type);

    IrOp op_main   = subtract ? IrOp::Sub        : IrOp::Add;
    IrOp op_carry  = subtract ? IrOp::SubBorrow  : IrOp::AddCarry;
    IrOp op_over   = subtract ? IrOp::SubOverflow: IrOp::AddOverflow;

    IrValue mid = ctx.emit_binop(op_main, a, b);
    IrValue r   = ctx.emit_binop(op_main, mid, cf_w);

    IrValue cf1 = ctx.emit_binop_i1(op_carry, a, b);
    IrValue cf2 = ctx.emit_binop_i1(op_carry, mid, cf_w);
    ctx.emit_set_flag(Flag::Cf, ctx.emit_binop_i1(IrOp::Or, cf1, cf2));
    IrValue of1 = ctx.emit_binop_i1(op_over, a, b);
    IrValue of2 = ctx.emit_binop_i1(op_over, mid, cf_w);
    ctx.emit_set_flag(Flag::Of, ctx.emit_binop_i1(IrOp::Or, of1, of2));
    ctx.set_zf_sf(r);
    store_lvalue(insn.operands[0], r, ctx);
}

}  // namespace ember::x64_lift

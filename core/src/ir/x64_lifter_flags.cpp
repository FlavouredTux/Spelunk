// RFLAGS materialization, LAHF/SAHF, carry-flag ops, BMI and FMA.

#include <string>
#include <string_view>
#include <utility>

#include <spelunk/common/types.hpp>
#include <spelunk/disasm/instruction.hpp>
#include <spelunk/disasm/register.hpp>
#include <spelunk/ir/ir.hpp>

#include "x64_lifter_internal.hpp"

namespace spelunk::x64_lift {

void update_shift_parity(LiftCtx& ctx, IrValue result,
                         IrValue original_count, IrValue nonzero) {
    const u64 mask = type_bits(result.type) == 64 ? 63u : 31u;
    const bool known = original_count.kind == IrValueKind::Imm;
    if (known && (static_cast<u64>(original_count.imm) & mask) == 0) return;
    IrValue previous;
    if (!known) previous = jcc_predicate(Mnemonic::Jp, ctx);
    ctx.last_flag_src = result;
    ctx.last_pf_value = {};
    ctx.last_fp_cmp_a = {};
    ctx.last_fp_cmp_b = {};
    if (!known) {
        const IrValue updated = jcc_predicate(Mnemonic::Jp, ctx);
        ctx.last_pf_value = ctx.select(nonzero, updated, previous);
        ctx.last_flag_src = {};
    }
}

IrValue flag_to_i64_bit(LiftCtx& ctx, IrValue flag, unsigned shift) {
    IrValue bit = ctx.emit_convert(IrOp::ZExt, flag, IrType::I64);
    if (shift != 0) {
        bit = ctx.emit_binop(IrOp::Shl, bit,
                             ctx.imm(static_cast<i64>(shift), IrType::I64));
    }
    return bit;
}

IrValue bit_from_i64(LiftCtx& ctx, IrValue v, unsigned bit) {
    IrValue masked = ctx.emit_binop(IrOp::And, v,
                                    ctx.imm(static_cast<i64>(u64{1} << bit),
                                            IrType::I64));
    return ctx.emit_cmp(IrOp::CmpNe, masked, ctx.imm(0, IrType::I64));
}

IrValue build_rflags_value(LiftCtx& ctx) {
    IrValue rflags = ctx.imm(0x2, IrType::I64);  // bit 1 is architecturally set
    rflags = ctx.emit_binop(IrOp::Or, rflags,
                            flag_to_i64_bit(ctx, ctx.flag_val(Flag::Cf), 0));
    rflags = ctx.emit_binop(IrOp::Or, rflags,
                            flag_to_i64_bit(ctx, jcc_predicate(Mnemonic::Jp, ctx), 2));
    rflags = ctx.emit_binop(IrOp::Or, rflags,
                            flag_to_i64_bit(ctx, ctx.flag_val(Flag::Zf), 6));
    rflags = ctx.emit_binop(IrOp::Or, rflags,
                            flag_to_i64_bit(ctx, ctx.flag_val(Flag::Sf), 7));
    rflags = ctx.emit_binop(IrOp::Or, rflags,
                            flag_to_i64_bit(ctx, ctx.flag_val(Flag::Of), 11));
    return rflags;
}

void restore_rflags_value(LiftCtx& ctx, IrValue rflags) {
    rflags = ctx.match_size(rflags, IrType::I64, /*sign_ext=*/false);
    IrValue cf = bit_from_i64(ctx, rflags, 0);
    IrValue pf = bit_from_i64(ctx, rflags, 2);
    IrValue zf = bit_from_i64(ctx, rflags, 6);
    IrValue sf = bit_from_i64(ctx, rflags, 7);
    IrValue of = bit_from_i64(ctx, rflags, 11);

    ctx.emit_set_flag(Flag::Cf, cf);
    ctx.emit_set_flag(Flag::Zf, zf);
    ctx.emit_set_flag(Flag::Sf, sf);
    ctx.emit_set_flag(Flag::Of, of);
    ctx.last_pf_value = pf;
    ctx.last_flag_src = {};
    ctx.last_fp_cmp_a = {};
    ctx.last_fp_cmp_b = {};
}

void lift_pushf(LiftCtx& ctx) {
    IrValue rflags = build_rflags_value(ctx);
    IrValue rsp = ctx.reg(Reg::Rsp);
    IrValue new_rsp = ctx.emit_binop(IrOp::Sub, rsp, ctx.imm(8, IrType::I64));
    ctx.emit_store(new_rsp, rflags);
    ctx.emit_assign(ctx.reg(Reg::Rsp), new_rsp);
}

void lift_popf(LiftCtx& ctx) {
    IrValue rsp = ctx.reg(Reg::Rsp);
    IrValue rflags = ctx.emit_load(rsp, IrType::I64);
    IrValue new_rsp = ctx.emit_binop(IrOp::Add, rsp, ctx.imm(8, IrType::I64));
    ctx.emit_assign(ctx.reg(Reg::Rsp), new_rsp);
    restore_rflags_value(ctx, rflags);
}

void lift_leave(LiftCtx& ctx) {
    IrValue rbp = ctx.reg(Reg::Rbp);
    ctx.emit_assign(ctx.reg(Reg::Rsp), rbp);
    IrValue rsp = ctx.reg(Reg::Rsp);
    IrValue val = ctx.emit_load(rsp, IrType::I64);
    IrValue new_rsp = ctx.emit_binop(IrOp::Add, rsp, ctx.imm(8, IrType::I64));
    ctx.emit_assign(ctx.reg(Reg::Rbp), val);
    ctx.emit_assign(ctx.reg(Reg::Rsp), new_rsp);
}

IrValue flag_to_i8_bit(LiftCtx& ctx, IrValue flag, unsigned shift) {
    IrValue bit = ctx.emit_convert(IrOp::ZExt, flag, IrType::I8);
    if (shift != 0) {
        bit = ctx.emit_binop(IrOp::Shl, bit,
                             ctx.imm(static_cast<i64>(shift), IrType::I8));
    }
    return bit;
}

IrValue bit_from_ah(LiftCtx& ctx, IrValue ah, unsigned bit) {
    IrValue masked = ctx.emit_binop(IrOp::And, ah,
                                    ctx.imm(static_cast<i64>(1u << bit), IrType::I8));
    return ctx.emit_cmp(IrOp::CmpNe, masked, ctx.imm(0, IrType::I8));
}

void lift_lahf(LiftCtx& ctx) {
    IrValue cf = flag_to_i8_bit(ctx, ctx.flag_val(Flag::Cf), 0);
    IrValue pf = flag_to_i8_bit(ctx, jcc_predicate(Mnemonic::Jp, ctx), 2);
    IrValue zf = flag_to_i8_bit(ctx, ctx.flag_val(Flag::Zf), 6);
    IrValue sf = flag_to_i8_bit(ctx, ctx.flag_val(Flag::Sf), 7);

    IrValue ah = ctx.imm(0x02, IrType::I8);
    ah = ctx.emit_binop(IrOp::Or, ah, cf);
    ah = ctx.emit_binop(IrOp::Or, ah, pf);
    ah = ctx.emit_binop(IrOp::Or, ah, zf);
    ah = ctx.emit_binop(IrOp::Or, ah, sf);
    ctx.write_reg(Reg::Ah, ah);
}

void lift_sahf(LiftCtx& ctx) {
    IrValue ah = ctx.read_reg(Reg::Ah);
    IrValue cf = bit_from_ah(ctx, ah, 0);
    IrValue pf = bit_from_ah(ctx, ah, 2);
    IrValue zf = bit_from_ah(ctx, ah, 6);
    IrValue sf = bit_from_ah(ctx, ah, 7);

    ctx.emit_set_flag(Flag::Cf, cf);
    ctx.emit_set_flag(Flag::Zf, zf);
    ctx.emit_set_flag(Flag::Sf, sf);
    ctx.last_pf_value = pf;
    ctx.last_flag_src = {};
    ctx.last_fp_cmp_a = {};
    ctx.last_fp_cmp_b = {};
}

void lift_carry_flag_op(LiftCtx& ctx, Mnemonic mn) {
    switch (mn) {
        case Mnemonic::Clc:
            ctx.emit_set_flag(Flag::Cf, ctx.imm(0, IrType::I1));
            break;
        case Mnemonic::Stc:
            ctx.emit_set_flag(Flag::Cf, ctx.imm(1, IrType::I1));
            break;
        case Mnemonic::Cmc:
            ctx.emit_set_flag(Flag::Cf, ctx.emit_unop(IrOp::Not, ctx.flag_val(Flag::Cf)));
            break;
        default:
            break;
    }
}

void lift_bmi_three_operand(LiftCtx& ctx, Mnemonic mnemonic) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 3) return;
    IrValue first = materialize_rvalue(insn.operands[1], ctx);
    IrValue second = materialize_rvalue(insn.operands[2], ctx);
    if (first.kind == IrValueKind::None || second.kind == IrValueKind::None) return;
    const IrType result_type = operand_type(insn.operands[0]);
    first = ctx.match_size(first, result_type, /*sign_ext=*/false);
    second = ctx.match_size(second, result_type, /*sign_ext=*/false);

    IrValue result;
    if (mnemonic == Mnemonic::Andn) {
        result = ctx.emit_binop(IrOp::And, ctx.emit_unop(IrOp::Not, first), second);
        ctx.set_zf_sf(result);
        ctx.clear_cf_of();
        // ANDN leaves PF undefined, so do not infer it from the result.
        ctx.last_flag_src = {};
    } else if (mnemonic == Mnemonic::Shlx) {
        result = ctx.emit_binop(IrOp::Shl, first, second);
    } else if (mnemonic == Mnemonic::Shrx) {
        result = ctx.emit_binop(IrOp::Lshr, first, second);
    } else if (mnemonic == Mnemonic::Sarx) {
        result = ctx.emit_binop(IrOp::Ashr, first, second);
    } else {
        IrInst intrinsic;
        intrinsic.op = IrOp::Intrinsic;
        intrinsic.name = mnemonic == Mnemonic::Bzhi ? "_bzhi_u64"
            : (mnemonic == Mnemonic::Pext ? "_pext_u64" : "_pdep_u64");
        intrinsic.dst = ctx.temp(result_type);
        intrinsic.srcs[0] = first;
        intrinsic.srcs[1] = second;
        intrinsic.src_count = 2;
        result = intrinsic.dst;
        ctx.emit(std::move(intrinsic));
    }
    store_lvalue(insn.operands[0], result, ctx);
}

void lift_mulx(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 3) return;
    IrValue source = materialize_rvalue(insn.operands[2], ctx);
    if (source.kind == IrValueKind::None) return;
    const IrType result_type = operand_type(insn.operands[0]);
    source = ctx.match_size(source, result_type, /*sign_ext=*/false);
    IrValue multiplier = ctx.match_size(
        ctx.read_reg(result_type == IrType::I64 ? Reg::Rdx : Reg::Edx),
        result_type, /*sign_ext=*/false);
    IrValue results[2];
    for (u8 output = 0; output < 2; ++output) {
        IrInst intrinsic;
        intrinsic.op = IrOp::Intrinsic;
        intrinsic.name = output == 0 ? "mulx.high" : "mulx.low";
        if (result_type == IrType::I32) intrinsic.name += "32";
        intrinsic.dst = ctx.temp(result_type);
        intrinsic.srcs[0] = multiplier;
        intrinsic.srcs[1] = source;
        intrinsic.src_count = 2;
        results[output] = intrinsic.dst;
        ctx.emit(std::move(intrinsic));
    }
    for (u8 output = 0; output < 2; ++output)
        store_lvalue(insn.operands[output], results[output], ctx);
}

void lift_fma(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 3) return;
    const bool scalar_single = insn.mnemonic == Mnemonic::Vfmadd132ss ||
        insn.mnemonic == Mnemonic::Vfmadd213ss ||
        insn.mnemonic == Mnemonic::Vfmadd231ss;
    const bool scalar_double = insn.mnemonic == Mnemonic::Vfmadd132sd ||
        insn.mnemonic == Mnemonic::Vfmadd213sd ||
        insn.mnemonic == Mnemonic::Vfmadd231sd;
    IrType type = scalar_single ? IrType::F32 :
        (scalar_double ? IrType::F64 :
            (insn.x86_vector_bits == 3 ? IrType::I512 :
             (insn.x86_vector_bits == 2 ? IrType::I256 : IrType::I128)));
    IrValue destination = read_xmm(ctx, insn.operands[0], type);
    IrValue first = read_xmm(ctx, insn.operands[1], type);
    IrValue second = read_xmm(ctx, insn.operands[2], type);
    if (destination.kind == IrValueKind::None || first.kind == IrValueKind::None ||
        second.kind == IrValueKind::None) return;
    IrInst intrinsic;
    intrinsic.op = IrOp::Intrinsic;
    intrinsic.name = std::string(mnemonic_name(insn.mnemonic));
    if (type == IrType::I256) intrinsic.name = "_mm256_" + intrinsic.name;
    else if (type == IrType::I512) intrinsic.name = "_mm512_" + intrinsic.name;
    intrinsic.dst = ctx.temp(type);
    intrinsic.srcs[0] = destination;
    intrinsic.srcs[1] = first;
    intrinsic.srcs[2] = second;
    intrinsic.src_count = 3;
    IrValue result = intrinsic.dst;
    ctx.emit(std::move(intrinsic));
    write_xmm(ctx, insn.operands[0], result, type);
}

void lift_intrinsic(LiftCtx& ctx, std::string_view name) {
    const auto& insn = *ctx.insn;
    IrInst i;
    i.op   = IrOp::Intrinsic;
    i.name = std::string(name);
    // Pull up to 3 operands through as sources so atomics (xadd, cmpxchg,
    // lock xchg, ...) render with their arguments instead of as empty
    // `xadd();` calls. Memory operands lift as loads, which is accurate
    // for the read-modify-write side and at worst slightly lossy for the
    // write-back - still more useful than nothing.
    for (u8 j = 0; j < insn.num_operands && j < 3; ++j) {
        IrValue v = materialize_rvalue(insn.operands[j], ctx);
        if (v.kind == IrValueKind::None) break;
        i.srcs[i.src_count++] = v;
    }
    ctx.emit(std::move(i));
}

}  // namespace spelunk::x64_lift
